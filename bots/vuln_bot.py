"""
VULNERABILITY BOT
=================
Posts vulnerabilities worth knowing about, with the context you need to triage:

  * CISA KEV  – "Known Exploited Vulnerabilities": attackers are using these NOW.
                Every new KEV entry is posted (to its own channel if you like).
  * NVD       – the US National Vulnerability Database. We look at CVEs that were
                published or (re)scored recently and post the ones that pass your
                filters in config.yaml (severity, watchlist, EPSS).
  * EPSS      – FIRST's Exploit Prediction Scoring System: the probability a CVE
                gets exploited in the next 30 days. Added to every post.

Run it:
    python -m bots.vuln_bot --dry-run
    python -m bots.vuln_bot
    python -m bots.vuln_bot --fixtures lessons/sample_data --dry-run   # offline
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from .common import ROOT, STATE_DIR, State, env, http_session, iso, load_config, load_dotenv, parse_iso, setup_logging, utcnow
from .discord_post import COLOURS, Webhook, build_embed, truncate

log = logging.getLogger("bots.vulns")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

SEV_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Newest CVSS version first. CVSS v4.0 is newest, v2 is legacy.
METRIC_KEYS = [("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")]

# Which reference links are most useful, and how to label them.
REF_PRIORITY = [
    ("Vendor Advisory", "Vendor advisory"),
    ("Patch", "Patch"),
    ("Mitigation", "Mitigation"),
    ("Exploit", "Exploit / PoC"),
    ("Third Party Advisory", "Advisory"),
]


@dataclass
class Vuln:
    cve_id: str
    description: str = ""
    published: datetime | None = None
    status: str = ""
    severity: str | None = None
    score: float | None = None
    cvss_version: str | None = None
    vector: str | None = None
    cwes: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    references: list[tuple[str, list[str]]] = field(default_factory=list)
    epss: float | None = None
    percentile: float | None = None


# --------------------------------------------------------------------------- #
#  Parsing NVD's JSON
# --------------------------------------------------------------------------- #
def best_metric(metrics: dict) -> tuple[str | None, float | None, str | None, str | None]:
    """Pick the CVSS score to show: newest version, NVD's own score preferred.

    'Primary' = scored by NVD analysts. 'Secondary' = scored by the CNA (often
    the vendor). Brand-new CVEs frequently only have a Secondary score.
    """
    for key, version in METRIC_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        entries = sorted(entries, key=lambda m: m.get("type") != "Primary")
        metric = entries[0]
        data = metric.get("cvssData", {})
        severity = data.get("baseSeverity") or metric.get("baseSeverity")  # v2 keeps it outside cvssData
        return (severity.upper() if severity else None, data.get("baseScore"), version, data.get("vectorString"))
    return None, None, None, None


def cpe_to_name(cpe: str) -> str | None:
    """cpe:2.3:a:fortinet:fortios:7.2.0:*:... → 'fortinet fortios'"""
    parts = cpe.split(":")
    if len(parts) < 5:
        return None
    return f"{parts[3]} {parts[4]}".replace("_", " ").title()


def parse_nvd(cve: dict) -> Vuln:
    severity, score, version, vector = best_metric(cve.get("metrics", {}))
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")

    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            value = d.get("value", "")
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)

    products: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                name = cpe_to_name(match.get("criteria", "")) if match.get("vulnerable") else None
                if name and name not in products:
                    products.append(name)

    return Vuln(
        cve_id=cve["id"],
        description=description,
        published=parse_iso(cve.get("published")),
        status=cve.get("vulnStatus", ""),
        severity=severity,
        score=score,
        cvss_version=version,
        vector=vector,
        cwes=cwes,
        products=products,
        references=[(r["url"], r.get("tags", [])) for r in cve.get("references", []) if r.get("url")],
    )


# --------------------------------------------------------------------------- #
#  Fetching
# --------------------------------------------------------------------------- #
def nvd_time(dt: datetime) -> str:
    """NVD wants e.g. 2026-10-16T09:00:00.000 (UTC)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def nvd_get(session, params: dict, api_key: str | None) -> dict:
    headers = {"apiKey": api_key} if api_key else {}
    for attempt in range(3):
        resp = session.get(NVD_URL, params=params, headers=headers, timeout=60)
        # NVD answers 403 (not 429) when you go over the public rate limit.
        if resp.status_code in (403, 503) and attempt < 2:
            log.info("NVD said HTTP %s — waiting 30s and retrying", resp.status_code)
            time.sleep(30)
            continue
        resp.raise_for_status()
        return resp.json()
    raise RuntimeError("NVD unavailable")


def fetch_nvd_window(session, start: datetime, end: datetime, api_key: str | None,
                     fixtures: Path | None = None, max_pages: int = 10) -> list[dict]:
    """All CVEs *modified* between start and end (new CVEs count as modified).

    Why 'modified' and not 'published'? NVD is often days behind on scoring.
    A CVE published yesterday with no score gets its score today — that's a
    modification, so this window catches it.
    """
    if fixtures:
        data = json.loads((fixtures / "nvd.json").read_text(encoding="utf-8"))
        return [v["cve"] for v in data.get("vulnerabilities", [])]

    cves: list[dict] = []
    params = {
        "lastModStartDate": nvd_time(start),
        "lastModEndDate": nvd_time(end),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    for page in range(max_pages):
        data = nvd_get(session, params, api_key)
        cves.extend(v["cve"] for v in data.get("vulnerabilities", []))
        params["startIndex"] += params["resultsPerPage"]
        if params["startIndex"] >= data.get("totalResults", 0):
            break
        # Public limit is 5 requests / 30s; with a key it's 50 / 30s.
        time.sleep(0.7 if api_key else 6.5)
    log.info("NVD: %d CVE(s) modified in window", len(cves))
    return cves


def fetch_single_cve(session, cve_id: str, api_key: str | None, fixtures: Path | None = None) -> dict | None:
    if fixtures:
        for cve in fetch_nvd_window(session, utcnow(), utcnow(), None, fixtures):
            if cve["id"] == cve_id:
                return cve
        return None
    data = nvd_get(session, {"cveId": cve_id}, api_key)
    items = data.get("vulnerabilities", [])
    return items[0]["cve"] if items else None


def fetch_kev(session, fixtures: Path | None = None) -> list[dict]:
    if fixtures:
        data = json.loads((fixtures / "kev.json").read_text(encoding="utf-8"))
    else:
        resp = session.get(KEV_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
    log.info("KEV: catalogue version %s, %d entries", data.get("catalogVersion"), len(data.get("vulnerabilities", [])))
    return data.get("vulnerabilities", [])


def fetch_epss(session, cve_ids: list[str], fixtures: Path | None = None) -> dict[str, tuple[float, float]]:
    """{cve_id: (probability, percentile)}. Queries 100 CVEs per request."""
    scores: dict[str, tuple[float, float]] = {}
    if not cve_ids:
        return scores
    if fixtures:
        rows = json.loads((fixtures / "epss.json").read_text(encoding="utf-8")).get("data", [])
    else:
        rows = []
        for i in range(0, min(len(cve_ids), 1000), 100):
            resp = session.get(EPSS_URL, params={"cve": ",".join(cve_ids[i:i + 100])}, timeout=30)
            resp.raise_for_status()
            rows.extend(resp.json().get("data", []))
    for row in rows:
        try:
            scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
        except (KeyError, ValueError):
            continue
    return scores


# --------------------------------------------------------------------------- #
#  Filtering: is this CVE worth a post?
# --------------------------------------------------------------------------- #
def watchlist_match(v: Vuln, watchlist: list[str]) -> str | None:
    text = f"{v.description} {' '.join(v.products)}".lower()
    for term in watchlist:
        if re.search(rf"\b{re.escape(term.lower())}\b", text):
            return term
    return None


def decide_reason(v: Vuln, cfg: dict) -> str | None:
    """Return a human reason to post this CVE, or None to skip it."""
    rank = SEV_RANK.get(v.severity or "", 0)
    if rank >= SEV_RANK[cfg.get("min_severity", "CRITICAL").upper()]:
        return f"{v.severity.title()} severity"
    term = watchlist_match(v, cfg.get("watchlist", []))
    if term and rank >= SEV_RANK[cfg.get("watchlist_min_severity", "HIGH").upper()]:
        return f"{v.severity.title()} severity + on your watchlist ({term})"
    min_epss = cfg.get("min_epss")
    if min_epss is not None and v.epss is not None and v.epss >= float(min_epss):
        return f"High chance of exploitation (EPSS {v.epss:.0%})"
    return None


# --------------------------------------------------------------------------- #
#  Embeds
# --------------------------------------------------------------------------- #
def severity_text(v: Vuln | None) -> str:
    if not v or not v.severity:
        return "Not scored yet"
    return f"**{v.severity.title()}** · {v.score} (CVSS {v.cvss_version})"


def epss_text(epss: float | None, pct: float | None) -> str:
    if epss is None or pct is None:
        return "Not scored yet (new CVEs get a score within a day or so)"
    return f"**{epss:.1%}** chance in next 30 days\nTop {max((1 - pct) * 100, 0.1):.1f}% of all CVEs"


def nvd_link(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def cwe_links(cwes: list[str]) -> str:
    return " ".join(f"[{c}](https://cwe.mitre.org/data/definitions/{c.split('-')[1]}.html)" for c in cwes[:3])


def reference_links(refs: list[tuple[str, list[str]]], limit: int = 4) -> str:
    chosen: list[str] = []
    used: set[str] = set()
    for tag, label in REF_PRIORITY:
        for url, tags in refs:
            if tag in tags and url not in used and len(chosen) < limit:
                chosen.append(f"[{label}]({url})")
                used.add(url)
    for url, _ in refs:  # top up with untagged refs
        if url not in used and len(chosen) < limit:
            chosen.append(f"[{urlsplit(url).netloc or 'Reference'}]({url})")
            used.add(url)
    return " · ".join(chosen)


def vuln_embed(v: Vuln, reason: str, kev: dict | None = None) -> dict:
    product = v.products[0] if v.products else None
    title = f"{v.cve_id} — {product}" if product else v.cve_id
    if kev:
        title = "🔥 " + title
    description = truncate(v.description, 900) + f"\n\n**Why you're seeing this:** {reason}"
    known = f"**Yes** — on CISA KEV since {kev['dateAdded']}" if kev else "Not on CISA KEV (no confirmed exploitation yet)"
    return build_embed(
        title=title,
        url=nvd_link(v.cve_id),
        description=description,
        colour=COLOURS.get((v.severity or "info").lower(), COLOURS["info"]),
        fields=[
            ("Severity", severity_text(v), True),
            ("Exploit likelihood (EPSS)", epss_text(v.epss, v.percentile), True),
            ("Known exploited?", known, True),
            ("Affected", "\n".join(v.products[:4]) or "Awaiting NVD analysis", True),
            ("Weakness", cwe_links(v.cwes), True),
            ("Published", v.published.strftime("%d %b %Y") if v.published else "", True),
            ("Links", reference_links(v.references)),
        ],
        footer="Sources: NVD · FIRST EPSS · CISA KEV",
        timestamp=v.published,
    )


def kev_embed(entry: dict, v: Vuln | None) -> dict:
    cve_id = entry["cveID"]
    ransomware = "**Yes — known ransomware use**" if entry.get("knownRansomwareCampaignUse") == "Known" else "Not known"
    notes_links = [u.strip() for u in (entry.get("notes") or "").split(";") if u.strip().startswith("http")]
    links = " · ".join([f"[NVD]({nvd_link(cve_id)})"] + [f"[{urlsplit(u).netloc}]({u})" for u in notes_links[:3]])
    action = entry.get("requiredAction", "")
    if entry.get("dueDate"):
        action += f"\n_US federal agencies must fix by {entry['dueDate']} (BOD 22-01)._"
    return build_embed(
        title=f"🔥 Actively exploited: {cve_id}",
        url=nvd_link(cve_id),
        description=f"**{entry.get('vulnerabilityName', '')}**\n{entry.get('shortDescription', '')}",
        colour=COLOURS["critical"],
        fields=[
            ("Vendor / product", f"{entry.get('vendorProject', '')} {entry.get('product', '')}".strip(), True),
            ("Added to KEV", entry.get("dateAdded", ""), True),
            ("Ransomware", ransomware, True),
            ("Severity", severity_text(v), True),
            ("Exploit likelihood (EPSS)", epss_text(v.epss if v else None, v.percentile if v else None), True),
            ("Weakness", cwe_links(entry.get("cwes") or (v.cwes if v else [])), True),
            ("Required action", action),
            ("Links", links),
        ],
        footer="Source: CISA Known Exploited Vulnerabilities catalogue",
    )


def overflow_embed(extra: list[tuple[Vuln, str, dict | None]]) -> dict:
    lines = []
    for v, _, _ in extra[:25]:
        sev = f"{v.severity.title()} {v.score}" if v.severity else "Unscored"
        lines.append(f"• [{v.cve_id}]({nvd_link(v.cve_id)}) — {sev} — {truncate(v.description, 90)}")
    if len(extra) > 25:
        lines.append(f"…and {len(extra) - 25} more")
    return build_embed(
        title=f"+{len(extra)} more CVEs matched your filters this run",
        description="\n".join(lines),
        colour=COLOURS["info"],
        footer="Tighten min_severity / watchlist in config.yaml if this is too noisy",
    )


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def apply_epss(vulns: list[Vuln], scores: dict[str, tuple[float, float]]) -> None:
    for v in vulns:
        if v.cve_id in scores:
            v.epss, v.percentile = scores[v.cve_id]


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Post vulnerabilities to Discord")
    parser.add_argument("--dry-run", action="store_true", help="print posts instead of sending; don't save state")
    parser.add_argument("--fixtures", type=Path, help="read sample data from this folder instead of the internet")
    parser.add_argument("--state", type=Path, default=STATE_DIR / "vuln_state.json")
    parser.add_argument("--config", type=Path, default=ROOT / "config.yaml")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    setup_logging(args.verbose)
    load_dotenv()
    if args.fixtures and (args.fixtures / "now.txt").exists() and not env("BOT_NOW"):
        os.environ["BOT_NOW"] = (args.fixtures / "now.txt").read_text().strip()

    full_cfg = load_config(args.config)
    cfg = full_cfg["vulns"]
    session = http_session()
    state = State(args.state, read_only=args.dry_run)
    api_key = env("NVD_API_KEY")
    max_posts = int(cfg.get("max_posts_per_run", 8))
    delay = 0 if args.dry_run else cfg.get("post_delay_seconds", 2)

    vuln_hook = Webhook(env("DISCORD_WEBHOOK_VULNS"), cfg.get("username"), cfg.get("avatar_url"),
                        dry_run=args.dry_run, session=session)
    kev_hook = Webhook(env("DISCORD_WEBHOOK_KEV") or env("DISCORD_WEBHOOK_VULNS"), cfg.get("username"),
                       cfg.get("avatar_url"), dry_run=args.dry_run, session=session)
    errors: list[str] = []
    posted = 0

    # ------------------------------------------------------------------ KEV
    kev_by_id: dict[str, dict] = {}
    if cfg.get("kev_enabled", True):
        try:
            kev = fetch_kev(session, args.fixtures)
        except Exception as exc:  # noqa: BLE001
            log.warning("KEV fetch failed: %s", exc)
            errors.append(f"CISA KEV: {exc}")
            kev = []
        kev_by_id = {e["cveID"]: e for e in kev if "cveID" in e}
        new = sorted((e for e in kev_by_id.values() if not state.seen(f"kev:{e['cveID']}")),
                     key=lambda e: e.get("dateAdded", ""))

        if kev and not state.meta.get("kev_seeded"):
            keep = int(cfg.get("kev_first_run_posts", 3))
            for e in (new[:-keep] if keep else new):
                state.mark(f"kev:{e['cveID']}", save=False)
            new = new[-keep:] if keep else []
            state.meta["kev_seeded"] = True
            log.info("KEV first run: seeded %d entries, posting newest %d", len(kev_by_id), len(new))

        new = new[:max_posts]
        try:
            kev_epss = fetch_epss(session, [e["cveID"] for e in new], args.fixtures)
        except Exception as exc:  # noqa: BLE001
            log.warning("EPSS lookup failed: %s", exc)
            kev_epss = {}

        for entry in new:
            cve_id = entry["cveID"]
            v = None
            try:
                raw = fetch_single_cve(session, cve_id, api_key, args.fixtures)
                v = parse_nvd(raw) if raw else None
            except Exception as exc:  # noqa: BLE001 — NVD details are a nice-to-have here
                log.debug("NVD lookup for %s failed: %s", cve_id, exc)
            if v is None:
                v = Vuln(cve_id=cve_id)
            apply_epss([v], kev_epss)
            if kev_hook.send(embeds=[kev_embed(entry, v)]):
                state.mark(f"kev:{cve_id}")
                state.mark(f"nvd:{cve_id}")  # already covered — don't post it again from NVD
                posted += 1
            else:
                errors.append(f"Discord rejected KEV post for {cve_id}")
            time.sleep(delay)

    # ------------------------------------------------------------------ NVD
    now = utcnow()
    last_end = parse_iso(state.meta.get("last_nvd_end"))
    # Overlap the previous window by an hour so nothing slips through the gap;
    # the state file stops anything being posted twice.
    start = (last_end - timedelta(hours=1)) if last_end else now - timedelta(hours=24)
    start = max(start, now - timedelta(days=7))

    try:
        raw_cves = fetch_nvd_window(session, start, now, api_key, args.fixtures)
    except Exception as exc:  # noqa: BLE001
        log.warning("NVD fetch failed: %s", exc)
        errors.append(f"NVD: {exc}")
        raw_cves = None

    if raw_cves is not None:
        max_age = timedelta(days=int(cfg.get("max_age_days", 14)))
        vulns = [parse_nvd(c) for c in raw_cves]
        vulns = [
            v for v in vulns
            if v.status != "Rejected"
            and v.published and now - v.published <= max_age
            and not state.seen(f"nvd:{v.cve_id}")
        ]
        try:
            apply_epss(vulns, fetch_epss(session, [v.cve_id for v in vulns], args.fixtures))
        except Exception as exc:  # noqa: BLE001
            log.warning("EPSS lookup failed: %s", exc)

        candidates: list[tuple[Vuln, str, dict | None]] = []
        for v in vulns:
            kev_entry = kev_by_id.get(v.cve_id)
            reason = decide_reason(v, cfg) or ("On CISA KEV — actively exploited" if kev_entry else None)
            if reason:
                candidates.append((v, reason, kev_entry))

        # Most severe first, then most likely to be exploited.
        candidates.sort(key=lambda c: (SEV_RANK.get(c[0].severity or "", 0), c[0].epss or 0), reverse=True)
        log.info("NVD: %d new CVE(s) in range, %d match your filters", len(vulns), len(candidates))

        to_post, extra = candidates[:max_posts], candidates[max_posts:]
        for v, reason, kev_entry in to_post:
            if vuln_hook.send(embeds=[vuln_embed(v, reason, kev_entry)]):
                state.mark(f"nvd:{v.cve_id}")
                posted += 1
            else:
                errors.append(f"Discord rejected post for {v.cve_id}")
            time.sleep(delay)

        if extra:
            # Don't flood the channel and don't silently drop anything:
            # one compact summary post for the rest.
            if vuln_hook.send(embeds=[overflow_embed(extra)]):
                for v, _, _ in extra:
                    state.mark(f"nvd:{v.cve_id}", save=False)

        state.meta["last_nvd_end"] = iso(now)

    pruned = state.prune(full_cfg.get("state", {}).get("keep_days", 60))
    state.meta["last_run"] = iso(utcnow())
    fresh_errors = state.new_errors(errors)  # only tell #bot-logs about NEW problems
    state.save()
    log.info("Done: posted %d, pruned %d old IDs, %d error(s)", posted, pruned, len(errors))

    logs_url = env("DISCORD_WEBHOOK_LOGS")
    if fresh_errors and (logs_url or args.dry_run):
        try:
            Webhook(logs_url, username="Bot Logs", dry_run=args.dry_run, session=session).send(
                content="**Vuln bot problems this run:**\n" + "\n".join(f"• {e}" for e in fresh_errors[:15]))
        except ValueError:
            pass

    both_failed = raw_cves is None and (not cfg.get("kev_enabled", True) or not kev_by_id)
    return 1 if both_failed else 0


if __name__ == "__main__":
    raise SystemExit(run())
