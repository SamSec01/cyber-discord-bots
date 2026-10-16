"""
LESSON 7 — What's actually being exploited? (CISA KEV + EPSS)
=============================================================
Goal: go from "lots of scary CVEs" to "the ones attackers are using".

Two free data sources that change how you prioritise:

CISA KEV  (Known Exploited Vulnerabilities catalogue)
  A list of CVEs with evidence of exploitation in the wild. If it's on KEV,
  someone is attacking it right now. One JSON file, updated as CISA adds entries:
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  "dueDate" is the US federal deadline (BOD 22-01) — a useful urgency signal
  for everyone else. "knownRansomwareCampaignUse" = "Known" means ransomware
  crews use it.

EPSS  (Exploit Prediction Scoring System, by FIRST)
  The probability (0-1) that a CVE will be exploited in the next 30 days,
  from a model trained on real attack data. Updated daily.
    epss 0.91       → 91% likely to see exploitation in 30 days
    percentile 0.99 → riskier than 99% of all CVEs
  https://api.first.org/data/v1/epss?cve=CVE-2024-3400,CVE-2021-44228

    CVSS = how bad IF exploited.  EPSS = how LIKELY.  KEV = it IS happening.

Run it
------
    python lessons/lesson7_kev_epss.py --dry-run             # live data, print the post
    python lessons/lesson7_kev_epss.py                       # post newest KEV entry to Discord
    python lessons/lesson7_kev_epss.py --offline --dry-run

Try it
------
1. How many KEV entries have knownRansomwareCampaignUse == "Known"?
2. Find the vendor with the most KEV entries (collections.Counter is your friend).
3. Look up EPSS for a CVE you dealt with at work. Did the score match your gut?
"""
import json
import sys

import requests

from _env import SAMPLE_DATA, load_env, need

load_env()
offline = "--offline" in sys.argv

# --- KEV ------------------------------------------------------------------------
if offline:
    kev = json.loads((SAMPLE_DATA / "kev.json").read_text(encoding="utf-8"))
else:
    kev = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                       timeout=60).json()

entries = sorted(kev["vulnerabilities"], key=lambda e: e["dateAdded"], reverse=True)
print(f"KEV catalogue {kev['catalogVersion']}: {len(entries)} exploited CVEs\n")
print("Newest 5:")
for e in entries[:5]:
    print(f"  {e['dateAdded']}  {e['cveID']:<16} {e['vendorProject']} {e['product']}")

# --- EPSS for those 5 (one request, comma-separated) --------------------------------
ids = [e["cveID"] for e in entries[:5]]
if offline:
    rows = json.loads((SAMPLE_DATA / "epss.json").read_text(encoding="utf-8"))["data"]
else:
    rows = requests.get("https://api.first.org/data/v1/epss", params={"cve": ",".join(ids)}, timeout=30).json()["data"]
epss = {r["cve"]: (float(r["epss"]), float(r["percentile"])) for r in rows}

print("\nEPSS:")
for cve_id in ids:
    if cve_id in epss:
        p, pct = epss[cve_id]
        print(f"  {cve_id:<16} {p:6.1%} likely in 30 days  (higher than {pct:.1%} of CVEs)")
    else:
        print(f"  {cve_id:<16} not scored yet")

# --- Post the newest one ----------------------------------------------------------
newest = entries[0]
p = epss.get(newest["cveID"])
embed = {
    "title": f"🔥 Actively exploited: {newest['cveID']}",
    "url": f"https://nvd.nist.gov/vuln/detail/{newest['cveID']}",
    "description": f"**{newest['vulnerabilityName']}**\n{newest['shortDescription']}",
    "color": 0xC62828,
    "fields": [
        {"name": "Product", "value": f"{newest['vendorProject']} {newest['product']}", "inline": True},
        {"name": "Added", "value": newest["dateAdded"], "inline": True},
        {"name": "Ransomware", "value": newest["knownRansomwareCampaignUse"], "inline": True},
        {"name": "EPSS", "value": f"{p[0]:.1%}" if p else "Not scored yet", "inline": True},
        {"name": "Required action", "value": newest["requiredAction"][:1024]},
    ],
    "footer": {"text": "Lesson 7 · CISA KEV + FIRST EPSS"},
}
payload = {"username": "Vuln Watch (lesson 7)", "embeds": [embed], "allowed_mentions": {"parse": []}}

if "--dry-run" in sys.argv:
    print("\n" + json.dumps(payload, indent=2, ensure_ascii=False))
else:
    r = requests.post(need("DISCORD_WEBHOOK_VULNS"), json=payload, timeout=10)
    print("\nPosted:", r.status_code, "" if r.ok else r.text)
