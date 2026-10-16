"""
Tests — run with:  python -m pytest -q

Nothing here touches the internet or Discord: the sample data in
lessons/sample_data stands in for the real APIs, and a fake "post" function
records what would have been sent to Discord.
"""
import json
import os
from pathlib import Path

import pytest
import requests
import yaml

from bots import context, discord_post, news_bot, vuln_bot
from bots.common import State

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "lessons" / "sample_data"


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #
class FakeResponse:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status
        self.ok = 200 <= status < 300
        self._body = body if body is not None else {}
        self.headers = headers or {}
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


@pytest.fixture
def discord(monkeypatch):
    """Capture everything POSTed to Discord instead of sending it."""
    sent = []

    def fake_post(self, url, json=None, **kwargs):
        sent.append({"url": url, "payload": json})
        return FakeResponse(200, {"id": "1"})

    monkeypatch.setattr(requests.Session, "post", fake_post)
    monkeypatch.setattr("time.sleep", lambda *_: None)
    monkeypatch.setenv("DISCORD_WEBHOOK_NEWS", "https://discord.com/api/webhooks/1/news")
    monkeypatch.setenv("DISCORD_WEBHOOK_VULNS", "https://discord.com/api/webhooks/2/vulns")
    monkeypatch.setenv("DISCORD_WEBHOOK_KEV", "https://discord.com/api/webhooks/3/kev")
    monkeypatch.delenv("DISCORD_WEBHOOK_LOGS", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("BOT_NOW", raising=False)
    yield sent
    os.environ.pop("BOT_NOW", None)  # the bots set this in fixtures mode


def write_config(tmp_path, **overrides) -> Path:
    cfg = yaml.safe_load((ROOT / "config.yaml").read_text())
    for dotted, value in overrides.items():
        section, key = dotted.split("__")
        cfg[section][key] = value
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return path


# --------------------------------------------------------------------------- #
#  Context helpers
# --------------------------------------------------------------------------- #
def test_extract_cves_dedupes_and_uppercases():
    text = "Fixes cve-2026-1234 and CVE-2026-1234, plus CVE-2025-123456."
    assert context.extract_cves(text) == ["CVE-2026-1234", "CVE-2025-123456"]


def test_clean_html_strips_tags_entities_and_boilerplate():
    raw = "<p>Hello &amp; <b>welcome</b></p><p>The post Foo appeared first on Bar.</p>"
    assert context.clean_html(raw) == "Hello & welcome"


def test_tags_use_word_boundaries():
    assert "Nation-state" not in context.detect_tags("New network adapter driver released")
    assert "Nation-state" in context.detect_tags("APT29 targets diplomats")


def test_strip_untrusted_removes_links_and_pings():
    out = context.strip_untrusted("Click [here](https://evil.example) or https://evil.example now @everyone")
    assert "evil" not in out
    assert "@everyone" not in out


def test_validate_ai_output_good_and_bad():
    good = context.validate_ai_output({
        "summary": "A thing happened. See https://evil.example",
        "why_it_matters": "It matters.",
        "who_is_affected": "Not stated",
        "actions": ["Patch now", 42, ""],
        "severity": "HIGH",
    })
    assert good["summary"] == "A thing happened. See"
    assert good["who_is_affected"] == ""
    assert good["actions"] == ["Patch now"]
    assert good["severity"] == "high"

    assert context.validate_ai_output("not a dict") is None
    assert context.validate_ai_output({"summary": ""}) is None
    assert context.validate_ai_output({"summary": "ok", "severity": "apocalyptic"})["severity"] == ""


def test_gemini_parses_json_and_disables_on_quota(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    answer = {"summary": "S.", "why_it_matters": "W.", "who_is_affected": "Admins",
              "actions": ["Do X"], "severity": "medium"}
    body = {"candidates": [{"content": {"parts": [
        {"text": "thinking...", "thought": True},
        {"text": "```json\n" + json.dumps(answer) + "\n```"},
    ]}}]}

    class Session:
        def __init__(self, resp):
            self.resp = resp

        def post(self, *a, **k):
            return self.resp

    ai = context.GeminiSummariser("key", "model", Session(FakeResponse(200, body)), min_interval=0)
    assert ai.summarise("t", "s", "x" * 200)["who_is_affected"] == "Admins"

    ai = context.GeminiSummariser("key", "model", Session(FakeResponse(429, {})), min_interval=0)
    assert ai.summarise("t", "s", "x" * 200) is None
    assert ai.disabled


def test_build_news_context_with_ai_merges_rules_and_ai(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    article = "<html><body><nav>Menu</nav><article>" + "".join(
        f"<p>Paragraph {i} about the exploited flaw CVE-2026-1111 and how attackers abuse it in the wild.</p>"
        for i in range(10)) + "</article></body></html>"
    ai_answer = {"summary": "AI summary.", "why_it_matters": "Because.", "who_is_affected": "VPN users",
                 "actions": ["Patch"], "severity": "critical"}

    class Session:
        def get(self, url, **k):
            resp = FakeResponse(200, {}, {"Content-Type": "text/html; charset=utf-8"})
            resp.text = article
            return resp

        def post(self, *a, **k):
            return FakeResponse(200, {"candidates": [{"content": {"parts": [{"text": json.dumps(ai_answer)}]}}]})

    session = Session()
    ai = context.GeminiSummariser("key", "model", session, min_interval=0)
    ctx = context.build_news_context("Vendor fixes VPN bug", "Src", "https://example.com/a",
                                     "<p>Short RSS summary of the bug.</p>", session, ai)
    assert ctx["ai_used"] is True
    assert ctx["summary"] == "AI summary."
    assert ctx["severity"] == "critical"
    assert "CVE-2026-1111" in ctx["cves"]        # found in the full article, not the RSS summary


# --------------------------------------------------------------------------- #
#  Discord embeds
# --------------------------------------------------------------------------- #
def test_build_embed_respects_discord_limits():
    embed = discord_post.build_embed(
        title="T" * 500,
        description="D" * 5000,
        fields=[(f"Field {i}", "V" * 2000) for i in range(30)] + [("Empty", "")],
        footer="F" * 3000,
    )
    assert len(embed["title"]) <= 256
    assert len(embed["description"]) <= 4096
    assert len(embed["fields"]) <= 25
    assert all(len(f["value"]) <= 1024 for f in embed["fields"])
    assert discord_post.embed_size(embed) <= 6000
    assert all(f["name"] != "Empty" for f in embed["fields"])


def test_webhook_rejects_non_discord_urls():
    with pytest.raises(ValueError):
        discord_post.Webhook("https://evil.example/api/webhooks/1/x")


def test_webhook_retries_after_rate_limit(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    responses = [FakeResponse(429, {"retry_after": 0.1}), FakeResponse(200, {"id": "1"})]

    class Session:
        def post(self, *a, **k):
            return responses.pop(0)

    hook = discord_post.Webhook("https://discord.com/api/webhooks/1/x", session=Session())
    assert hook.send(content="hi") is True
    assert responses == []


# --------------------------------------------------------------------------- #
#  NVD parsing and filtering
# --------------------------------------------------------------------------- #
def test_best_metric_prefers_newest_version_and_primary():
    metrics = {
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}},
            {"type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}},
        ],
        "cvssMetricV2": [{"type": "Primary", "baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}],
    }
    assert vuln_bot.best_metric(metrics)[:3] == ("HIGH", 7.5, "3.1")
    assert vuln_bot.best_metric({"cvssMetricV2": metrics["cvssMetricV2"]})[:3] == ("MEDIUM", 5.0, "2.0")
    assert vuln_bot.best_metric({}) == (None, None, None, None)


def test_decide_reason():
    cfg = {"min_severity": "CRITICAL", "watchlist": ["fortinet"], "watchlist_min_severity": "HIGH", "min_epss": 0.1}
    V = vuln_bot.Vuln
    assert "Critical" in vuln_bot.decide_reason(V("C", severity="CRITICAL"), cfg)
    assert "watchlist" in vuln_bot.decide_reason(V("C", "Bug in Fortinet FortiOS", severity="HIGH"), cfg)
    assert vuln_bot.decide_reason(V("C", "Bug in Fortinet FortiOS", severity="MEDIUM"), cfg) is None
    assert "EPSS" in vuln_bot.decide_reason(V("C", severity="LOW", epss=0.4), cfg)
    assert vuln_bot.decide_reason(V("C", "Bug in fortinetwork thing", severity="HIGH"), cfg) is None


# --------------------------------------------------------------------------- #
#  End-to-end: whole bots against sample data
# --------------------------------------------------------------------------- #
def test_news_bot_end_to_end(tmp_path, discord):
    state = tmp_path / "news.json"
    config = write_config(tmp_path, news__first_run_posts=10)
    args = ["--fixtures", str(SAMPLES), "--state", str(state), "--config", str(config)]

    assert news_bot.run(args) == 0
    # 7 items in the feed − 1 duplicate headline − 1 too old = 5 posts
    assert len(discord) == 5
    for msg in discord:
        assert msg["payload"]["allowed_mentions"] == {"parse": []}
    titles = [m["payload"]["embeds"][0]["title"] for m in discord]
    assert not any("too old" in t for t in titles)
    assert all("utm_" not in m["payload"]["embeds"][0]["url"] for m in discord)
    first_embed = discord[0]["payload"]["embeds"][0]
    assert first_embed["timestamp"] <= discord[-1]["payload"]["embeds"][0]["timestamp"]  # oldest first

    # Second run: nothing new, so nothing posted.
    discord.clear()
    os.environ.pop("BOT_NOW", None)
    assert news_bot.run(args) == 0
    assert discord == []
    assert len(json.loads(state.read_text())["seen"]) == 7


def test_news_bot_first_run_does_not_flood(tmp_path, discord):
    state = tmp_path / "news.json"
    news_bot.run(["--fixtures", str(SAMPLES), "--state", str(state)])
    assert len(discord) == 3  # first_run_posts default


def test_vuln_bot_end_to_end(tmp_path, discord):
    state = tmp_path / "vulns.json"
    args = ["--fixtures", str(SAMPLES), "--state", str(state)]

    assert vuln_bot.run(args) == 0
    kev_posts = [m for m in discord if m["url"].endswith("/kev")]
    nvd_posts = [m for m in discord if m["url"].endswith("/vulns")]
    assert len(kev_posts) == 3                  # newest 3 KEV entries on first run
    nvd_ids = [m["payload"]["embeds"][0]["url"].rsplit("/", 1)[1] for m in nvd_posts]
    # 0001 already went out as a KEV alert; 0003 medium; 0004 unscored;
    # 0006 rejected; 0007 too old → leaves 0008 (critical), 0005 (EPSS), 0002 (watchlist)
    assert nvd_ids == ["CVE-2099-0008", "CVE-2099-0005", "CVE-2099-0002"]

    saved = json.loads(state.read_text())
    assert saved["meta"]["kev_seeded"] is True
    assert "last_nvd_end" in saved["meta"]

    discord.clear()
    os.environ.pop("BOT_NOW", None)
    assert vuln_bot.run(args) == 0
    assert discord == []


def test_vuln_bot_overflow_summary(tmp_path, discord):
    config = write_config(tmp_path, vulns__max_posts_per_run=1, vulns__kev_enabled=False)
    vuln_bot.run(["--fixtures", str(SAMPLES), "--state", str(tmp_path / "v.json"), "--config", str(config)])
    titles = [m["payload"]["embeds"][0]["title"] for m in discord]
    assert titles[0].startswith("CVE-2099-0001")   # most severe (KEV off this time)
    assert titles[-1].startswith("+3 more CVEs")


def test_errors_are_reported_once_until_they_change(tmp_path):
    s = State(tmp_path / "s.json")
    assert s.new_errors(["Feed A: 403"]) == ["Feed A: 403"]
    assert s.new_errors(["Feed A: 403"]) == []                       # same problem → stay quiet
    assert s.new_errors(["Feed A: 403", "NVD: 503"]) == ["NVD: 503"]  # only the new one
    assert s.new_errors([]) == []
    assert s.new_errors(["Feed A: 403"]) == ["Feed A: 403"]          # broke again → tell me


def test_corrupt_state_is_treated_as_first_run(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{not json")
    s = State(path)
    assert s.first_run
    s.mark("x")
    assert json.loads(path.read_text())["seen"].keys() == {"x"}
