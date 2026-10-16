"""
Preview what the bots would post — as Discord-style cards in your browser —
without sending anything to Discord.

    python tools/preview_embeds.py            # sample data (offline)
    python tools/preview_embeds.py --live     # real feeds/APIs, still posts nothing

Great for tuning config.yaml (feeds, watchlist, severities) without spamming
your channel. Writes preview.html in the project root and opens it.
"""
from __future__ import annotations

import html
import re
import sys
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bots import discord_post, news_bot, vuln_bot  # noqa: E402

captured: list[tuple[str, dict]] = []
current_bot = "news"


def fake_send(self, embeds=None, content=None):
    captured.append((current_bot, {"username": self.username, "embeds": embeds or [], "content": content}))
    return True


def md(text: str) -> str:
    """Just enough Discord markdown → HTML for a preview."""
    out = html.escape(text or "")
    out = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r'<a href="\2">\1</a>', out)
    out = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", out)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"(?<![\w*])_(.+?)_(?![\w*])", r"<i>\1</i>", out)
    return out.replace("\n", "<br>")


def card(bot: str, msg: dict) -> str:
    parts = []
    for e in msg["embeds"]:
        colour = f"#{e.get('color', 0x4f545c):06x}"
        fields = "".join(
            f'<div class="f{" inline" if f.get("inline") else ""}"><div class="fn">{md(f["name"])}</div>'
            f'<div class="fv">{md(f["value"])}</div></div>'
            for f in e.get("fields", [])
        )
        title = md(e.get("title", ""))
        if e.get("url"):
            title = f'<a href="{html.escape(e["url"])}">{title}</a>'
        ts = e.get("timestamp", "")[:16].replace("T", " ")
        footer = " · ".join(x for x in [e.get("footer", {}).get("text", ""), ts] if x)
        parts.append(
            f'<div class="embed" style="border-left-color:{colour}">'
            + (f'<div class="author">{md(e["author"]["name"])}</div>' if e.get("author") else "")
            + f'<div class="title">{title}</div>'
            + (f'<div class="desc">{md(e.get("description", ""))}</div>' if e.get("description") else "")
            + (f'<div class="fields">{fields}</div>' if fields else "")
            + (f'<div class="footer">{md(footer)}</div>' if footer else "")
            + "</div>"
        )
    content = f'<div class="content">{md(msg["content"])}</div>' if msg.get("content") else ""
    name = html.escape(msg.get("username") or "Bot")
    return (f'<div class="msg"><div class="avatar">{name[0]}</div><div class="body">'
            f'<div class="who">{name} <span class="badge">APP</span> <span class="chan">#{bot}</span></div>'
            f"{content}{''.join(parts)}</div></div>")


CSS = """
body{background:#313338;color:#dbdee1;font:15px/1.4 "gg sans","Segoe UI",Helvetica,Arial,sans-serif;margin:0;padding:24px}
h1{font-size:18px;color:#f2f3f5;margin:0 0 4px} p.note{color:#949ba4;margin:0 0 24px;font-size:13px}
.msg{display:flex;gap:14px;max-width:620px;margin-bottom:22px}
.avatar{flex:none;width:40px;height:40px;border-radius:50%;background:#5865f2;color:#fff;display:grid;place-items:center;font-weight:700}
.who{color:#f2f3f5;font-weight:600;margin-bottom:4px}.badge{background:#5865f2;color:#fff;font-size:10px;padding:1px 4px;border-radius:3px;vertical-align:2px}
.chan{color:#949ba4;font-weight:400;font-size:12px}
.embed{background:#2b2d31;border-left:4px solid;border-radius:4px;padding:10px 16px 14px;margin-top:4px}
.author{font-size:13px;font-weight:600;color:#f2f3f5;margin-bottom:6px}
.title{font-weight:700;margin-bottom:8px}.title a{color:#00a8fc;text-decoration:none}
.desc{font-size:14px;margin-bottom:8px}.fields{display:flex;flex-wrap:wrap;gap:8px 16px;margin-top:6px}
.f{flex:1 0 100%;font-size:14px}.f.inline{flex:1 0 28%;min-width:150px}
.fn{font-weight:700;color:#f2f3f5;margin-bottom:2px}a{color:#00a8fc}
code{background:#1e1f22;border-radius:3px;padding:1px 4px;font-size:13px}
.footer{font-size:12px;color:#949ba4;margin-top:10px}.content{margin-bottom:4px}
"""


def main() -> None:
    global current_bot
    live = "--live" in sys.argv
    discord_post.Webhook.send = fake_send  # swap in our recorder: nothing reaches Discord
    common = ["--dry-run", "--state", str(ROOT / "state" / "_preview.json")]
    if not live:
        common += ["--fixtures", str(ROOT / "lessons" / "sample_data")]

    current_bot = "cyber-news"
    news_bot.run(common + (["--no-ai"] if not live else []))
    current_bot = "vuln-alerts"
    vuln_bot.run(common)

    out = ROOT / "preview.html"
    body = "".join(card(bot, msg) for bot, msg in captured)
    out.write_text(
        f"<!doctype html><meta charset=utf-8><title>Bot preview</title><style>{CSS}</style>"
        f"<h1>Bot preview — {len(captured)} message(s)</h1>"
        f"<p class=note>{'Live data' if live else 'Sample data'} · nothing was sent to Discord · "
        f"approximate rendering</p>{body}",
        encoding="utf-8",
    )
    print(f"\nWrote {out}")
    if "--no-open" not in sys.argv:
        webbrowser.open(out.as_uri())


if __name__ == "__main__":
    main()
