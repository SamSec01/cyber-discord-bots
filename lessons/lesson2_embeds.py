"""
LESSON 2 — Rich embeds (the "card" look)
========================================
Goal: send a proper news card instead of plain text.

An *embed* is a block of structured JSON that Discord draws as a card:

    ┃ author            ← small text above the title (we use the news source)
    ┃ Title (clickable) ← links to "url"
    ┃ description       ← the main text, supports **markdown**
    ┃ field | field     ← name/value pairs; inline ones sit side by side
    ┃ footer · timestamp
     ↑ the coloured bar on the left is "color"

Discord's limits (go over ANY and the whole message is rejected with HTTP 400):
    title 256 · description 4,096 · 25 fields · field name 256 · field value 1,024
    footer 2,048 · and 6,000 characters in total across the embed.

Run it
------
    python lessons/lesson2_embeds.py
    python lessons/lesson2_embeds.py --dry-run

Try it
------
1. Change the colour. Colours are hex numbers: 0xC62828 is red, 0x2E7D32 green.
2. Set "inline": False on the CVE field — see how the layout changes.
3. Make the title 300 characters long and run it (not dry-run). Read the 400 error.
   Then look at truncate() in bots/discord_post.py to see how the real bot avoids it.
"""
import json
import sys
from datetime import datetime, timezone

import requests

from _env import load_env, need

load_env()

embed = {
    "author": {"name": "Sample Security News"},
    "title": "ExampleCorp patches actively exploited VPN zero-day",
    "url": "https://example.com/news/examplevpn-zero-day",
    "description": (
        "ExampleCorp has released emergency updates for its ExampleVPN gateway after "
        "attackers were seen exploiting a critical command injection flaw.\n\n"
        "**Why it matters:** Unauthenticated attackers can run commands as root on "
        "internet-facing gateways — a common way into a network."
    ),
    "color": 0xC62828,   # red = critical
    "fields": [
        {"name": "Who's affected", "value": "ExampleVPN gateways before 9.4.2", "inline": False},
        {"name": "What to do", "value": "• Patch to 9.4.2\n• Check logs for unexpected admin sessions", "inline": False},
        {"name": "CVEs", "value": "[CVE-2099-0001](https://nvd.nist.gov/vuln/detail/CVE-2099-0001)", "inline": True},
        {"name": "Tags", "value": "`Zero-day` `Actively exploited`", "inline": True},
    ],
    "footer": {"text": "Lesson 2 · sample data"},
    # ISO-8601 time; Discord shows it in each reader's own timezone.
    "timestamp": datetime.now(timezone.utc).isoformat(),
}

payload = {
    "username": "Cyber News (lesson 2)",
    "embeds": [embed],                    # a list: up to 10 embeds per message
    # SECURITY: switch off @everyone/@here/role pings for this message.
    # Embeds can't ping anyway, but plain "content" can — make it a habit.
    "allowed_mentions": {"parse": []},
}

if "--dry-run" in sys.argv:
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    sys.exit(0)

response = requests.post(need("DISCORD_WEBHOOK_NEWS"), json=payload, timeout=10)
print("Status code:", response.status_code, "" if response.ok else response.text)
