"""
LESSON 4 — Remembering what you've posted
=========================================
Goal: post only NEW stories, every time the script runs.

A feed always lists the latest ~10-50 articles. Run lesson 3 twice and you get
the same list twice. To post only new ones, the bot needs a memory: a file
recording the ID of everything it has already posted.

    run 1:  feed = [A, B, C]   seen = {}         → post A, B, C   → seen = {A,B,C}
    run 2:  feed = [B, C, D]   seen = {A,B,C}    → post D         → seen = {A,B,C,D}

Three traps the real bot handles (look for them in bots/news_bot.py):
  1. FIRST RUN FLOOD — on run 1 *everything* is new. With 7 feeds that's ~100
     posts at once. Fix: on the first run, post only the newest few and quietly
     mark the rest as seen.
  2. DUPLICATES — the same link with different tracking junk (?utm_source=rss)
     looks "new". Fix: normalise links before using them as IDs.
  3. CRASHES — if the script dies after posting 3 of 5, and only saves at the
     end, those 3 get posted again next time. Fix: save after every post.

Run it (twice!)
---------------
    python lessons/lesson4_remember.py --offline --dry-run
    python lessons/lesson4_remember.py --offline --dry-run     ← nothing new now
    del lessons\\seen.json   (Windows)  /  rm lessons/seen.json   (Mac/Linux) to reset

Try it
------
1. Run it twice and watch the second run post nothing.
2. Open lessons/seen.json in an editor. It's just JSON — your bot's memory.
3. Delete one line from seen.json and run again. What happens?
"""
import json
import sys
from pathlib import Path

import feedparser
import requests

from _env import SAMPLE_DATA, load_env, need

load_env()
dry_run = "--dry-run" in sys.argv
SEEN_FILE = Path(__file__).parent / "seen.json"
FIRST_RUN_POSTS = 3

# 1. Load memory (a JSON list of IDs). No file yet = first run.
first_run = not SEEN_FILE.exists()
seen = set(json.loads(SEEN_FILE.read_text())) if not first_run else set()

# 2. Get the feed.
if "--offline" in sys.argv:
    entries = feedparser.parse((SAMPLE_DATA / "feed.xml").read_bytes()).entries
else:
    resp = requests.get("https://feeds.feedburner.com/TheHackersNews", timeout=20)
    entries = feedparser.parse(resp.content).entries


def entry_id(entry):
    # Prefer the feed's own unique ID; fall back to the link without "?..." junk.
    return entry.get("id") or entry.get("link", "").split("?")[0]


# 3. Keep only the ones we haven't seen. Feeds list newest first; reverse to post oldest first.
new = [e for e in reversed(entries) if entry_id(e) not in seen]
print(f"{len(entries)} in feed, {len(new)} new" + (" (first run)" if first_run else ""))

if first_run:
    for e in new[:-FIRST_RUN_POSTS]:
        seen.add(entry_id(e))          # remember quietly, don't post
    new = new[-FIRST_RUN_POSTS:]


def save():
    SEEN_FILE.write_text(json.dumps(sorted(seen), indent=1))


# 4. Post each new one, saving after EACH post (trap 3).
for e in new:
    payload = {
        "embeds": [{"title": e.get("title", "")[:256], "url": e.get("link")}],
        "allowed_mentions": {"parse": []},
    }
    if dry_run:
        print("Would post:", e.get("title"))
    else:
        r = requests.post(need("DISCORD_WEBHOOK_NEWS"), json=payload, timeout=10)
        print(r.status_code, e.get("title"))
        if not r.ok:
            continue                   # don't mark as seen if it didn't post
    seen.add(entry_id(e))
    save()

save()
print("Memory now holds", len(seen), "IDs →", SEEN_FILE)
