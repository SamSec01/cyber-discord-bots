"""
LESSON 3 — Reading news feeds (RSS)
===================================
Goal: pull the latest stories from a security news site.

Nearly every news site publishes an RSS (or Atom) feed: an XML file listing
recent articles with title, link, date and a short summary. It's made for
machines, so it's far more reliable than scraping the web page.

The feedparser library downloads/parses a feed and gives you a list of
"entries". It copes with RSS *and* Atom and with the many date formats sites use.

Run it
------
    python lessons/lesson3_read_rss.py                    # The Hacker News
    python lessons/lesson3_read_rss.py https://therecord.media/feed
    python lessons/lesson3_read_rss.py --offline          # sample file, no internet

Try it
------
1. Try each feed in config.yaml. Which give long summaries, which short?
2. Print entry.keys() for one entry — what other data is in there?
3. Point it at a normal web page (not a feed). What does feedparser do?
   Look at 'bozo' — feedparser's flag for "this XML is broken".
"""
import sys

import feedparser
import requests

from _env import SAMPLE_DATA, load_env

load_env()
args = [a for a in sys.argv[1:] if not a.startswith("--")]
url = args[0] if args else "https://feeds.feedburner.com/TheHackersNews"

if "--offline" in sys.argv:
    content = (SAMPLE_DATA / "feed.xml").read_bytes()
else:
    # Download it ourselves with requests so we control the timeout and the
    # User-Agent (some sites block the default Python one).
    response = requests.get(url, timeout=20, headers={"User-Agent": "cyber-discord-bots-lesson/1.0"})
    response.raise_for_status()   # turns 4xx/5xx into an exception
    content = response.content

feed = feedparser.parse(content)
print("Feed title:", feed.feed.get("title"))
print("Broken XML?", bool(feed.bozo))
print("Entries:", len(feed.entries), "\n")

for entry in feed.entries[:5]:
    print("•", entry.get("title"))
    print("  link:     ", entry.get("link"))
    print("  published:", entry.get("published", "(no date)"))
    summary = entry.get("summary", "")
    print("  summary:  ", (summary[:150] + "…") if len(summary) > 150 else summary)
    print()
