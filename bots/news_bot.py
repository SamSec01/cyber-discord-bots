"""
CYBER NEWS BOT
==============
Reads security news RSS feeds and posts each new story to Discord as a rich
embed with context: summary, why it matters, who's affected, what to do,
CVEs mentioned and topic tags.

Run it:
    python -m bots.news_bot --dry-run            # print what it would post
    python -m bots.news_bot                      # post for real
    python -m bots.news_bot --fixtures lessons/sample_data --dry-run   # offline

The flow (each step is one function below):
    fetch feeds → normalise items → drop seen/old → add context → post → remember
"""
from __future__ import annotations

import argparse
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import feedparser

from .common import ROOT, STATE_DIR, State, env, http_session, iso, load_config, load_dotenv, setup_logging, utcnow
from .context import GeminiSummariser, build_news_context
from .discord_post import COLOURS, Webhook, build_embed

log = logging.getLogger("bots.news")


@dataclass
class Item:
    key: str            # unique ID we remember in state
    title: str
    link: str
    source: str
    published: datetime | None
    summary_html: str


# --------------------------------------------------------------------------- #
#  Fetching
# --------------------------------------------------------------------------- #
def normalise_link(url: str) -> str:
    """Strip tracking junk (utm_*, fragments) so the same article = same key."""
    parts = urlsplit(url.strip())
    query = [(k, v) for k, v in parse_qsl(parts.query) if not k.lower().startswith(("utm_", "fbclid", "gclid"))]
    return urlunsplit((parts.scheme, parts.netloc.lower(), parts.path, urlencode(query), ""))


def entry_published(entry) -> datetime | None:
    """feedparser turns the many date formats feeds use into a time.struct_time."""
    for field in ("published_parsed", "updated_parsed"):
        value = entry.get(field)
        if value:
            return datetime(*value[:6], tzinfo=timezone.utc)
    return None


def parse_feed(content: bytes, source: str) -> list[Item]:
    parsed = feedparser.parse(content)
    if parsed.bozo and not parsed.entries:
        # bozo = feedparser found the XML malformed. With no entries it's useless.
        raise ValueError(f"unreadable feed ({parsed.get('bozo_exception')})")
    items = []
    for entry in parsed.entries:
        link = entry.get("link", "")
        title = (entry.get("title") or "").strip()
        if not link or not title:
            continue
        link = normalise_link(link)
        summary = entry.get("summary") or entry.get("description") or ""
        items.append(Item(
            key=f"news:{link}",
            title=title,
            link=link,
            source=source,
            published=entry_published(entry),
            summary_html=summary,
        ))
    return items


def fetch_feed(session, feed: dict, fixtures: Path | None = None) -> list[Item]:
    if fixtures:
        return parse_feed((fixtures / "feed.xml").read_bytes(), feed["name"])
    resp = session.get(feed["url"], timeout=20)
    resp.raise_for_status()
    return parse_feed(resp.content, feed["name"])


# --------------------------------------------------------------------------- #
#  Choosing what to post
# --------------------------------------------------------------------------- #
def select_items(items: list[Item], state: State, cfg: dict) -> list[Item]:
    """Decide which items to post this run. Marks skipped items as seen."""
    now = utcnow()
    max_age = timedelta(hours=cfg.get("max_age_hours", 48))

    fresh: list[Item] = []
    seen_titles: set[str] = set()
    for item in items:
        if state.seen(item.key):
            continue
        # Same headline from two feeds (or one feed listing it twice) → post once.
        title_key = item.title.lower().strip()
        if title_key in seen_titles:
            state.mark(item.key, save=False)
            continue
        seen_titles.add(title_key)
        if item.published and now - item.published > max_age:
            state.mark(item.key, save=False)  # too old — remember it so we never post it
            continue
        fresh.append(item)

    # Oldest first, so the channel reads in chronological order.
    fresh.sort(key=lambda i: i.published or now)

    if state.first_run:
        # First run: every article in every feed is "new". Post only the newest
        # few and quietly remember the rest, or we'd dump ~100 posts at once.
        keep = cfg.get("first_run_posts", 3)
        for item in fresh[:-keep] if keep else fresh:
            state.mark(item.key, save=False)
        fresh = fresh[-keep:] if keep else []
        log.info("First run: seeded state, posting the newest %d", len(fresh))

    return fresh[: cfg.get("max_posts_per_run", 8)]


# --------------------------------------------------------------------------- #
#  Building the embed
# --------------------------------------------------------------------------- #
def news_embed(item: Item, ctx: dict) -> dict:
    description = ctx["summary"] or "_No summary in the feed — open the article for details._"
    if ctx.get("why_it_matters"):
        description += f"\n\n**Why it matters:** {ctx['why_it_matters']}"

    fields = []
    if ctx.get("who_is_affected"):
        fields.append(("Who's affected", ctx["who_is_affected"]))
    if ctx.get("actions"):
        fields.append(("What to do", "\n".join(f"• {a}" for a in ctx["actions"])))
    if ctx.get("cves"):
        links = [f"[{c}](https://nvd.nist.gov/vuln/detail/{c})" for c in ctx["cves"][:8]]
        fields.append(("CVEs mentioned", " · ".join(links), True))
    if ctx.get("tags"):
        fields.append(("Tags", " ".join(f"`{t}`" for t in ctx["tags"][:6]), True))

    # Always label AI-written text, so readers know to check the source.
    footer = "AI-generated summary · check the original before acting" if ctx.get("ai_used") else None
    return build_embed(
        title=item.title,
        url=item.link,
        description=description,
        colour=COLOURS.get(ctx.get("severity") or "info", COLOURS["info"]),
        fields=fields,
        footer=footer,
        author=item.source,
        timestamp=item.published,
    )


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def report_errors(errors: list[str], dry_run: bool, session) -> None:
    url = env("DISCORD_WEBHOOK_LOGS")
    if not errors or (not url and not dry_run):
        return
    try:
        Webhook(url, username="Bot Logs", dry_run=dry_run, session=session).send(
            content="**News bot problems this run:**\n" + "\n".join(f"• {e}" for e in errors[:15])
        )
    except ValueError:
        pass


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Post cyber security news to Discord")
    parser.add_argument("--dry-run", action="store_true", help="print posts instead of sending; don't save state")
    parser.add_argument("--fixtures", type=Path, help="read sample data from this folder instead of the internet")
    parser.add_argument("--no-ai", action="store_true", help="skip Gemini even if a key is set")
    parser.add_argument("--state", type=Path, default=STATE_DIR / "news_state.json")
    parser.add_argument("--config", type=Path, default=ROOT / "config.yaml")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    setup_logging(args.verbose)
    load_dotenv()
    if args.fixtures and (args.fixtures / "now.txt").exists() and not env("BOT_NOW"):
        # Sample data has fixed dates, so pretend "now" is when it was made.
        os.environ["BOT_NOW"] = (args.fixtures / "now.txt").read_text().strip()
    cfg = load_config(args.config)["news"]
    session = http_session()
    state = State(args.state, read_only=args.dry_run)

    feeds = [f for f in cfg.get("feeds", []) if f.get("enabled", True)]
    if args.fixtures:
        feeds = [{"name": "Sample Feed", "url": "fixture"}]

    # 1. Fetch every feed. One broken feed must not stop the others.
    items: list[Item] = []
    errors: list[str] = []
    failed_feeds = 0
    for feed in feeds:
        try:
            got = fetch_feed(session, feed, args.fixtures)
            log.info("%-20s %d items", feed["name"], len(got))
            items.extend(got)
        except Exception as exc:  # noqa: BLE001 — we really do want to catch everything here
            log.warning("%-20s FAILED: %s", feed["name"], exc)
            errors.append(f"{feed['name']}: {exc}")
            failed_feeds += 1

    # 2. Pick what to post.
    to_post = select_items(items, state, cfg)
    log.info("%d new article(s) to post", len(to_post))

    # 3. Optional AI helper.
    ai = None
    ai_cfg = cfg.get("ai", {})
    key = env("GEMINI_API_KEY")
    if key and ai_cfg.get("enabled", True) and not args.no_ai:
        ai = GeminiSummariser(key, ai_cfg.get("model", "gemini-flash-lite-latest"), session,
                              float(ai_cfg.get("min_seconds_between_calls", 5)))

    webhook = Webhook(env("DISCORD_WEBHOOK_NEWS"), cfg.get("username"), cfg.get("avatar_url"),
                      dry_run=args.dry_run, session=session)

    # 4. Post, remembering each one straight away (so a crash halfway through
    #    doesn't cause duplicates next run).
    posted = 0
    for item in to_post:
        ctx = build_news_context(item.title, item.source, item.link, item.summary_html, session, ai,
                                 fetch_full_article=cfg.get("fetch_full_article", True) and not args.fixtures)
        if webhook.send(embeds=[news_embed(item, ctx)]):
            state.mark(item.key)
            posted += 1
        else:
            errors.append(f"Discord rejected: {item.title[:80]}")
        if not args.dry_run:
            time.sleep(cfg.get("post_delay_seconds", 2))

    # 5. Tidy up and save.
    pruned = state.prune(load_config(args.config).get("state", {}).get("keep_days", 60))
    state.meta["last_run"] = iso(utcnow())
    fresh_errors = state.new_errors(errors)  # only tell #bot-logs about NEW problems
    state.save()
    log.info("Done: posted %d, pruned %d old IDs, %d error(s)", posted, pruned, len(errors))
    report_errors(fresh_errors, args.dry_run, session)

    # Exit code 1 only if *everything* failed, so GitHub shows a red X.
    return 1 if feeds and failed_feeds == len(feeds) else 0


if __name__ == "__main__":
    raise SystemExit(run())
