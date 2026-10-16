"""
Posting to Discord through webhooks.

A webhook is just a secret URL. POST some JSON to it and a message appears in
the channel. No bot account, no server to keep running, no gateway connection.

This module:
  * builds "embeds" (the rich cards) while respecting Discord's size limits
  * sends them, handling Discord's rate limits (HTTP 429)
  * blocks @everyone / @here / role pings that might be hiding in article text
"""
from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime

import requests

log = logging.getLogger("bots.discord")

# Discord's hard limits for embeds. Go over any of these and the whole
# message is rejected with HTTP 400 — so we trim everything ourselves.
LIMITS = {
    "title": 256,
    "description": 4096,
    "field_name": 256,
    "field_value": 1024,
    "fields": 25,
    "footer": 2048,
    "author": 256,
    "total": 6000,  # all text in all embeds of one message combined
}

# Embed colours are integers. 0xRRGGBB is just hex colour notation.
COLOURS = {
    "critical": 0xC62828,  # red
    "high": 0xEF6C00,      # orange
    "medium": 0xF9A825,    # amber
    "low": 0x1565C0,       # blue
    "info": 0x546E7A,      # grey-blue
}

VALID_PREFIXES = (
    "https://discord.com/api/webhooks/",
    "https://discordapp.com/api/webhooks/",
    "https://canary.discord.com/api/webhooks/",
    "https://ptb.discord.com/api/webhooks/",
)


def truncate(text: str | None, limit: int) -> str:
    """Cut text to fit a limit, ending with … so readers know it was cut."""
    if not text:
        return ""
    text = str(text).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def embed_size(embed: dict) -> int:
    """Count the characters Discord counts towards the 6,000 total."""
    size = len(embed.get("title", "")) + len(embed.get("description", ""))
    size += len(embed.get("footer", {}).get("text", ""))
    size += len(embed.get("author", {}).get("name", ""))
    for f in embed.get("fields", []):
        size += len(f["name"]) + len(f["value"])
    return size


def build_embed(
    title: str,
    url: str | None = None,
    description: str | None = None,
    colour: int | None = None,
    fields: list[tuple[str, str] | tuple[str, str, bool]] | None = None,
    footer: str | None = None,
    author: str | None = None,
    timestamp: datetime | None = None,
) -> dict:
    """Build a Discord embed dict that is guaranteed to fit the limits.

    fields: list of (name, value) or (name, value, inline). Empty values are
    skipped, so callers can pass optional data without lots of if-statements.
    """
    embed: dict = {"title": truncate(title, LIMITS["title"])}
    if url:
        embed["url"] = url
    if description:
        embed["description"] = truncate(description, LIMITS["description"])
    if colour is not None:
        embed["color"] = colour  # Discord's API uses the US spelling
    if author:
        embed["author"] = {"name": truncate(author, LIMITS["author"])}
    if footer:
        embed["footer"] = {"text": truncate(footer, LIMITS["footer"])}
    if timestamp:
        embed["timestamp"] = timestamp.isoformat()

    out_fields = []
    for item in fields or []:
        name, value = item[0], item[1]
        inline = item[2] if len(item) > 2 else False
        if not value or not str(value).strip():
            continue
        out_fields.append(
            {
                "name": truncate(name, LIMITS["field_name"]),
                "value": truncate(value, LIMITS["field_value"]),
                "inline": bool(inline),
            }
        )
    if out_fields:
        embed["fields"] = out_fields[: LIMITS["fields"]]

    # Enforce the 6,000-character total: shorten the description first,
    # then drop fields from the end until it fits.
    overflow = embed_size(embed) - LIMITS["total"]
    if overflow > 0 and embed.get("description"):
        keep = max(200, len(embed["description"]) - overflow - 10)
        embed["description"] = truncate(embed["description"], keep)
    while embed_size(embed) > LIMITS["total"] and embed.get("fields"):
        embed["fields"].pop()
    return embed


class Webhook:
    """Send messages to one Discord channel via its webhook URL."""

    def __init__(
        self,
        url: str | None,
        username: str | None = None,
        avatar_url: str | None = None,
        dry_run: bool = False,
        session: requests.Session | None = None,
    ):
        # One secret can hold several webhook URLs separated by commas or
        # spaces, so the same feed can go to more than one server.
        self.urls = [u for u in re.split(r"[\s,]+", url or "") if u]
        if not dry_run:
            if not self.urls:
                raise ValueError("Webhook URL is missing — set it in .env or GitHub Secrets")
            for u in self.urls:
                if not u.startswith(VALID_PREFIXES):
                    raise ValueError("That doesn't look like a Discord webhook URL")
        self.username = username or None
        self.avatar_url = avatar_url or None
        self.dry_run = dry_run
        self.session = session or requests.Session()

    def send(self, embeds: list[dict] | None = None, content: str | None = None) -> bool:
        payload: dict = {
            # SECURITY: never let text from the internet ping people.
            # Mentions inside embeds never notify anyone, but mentions in plain
            # message "content" do — so a headline containing "@everyone" sent
            # as content would ping your whole server. parse: [] switches off
            # every kind of mention for this message, whatever the text says.
            "allowed_mentions": {"parse": []},
        }
        if content:
            payload["content"] = truncate(content, 2000)
        if embeds:
            payload["embeds"] = embeds[:10]  # max 10 embeds per message
        if self.username:
            payload["username"] = self.username
        if self.avatar_url:
            payload["avatar_url"] = self.avatar_url

        if self.dry_run:
            print("\n----- DRY RUN: would POST this to Discord -----")
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return True

        # Counts as sent if at least one channel got it, so a single broken
        # webhook doesn't cause duplicates in the channels that work.
        results = [self._post(url, payload) for url in self.urls]
        return any(results)

    def _post(self, url: str, payload: dict) -> bool:
        for attempt in range(5):
            try:
                resp = self.session.post(url, json=payload, params={"wait": "true"}, timeout=20)
            except requests.RequestException as exc:
                log.warning("Discord request failed (%s), retrying", exc)
                time.sleep(2 ** attempt)
                continue

            if resp.status_code == 429:
                # Rate limited. Discord tells us exactly how long to wait.
                try:
                    wait = float(resp.json().get("retry_after", 2))
                except ValueError:
                    wait = 2.0
                log.info("Rate limited by Discord, waiting %.1fs", wait)
                time.sleep(wait + 0.5)
                continue
            if resp.status_code >= 500:
                time.sleep(2 ** attempt)
                continue
            if not resp.ok:
                # 400 = we sent something invalid (Discord says what in the body)
                # 401/404 = webhook deleted or URL wrong
                log.error("Discord rejected the message: HTTP %s %s", resp.status_code, resp.text[:500])
                return False

            # Be polite: if this was our last request in the bucket, wait it out.
            if resp.headers.get("X-RateLimit-Remaining") == "0":
                time.sleep(float(resp.headers.get("X-RateLimit-Reset-After", 1)))
            return True

        log.error("Gave up posting to Discord after 5 attempts")
        return False
