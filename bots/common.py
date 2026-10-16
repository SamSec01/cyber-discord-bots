"""
Shared plumbing used by both bots:

  * load_dotenv()   – read secrets from a local .env file (for running on your PC)
  * load_config()   – read config.yaml
  * http_session()  – a requests Session with a User-Agent, timeouts and retries
  * State           – the bot's memory of what it has already posted
  * time helpers    – everything is handled in UTC to avoid timezone bugs
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ROOT = Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / "state"

# Identify yourself to the sites you pull from. Some APIs (NVD especially)
# treat anonymous / default python-requests traffic with suspicion.
USER_AGENT = "cyber-discord-bots/1.0 (+https://github.com/)"

log = logging.getLogger("bots")


# --------------------------------------------------------------------------- #
#  Setup helpers
# --------------------------------------------------------------------------- #
def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    # Windows consoles sometimes choke on emoji; force UTF-8 output.
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass


def load_dotenv(path: Path | None = None) -> None:
    """Tiny .env reader: KEY=value lines → environment variables.

    Real environment variables win (setdefault), so GitHub Secrets always
    override anything in a stray .env file.
    """
    path = path or ROOT / ".env"
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        if value:
            os.environ.setdefault(key.strip(), value)


def load_config(path: Path | None = None) -> dict:
    path = path or ROOT / "config.yaml"
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def env(name: str) -> str | None:
    """Read an environment variable, treating empty strings as 'not set'."""
    value = os.environ.get(name, "").strip()
    return value or None


def http_session() -> requests.Session:
    """A Session that retries GETs on flaky errors and rate limits.

    Retry(backoff_factor=2) waits 2s, 4s, 8s... between attempts and honours
    a server's Retry-After header. Only GET is retried automatically —
    retrying a POST could double-post.
    """
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# --------------------------------------------------------------------------- #
#  Time helpers — ALWAYS work in UTC, convert only for display.
# --------------------------------------------------------------------------- #
def utcnow() -> datetime:
    override = env("BOT_NOW")  # lets tests / fixtures "time travel"
    if override:
        return parse_iso(override) or datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


def parse_iso(value: str | None) -> datetime | None:
    """Parse ISO-8601 strings like '2026-10-16T09:15:00.123' or '...Z'."""
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # NVD/KEV times are UTC
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
#  State: the bot's memory
# --------------------------------------------------------------------------- #
class State:
    """Remembers which items have been posted, in a small JSON file.

    {
      "seen": {"news:https://...": "2026-10-16T09:00:00Z", ...},
      "meta": {"last_nvd_end": "2026-10-16T09:00:00Z"}
    }

    The workflow commits this file back to the repo after every run — that's
    how a bot with no server "remembers" between runs.
    """

    def __init__(self, path: Path, read_only: bool = False):
        self.path = Path(path)
        self.read_only = read_only
        self.first_run = not self.path.exists()
        self.data = {"seen": {}, "meta": {}}
        if not self.first_run:
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                self.data["seen"] = dict(loaded.get("seen", {}))
                self.data["meta"] = dict(loaded.get("meta", {}))
            except (json.JSONDecodeError, OSError) as exc:
                # A corrupt state file must not crash the bot — but treat it as
                # a first run so we don't flood the channel either.
                log.warning("State file %s unreadable (%s) — starting fresh", self.path, exc)
                self.first_run = True

    @property
    def meta(self) -> dict:
        return self.data["meta"]

    def seen(self, key: str) -> bool:
        return key in self.data["seen"]

    def mark(self, key: str, when: datetime | None = None, save: bool = True) -> None:
        self.data["seen"][key] = iso(when or utcnow())
        if save:
            self.save()

    def prune(self, keep_days: int) -> int:
        cutoff = utcnow() - timedelta(days=keep_days)
        before = len(self.data["seen"])
        self.data["seen"] = {
            k: v for k, v in self.data["seen"].items() if (parse_iso(v) or utcnow()) >= cutoff
        }
        return before - len(self.data["seen"])

    def new_errors(self, errors: list[str]) -> list[str]:
        """Errors that weren't there last run.

        A permanently broken feed would otherwise post the same complaint to
        #bot-logs every 30 minutes. This way you hear about it once, and again
        only if it recovers and breaks again.
        """
        previous = set(self.meta.get("last_errors", []))
        self.meta["last_errors"] = errors
        return [e for e in errors if e not in previous]

    def save(self) -> None:
        if self.read_only:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        # Write to a temp file then swap it in, so a crash mid-write can't
        # leave a half-written (corrupt) state file.
        tmp.write_text(json.dumps(self.data, indent=1, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)
