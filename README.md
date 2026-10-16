# Cyber Discord Bots

Two free, open-source bots that turn a Discord server into a cyber threat-intel feed:

| Bot | Posts | Sources | Runs |
|-----|-------|---------|------|
| **News bot** (`bots/news_bot.py`) | Security news **with context**: summary, why it matters, who's affected, what to do, CVEs mentioned, topic tags, severity colour | RSS feeds (The Hacker News, BleepingComputer, The Record, SecurityWeek, Krebs, Dark Reading, NCSC UK — edit in `config.yaml`) + optional Gemini AI | every 30 min |
| **Vuln bot** (`bots/vuln_bot.py`) | **Actively exploited** CVEs (CISA KEV) and new CVEs that pass your filters (severity, vendor watchlist, exploit likelihood), each with CVSS, EPSS, KEV status, affected products, weakness type and advisory links | NVD, CISA KEV, FIRST EPSS | every hour |

Everything runs on GitHub Actions and posts through Discord webhooks — **no server, no hosting, £0**.

```
 RSS feeds ─┐                                   ┌─► #cyber-news
 NVD ───────┼─► GitHub Actions (cron) ─ Python ─┼─► #vuln-alerts
 CISA KEV ──┤          │                        └─► #actively-exploited
 EPSS ──────┘          └─ state/*.json committed back = the bots' memory
```

New to this? Work through **`lessons/`** first (see `lessons/README.md`) — it builds the same thing step by step.

---

## Quick start

### 1. Discord
1. Create a server and these channels: `#cyber-news`, `#vuln-alerts`, `#actively-exploited` (optional), `#bot-logs` (optional, private).
2. For each bot channel: **Edit Channel → Integrations → Webhooks → New Webhook → Copy Webhook URL**.
3. Make bot channels read-only: **Edit Channel → Permissions → @everyone → Send Messages ✗** (leave *Create Public Threads* and *Send Messages in Threads* on so people can discuss each post in a thread).

> A webhook URL is a password: anyone who has it can post in your channel. Never commit it. If it leaks, delete the webhook and make a new one.

### 2. Run it on your PC

```powershell
# Windows (PowerShell)
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env      # then open .env and paste your webhook URLs
```
```bash
# macOS / Linux
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

```bash
python -m pytest -q                                              # tests (offline)
python -m bots.news_bot --fixtures lessons/sample_data --dry-run # offline demo, prints JSON
python -m bots.news_bot --dry-run                                # live feeds, prints JSON
python -m bots.news_bot                                          # live, posts to Discord
python -m bots.vuln_bot --dry-run
python -m bots.vuln_bot
```

`--dry-run` never posts and never saves state, so you can run it as often as you like.

### 3. Optional free API keys (add to `.env`)
* **`GEMINI_API_KEY`** — [Google AI Studio](https://aistudio.google.com/) → *Get API key*. Turns on AI-written summaries / "why it matters". Without it, the news bot still adds rule-based context.
* **`NVD_API_KEY`** — [request one from NIST](https://nvd.nist.gov/developers/request-an-api-key). Raises NVD's rate limit from 5 to 50 requests per 30 seconds.

### 4. Put it on autopilot (GitHub Actions)
1. Create a **public** GitHub repo and push this folder to it (`.env` is git-ignored, so your secrets stay local).
2. Repo **Settings → Secrets and variables → Actions → New repository secret**, add:
   `DISCORD_WEBHOOK_NEWS`, `DISCORD_WEBHOOK_VULNS`, and optionally `DISCORD_WEBHOOK_KEV`, `DISCORD_WEBHOOK_LOGS`, `GEMINI_API_KEY`, `NVD_API_KEY`.
3. **Actions** tab → enable workflows → pick *News bot* → **Run workflow**. Then the same for *Vulnerability bot*.
4. From then on they run on their own schedule.

Why public? Actions minutes are free and unlimited for public repos. A private repo gets 2,000 free minutes a month, and these two schedules use a little more than that — if you want it private, change the news schedule to hourly.

---

## Tuning (`config.yaml`)

* **Feeds** — add/remove/disable RSS feeds.
* **`vulns.min_severity`** — `CRITICAL` by default. `HIGH` is much noisier.
* **`vulns.watchlist`** — vendors/products you look after. CVEs mentioning them are posted from `watchlist_min_severity` (HIGH) upwards.
* **`vulns.min_epss`** — also post anything with at least this chance of exploitation (0.10 = 10%).
* **`max_posts_per_run`** — flood protection. Extra vuln matches are rolled into one summary post.
* **`first_run_posts`** / **`kev_first_run_posts`** — how much to post the very first time.

## Project layout

```
bots/
  common.py        config, .env loading, HTTP session with retries, State (memory)
  discord_post.py  embed builder (enforces Discord limits) + webhook sender (rate limits)
  context.py       HTML cleaning, CVE regex, tags, Gemini summariser + output validation
  news_bot.py      the news bot
  vuln_bot.py      the vulnerability bot
lessons/           step-by-step course + offline sample_data/
tests/             pytest suite (no internet needed)
state/             the bots' memory, committed by Actions
.github/workflows/ news.yml, vulns.yml (schedules), tests.yml (runs tests on push)
```

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Webhook URL is missing` | Secret not set, or named differently from the workflow file. |
| Discord `HTTP 400` | Something broke an embed limit or the JSON — the error body says which field. |
| Discord `HTTP 401/404` | Webhook was deleted or the URL is wrong. Make a new one, update the secret. |
| A feed always `FAILED` | Site blocks bots or changed its feed URL. Disable it in `config.yaml`. |
| NVD `HTTP 403` | Rate limit. The bot waits and retries; add `NVD_API_KEY` for headroom. |
| Gemini `429` | Free-tier quota hit. The bot falls back to rule-based context automatically. |
| Workflow can't `git push` (403) | Repo **Settings → Actions → General → Workflow permissions → Read and write**. |
| Bot posted lots at once | It was a first run (state file missing). Expected once. |
| Runs a few minutes late | Normal for GitHub's scheduler at busy times. |
| Got an email saying a workflow was disabled | GitHub pauses schedules in public repos with no activity for 60 days. Re-enable it on the Actions tab. |
| Want to start over | Delete `state/news_state.json` or `state/vuln_state.json` and push. |

## Data sources & terms
* [NVD](https://nvd.nist.gov/developers) — "This product uses data from the NVD API but is not endorsed or certified by the NVD."
* [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
* [FIRST EPSS](https://www.first.org/epss/)
* News content belongs to the publishers; the bot posts a short summary and always links to the original.
* Gemini free tier: Google may use what you send to improve its products — fine for public news, never send anything private through it.
