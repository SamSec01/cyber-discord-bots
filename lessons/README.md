# Lessons

Run these in order from the project root, e.g. `python lessons/lesson1_hello_webhook.py`.
Each file starts with an explanation, then a "Try it" list — do the challenges, that's where the learning happens.

| # | File | You learn |
|---|------|-----------|
| 1 | `lesson1_hello_webhook.py` | HTTP POST, JSON, webhooks, keeping secrets out of code |
| 2 | `lesson2_embeds.py` | Discord embeds, colours, fields, size limits, blocking pings |
| 3 | `lesson3_read_rss.py` | RSS/Atom feeds with feedparser |
| 4 | `lesson4_remember.py` | State and de-duplication, first-run floods, saving safely |
| 5 | `lesson5_add_context.py` | Regex, keyword tagging, calling an AI API, prompt injection defence |
| 6 | `lesson6_nvd_cves.py` | CVE / CVSS / CWE / CPE and the NVD API |
| 7 | `lesson7_kev_epss.py` | CISA KEV and EPSS — prioritising by real-world exploitation |
| 8 | `.github/workflows/*.yml` | Running it all for free on a schedule with GitHub Actions |

Flags most lessons accept:

* `--dry-run` — print the JSON instead of posting to Discord
* `--offline` — use the made-up data in `sample_data/` instead of the internet

The finished bots in `bots/` are the same ideas, tidied into reusable functions with error handling.
