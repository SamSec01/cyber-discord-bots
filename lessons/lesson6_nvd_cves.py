"""
LESSON 6 — Pulling CVEs from the NVD
====================================
Goal: get yesterday's new vulnerabilities and find the ones that matter.

Vocabulary
----------
CVE   A unique ID for one vulnerability: CVE-2026-12345. Assigned by a CNA
      (often the vendor). Just an ID + description — no judgement of severity.
NVD   The US National Vulnerability Database (run by NIST). Takes every CVE and
      adds analysis: CVSS score, affected products (CPE), weakness type (CWE).
      It's often days or weeks behind, so new CVEs may only have the vendor's
      own score (marked "Secondary") or no score at all yet.
CVSS  0-10 severity score. 9.0+ Critical, 7.0+ High, 4.0+ Medium, else Low.
      Severity ≠ risk: a 9.8 in software nobody runs matters less than a 7.5
      in your VPN that's being exploited today.
CWE   The *type* of bug: CWE-79 = cross-site scripting, CWE-78 = OS command injection.
CPE   A standard name for a product: cpe:2.3:a:vendor:product:version:...

The API
-------
    GET https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=...&pubEndDate=...
Free, no account needed. Without a key: 5 requests per 30 seconds. With a free
key (https://nvd.nist.gov/developers/request-an-api-key): 50 per 30 seconds.
Over the limit, NVD answers HTTP 403 — wait and retry.

Run it
------
    python lessons/lesson6_nvd_cves.py              # last 24 hours, live
    python lessons/lesson6_nvd_cves.py --offline    # sample data

Try it
------
1. Change the window to 3 days. How many CVEs a day is "normal"?
2. Add the parameter "keywordSearch": "fortinet" — what comes back?
3. How many new CVEs have NO score yet? That's why the real bot watches for
   CVEs *modified* recently, not just published — it catches them once scored.
"""
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

import requests

from _env import SAMPLE_DATA, load_env

load_env()

if "--offline" in sys.argv:
    data = json.loads((SAMPLE_DATA / "nvd.json").read_text(encoding="utf-8"))
else:
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=24)
    fmt = "%Y-%m-%dT%H:%M:%S.000"   # the date format NVD expects (UTC)
    params = {"pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt), "resultsPerPage": 2000}
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}   # optional: higher rate limit
    print("Asking NVD for CVEs published since", params["pubStartDate"], "UTC …")
    resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, headers=headers, timeout=60)
    print("HTTP", resp.status_code)
    resp.raise_for_status()
    data = resp.json()

print("Total results:", data["totalResults"], "\n")


def severity(cve):
    """Newest CVSS version available → (severity, score)."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        metrics = cve.get("metrics", {}).get(key)
        if metrics:
            d = metrics[0]["cvssData"]
            return d["baseSeverity"], d["baseScore"]
    return "UNSCORED", None


counts = Counter()
criticals = []
for item in data["vulnerabilities"]:
    cve = item["cve"]                      # each result wraps the record in "cve"
    sev, score = severity(cve)
    counts[sev] += 1
    if sev == "CRITICAL":
        desc = next(d["value"] for d in cve["descriptions"] if d["lang"] == "en")
        criticals.append((score, cve["id"], desc))

print("By severity:", dict(counts), "\n")
print("Critical ones:")
for score, cve_id, desc in sorted(criticals, reverse=True)[:10]:
    print(f"  {cve_id}  ({score})  {desc[:110]}…")
