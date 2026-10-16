"""
LESSON 1 — Your first message
=============================
Goal: make a message appear in your Discord channel from Python.

How it works
------------
A Discord *webhook* is a secret URL tied to one channel. If you send an HTTP
POST request to it with some JSON, Discord shows that JSON as a message.

    Your script  --(HTTP POST + JSON)-->  discord.com/api/webhooks/...  -->  #channel

That's the whole trick behind both bots. Everything else is deciding WHAT to send.

Run it
------
    python lessons/lesson1_hello_webhook.py            # sends for real
    python lessons/lesson1_hello_webhook.py --dry-run  # just prints the JSON

Try it
------
1. Run it and check your channel.
2. Change "username" and run it again — the sender name changes.
3. Break the URL on purpose (delete the last character in .env). What status
   code comes back? (Hint: 401 or 404.) Error codes are clues — learn to read them.
"""
import json
import sys

import requests

from _env import load_env, need

load_env()
dry_run = "--dry-run" in sys.argv

# The JSON "payload" — a Python dict that requests turns into JSON for us.
payload = {
    "content": "Hello from my cyber news bot 👋",   # the message text (max 2,000 chars)
    "username": "Cyber News (lesson 1)",            # overrides the webhook's name
}

if dry_run:
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    sys.exit(0)

url = need("DISCORD_WEBHOOK_NEWS")
response = requests.post(url, json=payload, timeout=10)

# HTTP status codes:  2xx = worked,  4xx = you sent something wrong,  5xx = their problem.
# Discord webhooks answer 204 "No Content" on success (worked, nothing to say back).
print("Status code:", response.status_code)
if response.ok:
    print("It worked — check your Discord channel!")
else:
    print("Discord said:", response.text)
