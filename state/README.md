# state/

The bots' memory. `news_state.json` and `vuln_state.json` appear here after
the first run and record every item already posted, so nothing is posted twice.

GitHub Actions commits these files back to the repo after each run.

To make a bot "start fresh" (it will do a quiet first run again), delete its
state file and push.
