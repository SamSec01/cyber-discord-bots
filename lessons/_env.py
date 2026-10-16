"""
Helper used by every lesson: loads your secrets from the .env file in the
project root, so you don't have to paste webhook URLs into code.

(Never put secrets in code. Code gets committed, shared and screenshotted.)
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DATA = Path(__file__).resolve().parent / "sample_data"


def load_env():
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                if value.strip():
                    os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # emoji-safe output on Windows
    except Exception:
        pass


def need(name):
    """Get a required setting or explain how to fix it."""
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"\n{name} isn't set.\nCopy .env.example to .env and paste your value in, "
                 f"or run with --dry-run to just print what would be sent.\n")
    return value
