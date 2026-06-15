#!/usr/bin/env python3
"""
EASM Scanner — Interactive API Key Setup
==========================================
Reads/writes the .env file. Shows which keys are already set,
prompts for missing/changed values. Empty input keeps the existing value.

Usage:
    python setup_keys.py            # interactive
    python setup_keys.py --status   # only print what is configured
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ENV_PATH = Path(__file__).parent / ".env"
EXAMPLE_PATH = Path(__file__).parent / ".env.example"

KEYS = [
    {
        "name": "VT_API_KEY",
        "label": "VirusTotal",
        "desc": "Domain + IP reputation lookup",
        "url": "https://www.virustotal.com/gui/my-apikey",
        "free": "yes (500/day)",
    },
    {
        "name": "HIBP_API_KEY",
        "label": "Have I Been Pwned",
        "desc": "Breach search for domain emails",
        "url": "https://haveibeenpwned.com/API/Key",
        "free": "no ($3.95/month)",
    },
    {
        "name": "ABUSEIPDB_API_KEY",
        "label": "AbuseIPDB",
        "desc": "IP abuse confidence score",
        "url": "https://www.abuseipdb.com/account/api",
        "free": "yes (1k/day)",
    },
    {
        "name": "GSB_API_KEY",
        "label": "Google Safe Browsing",
        "desc": "Google phishing/malware flag check",
        "url": "https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com",
        "free": "yes (10k/day)",
    },
    {
        "name": "SHODAN_API_KEY",
        "label": "Shodan",
        "desc": "Passive port/CVE/banner data",
        "url": "https://account.shodan.io/",
        "free": "$5 one-time for dev tier",
    },
    {
        "name": "GITHUB_TOKEN",
        "label": "GitHub Token",
        "desc": "Code search for leaked secrets",
        "url": "https://github.com/settings/tokens (scope: public_repo)",
        "free": "yes",
    },
    {
        "name": "EASM_WEBHOOK_URL",
        "label": "Slack/Discord Webhook",
        "desc": "Live alerts on state diffs",
        "url": "Slack: api.slack.com/messaging/webhooks · Discord: Channel → Integrations",
        "free": "yes",
    },
]

# ANSI colors
GRN = "\033[32m"; YEL = "\033[33m"; RED = "\033[31m"
DIM = "\033[2m";  BLD = "\033[1m";  RST = "\033[0m"


def parse_env(text: str) -> dict[str, str]:
    """Parse a simple .env (KEY=VALUE, optional quotes)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$', line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        out[key] = val
    return out


def render_env(values: dict[str, str]) -> str:
    """Re-render a clean .env file, comments included."""
    lines = ["# EASM Scanner API Keys — managed by setup_keys.py", ""]
    for k in KEYS:
        v = values.get(k["name"], "")
        lines.append(f'# {k["label"]} — {k["desc"]}')
        lines.append(f'{k["name"]}="{v}"')
        lines.append("")
    # Preserve any unknown keys the user added manually
    known = {k["name"] for k in KEYS}
    extras = {k: v for k, v in values.items() if k not in known}
    if extras:
        lines.append("# Custom / additional keys")
        for k, v in extras.items():
            lines.append(f'{k}="{v}"')
        lines.append("")
    return "\n".join(lines)


def mask(value: str) -> str:
    if not value:
        return f"{DIM}(not set){RST}"
    if len(value) <= 8:
        return f"{GRN}***{RST}"
    return f"{GRN}{value[:4]}…{value[-4:]}{RST} {DIM}({len(value)} chars){RST}"


def status(values: dict[str, str]) -> None:
    print(f"\n{BLD}EASM Scanner — API Key Status{RST}")
    print(f"{DIM}{ENV_PATH}{RST}\n")
    set_count = 0
    for k in KEYS:
        v = values.get(k["name"], "")
        if v:
            set_count += 1
        print(f"  {BLD}{k['label']:25s}{RST} {mask(v)}")
        if not v:
            print(f"  {DIM}    → {k['desc']}{RST}")
            print(f"  {DIM}    → free: {k['free']} · {k['url']}{RST}")
    print(f"\n  {set_count}/{len(KEYS)} keys configured.\n")


def prompt(values: dict[str, str]) -> dict[str, str]:
    print(f"\n{BLD}Interactive setup{RST}  {DIM}(empty input keeps current value, 'd' deletes){RST}\n")
    new = dict(values)
    for k in KEYS:
        cur = values.get(k["name"], "")
        print(f"{BLD}{k['label']}{RST}  {DIM}— {k['desc']}{RST}")
        print(f"  {DIM}{k['url']}{RST}")
        print(f"  current: {mask(cur)}")
        try:
            entered = input(f"  new value [{YEL}skip{RST}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Aborted, nothing written.")
            sys.exit(1)
        if entered == "":
            pass  # keep
        elif entered.lower() == "d":
            new[k["name"]] = ""
            print(f"  {RED}cleared{RST}")
        else:
            new[k["name"]] = entered
            print(f"  {GRN}saved{RST}")
        print()
    return new


def main():
    ap = argparse.ArgumentParser(description="Manage EASM Scanner API keys in .env")
    ap.add_argument("--status", action="store_true", help="Only show current key status")
    args = ap.parse_args()

    if not ENV_PATH.exists():
        if EXAMPLE_PATH.exists():
            print(f"{YEL}.env doesn't exist yet — bootstrapping from .env.example{RST}")
            ENV_PATH.write_text(EXAMPLE_PATH.read_text())
        else:
            ENV_PATH.write_text("")

    values = parse_env(ENV_PATH.read_text())

    if args.status:
        status(values)
        return

    status(values)
    new_values = prompt(values)

    ENV_PATH.write_text(render_env(new_values))
    try:
        os.chmod(ENV_PATH, 0o600)
    except OSError:
        pass

    print(f"{GRN}✓ Wrote {ENV_PATH}{RST}")
    status(new_values)


if __name__ == "__main__":
    main()
