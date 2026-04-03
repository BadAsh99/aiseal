#!/usr/bin/env python3
"""
Argus — Ghost99RT Alert Relay
Polls Ghost99RT for flagged interactions and posts to #argus-alerts.
Never sleeps. Always watching.
"""

import os
import json
import time
import requests
from pathlib import Path
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

load_dotenv()

GHOST99RT_URL = os.environ.get("GHOST99RT_URL", "http://127.0.0.1:8888")
ALERT_CHANNEL = "#argus-alerts"
POLL_INTERVAL = 30  # seconds
STATE_FILE = Path(__file__).parent / ".argus_state.json"

slack = WebClient(token=os.environ["SLACK_BOT_TOKEN"])


def load_seen() -> set:
    if STATE_FILE.exists():
        return set(json.loads(STATE_FILE.read_text()).get("seen", []))
    return set()


def save_seen(seen: set):
    STATE_FILE.write_text(json.dumps({"seen": list(seen)}))


def fetch_logs() -> list:
    try:
        r = requests.get(f"{GHOST99RT_URL}/logs", timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[Argus] Ghost99RT unreachable: {e}", flush=True)
        return []


def format_alert(row: dict) -> str:
    scan = row.get("scan_result", {})
    prompt_scan = scan.get("prompt_scan", {})
    resp_scan = scan.get("response_scan", {})

    severity = prompt_scan.get("severity") or resp_scan.get("severity") or "unknown"
    reason = prompt_scan.get("reason") or resp_scan.get("reason") or "No reason captured"
    emoji = "🚨" if severity == "high" else "⚠️"

    prompt = row.get("prompt", "")
    preview = (prompt[:120] + "...") if len(prompt) > 120 else prompt

    return (
        f"{emoji} *ARGUS ALERT*\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"*Severity:* `{severity.upper()}` | *Project:* `{row.get('project', 'unknown')}`\n"
        f"*Model:* `{row.get('model', 'unknown')}` | *Latency:* `{row.get('latency_ms', '?')}ms`\n"
        f"*Tokens:* `{row.get('tokens_in', '?')} in / {row.get('tokens_out', '?')} out`\n"
        f"*Pattern:* {reason}\n"
        f"*Prompt preview:*\n```{preview}```\n"
        f"_Argus sees everything. — ARIA!_"
    )


def post_alert(message: str):
    try:
        slack.chat_postMessage(channel=ALERT_CHANNEL, text=message)
        print(f"[Argus] Alert posted to {ALERT_CHANNEL}", flush=True)
    except SlackApiError as e:
        print(f"[Argus] Slack error: {e.response['error']}", flush=True)


def run():
    print("[Argus] Online. Watching Ghost99RT.", flush=True)
    seen = load_seen()

    while True:
        logs = fetch_logs()
        new_ids = set()

        for row in logs:
            interaction_id = row.get("id")
            if not interaction_id:
                continue
            new_ids.add(interaction_id)
            if interaction_id in seen:
                continue
            if row.get("flagged"):
                print(f"[Argus] Flagged: {interaction_id}", flush=True)
                post_alert(format_alert(row))

        seen.update(new_ids)
        save_seen(seen)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
