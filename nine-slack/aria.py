#!/usr/bin/env python3
"""
ARIA! — Adaptive Risk Intelligence Analyst
Slack bot powered by Claude. Part of the AISeal platform.
"""

import os
import re
import json
from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from anthropic import Anthropic

load_dotenv()

app = App(token=os.environ["SLACK_BOT_TOKEN"])
client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

CUSTOMERS_FILE = os.path.join(os.path.dirname(__file__), "customers.json")

SYSTEM_PROMPT = """You are ARIA — Adaptive Risk Intelligence Analyst — the AI security intelligence layer of the AISeal platform.

You are a direct, technical AI security analyst. You help Professional Services consultants and their managers at Palo Alto Networks with:

1. AI security questions — OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, prompt injection, RAG poisoning, excessive agency, MCP security
2. AIRS deployment guidance — Prisma AIRS architecture, deployment stages, customer status
3. AISeal scan interpretation — TrustScore analysis, finding explanations, remediation guidance
4. PS workflow — deployment stage tracking, customer status, next steps

Your communication style:
- BLUF — answer first, explain after
- Technical peer tone — no hand-holding, no fluff
- Short and direct
- If you don't know something, say so — never guess on security details

You are part of the AISeal product family:
- AISeal Scan: OWASP LLM Top 10 scanner, TrustScore 0-100
- AISeal Monitor: Runtime LLM surveillance via Ghost99RT
- AISeal Cert: AI vendor certification platform
- Lumen: PS deployment status and metrics tracker
- Argus: Runtime alerting, never sleeps

Always sign off responses with: *— ARIA!*"""


# ── Lumen data helpers ──

def load_customers():
    with open(CUSTOMERS_FILE) as f:
        return json.load(f)["customers"]


def score_bar(score):
    if score is None:
        return "no scan"
    if score >= 80:
        return f"{score}/100 ✅"
    if score >= 60:
        return f"{score}/100 ⚠️"
    return f"{score}/100 🔴"


def stage_emoji(stage):
    return {
        "Proposal": "📋",
        "Experiment": "🧪",
        "Pilot": "🚀",
        "Production": "✅",
    }.get(stage, "❓")


def fmt_customer(c):
    score = score_bar(c.get("trustscore"))
    stage = c.get("airs_stage", "Unknown")
    emoji = stage_emoji(stage)
    last = c.get("last_scan") or "never"
    notes = c.get("notes", "")
    return (
        f"*{c['name']}* — {emoji} {stage} | TrustScore: {score} | Last scan: {last}\n"
        f"  _{notes}_"
    )


# ── Lumen commands ──

def cmd_status(query):
    customers = load_customers()
    matches = [c for c in customers if query.lower() in c["name"].lower()]
    if not matches:
        return f"No customer found matching *{query}*."
    return "\n\n".join(fmt_customer(c) for c in matches)


def cmd_my_accounts(owner):
    customers = load_customers()
    mine = [c for c in customers if c.get("owner", "").lower() == owner.lower()]
    if not mine:
        return f"No accounts found for *{owner}*."
    header = f"*Your accounts ({len(mine)}):*\n"
    return header + "\n\n".join(fmt_customer(c) for c in mine)


def cmd_team_view():
    customers = load_customers()
    by_owner = {}
    for c in customers:
        owner = c.get("owner", "unassigned")
        by_owner.setdefault(owner, []).append(c)

    lines = ["*Team View — All Accounts:*\n"]
    for owner, accounts in sorted(by_owner.items()):
        lines.append(f"*{owner}* ({len(accounts)} accounts)")
        for c in accounts:
            lines.append(fmt_customer(c))
        lines.append("")
    return "\n".join(lines)


def cmd_at_risk(threshold=70):
    customers = load_customers()
    at_risk = [c for c in customers if c.get("trustscore") is not None and c["trustscore"] < threshold]
    if not at_risk:
        return f"No customers below TrustScore {threshold}. All clear. ✅"
    header = f"*At-risk accounts (TrustScore < {threshold}):*\n"
    return header + "\n\n".join(fmt_customer(c) for c in at_risk)


def cmd_pipeline():
    customers = load_customers()
    stages = ["Proposal", "Experiment", "Pilot", "Production"]
    lines = ["*AIRS Deployment Pipeline:*\n"]
    for stage in stages:
        in_stage = [c for c in customers if c.get("airs_stage") == stage]
        emoji = stage_emoji(stage)
        lines.append(f"{emoji} *{stage}* ({len(in_stage)})")
        for c in in_stage:
            score = score_bar(c.get("trustscore"))
            lines.append(f"  • {c['name']} — {score}")
    return "\n".join(lines)


# ── Command router ──

LUMEN_HELP = """*Lumen commands:*
• `status <customer>` — deployment stage + TrustScore
• `my accounts` — your assigned customers
• `team view` — all accounts across the team
• `at-risk` — customers below TrustScore 70
• `pipeline` — all customers by AIRS stage
• anything else — ask ARIA directly"""


def route_command(text: str, user_name: str) -> str | None:
    t = text.lower().strip()

    if t in ("help", "lumen", "commands"):
        return LUMEN_HELP

    if t.startswith("status "):
        return cmd_status(text[7:].strip())

    if t in ("my accounts", "my customers", "accounts"):
        return cmd_my_accounts(user_name)

    if t in ("team view", "team", "all accounts"):
        return cmd_team_view()

    if t in ("at-risk", "at risk", "risk"):
        return cmd_at_risk()

    if t in ("pipeline", "stages", "deployment"):
        return cmd_pipeline()

    return None


# ── AI fallback ──

def ask_aria(question: str) -> str:
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": question}],
    )
    return response.content[0].text


# ── Slack handlers ──

def get_user_name(user_id: str) -> str:
    try:
        result = app.client.users_info(user=user_id)
        return result["user"]["name"]
    except Exception:
        return "unknown"


def handle_text(text: str, user_id: str, say):
    user_name = get_user_name(user_id)
    lumen_response = route_command(text, user_name)
    if lumen_response:
        say(lumen_response)
    else:
        say(":brain: thinking...")
        say(ask_aria(text))


@app.event("app_mention")
def handle_mention(event, say):
    text = re.sub(r"<@[^>]+>", "", event.get("text", "")).strip()
    if not text:
        say(f"You called? Try `help` for Lumen commands or ask me anything. *— ARIA!*")
        return
    handle_text(text, event["user"], say)


@app.event("message")
def handle_dm(event, say):
    if event.get("channel_type") != "im":
        return
    if event.get("bot_id"):
        return
    text = event.get("text", "").strip()
    if not text:
        return
    handle_text(text, event["user"], say)


if __name__ == "__main__":
    print("ARIA! is online.")
    handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    handler.start()
