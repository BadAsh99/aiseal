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

PERSONAL_PROMPT = """You are ARIA — personal AI assistant to Ash Clements.

About Ash:
- Sr. Professional Services Consultant at Palo Alto Networks (SASE, PCNSE)
- Based in Phoenix, AZ
- Building AISeal — an AI Trust & Certification Platform (aiseal.ai)
- Targeting the AIRS Specialist role at PANW
- Stack: Python, Next.js, TypeScript, Terraform, Docker, Azure/GCP/AWS
- Projects: AISeal, ARIA (you), Ghost99RT, badash-killchain, CastleDesk
- Communication: BLUF, no fluff, technical peer, dry humor welcome

Your role in DMs:
- General purpose assistant — anything Ash needs, not just security
- Help him think through problems, draft content, debug code, plan strategy
- You know his full context — career pivot, interview prep, product roadmap
- Be direct, be useful, skip the formalities

You still know everything about AI security, AISeal, AIRS, and PANW — that context is always available.

Sign off with: *— ARIA!*"""


# ── Lumen data helpers ──

def load_customers():
    with open(CUSTOMERS_FILE) as f:
        return json.load(f)["customers"]


STAGE_ABBR = {
    "Proposal":   "St.1",
    "Experiment": "St.2",
    "Pilot":      "St.3",
    "Production": "St.4",
}


def status_label(score):
    if score is None:
        return ("🔵", "In Progress")
    if score >= 80:
        return ("✅", "On Track")
    if score >= 60:
        return ("⚠️ ", "Stalled")
    return ("🔴", "At Risk")


def fmt_customer(c):
    stage = c.get("airs_stage", "Unknown")
    score = c.get("trustscore")
    last = c.get("last_scan") or "never"
    notes = c.get("notes", "")
    emoji, label = status_label(score)
    score_str = str(score) if score is not None else "—"
    return (
        f"*{c['name']}* — {STAGE_ABBR.get(stage, stage)} | Score: {score_str} | {emoji} {label} | Last scan: {last}\n"
        f"  _{notes}_"
    )


def table_row(name, owner, stage, score, status_emoji, status_text):
    return f"  {name:<20} {owner:<18} {stage:<6} {score:<6} {status_emoji} {status_text}"


def build_table(customers):
    header  = f"  {'ACCOUNT':<20} {'OWNER':<18} {'STAGE':<6} {'SCORE':<6} STATUS"
    divider = "  " + "─" * 62
    rows = []
    for c in customers:
        score = c.get("trustscore")
        stage = STAGE_ABBR.get(c.get("airs_stage", ""), "—")
        score_str = str(score) if score is not None else "—"
        emoji, label = status_label(score)
        rows.append(table_row(c["name"], c.get("owner", "—"), stage, score_str, emoji, label))
    return header + "\n" + divider + "\n" + "\n".join(rows)


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
    lines = [f"*Your Accounts ({len(mine)})*", "━" * 44]
    lines.append(build_table(mine))
    return "\n".join(lines)


def cmd_team_view():
    customers = load_customers()
    lines = ["*TEAM VIEW — All Accounts*", "━" * 44]
    lines.append(build_table(customers))
    return "```" + "\n".join(lines) + "```"


def cmd_at_risk(threshold=70):
    customers = load_customers()
    at_risk = [c for c in customers if c.get("trustscore") is not None and c["trustscore"] < threshold]
    if not at_risk:
        return f"No customers below TrustScore {threshold}. All clear. ✅"
    lines = [f"*At-Risk Accounts (TrustScore < {threshold})*", "━" * 44]
    lines.append(build_table(at_risk))
    return "```" + "\n".join(lines) + "```"


def cmd_pipeline():
    customers = load_customers()
    stage_order = ["Proposal", "Experiment", "Pilot", "Production"]
    stage_icons = {"Proposal": "📋", "Experiment": "🧪", "Pilot": "🚀", "Production": "✅"}
    lines = ["*AIRS Deployment Pipeline*", "━" * 44]
    for stage in stage_order:
        abbr = STAGE_ABBR[stage]
        icon = stage_icons[stage]
        in_stage = [c for c in customers if c.get("airs_stage") == stage]
        lines.append(f"\n{icon} *{stage}* ({abbr}) — {len(in_stage)} account{'s' if len(in_stage) != 1 else ''}")
        for c in in_stage:
            score = c.get("trustscore")
            emoji, label = status_label(score)
            score_str = str(score) if score is not None else "—"
            lines.append(f"  • *{c['name']}* — Score: {score_str} {emoji} {label}")
    return "\n".join(lines)


# ── Command router ──

LUMEN_HELP = """*Lumen commands:*
• `status <customer>` — deployment stage + TrustScore
• `my accounts` — your assigned customers
• `team view` — all accounts across the team
• `at-risk` — customers below TrustScore 70
• `pipeline` — all customers by AIRS stage
• anything else — ask ARIA directly"""


STATUS_TRIGGERS = (
    "latest on", "status of", "update on", "tell me about",
    "what's the", "whats the", "how is", "info on", "details on",
    "provide", "give me", "show me", "pull up", "check on",
)


def natural_language_customer_lookup(text: str) -> str | None:
    """Check if text is a natural language customer query. Return cmd_status result or None."""
    t = text.lower()
    customers = load_customers()
    for c in customers:
        if c["name"].lower() in t:
            # Check if it looks like a status request, or just mentions the customer
            if any(trigger in t for trigger in STATUS_TRIGGERS) or "status" in t or "score" in t or "stage" in t:
                return cmd_status(c["name"])
    return None


def route_command(text: str, user_name: str) -> str | None:
    t = " ".join(text.lower().split())  # normalize all whitespace

    if t in ("help", "lumen", "commands"):
        return LUMEN_HELP

    if t in ("whoami", "who am i", "my id"):
        return f"You are `{user_name}` — that's what ARIA sees as your owner ID. Use this in customers.json."

    if t.startswith("status "):
        return cmd_status(text[7:].strip())

    if any(t == phrase or t.startswith(phrase) for phrase in (
        "my accounts", "my customers", "accounts", "list my", "show my",
        "list all my", "show all my", "all my accounts", "all my customers",
    )):
        return cmd_my_accounts(user_name)

    if t in ("team view", "team", "all accounts"):
        return cmd_team_view()

    if t in ("at-risk", "at risk", "risk"):
        return cmd_at_risk()

    if t in ("pipeline", "stages", "deployment"):
        return cmd_pipeline()

    # Natural language customer lookup
    return natural_language_customer_lookup(text)


# ── AI fallback ──

def ask_aria(question: str, personal: bool = False) -> str:
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=PERSONAL_PROMPT if personal else SYSTEM_PROMPT,
        messages=[{"role": "user", "content": question}],
    )
    return response.content[0].text


# ── Slack handlers ──

def get_user_name(user_id: str) -> str:
    try:
        result = app.client.users_info(user=user_id)
        user = result["user"]
        return (
            user.get("profile", {}).get("display_name")
            or user.get("name")
            or user_id
        )
    except Exception:
        return user_id


def handle_text(text: str, user_id: str, say, personal: bool = False):
    user_name = get_user_name(user_id)
    if not personal:
        lumen_response = route_command(text, user_name)
        if lumen_response:
            say(lumen_response)
            return
    say(":brain: thinking...")
    say(ask_aria(text, personal=personal))


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
    handle_text(text, event["user"], say, personal=True)


if __name__ == "__main__":
    print("ARIA! is online.")
    handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    handler.start()
