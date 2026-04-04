#!/usr/bin/env python3
"""
ARIA! — Adaptive Risk Intelligence Analyst
Slack bot powered by Claude. Part of the AISeal platform.
"""

import os
import re
import json
import threading
import time as _time
from datetime import datetime
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

def days_since(date_str: str) -> int | None:
    if not date_str:
        return None
    try:
        from datetime import date
        d = date.fromisoformat(date_str)
        return (date.today() - d).days
    except Exception:
        return None


def days_in_stage(stage_since: str) -> str:
    d = days_since(stage_since)
    if d is None:
        return "unknown"
    return f"{d} days"


def cmd_prep(query: str) -> str:
    """90-second call prep for a customer."""
    customers = load_customers()
    matches = [c for c in customers if query.lower() in c["name"].lower()]
    if not matches:
        return f"No customer found matching *{query}*."
    c = matches[0]

    stage = c.get("airs_stage", "Unknown")
    score = c.get("trustscore")
    score_str = str(score) if score is not None else "No scan yet"
    emoji, label = status_label(score)
    abbr = STAGE_ABBR.get(stage, stage)
    stage_since = c.get("stage_since", "")
    in_stage = days_in_stage(stage_since)
    last_interaction = c.get("last_interaction") or "unknown"
    days_ago = days_since(last_interaction)
    last_str = f"{last_interaction} ({days_ago}d ago)" if days_ago is not None else last_interaction
    next_action = c.get("next_action") or "None set"
    next_due = c.get("next_action_due") or "No date"
    due_in = days_since(next_due)
    due_str = f"{next_due}"
    if due_in is not None:
        if due_in < 0:
            due_str += f" _(in {abs(due_in)} days)_"
        elif due_in == 0:
            due_str += " _⚠️ DUE TODAY_"
        else:
            due_str += f" _⚠️ OVERDUE {due_in}d_"

    stakeholders = c.get("stakeholders", [])
    stakeholder_lines = "\n".join(
        f"  • {s['name']} — {s['role']}" for s in stakeholders
    ) or "  None on file"

    notes = c.get("notes", "None")

    lines = [
        f"📋 *CALL PREP — {c['name'].upper()}*",
        "━" * 44,
        f"*Stage:* {abbr} — {stage}  _(in stage: {in_stage})_",
        f"*TrustScore:* {score_str}  {emoji} {label}",
        f"*Last Interaction:* {last_str}",
        "",
        f"*Next Action:* {next_action}",
        f"*Due:* {due_str}",
        "",
        "*Stakeholders:*",
        stakeholder_lines,
        "",
        f"*Notes:* {notes}",
        "",
        "_— ARIA!_",
    ]
    return "\n".join(lines)


def cmd_daily_digest(owner: str = None) -> str:
    """Morning digest — red/yellow/green accounts with suggested actions."""
    from datetime import date
    customers = load_customers()
    if owner:
        customers = [c for c in customers if c.get("owner", "").lower() == owner.lower()]

    red, yellow, green = [], [], []

    for c in customers:
        score = c.get("trustscore")
        last_scan = c.get("last_scan")
        next_due = c.get("next_action_due")
        days_no_scan = days_since(last_scan) if last_scan else 999
        overdue = False
        if next_due:
            d = days_since(next_due)
            overdue = d is not None and d > 0

        if score is not None and score < 60 or days_no_scan > 20 or overdue:
            red.append(c)
        elif score is not None and score < 75 or days_no_scan > 10:
            yellow.append(c)
        else:
            green.append(c)

    today = date.today().strftime("%A, %B %d")
    lines = [f"☀️ *ARIA DAILY DIGEST — {today}*", "━" * 44, ""]

    if red:
        lines.append(f"🔴 *Needs Attention ({len(red)})*")
        for c in red:
            next_action = c.get("next_action", "No action set")
            lines.append(f"  • *{c['name']}* — {next_action}")
        lines.append("")

    if yellow:
        lines.append(f"⚠️  *Watch ({len(yellow)})*")
        for c in yellow:
            lines.append(f"  • *{c['name']}* — Score: {c.get('trustscore', '—')}, last scan: {c.get('last_scan', 'never')}")
        lines.append("")

    if green:
        lines.append(f"✅ *On Track ({len(green)})*")
        for c in green:
            lines.append(f"  • {c['name']}")
        lines.append("")

    lines.append("_Use `@ARIA prep <customer>` before any call. — ARIA!_")
    return "\n".join(lines)


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


# ── Manager commands ──

def _account_health_bucket(c):
    """Return 'at-risk', 'stalled', or 'on-track' for grouping."""
    score = c.get("trustscore")
    next_due = c.get("next_action_due")
    overdue = False
    if next_due:
        d = days_since(next_due)
        overdue = d is not None and d > 0
    if overdue or (score is not None and score < 60) or score is None:
        return "at-risk"
    if score < 80:
        return "stalled"
    return "on-track"


def _fmt_manager_row(c):
    """One-line account summary for manager views."""
    score = c.get("trustscore")
    score_str = str(score) if score is not None else "—"
    stage = STAGE_ABBR.get(c.get("airs_stage", ""), "—")
    emoji, _ = status_label(score)
    next_action = c.get("next_action") or "None set"
    next_due = c.get("next_action_due") or "—"
    last = c.get("last_interaction") or "—"
    days_idle = days_since(last)
    idle_str = f"{days_idle}d ago" if days_idle is not None else "unknown"

    overdue_flag = ""
    if next_due and next_due != "—":
        d = days_since(next_due)
        if d is not None and d > 0:
            overdue_flag = f"  ⚠️ OVERDUE {d}d"
        elif d == 0:
            overdue_flag = "  ⚠️ DUE TODAY"

    return (
        f"  • *{c['name']}* — {stage} | Score: {score_str} {emoji} | Last contact: {idle_str}\n"
        f"    Action: {next_action} (due {next_due}){overdue_flag}"
    )


def cmd_manager_engineer(engineer: str) -> str:
    """All accounts for a specific PS engineer, grouped by health."""
    customers = load_customers()
    accts = [c for c in customers if c.get("owner", "").lower() == engineer.lower()]
    if not accts:
        return f"No accounts found for engineer *{engineer}*."

    buckets = {"at-risk": [], "stalled": [], "on-track": []}
    for c in accts:
        buckets[_account_health_bucket(c)].append(c)

    overdue_count = sum(
        1 for c in accts
        if c.get("next_action_due") and days_since(c["next_action_due"]) is not None and days_since(c["next_action_due"]) > 0
    )

    lines = [
        f"👤 *MANAGER VIEW — {engineer}*",
        "━" * 44,
        f"*{len(accts)} accounts* | 🔴 {len(buckets['at-risk'])} at-risk | ⚠️  {len(buckets['stalled'])} stalled | ✅ {len(buckets['on-track'])} on track | {overdue_count} overdue action{'s' if overdue_count != 1 else ''}",
        "",
    ]

    if buckets["at-risk"]:
        lines.append(f"🔴 *At-Risk ({len(buckets['at-risk'])})*")
        for c in buckets["at-risk"]:
            lines.append(_fmt_manager_row(c))
        lines.append("")

    if buckets["stalled"]:
        lines.append(f"⚠️  *Stalled ({len(buckets['stalled'])})*")
        for c in buckets["stalled"]:
            lines.append(_fmt_manager_row(c))
        lines.append("")

    if buckets["on-track"]:
        lines.append(f"✅ *On Track ({len(buckets['on-track'])})*")
        for c in buckets["on-track"]:
            lines.append(_fmt_manager_row(c))
        lines.append("")

    lines.append("_— ARIA!_")
    return "\n".join(lines)


def cmd_manager_summary() -> str:
    """Team-wide executive summary across all engineers."""
    customers = load_customers()

    engineers: dict[str, list] = {}
    for c in customers:
        owner = c.get("owner", "unknown")
        engineers.setdefault(owner, []).append(c)

    stage_order = ["Proposal", "Experiment", "Pilot", "Production"]
    stage_counts = {s: 0 for s in stage_order}
    for c in customers:
        s = c.get("airs_stage", "")
        if s in stage_counts:
            stage_counts[s] += 1

    lines = [
        "📊 *MANAGER SUMMARY — Team Overview*",
        "━" * 44,
        f"*{len(customers)} total accounts* across *{len(engineers)} engineer{'s' if len(engineers) != 1 else ''}*",
        "",
        "*Pipeline Distribution:*",
    ]
    stage_icons = {"Proposal": "📋", "Experiment": "🧪", "Pilot": "🚀", "Production": "✅"}
    for s in stage_order:
        icon = stage_icons[s]
        lines.append(f"  {icon} {s}: {stage_counts[s]}")

    lines.append("")
    lines.append("*Engineer Breakdown:*")

    most_at_risk_eng = None
    most_at_risk_count = -1
    worst_overdue_eng = None
    worst_overdue_days = -1

    for eng, accts in sorted(engineers.items()):
        at_risk = [c for c in accts if _account_health_bucket(c) == "at-risk"]
        stalled = [c for c in accts if _account_health_bucket(c) == "stalled"]
        on_track = [c for c in accts if _account_health_bucket(c) == "on-track"]

        overdue_days_list = []
        for c in accts:
            nd = c.get("next_action_due")
            if nd:
                d = days_since(nd)
                if d is not None and d > 0:
                    overdue_days_list.append(d)

        overdue_count = len(overdue_days_list)
        max_overdue = max(overdue_days_list) if overdue_days_list else 0

        if len(at_risk) > most_at_risk_count:
            most_at_risk_count = len(at_risk)
            most_at_risk_eng = eng

        if max_overdue > worst_overdue_days:
            worst_overdue_days = max_overdue
            worst_overdue_eng = eng

        lines.append(
            f"  • *{eng}* — {len(accts)} accounts | "
            f"🔴 {len(at_risk)} at-risk | ⚠️  {len(stalled)} stalled | ✅ {len(on_track)} on track"
            + (f" | {overdue_count} overdue (max {max_overdue}d)" if overdue_count else "")
        )

    lines.append("")
    if most_at_risk_eng:
        lines.append(f"🔴 *Most at-risk accounts:* {most_at_risk_eng} ({most_at_risk_count})")
    if worst_overdue_eng and worst_overdue_days > 0:
        lines.append(f"⏰ *Most overdue:* {worst_overdue_eng} ({worst_overdue_days}d past due)")

    lines.append("")
    lines.append("_— ARIA!_")
    return "\n".join(lines)


def cmd_manager_overdue() -> str:
    """All overdue actions across the entire team, sorted by most overdue."""
    customers = load_customers()

    overdue = []
    for c in customers:
        nd = c.get("next_action_due")
        if nd:
            d = days_since(nd)
            if d is not None and d > 0:
                overdue.append((d, c))

    if not overdue:
        return "No overdue actions across the team. Clean slate. ✅\n\n_— ARIA!_"

    overdue.sort(key=lambda x: x[0], reverse=True)

    lines = [
        f"⏰ *OVERDUE ACTIONS — {len(overdue)} account{'s' if len(overdue) != 1 else ''}*",
        "━" * 44,
        "",
    ]
    for d, c in overdue:
        action = c.get("next_action") or "No action set"
        nd = c.get("next_action_due")
        lines.append(
            f"  • *{c['name']}* — owner: `{c.get('owner', '—')}` | {STAGE_ABBR.get(c.get('airs_stage', ''), '—')} | *{d}d overdue* (due {nd})\n"
            f"    Action: {action}"
        )

    lines.append("")
    lines.append("_— ARIA!_")
    return "\n".join(lines)


def cmd_manager_engineer_customer(engineer: str, customer_query: str) -> str:
    """Call-prep-style drill-down for one customer on one engineer's book."""
    customers = load_customers()
    accts = [c for c in customers if c.get("owner", "").lower() == engineer.lower()]
    if not accts:
        return f"No accounts found for engineer *{engineer}*."
    matches = [c for c in accts if customer_query.lower() in c["name"].lower()]
    if not matches:
        return f"No account matching *{customer_query}* found under *{engineer}*."
    # Reuse cmd_prep output — it already formats the full call-prep view
    return cmd_prep(matches[0]["name"])


# ── Command router ──

LUMEN_HELP = """*Lumen commands:*
• `prep <customer>` — 90-second call prep (stage, score, stakeholders, next action)
• `status <customer>` — deployment stage + TrustScore
• `my accounts` — your assigned customers
• `team view` — all accounts across the team
• `at-risk` — customers below TrustScore 70
• `pipeline` — all customers by AIRS stage
• `digest` — daily health summary (red/yellow/green)

*Manager commands:*
• `manager <engineer>` — all accounts for one PS engineer, grouped by health
• `manager summary` — team-wide executive summary with health stats
• `manager overdue` — all overdue actions across the team, sorted by most overdue
• `manager <engineer> <customer>` — full call-prep drill-down for a specific engagement

• `/forget` — clear this thread's memory
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

    if t.startswith("prep "):
        return cmd_prep(text[5:].strip())

    if t in ("digest", "daily digest", "morning digest", "daily", "summary"):
        return cmd_daily_digest(user_name)

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

    # Manager commands
    if t.startswith("manager "):
        rest = text[8:].strip()  # preserve original casing after "manager "
        rest_lower = rest.lower()

        if rest_lower in ("summary", "team summary", "team"):
            return cmd_manager_summary()

        if rest_lower in ("overdue", "overdue actions", "all overdue"):
            return cmd_manager_overdue()

        # "manager <engineer> <customer>" — two tokens, second is customer query
        # Heuristic: if rest contains a space, split on first space and check if
        # first token is a known engineer; if so treat remainder as customer query.
        if " " in rest_lower:
            parts = rest.split(" ", 1)
            eng_token = parts[0]
            customer_token = parts[1]
            customers_loaded = load_customers()
            known_owners = {c.get("owner", "").lower() for c in customers_loaded}
            if eng_token.lower() in known_owners:
                return cmd_manager_engineer_customer(eng_token, customer_token)

        # "manager <engineer>"
        return cmd_manager_engineer(rest)

    # Natural language customer lookup
    return natural_language_customer_lookup(text)


# ── Per-thread memory (last 10 turns per thread) ──

THREAD_MEMORY: dict[str, list] = {}
THREAD_MEMORY_LIMIT = 10


def get_thread_history(thread_id: str) -> list:
    return THREAD_MEMORY.get(thread_id, [])


def update_thread_history(thread_id: str, role: str, content: str):
    if thread_id not in THREAD_MEMORY:
        THREAD_MEMORY[thread_id] = []
    THREAD_MEMORY[thread_id].append({"role": role, "content": content})
    # Keep last N turns (user+assistant pairs)
    if len(THREAD_MEMORY[thread_id]) > THREAD_MEMORY_LIMIT * 2:
        THREAD_MEMORY[thread_id] = THREAD_MEMORY[thread_id][-THREAD_MEMORY_LIMIT * 2:]


def forget_thread(thread_id: str):
    THREAD_MEMORY.pop(thread_id, None)


# ── AI fallback ──

def ask_aria(question: str, personal: bool = False, thread_id: str = None) -> str:
    history = get_thread_history(thread_id) if thread_id else []
    messages = history + [{"role": "user", "content": question}]
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=PERSONAL_PROMPT if personal else SYSTEM_PROMPT,
        messages=messages,
    )
    reply = response.content[0].text
    if thread_id:
        update_thread_history(thread_id, "user", question)
        update_thread_history(thread_id, "assistant", reply)
    return reply


# ── Block Kit helpers ──

def blocks_text(text: str) -> list:
    """Wrap plain text in a simple Block Kit section."""
    return [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]


def blocks_customer(c: dict) -> list:
    """Rich Block Kit card for a single customer."""
    stage = c.get("airs_stage", "Unknown")
    score = c.get("trustscore")
    last = c.get("last_scan") or "never"
    notes = c.get("notes", "")
    emoji, label = status_label(score)
    score_str = str(score) if score is not None else "—"
    abbr = STAGE_ABBR.get(stage, stage)

    return [
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Account*\n{c['name']}"},
                {"type": "mrkdwn", "text": f"*Owner*\n{c.get('owner', '—')}"},
                {"type": "mrkdwn", "text": f"*Stage*\n{abbr} — {stage}"},
                {"type": "mrkdwn", "text": f"*TrustScore*\n{score_str}  {emoji} {label}"},
                {"type": "mrkdwn", "text": f"*Last Scan*\n{last}"},
            ],
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": f"_{notes}_"}} if notes else {"type": "divider"},
    ]


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


def handle_text(text: str, user_id: str, say, personal: bool = False, thread_ts: str = None):
    user_name = get_user_name(user_id)
    thread_id = thread_ts or user_id
    reply_kwargs = {"thread_ts": thread_ts} if thread_ts else {}

    # /forget command
    if text.lower().strip() in ("/forget", "forget", "clear memory", "forget thread"):
        forget_thread(thread_id)
        say(text="Memory cleared for this thread. *— ARIA!*", **reply_kwargs)
        return

    if not personal:
        lumen_response = route_command(text, user_name)
        if lumen_response:
            # Use Block Kit for customer status, plain text for everything else
            if lumen_response.startswith("*Acme") or "\nSt." in lumen_response or "TEAM VIEW" in lumen_response:
                say(text=lumen_response, **reply_kwargs)
            else:
                say(text=lumen_response, **reply_kwargs)
            return

    say(text=":brain: thinking...", **reply_kwargs)
    reply = ask_aria(text, personal=personal, thread_id=thread_id)
    say(text=reply, **reply_kwargs)


@app.event("app_mention")
def handle_mention(event, say):
    text = re.sub(r"<@[^>]+>", "", event.get("text", "")).strip()
    thread_ts = event.get("thread_ts") or event.get("ts")
    if not text:
        say(text="You called? Try `help` for Lumen commands or ask me anything. *— ARIA!*",
            thread_ts=thread_ts)
        return
    handle_text(text, event["user"], say, thread_ts=thread_ts)


@app.event("message")
def handle_dm(event, say):
    if event.get("channel_type") != "im":
        return
    if event.get("bot_id"):
        return
    text = event.get("text", "").strip()
    if not text:
        return
    # DMs: use user_id as thread context for persistent memory
    handle_text(text, event["user"], say, personal=True, thread_ts=None)


def daily_digest_scheduler():
    """Post daily digest to #all-bash99 at 8:00 AM every day."""
    DIGEST_CHANNEL = "#all-bash99"
    DIGEST_HOUR = 8
    posted_today = None

    while True:
        now = datetime.now()
        if now.hour == DIGEST_HOUR and now.date() != posted_today:
            try:
                digest = cmd_daily_digest()
                app.client.chat_postMessage(channel=DIGEST_CHANNEL, text=digest)
                posted_today = now.date()
                print(f"[ARIA] Daily digest posted to {DIGEST_CHANNEL}", flush=True)
            except Exception as e:
                print(f"[ARIA] Digest post failed: {e}", flush=True)
        _time.sleep(60)


if __name__ == "__main__":
    print("ARIA! is online.")
    threading.Thread(target=daily_digest_scheduler, daemon=True).start()
    handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    handler.start()
