#!/usr/bin/env python3
"""
ARIA! — Neural Intelligence Node Engine
Slack bot powered by Claude. Part of the AISeal platform.
"""

import os
import re
from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from anthropic import Anthropic

load_dotenv()

app = App(token=os.environ["SLACK_BOT_TOKEN"])
client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

SYSTEM_PROMPT = """You are ARIA — Neural Intelligence Node Engine — the AI security intelligence layer of the AISeal platform.

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


def ask_aria(question: str, context: str = "") -> str:
    messages = []
    if context:
        messages.append({"role": "user", "content": f"Context: {context}\n\nQuestion: {question}"})
    else:
        messages.append({"role": "user", "content": question})

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=messages,
    )
    return response.content[0].text


@app.event("app_mention")
def handle_mention(event, say):
    text = re.sub(r"<@[^>]+>", "", event.get("text", "")).strip()
    if not text:
        say("You called? Ask me anything. *— ARIA!*")
        return
    say(f":brain: thinking...")
    response = ask_aria(text)
    say(response)


@app.event("message")
def handle_dm(event, say):
    if event.get("channel_type") != "im":
        return
    if event.get("bot_id"):
        return
    text = event.get("text", "").strip()
    if not text:
        return
    say(f":brain: thinking...")
    response = ask_aria(text)
    say(response)


if __name__ == "__main__":
    print("ARIA! is online.")
    handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    handler.start()
