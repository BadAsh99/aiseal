#!/usr/bin/env python3
"""
bash — IRIS personal terminal client for Ash Clements
Streaming. Markdown. Persistent sessions. Direct Claude. No limits.
"""

import os
import re
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from anthropic import Anthropic
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich.markdown import Markdown
from rich.live import Live
from rich.table import Table
from prompt_toolkit import prompt
from prompt_toolkit.styles import Style
from prompt_toolkit.history import FileHistory

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
console = Console()

DB_PATH = Path.home() / ".iris_sessions.db"
HISTORY_FILE = Path.home() / ".iris_prompt_history"

SYSTEM_PROMPT = """You are IRIS — personal AI assistant to Ash Clements.

About Ash:
- Sr. Professional Services Consultant at Palo Alto Networks (SASE, PCNSE)
- Based in Phoenix, AZ
- Building AISeal — an AI Trust & Certification Platform (aiseal.ai)
- Targeting the AIRS Specialist role at PANW
- Stack: Python, Next.js, TypeScript, Terraform, Docker, Azure/GCP/AWS
- Projects: AISeal, IRIS (you), Ghost99RT, badash-killchain, CastleDesk
- Lab: Ubuntu 24.04 in Parallels on MacBook Pro M3 Pro
- Communication: BLUF, no fluff, technical peer, dry humor welcome

Your role:
- General purpose assistant — anything Ash needs, not just security
- Help him think through problems, draft content, debug code, plan strategy
- You know his full context — career pivot, interview prep, AISeal product roadmap
- Be direct, be useful, skip the formalities
- You still have full AI security knowledge — OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, AIRS

Sign off with: — IRIS"""

prompt_style = Style.from_dict({
    "": "#c9d1d9",
    "prompt": "#a855f7 bold",
})


# ── Session persistence ──

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            tokens_in INTEGER DEFAULT 0,
            tokens_out INTEGER DEFAULT 0,
            latency_ms INTEGER DEFAULT 0,
            ts TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def save_turn(session_id: str, role: str, content: str, tokens_in=0, tokens_out=0, latency_ms=0):
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (session_id, role, content, tokens_in, tokens_out, latency_ms, ts) VALUES (?,?,?,?,?,?,?)",
        (session_id, role, content, tokens_in, tokens_out, latency_ms, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def load_session(session_id: str) -> list:
    conn = get_db()
    rows = conn.execute(
        "SELECT role, content FROM sessions WHERE session_id=? ORDER BY id ASC", (session_id,)
    ).fetchall()
    conn.close()
    return [{"role": r[0], "content": r[1]} for r in rows]


def list_sessions() -> list:
    conn = get_db()
    rows = conn.execute("""
        SELECT session_id, MIN(ts) as started, COUNT(*)/2 as turns,
               SUBSTR(MIN(CASE WHEN role='user' THEN content END), 1, 60) as preview
        FROM sessions GROUP BY session_id ORDER BY started DESC LIMIT 10
    """).fetchall()
    conn.close()
    return rows


# ── UI helpers ──

def print_header(session_id: str):
    console.print()
    title = Text("I R I S", style="bold #a855f7")
    subtitle = Text(f"Personal Mode  ·  Direct Claude  ·  session: {session_id[:8]}", style="#484f58")
    console.print(Panel(
        Text.assemble(title, "\n", subtitle),
        border_style="#2d1f4a",
        padding=(0, 2),
    ))
    console.print(Text(
        "  /new  — new session   /sessions  — list saved   /load <id>  — resume   /retry  — regenerate   /exit  — quit",
        style="#30363d"
    ))
    console.print()


def print_user(text: str):
    ts = datetime.now().strftime("%H:%M:%S")
    console.print(Text(f"  ASH  {ts}", style="#3d8bff dim"))
    console.print(Panel(
        Text(text, style="#cdd9ea"),
        border_style="#1f4a8f",
        padding=(0, 2),
    ))


def print_iris_streaming(session_id: str, history: list) -> tuple[str, int, int, int]:
    """Stream response, render live, return (reply, tokens_in, tokens_out, latency_ms)."""
    console.print(Text("  IRIS", style="#a855f7 dim"))

    full_text = ""
    tokens_in = 0
    tokens_out = 0
    start = time.time()

    with client.messages.stream(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=history,
    ) as stream:
        with Live(console=console, refresh_per_second=15) as live:
            for text_chunk in stream.text_stream:
                full_text += text_chunk
                live.update(Panel(
                    Markdown(full_text),
                    border_style="#2d1f4a",
                    padding=(0, 2),
                ))

        msg = stream.get_final_message()
        tokens_in = msg.usage.input_tokens
        tokens_out = msg.usage.output_tokens

    latency_ms = round((time.time() - start) * 1000)
    meta = f"  {latency_ms}ms  ·  {tokens_in}in / {tokens_out}out tokens"
    console.print(Text(meta, style="#30363d"))
    console.print()

    return full_text, tokens_in, tokens_out, latency_ms


def print_sessions(sessions: list):
    if not sessions:
        console.print(Text("  No saved sessions.", style="#484f58"))
        return
    table = Table(show_header=True, header_style="bold #a855f7", border_style="#2d1f4a", padding=(0, 1))
    table.add_column("ID (first 8)", style="#a855f7")
    table.add_column("Started", style="#484f58")
    table.add_column("Turns", style="#484f58", justify="right")
    table.add_column("Preview", style="#cdd9ea")
    for row in sessions:
        sid, started, turns, preview = row
        table.add_row(sid[:8], started[:16], str(turns), (preview or "")[:60])
    console.print(table)
    console.print()


def print_err(text: str):
    console.print(Text(f"  ✗ {text}", style="#f85149"))
    console.print()


# ── Main ──

def new_session_id() -> str:
    import uuid
    return str(uuid.uuid4())


def main():
    session_id = new_session_id()
    history = []

    print_header(session_id)

    while True:
        try:
            user_input = prompt(
                [("class:prompt", "  › ")],
                style=prompt_style,
                multiline=False,
                history=FileHistory(str(HISTORY_FILE)),
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print(Text("\n  Later.\n", style="#484f58"))
            break

        if not user_input:
            continue

        cmd = user_input.lower()

        if cmd in ("/exit", "/quit", "exit", "quit"):
            console.print(Text("\n  Later.\n", style="#484f58"))
            break

        if cmd == "/new":
            session_id = new_session_id()
            history.clear()
            console.print()
            console.print(Rule(style="#21262d"))
            console.print(Text(f"  New session: {session_id[:8]}\n", style="#484f58"))
            continue

        if cmd == "/sessions":
            print_sessions(list_sessions())
            continue

        if cmd.startswith("/load "):
            prefix = cmd[6:].strip()
            conn = get_db()
            row = conn.execute(
                "SELECT session_id FROM sessions WHERE session_id LIKE ? LIMIT 1", (f"{prefix}%",)
            ).fetchone()
            conn.close()
            if not row:
                print_err(f"No session found matching '{prefix}'")
                continue
            session_id = row[0]
            history = load_session(session_id)
            console.print(Text(f"  Loaded session {session_id[:8]} — {len(history)//2} turns\n", style="#484f58"))
            continue

        if cmd == "/retry":
            if len(history) >= 2 and history[-1]["role"] == "assistant":
                history.pop()
                history.pop()
                console.print(Text("  Retrying last prompt...\n", style="#484f58"))
                if not history:
                    continue
                user_input = history[-1]["content"] if history else ""
                history.pop()
            else:
                print_err("Nothing to retry.")
                continue

        print_user(user_input)
        history.append({"role": "user", "content": user_input})
        save_turn(session_id, "user", user_input)

        try:
            reply, tokens_in, tokens_out, latency_ms = print_iris_streaming(session_id, history)
        except Exception as e:
            print_err(str(e))
            history.pop()
            continue

        history.append({"role": "assistant", "content": reply})
        save_turn(session_id, "assistant", reply, tokens_in, tokens_out, latency_ms)


if __name__ == "__main__":
    main()
