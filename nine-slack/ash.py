#!/usr/bin/env python3
"""
ash — ARIA personal terminal client for Ash Clements
Direct Claude API. No gateway. No rate limits.
"""

import os
from datetime import datetime
from dotenv import load_dotenv
from anthropic import Anthropic
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich.live import Live
from prompt_toolkit import prompt
from prompt_toolkit.styles import Style

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
console = Console()

SYSTEM_PROMPT = """You are ARIA — personal AI assistant to Ash Clements.

About Ash:
- Sr. Professional Services Consultant at Palo Alto Networks (SASE, PCNSE)
- Based in Phoenix, AZ
- Building AISeal — an AI Trust & Certification Platform (aiseal.ai)
- Targeting the AIRS Specialist role at PANW
- Stack: Python, Next.js, TypeScript, Terraform, Docker, Azure/GCP/AWS
- Projects: AISeal, ARIA (you), Ghost99RT, badash-killchain, CastleDesk
- Lab: Ubuntu 24.04 in Parallels on MacBook Pro M3 Pro
- Communication: BLUF, no fluff, technical peer, dry humor welcome

Your role:
- General purpose assistant — anything Ash needs, not just security
- Help him think through problems, draft content, debug code, plan strategy
- You know his full context — career pivot, interview prep, AISeal product roadmap
- Be direct, be useful, skip the formalities
- You still have full AI security knowledge — OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, AIRS

Sign off with: — ARIA!"""

prompt_style = Style.from_dict({
    "": "#c9d1d9",
    "prompt": "#a855f7 bold",
})


def print_header():
    console.print()
    title = Text("A R I A", style="bold #a855f7")
    subtitle = Text("Adaptive Risk Intelligence Analyst  ·  Personal Mode  ·  Direct Claude", style="#484f58")
    console.print(Panel(
        Text.assemble(title, "\n", subtitle),
        border_style="#2d1f4a",
        padding=(0, 2),
    ))
    console.print(Text("  /new  — clear history   /exit  — quit   Ctrl+C  — quit", style="#30363d"))
    console.print()


def print_user(text: str):
    ts = datetime.now().strftime("%H:%M:%S")
    console.print(Text(f"  ASH  {ts}", style="#3d8bff dim"))
    console.print(Panel(
        Text(text, style="#cdd9ea"),
        border_style="#1f4a8f",
        padding=(0, 2),
    ))


def print_aria(text: str, tokens_in: int = 0, tokens_out: int = 0, latency_ms: int = 0):
    console.print(Text("  ARIA", style="#a855f7 dim"))
    console.print(Panel(
        Text(text, style="#d2c9ea"),
        border_style="#2d1f4a",
        padding=(0, 2),
    ))
    meta = f"  {latency_ms}ms  ·  {tokens_in}in / {tokens_out}out tokens"
    console.print(Text(meta, style="#30363d"))
    console.print()


def print_err(text: str):
    console.print(Text(f"  ✗ {text}", style="#f85149"))
    console.print()


def main():
    print_header()
    history = []

    while True:
        try:
            user_input = prompt(
                [("class:prompt", "  › ")],
                style=prompt_style,
                multiline=False,
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print(Text("\n  Later.\n", style="#484f58"))
            break

        if not user_input:
            continue

        if user_input.lower() in ("/exit", "/quit", "exit", "quit"):
            console.print(Text("\n  Later.\n", style="#484f58"))
            break

        if user_input.lower() == "/new":
            history.clear()
            console.print()
            console.print(Rule(style="#21262d"))
            console.print(Text("  History cleared.\n", style="#484f58"))
            continue

        print_user(user_input)
        history.append({"role": "user", "content": user_input})

        import time
        start = time.time()
        with Live(
            Text("  ● ● ●", style="#a855f7 dim"),
            console=console,
            refresh_per_second=4,
            transient=True,
        ):
            try:
                response = client.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=4096,
                    system=SYSTEM_PROMPT,
                    messages=history,
                )
            except Exception as e:
                print_err(str(e))
                history.pop()
                continue

        latency_ms = round((time.time() - start) * 1000)
        reply = response.content[0].text if response.content else ""
        tokens_in = response.usage.input_tokens
        tokens_out = response.usage.output_tokens

        history.append({"role": "assistant", "content": reply})
        print_aria(reply, tokens_in, tokens_out, latency_ms)


if __name__ == "__main__":
    main()
