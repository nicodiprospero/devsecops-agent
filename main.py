# -*- coding: utf-8 -*-
"""
VibeSec -- CLI Entry Point
Structured style: labeled sections, dividers, timestamps, status indicators.
"""

import os
import sys
import uuid
from datetime import datetime

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from dotenv import load_dotenv

load_dotenv()

if not os.getenv("GEMINI_API_KEY"):
    print("\n  [ERROR] GEMINI_API_KEY is not set.")
    print("  Copy .env.example to .env and add your API key.\n")
    sys.exit(1)

from rich.console import Console
from rich.rule import Rule
from rich.panel import Panel
from rich.text import Text
from rich.markdown import Markdown
from rich import box

from agent import create_agent

console = Console()

_BANNER = r"""
  _   ___ ___  ___ ___ ___
 | | / _ \_ _|| __/ __| __|
 | |_| (_) | | | _|\__ \ _|
 |____\___/___||___|___/___|

      Security scanner for AI-generated code
      Powered by Gemini  |  Agno Framework
"""

_HELP = """
[bold cyan]Commands[/bold cyan]
  [cyan]/help[/cyan]    Show this help message
  [cyan]/new[/cyan]     Start a fresh conversation session
  [cyan]/exit[/cyan]    Exit VibeSec

[bold cyan]Example queries[/bold cyan]
  • Scan [italic]https://github.com/owner/repo[/italic]
  • Audit dependencies in [italic]./requirements.txt[/italic]
  • Analyze the Dockerfile at [italic]./Dockerfile[/italic]
  • Check vulnerabilities for the [italic]flask[/italic] package on PyPI
  • Check if [italic]https://github.com/owner/repo[/italic] has exposed .env files
"""


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _divider(label: str = "", style: str = "dim cyan") -> None:
    if label:
        console.print(Rule(f"[dim]{label}[/dim]", style=style))
    else:
        console.print(Rule(style="dim"))


def _print_banner() -> None:
    console.print(
        Panel(
            Text(_BANNER, style="bold cyan", justify="center"),
            border_style="cyan",
            box=box.DOUBLE,
            subtitle="[dim]Type /help for commands[/dim]",
        )
    )


def _print_help() -> None:
    console.print(
        Panel(
            _HELP,
            title="[bold cyan][ HELP ][/bold cyan]",
            border_style="cyan",
            box=box.SIMPLE_HEAVY,
        )
    )


def _print_status(msg: str, style: str = "dim yellow") -> None:
    console.print(f"  [{_ts()}] {msg}", style=style)


def _get_response_content(response) -> str:
    if response is None:
        return "(no response)"
    if hasattr(response, "content") and response.content:
        return str(response.content)
    if hasattr(response, "message") and response.message:
        return str(response.message)
    return str(response)


def main() -> None:
    session_id = str(uuid.uuid4())[:8]
    agent = create_agent(session_id=session_id)

    _print_banner()
    console.print(f"  [dim]Session : [bold]{session_id}[/bold][/dim]\n")

    while True:
        try:
            _divider("INPUT")
            user_input = console.input("  [bold cyan]>[/bold cyan] ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n  [dim]Use /exit to quit.[/dim]")
            continue

        if not user_input:
            continue

        cmd = user_input.lower()

        if cmd == "/exit":
            _divider()
            _print_status("Session ended. Goodbye.", style="cyan")
            break

        if cmd == "/help":
            _print_help()
            continue

        if cmd == "/new":
            session_id = str(uuid.uuid4())[:8]
            agent = create_agent(session_id=session_id)
            _print_status(f"New session started. ID: [bold]{session_id}[/bold]", style="green")
            continue

        _divider("PROCESSING")
        _print_status("Scanning...", style="dim yellow")

        try:
            response = agent.run(user_input)
            content = _get_response_content(response)
        except Exception as exc:
            _divider("ERROR", style="red")
            console.print(f"  [bold red]Agent error:[/bold red] {exc}")
            _divider()
            continue

        _divider("RESPONSE", style="green")
        try:
            console.print(Markdown(content))
        except Exception:
            console.print(content)

        _divider()
        console.print()


if __name__ == "__main__":
    main()
