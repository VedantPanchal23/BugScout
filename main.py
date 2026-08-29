from __future__ import annotations

import os
import sys

# Ensure UTF-8 console output on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import time
import asyncio
import argparse
import threading
from rich.console import Console
from rich.panel import Panel

from core.pipeline import BugScoutPipeline
from core.scope_guard import ScopeViolationError
from core.llm import LLMManager, GroqProvider, GeminiProvider, HuggingFaceProvider, HeuristicSecurityEngine

console = Console(highlight=False)

BANNER = """[bold cyan]
  ____               ____                 _   
 | __ ) _   _  __ _ / ___|  ___ ___  _   _| |_ 
 |  _ \| | | |/ _` |\___ \ / __/ _ \| | | | __|
 | |_) | |_| | (_| | ___) | (_| (_) | |_| | |_ 
 |____/ \__,_|\__, ||____/ \___\___/ \__,_|\__|
              |___/                            
[/bold cyan][bold white]Autonomous Multi-Agent Bug Bounty & Attack Surface Scout v3.0[/bold white]
[dim]Zero-Cost | Ethical Boundary Enforcement | SARIF 2.1.0 | WAF Resilient[/dim]
"""


def start_mock_server_background():
    """Starts the built-in mock target on port 8888 in a background daemon thread."""
    import uvicorn
    from mock_target.server import app

    config = uvicorn.Config(app, host="127.0.0.1", port=8888, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.0)  # Allow server to initialize
    return server


def parse_args():
    parser = argparse.ArgumentParser(description="BugScout - Autonomous Bug Bounty Scout Platform")
    parser.add_argument("--config", default="config/scope.yaml", help="Path to scope.yaml config")
    parser.add_argument("--target", default=None, help="Override target URL in scope")
    parser.add_argument("--demo", action="store_true", help="Run local end-to-end demo against built-in mock target")
    parser.add_argument("--iterations", type=int, default=2, help="Max agentic feedback loop iterations")
    parser.add_argument("--llm", default="auto", choices=["auto", "groq", "gemini", "hf", "heuristic"], help="LLM backend selection")
    parser.add_argument("--resume", action="store_true", help="Resume scan from checkpoint if available")
    parser.add_argument("--checkpoint", default=None, help="Custom checkpoint file path")
    return parser.parse_args()


async def main_async():
    args = parse_args()
    console.print(BANNER)

    if args.demo:
        console.print("[bold yellow][*] Demo Mode Activated:[/bold yellow] Initializing built-in vulnerable test target at [cyan]http://127.0.0.1:8888[/cyan]...")
        start_mock_server_background()
        console.print("[bold green][+] Mock target server running in background.[/bold green]\n")

    # Select LLM provider
    custom_llm = None
    if args.llm == "groq":
        key = os.getenv("GROQ_API_KEY")
        if not key:
            console.print("[bold red]Error: GROQ_API_KEY environment variable not set.[/bold red]")
            sys.exit(1)
        custom_llm = GroqProvider(api_key=key)
    elif args.llm == "gemini":
        key = os.getenv("GEMINI_API_KEY")
        if not key:
            console.print("[bold red]Error: GEMINI_API_KEY environment variable not set.[/bold red]")
            sys.exit(1)
        custom_llm = GeminiProvider(api_key=key)
    elif args.llm == "hf":
        token = os.getenv("HF_TOKEN")
        if not token:
            console.print("[bold red]Error: HF_TOKEN environment variable not set.[/bold red]")
            sys.exit(1)
        custom_llm = HuggingFaceProvider(token=token)
    elif args.llm == "heuristic":
        custom_llm = HeuristicSecurityEngine()

    try:
        pipeline = BugScoutPipeline(
            config_path=args.config,
            custom_llm=custom_llm,
            max_iterations=args.iterations,
            resume=args.resume,
            checkpoint_path=args.checkpoint
        )
        if args.target:
            pipeline.context.target = args.target
            pipeline.scope_config.target = args.target

        await pipeline.run()

    except ScopeViolationError as sve:
        console.print(Panel(
            f"[bold red]SCOPE VIOLATION HALT:[/bold red]\n{sve}",
            title="ScopeGuard Kill-Switch",
            border_style="red"
        ))
        sys.exit(1)
    except FileNotFoundError as fnf:
        console.print(f"[bold red]Configuration Error:[/bold red] {fnf}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan paused by user. State checkpoint saved.[/bold yellow]")
        sys.exit(0)


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
