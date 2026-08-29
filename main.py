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
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from core.pipeline import BugScoutPipeline
from core.scope_guard import ScopeViolationError
from core.llm import LLMManager, GroqProvider, GeminiProvider, HuggingFaceProvider, HeuristicSecurityEngine
from evaluation.benchmark_runner import BenchmarkEvaluator
from evaluation.ab_comparison import ABComparisonRunner
from evaluation.ablation_study import AblationStudyRunner
from evaluation.safety_tester import SafetySuiteRunner
from evaluation.repeated_eval import RepeatedEvaluator
from evaluation.consistency_validator import CrossFormatConsistencyValidator

console = Console(highlight=False)

BANNER = """[bold cyan]
  ____               ____                 _   
 | __ ) _   _  __ _ / ___|  ___ ___  _   _| |_ 
 |  _ \| | | |/ _` |\___ \ / __/ _ \| | | | __|
 | |_) | |_| | (_| | ___) | (_| (_) | |_| | |_ 
 |____/ \__,_|\__, ||____/ \___\___/ \__,_|\__|
              |___/                            
[/bold cyan][bold white]BugScout — An LLM-Guided Multi-Agent Security Testing and Attack Surface Discovery Platform[/bold white]
[dim]Zero-Cost | 46-Case Ground Truth Benchmark | 4-Tier Ablation | 5-Run Stability Statistics[/dim]
"""


def start_mock_server_background():
    """Starts the built-in mock target on port 8888 in a background daemon thread."""
    import uvicorn
    from mock_target.server import app

    config = uvicorn.Config(app, host="127.0.0.1", port=8888, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.0)
    return server


def parse_args():
    parser = argparse.ArgumentParser(description="BugScout — An LLM-Guided Multi-Agent Security Testing Platform")
    parser.add_argument("url_pos", nargs="?", default=None, help="Target URL to scout (e.g. https://example.com)")
    parser.add_argument("--url", "--target", dest="target", default=None, help="Target URL to scout")
    parser.add_argument("--config", default="config/scope.yaml", help="Path to scope.yaml config")
    parser.add_argument("--demo", action="store_true", help="Run local end-to-end demo against built-in mock target")
    parser.add_argument("--evaluate", "--benchmark", action="store_true", help="Run 46-Case Ground Truth Benchmark Evaluation")
    parser.add_argument("--repeated-eval", action="store_true", help="Run 5-Run Statistical Stability Benchmark (Mean ± Std Dev)")
    parser.add_argument("--compare-modes", action="store_true", help="Run A/B Comparison Experiment: Blind Baseline vs Agentic AI")
    parser.add_argument("--ablation", action="store_true", help="Run 4-Tier Component Ablation Study")
    parser.add_argument("--safety-test", action="store_true", help="Run ScopeGuard Ethical Firewall & SSRF Safety Audit Suite")
    parser.add_argument("--trace", action="store_true", help="Display full explainable agent decision trail and audit log")
    parser.add_argument("--validate-consistency", action="store_true", help="Validate cross-format parity across SARIF, HTML, JSON, and MD")
    parser.add_argument("--iterations", type=int, default=2, help="Max agentic feedback loop iterations")
    parser.add_argument("--llm", default="auto", choices=["auto", "groq", "gemini", "hf", "heuristic"], help="LLM backend selection")
    parser.add_argument("--resume", action="store_true", help="Resume scan from checkpoint if available")
    parser.add_argument("--checkpoint", default=None, help="Custom checkpoint file path")
    return parser.parse_args()


async def main_async():
    args = parse_args()
    console.print(BANNER)

    # 1. Ground Truth Benchmark Evaluation Mode (46 Cases)
    if args.evaluate:
        evaluator = BenchmarkEvaluator()
        await evaluator.run_evaluation()
        return

    # 2. 5-Run Repeated Benchmark Statistical Evaluation Mode
    if args.repeated_eval:
        repeated_evaluator = RepeatedEvaluator(runs=5)
        await repeated_evaluator.run_repeated_evaluation()
        return

    # 3. A/B Comparison Experiment Mode (Unified 27-Vuln Workload)
    if args.compare_modes:
        ab_runner = ABComparisonRunner()
        await ab_runner.run_comparison()
        return

    # 4. 4-Tier Component Ablation Study Mode
    if args.ablation:
        ablation_runner = AblationStudyRunner()
        await ablation_runner.run_ablation_study()
        return

    # 5. ScopeGuard Safety Suite Mode (15 Tests)
    if args.safety_test:
        safety_runner = SafetySuiteRunner()
        await safety_runner.run_safety_tests()
        return

    # 6. Cross-Format Consistency Validation Mode
    if args.validate_consistency:
        validator = CrossFormatConsistencyValidator()
        valid, report = validator.validate()
        if valid:
            console.print(Panel(
                f"[bold green]Cross-Format Integrity Confirmed (100% Parity)![/bold green]\n"
                f"• JSON Findings: {report['counts']['json_findings_count']}\n"
                f"• SARIF Results: {report['counts']['sarif_results_count']}\n"
                f"• Markdown Findings: {report['counts']['markdown_findings_count']}\n"
                f"• HTML Findings: {report['counts']['html_findings_count']}\n"
                f"All 4 output artifacts are strictly canonical and synchronized.",
                title="Cross-Format Consistency Validator",
                border_style="green"
            ))
        else:
            console.print(f"[bold red]Consistency Check Failed:[/bold red] {report}")
        return

    target_url = args.target or args.url_pos

    # Interactive prompt if neither URL nor --demo was provided
    if not target_url and not args.demo:
        console.print("[bold yellow][?] No target URL specified via CLI arguments.[/bold yellow]")
        user_input = Prompt.ask(
            "[bold cyan]Enter target URL to scout[/bold cyan] [dim](or press Enter for built-in demo target)[/dim]",
            default="demo"
        )
        if user_input.strip().lower() == "demo" or not user_input.strip():
            args.demo = True
        else:
            target_url = user_input.strip()

    if args.demo and not target_url:
        console.print("[bold yellow][*] Demo Mode Activated:[/bold yellow] Initializing built-in test target at [cyan]http://127.0.0.1:8888[/cyan]...")
        start_mock_server_background()
        target_url = "http://127.0.0.1:8888"
        console.print("[bold green][+] Mock target server running in background.[/bold green]\n")

    # Display Pre-Flight Ethical Scope Authorization Banner
    parsed_host = urlparse(target_url).hostname or target_url
    console.print(Panel(
        f"[bold white]Pre-Flight Ethical Scope Authorization[/bold white]\n"
        f"  • [bold]Target URL:[/bold] {target_url}\n"
        f"  • [bold]Authorized Host:[/bold] {parsed_host}\n"
        f"  • [bold]Out-of-Scope Requests:[/bold] [bold red]BLOCKED[/bold red]\n"
        f"  • [bold]Private / SSRF IP Targets:[/bold] [bold red]BLOCKED[/bold red]\n"
        f"  • [bold]Safe Mode Constraints:[/bold] [bold green]ENABLED (Non-Destructive Only)[/bold green]",
        title="ScopeGuard Authorization Check",
        border_style="cyan"
    ))

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
            target_override=target_url,
            custom_llm=custom_llm,
            max_iterations=args.iterations,
            resume=args.resume,
            checkpoint_path=args.checkpoint
        )

        context = await pipeline.run()

        # Display explainable decision trace if --trace is set
        if args.trace:
            console.print("\n")
            trace_table = Table(title="BugScout Explainable Agent Decision Audit Trail", header_style="bold cyan")
            trace_table.add_column("Time", style="dim", width=12)
            trace_table.add_column("Agent", style="bold yellow", width=16)
            trace_table.add_column("Action", width=22)
            trace_table.add_column("Target / Endpoint", style="dim")
            trace_table.add_column("Decision", justify="center")
            trace_table.add_column("Reason / Explainability Rationale")

            for entry in context.audit_trail:
                dec_style = "bold green" if entry.decision in ["CONFIRMED", "ALLOWED", "AUTHENTICATED", "COMPLETE"] else "bold yellow"
                trace_table.add_row(
                    entry.timestamp,
                    entry.agent,
                    entry.action,
                    entry.target,
                    f"[{dec_style}]{entry.decision}[/{dec_style}]",
                    entry.reason
                )
            console.print(trace_table)

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
