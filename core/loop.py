from __future__ import annotations

import time
from rich.console import Console

from core.mission_context import MissionContext
from core.scope_guard import ScopeGuard
from core.llm import LLMProvider
from core.auth_manager import AuthManager
from core.waf_detector import WAFDetector
from agents.recon_agent import ReconAgent
from agents.hypothesis_agent import HypothesisAgent
from agents.payload_agent import PayloadAgent
from agents.observer_agent import ObserverAgent
from agents.report_agent import ReportAgent


class AgenticLoopController:
    """
    AgenticLoopController coordinates the autonomous security feedback cycle:
    Auth -> Recon -> Hypothesize -> Test (Payload + ScopeGuard + WAF) -> Observe -> Replanning Loop -> Report
    Supports atomic checkpointing and scan resuming.
    """

    def __init__(
        self,
        context: MissionContext,
        scope_guard: ScopeGuard,
        llm: LLMProvider,
        auth_manager: Optional[AuthManager] = None,
    ):
        self.context = context
        self.scope_guard = scope_guard
        self.llm = llm
        self.auth_manager = auth_manager or AuthManager(context.scope.auth)
        self.waf_detector = WAFDetector(context.waf_info)
        self.console = Console(highlight=False)

    async def execute_mission(self) -> MissionContext:
        if not self.context.stats.start_time:
            self.context.stats.start_time = time.time()

        self.console.print(f"\n[bold cyan]>>> Starting BugScout Mission against:[/bold cyan] [bold yellow]{self.context.target}[/bold yellow]")
        self.console.print(f"[dim]LLM Provider: {self.llm.name}[/dim]\n")

        # Stage 0: Dynamic Authentication (if configured)
        if self.auth_manager.is_configured():
            with self.console.status("[bold blue]0/5 Performing Dynamic Pre-Flight Authentication...[/bold blue]", spinner="dots"):
                headers, cookies = await self.auth_manager.authenticate()
                self.context.scope.custom_headers.update(headers)
                self.context.scope.session_cookies.update(cookies)
            self.console.print("  [green][+][/green] Authentication successful: Session tokens & cookies injected.")

        recon_agent = ReconAgent("ReconAgent", self.context, self.scope_guard, self.llm)
        hypothesis_agent = HypothesisAgent("HypothesisAgent", self.context, self.scope_guard, self.llm)
        payload_agent = PayloadAgent("PayloadAgent", self.context, self.scope_guard, self.llm)
        observer_agent = ObserverAgent("ObserverAgent", self.context, self.scope_guard, self.llm)
        report_agent = ReportAgent("ReportAgent", self.context, self.scope_guard, self.llm)

        # Stage 1: Reconnaissance (Skip if resuming and endpoints already exist)
        if not self.context.endpoint_map:
            with self.console.status("[bold blue]1/5 ReconAgent mapping attack surface...[/bold blue]", spinner="dots"):
                await recon_agent.run()
            self.console.print(f"  [green][+][/green] Recon complete: Discovered [bold]{len(self.context.endpoint_map)}[/bold] endpoints.")
            if self.context.scope.enable_checkpoints:
                self.context.save_checkpoint()
        else:
            self.console.print(f"  [dim][*] Resumed with {len(self.context.endpoint_map)} discovered endpoints.[/dim]")

        # Stage 2: Hypothesis Generation
        if not self.context.hypothesis_queue:
            with self.console.status("[bold magenta]2/5 HypothesisAgent reasoning about vulnerability risk vectors...[/bold magenta]", spinner="dots"):
                await hypothesis_agent.run()
            self.console.print(f"  [green][+][/green] Hypotheses ready: Formulated [bold]{len(self.context.hypothesis_queue)}[/bold] prioritized test hypotheses.")
            if self.context.scope.enable_checkpoints:
                self.context.save_checkpoint()
        else:
            self.console.print(f"  [dim][*] Resumed with {len(self.context.hypothesis_queue)} queued hypotheses.[/dim]")

        # Stage 3 & 4: Payload Testing & Observation (Agentic Feedback Loop)
        while self.context.current_iteration <= self.context.max_iterations:
            iteration_label = f"Iteration {self.context.current_iteration}/{self.context.max_iterations}"
            self.console.print(f"\n[bold yellow]--- Active Testing Cycle ({iteration_label}) ---[/bold yellow]")

            # 3. Payload Testing
            with self.console.status(f"[bold red]3/5 PayloadAgent executing non-destructive test probes ({iteration_label})...[/bold red]", spinner="dots"):
                await payload_agent.run()
            self.console.print(f"  [green][+][/green] Payloads tested: [bold]{len(self.context.test_results)}[/bold] test responses collected.")

            # 4. Observation & Anomaly Detection
            with self.console.status(f"[bold cyan]4/5 ObserverAgent evaluating response anomalies & differential state ({iteration_label})...[/bold cyan]", spinner="dots"):
                await observer_agent.run()
            self.console.print(f"  [green][+][/green] Observer complete: Identified [bold]{len(self.context.findings)}[/bold] confirmed/likely findings.")

            # Checkpoint after testing cycle
            if self.context.scope.enable_checkpoints:
                self.context.save_checkpoint()

            # Check if agentic replanning is triggered
            if self.context.replanning_triggered and self.context.current_iteration < self.context.max_iterations:
                self.console.print("  [bold magenta][!] Agentic Replanning Triggered: Refining hypotheses for secondary verification...[/bold magenta]")
                self.context.current_iteration += 1
            else:
                break

        # Stage 5: Synthesis & Reporting
        with self.console.status("[bold green]5/5 ReportAgent synthesizing CVSS metrics and generating Markdown/JSON/HTML/SARIF reports...[/bold green]", spinner="dots"):
            self.context.stats.end_time = time.time()
            self.context.stats.duration_seconds = self.context.stats.end_time - self.context.stats.start_time
            await report_agent.run()

        return self.context
