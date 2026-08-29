from __future__ import annotations

import time
from rich.console import Console

from core.mission_context import MissionContext
from core.scope_guard import ScopeGuard
from core.llm import LLMProvider
from agents.recon_agent import ReconAgent
from agents.hypothesis_agent import HypothesisAgent
from agents.payload_agent import PayloadAgent
from agents.observer_agent import ObserverAgent
from agents.report_agent import ReportAgent


class AgenticLoopController:
    """
    AgenticLoopController coordinates the autonomous security feedback cycle:
    Recon -> Hypothesize -> Test (PayloadAgent + ScopeGuard) -> Observe -> Replanning Loop -> Report
    """

    def __init__(
        self,
        context: MissionContext,
        scope_guard: ScopeGuard,
        llm: LLMProvider,
    ):
        self.context = context
        self.scope_guard = scope_guard
        self.llm = llm
        self.console = Console(highlight=False)

    async def execute_mission(self) -> MissionContext:
        self.context.stats.start_time = time.time()

        self.console.print(f"\n[bold cyan]>>> Starting BugScout Mission against:[/bold cyan] [bold yellow]{self.context.target}[/bold yellow]")
        self.console.print(f"[dim]LLM Provider: {self.llm.name}[/dim]\n")

        recon_agent = ReconAgent("ReconAgent", self.context, self.scope_guard, self.llm)
        hypothesis_agent = HypothesisAgent("HypothesisAgent", self.context, self.scope_guard, self.llm)
        payload_agent = PayloadAgent("PayloadAgent", self.context, self.scope_guard, self.llm)
        observer_agent = ObserverAgent("ObserverAgent", self.context, self.scope_guard, self.llm)
        report_agent = ReportAgent("ReportAgent", self.context, self.scope_guard, self.llm)

        # Stage 1: Reconnaissance
        with self.console.status("[bold blue]1/5 ReconAgent mapping attack surface...[/bold blue]", spinner="dots"):
            await recon_agent.run()
        self.console.print(f"  [green][+][/green] Recon complete: Discovered [bold]{len(self.context.endpoint_map)}[/bold] endpoints.")

        # Stage 2: Hypothesis Generation
        with self.console.status("[bold magenta]2/5 HypothesisAgent reasoning about vulnerability risk vectors...[/bold magenta]", spinner="dots"):
            await hypothesis_agent.run()
        self.console.print(f"  [green][+][/green] Hypotheses ready: Formulated [bold]{len(self.context.hypothesis_queue)}[/bold] prioritized test hypotheses.")

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

            # Check if agentic replanning is triggered
            if self.context.replanning_triggered and self.context.current_iteration < self.context.max_iterations:
                self.console.print("  [bold magenta][!] Agentic Replanning Triggered: Refining hypotheses for secondary verification...[/bold magenta]")
                self.context.current_iteration += 1
            else:
                break

        # Stage 5: Synthesis & Reporting
        with self.console.status("[bold green]5/5 ReportAgent synthesizing CVSS metrics and generating Markdown/JSON reports...[/bold green]", spinner="dots"):
            self.context.stats.end_time = time.time()
            self.context.stats.duration_seconds = self.context.stats.end_time - self.context.stats.start_time
            await report_agent.run()

        return self.context
