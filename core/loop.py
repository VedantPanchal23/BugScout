from __future__ import annotations

import time
from typing import Optional
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
from agents.validation_agent import ValidationAgent
from agents.report_agent import ReportAgent


class AgenticLoopController:
    """
    Coordinates the 6-Agent Autonomous Security Feedback Architecture:
    Stage 0: Dynamic Auth (AuthManager)
    Stage 1: Attack Surface Discovery (ReconAgent)
    Stage 2: Threat Reasoning (HypothesisAgent + LLM)
    Stage 3: Guarded Probing (PayloadAgent + ScopeGuard + WAFDetector)
    Stage 4: Signal Observation & Diffing (ObserverAgent)
    Stage 5: Deterministic Evidence Quality Validation (ValidationAgent)
    Stage 6: Multi-Format Synthesis & Manifest Generation (ReportAgent)
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

        self.context.record_audit("Controller", "Mission Start", self.context.target, "EXECUTE", f"Initialized mission with LLM {self.llm.name}")

        # Stage 0: Dynamic Authentication (if configured)
        if self.auth_manager.is_configured():
            with self.console.status("[bold blue]0/6 Performing Dynamic Pre-Flight Authentication...[/bold blue]", spinner="dots"):
                headers, cookies = await self.auth_manager.authenticate()
                self.context.scope.custom_headers.update(headers)
                self.context.scope.session_cookies.update(cookies)
                self.context.record_audit("AuthManager", "Pre-Flight Login", self.context.scope.auth.login_url or self.context.target, "AUTHENTICATED", "Session credentials injected.")
            self.console.print("  [green][+][/green] Authentication successful: Session tokens & cookies injected.")

        recon_agent = ReconAgent("ReconAgent", self.context, self.scope_guard, self.llm)
        hypothesis_agent = HypothesisAgent("HypothesisAgent", self.context, self.scope_guard, self.llm)
        payload_agent = PayloadAgent("PayloadAgent", self.context, self.scope_guard, self.llm)
        observer_agent = ObserverAgent("ObserverAgent", self.context, self.scope_guard, self.llm)
        validation_agent = ValidationAgent("ValidationAgent", self.context, self.scope_guard, self.llm)
        report_agent = ReportAgent("ReportAgent", self.context, self.scope_guard, self.llm)

        # Stage 1: Reconnaissance (Attack Surface Graph)
        if not self.context.endpoint_map:
            with self.console.status("[bold blue]1/6 ReconAgent mapping attack surface...[/bold blue]", spinner="dots"):
                await recon_agent.run()
            self.console.print(f"  [green][+][/green] Recon complete: Discovered [bold]{len(self.context.endpoint_map)}[/bold] endpoints.")
            self.context.record_audit("ReconAgent", "Attack Surface Mapping", self.context.target, "COMPLETE", f"Found {len(self.context.endpoint_map)} endpoints.")
            if self.context.scope.enable_checkpoints:
                self.context.save_checkpoint()
        else:
            self.console.print(f"  [dim][*] Resumed with {len(self.context.endpoint_map)} discovered endpoints.[/dim]")

        # Stage 2: Threat Reasoning & Prioritization
        if not self.context.hypothesis_queue:
            with self.console.status("[bold magenta]2/6 Threat Reasoning Agent formulating attack vectors...[/bold magenta]", spinner="dots"):
                await hypothesis_agent.run()
            
            # Policy Orchestration: Apply per-endpoint budgets and priority queue
            from core.policy_engine import PolicyEngine
            policy_engine = PolicyEngine()
            self.context.hypothesis_queue = policy_engine.filter_and_prioritize_hypotheses(
                self.context.hypothesis_queue,
                self.context.endpoint_map
            )

            self.console.print(f"  [green][+][/green] Hypotheses ready: Formulated [bold]{len(self.context.hypothesis_queue)}[/bold] prioritized test hypotheses.")
            self.context.record_audit("HypothesisAgent", "Threat Modeling", self.context.target, "COMPLETE", f"Formulated {len(self.context.hypothesis_queue)} hypotheses.")
            if self.context.scope.enable_checkpoints:
                self.context.save_checkpoint()
        else:
            self.console.print(f"  [dim][*] Resumed with {len(self.context.hypothesis_queue)} queued hypotheses.[/dim]")

        # Stage 3, 4 & 5: Payload Probing, Observation & Validation (Agentic Loop)
        while self.context.current_iteration <= self.context.max_iterations:
            iteration_label = f"Iteration {self.context.current_iteration}/{self.context.max_iterations}"
            self.console.print(f"\n[bold yellow]--- Active Testing Cycle ({iteration_label}) ---[/bold yellow]")

            # 3. Payload Probing
            with self.console.status(f"[bold red]3/6 Probe Agent executing guarded non-destructive probes ({iteration_label})...[/bold red]", spinner="dots"):
                await payload_agent.run()
            self.console.print(f"  [green][+][/green] Payloads tested: [bold]{len(self.context.test_results)}[/bold] test responses collected.")

            # 4. Observation & Signal Diffing
            with self.console.status(f"[bold cyan]4/6 Observation Agent evaluating response anomalies ({iteration_label})...[/bold cyan]", spinner="dots"):
                await observer_agent.run()
            self.console.print(f"  [green][+][/green] Observation complete: Identified candidate anomaly signals.")

            # 5. Deterministic Validation
            with self.console.status(f"[bold cyan]5/6 Validation Agent verifying evidence quality & confidence ({iteration_label})...[/bold cyan]", spinner="dots"):
                await validation_agent.run()
            self.console.print(f"  [green][+][/green] Validation complete: [bold]{len(self.context.findings)}[/bold] confirmed findings graduated.")

            # Checkpoint after testing cycle
            if self.context.scope.enable_checkpoints:
                self.context.save_checkpoint()

            # Check if agentic replanning is triggered
            if self.context.replanning_triggered and self.context.current_iteration < self.context.max_iterations:
                self.console.print("  [bold magenta][!] Agentic Replanning Triggered: Refining hypotheses for secondary verification...[/bold magenta]")
                self.context.record_audit("Controller", "Replanning Trigger", self.context.target, "REPLAN", f"Advancing to iteration {self.context.current_iteration + 1}")
                self.context.current_iteration += 1
            else:
                break

        # Stage 6: Synthesis & Reporting
        with self.console.status("[bold green]6/6 Reporting Agent synthesizing CVSS metrics and manifest...[/bold green]", spinner="dots"):
            self.context.stats.end_time = time.time()
            self.context.stats.duration_seconds = self.context.stats.end_time - self.context.stats.start_time
            await report_agent.run()
            self.context.record_audit("ReportAgent", "Report Generation", self.context.target, "COMPLETE", f"Published {len(self.context.findings)} findings across 4 formats.")

        return self.context
