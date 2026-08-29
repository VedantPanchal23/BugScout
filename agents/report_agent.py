from __future__ import annotations

import os
import json
import time
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from agents.base_agent import BaseAgent
from core.mission_context import Finding, Severity


class ReportAgent(BaseAgent):
    """
    ReportAgent synthesizes all findings into actionable intelligence:
    - Generates professional Markdown report (outputs/VulnerabilityReport.md)
    - Generates machine-readable JSON (outputs/VulnerabilityReport.json)
    - Computes CVSS 3.1 severity metrics and reproduction guides
    - Renders terminal summary with Rich UI
    """

    async def run(self) -> None:
        self.log("Synthesizing mission findings into final vulnerability reports...")
        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "outputs")
        os.makedirs(output_dir, exist_ok=True)

        md_path = os.path.join(output_dir, "VulnerabilityReport.md")
        json_path = os.path.join(output_dir, "VulnerabilityReport.json")

        # 1. Generate JSON report
        report_data = self._build_json_report()
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        # 2. Generate Markdown report
        md_content = self._build_markdown_report()
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        self.log(f"Vulnerability reports generated successfully at '{md_path}' and '{json_path}'.")

        # 3. Print Rich Terminal Summary
        self._print_rich_summary()

    def _build_json_report(self) -> Dict[str, Any]:
        return {
            "metadata": {
                "tool": "BugScout - Autonomous Bug Bounty Scout",
                "version": "1.0.0",
                "scan_date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "target": self.context.target,
                "duration_seconds": round(self.context.stats.duration_seconds, 2),
                "total_requests_sent": self.context.stats.total_requests_sent,
                "total_endpoints_discovered": len(self.context.endpoint_map),
                "total_findings": len(self.context.findings),
            },
            "scope": self.context.scope.model_dump(),
            "endpoints": [ep.model_dump() for ep in self.context.endpoint_map.values()],
            "findings": [f.model_dump() for f in self.context.findings]
        }

    def _build_markdown_report(self) -> str:
        findings = self.context.findings
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)
        info_count = sum(1 for f in findings if f.severity == Severity.INFORMATIONAL)

        lines = [
            "# ??? BugScout — Autonomous Vulnerability Assessment Report",
            "",
            f"**Target:** {self.context.target}  ",
            f"**Assessment Date:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}  ",
            f"**Scan Duration:** {self.context.stats.duration_seconds:.2f}s  ",
            f"**Requests Executed:** {self.context.stats.total_requests_sent} | **Scope Blocks:** {self.context.stats.blocked_requests_count}  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            "BugScout completed an autonomous reconnaissance and security verification cycle. Discovered endpoints were probed with contextual, non-destructive payloads under strict ScopeGuard boundaries.",
            "",
            "### Vulnerability Severity Breakdown",
            "",
            "| Severity | Count |",
            "|:---|:---:|",
            f"| ?? **Critical** | {crit_count} |",
            f"| ?? **High** | {high_count} |",
            f"| ?? **Medium** | {med_count} |",
            f"| ?? **Low** | {low_count} |",
            f"| ? **Informational** | {info_count} |",
            f"| **Total Findings** | **{len(findings)}** |",
            "",
            "---",
            "",
            "## 2. Discovered Attack Surface",
            "",
            "| Method | Path | Discovered Via | Identified Parameters |",
            "|:---|:---|:---|:---|",
        ]

        for ep in self.context.endpoint_map.values():
            params = ", ".join(ep.query_params + ep.body_params) or "None"
            lines.append(f"| {ep.method} | {ep.path} | {ep.source} | {params} |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Detailed Vulnerability Findings",
            ""
        ])

        if not findings:
            lines.append("*No security vulnerabilities were identified within the specified scope.*")
        else:
            for idx, f in enumerate(findings, 1):
                severity_emoji = {
                    Severity.CRITICAL: "??",
                    Severity.HIGH: "??",
                    Severity.MEDIUM: "??",
                    Severity.LOW: "??",
                    Severity.INFORMATIONAL: "?",
                }.get(f.severity, "??")

                lines.extend([
                    f"### {idx}. {severity_emoji} {f.title} ({f.severity.value})",
                    "",
                    f"- **Vulnerability Class:** {f.vuln_class.value}",
                    f"- **CWE:** {f.cwe_id}",
                    f"- **CVSS 3.1 Base Score:** {f.cvss_score} ({f.cvss_vector})",
                    f"- **Confidence:** {f.confidence.value}",
                    f"- **Affected Endpoint:** {f.http_method} {f.affected_endpoint}",
                    f"- **Target Parameter:** {f.parameter or 'N/A'}",
                    "",
                    "#### Description",
                    f"{f.description}",
                    "",
                    "#### Reproduction Steps",
                    ""
                ])
                for step in f.reproduction_steps:
                    lines.append(f"- {step}")

                lines.extend([
                    "",
                    "#### Proof of Concept (cURL)",
                    "`ash",
                    f"{f.reproduction_curl}",
                    "`",
                    "",
                    "#### Technical Evidence",
                    "`",
                    f"{f.evidence}",
                    "`",
                    "",
                    "#### Remediation Guidance",
                    f"{f.remediation}",
                    "",
                    "---",
                    ""
                ])

        lines.extend([
            "## 4. Ethical & Scope Compliance Notice",
            "",
            "This report was autonomously generated for authorized security assessment purposes only. Testing was strictly constrained to user-defined boundaries enforced by ScopeGuard.",
            ""
        ])

        return "\n".join(lines)

    def _print_rich_summary(self) -> None:
        console = Console()
        findings = self.context.findings

        table = Table(title="??? BugScout — Mission Findings Summary", header_style="bold cyan")
        table.add_column("ID", style="dim", width=8)
        table.add_column("Severity", justify="center")
        table.add_column("Vulnerability Title")
        table.add_column("Endpoint", style="green")
        table.add_column("CVSS", justify="center")
        table.add_column("Confidence", justify="center")

        for f in findings:
            sev_color = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "bold magenta",
                Severity.MEDIUM: "bold yellow",
                Severity.LOW: "bold blue",
                Severity.INFORMATIONAL: "dim white",
            }.get(f.severity, "white")

            table.add_row(
                f.id,
                f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                f.title,
                f"{f.http_method} {f.affected_endpoint}",
                str(f.cvss_score),
                f.confidence.value
            )

        console.print("\n")
        console.print(table)
        console.print(Panel(
            f"[bold green]Mission Complete![/bold green] Total Requests: {self.context.stats.total_requests_sent} | Endpoints: {len(self.context.endpoint_map)} | Findings: {len(findings)} | Duration: {self.context.stats.duration_seconds:.2f}s\n"
            f"?? Reports saved to [bold cyan]outputs/VulnerabilityReport.md[/bold cyan] and [bold cyan]outputs/VulnerabilityReport.json[/bold cyan]",
            title="Scan Summary",
            border_style="green"
        ))
