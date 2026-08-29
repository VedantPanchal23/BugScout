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
    - Generates standalone Interactive HTML Dashboard (outputs/VulnerabilityReport.html)
    - Generates OASIS SARIF 2.1.0 report for GitHub Security / CI-CD (outputs/VulnerabilityReport.sarif)
    - Computes CVSS 3.1 severity metrics and reproduction guides
    - Renders terminal summary with Rich UI
    """

    async def run(self) -> None:
        self.log("Synthesizing mission findings into Markdown, JSON, HTML Dashboard, and SARIF 2.1.0 reports...")
        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "outputs")
        os.makedirs(output_dir, exist_ok=True)

        md_path = os.path.join(output_dir, "VulnerabilityReport.md")
        json_path = os.path.join(output_dir, "VulnerabilityReport.json")
        html_path = os.path.join(output_dir, "VulnerabilityReport.html")
        sarif_path = os.path.join(output_dir, "VulnerabilityReport.sarif")

        # 1. Generate JSON report
        report_data = self._build_json_report()
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        # 2. Generate Markdown report
        md_content = self._build_markdown_report()
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        # 3. Generate Interactive HTML Dashboard
        html_content = self._build_html_dashboard(report_data)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        # 4. Generate SARIF 2.1.0 standard report
        sarif_data = self._build_sarif_report()
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)

        self.log(f"Reports generated successfully: Markdown ({md_path}), JSON ({json_path}), HTML ({html_path}), SARIF ({sarif_path}).")

        # 5. Print Rich Terminal Summary
        self._print_rich_summary()

    def _build_json_report(self) -> Dict[str, Any]:
        return {
            "metadata": {
                "tool": "BugScout - Autonomous Bug Bounty Scout",
                "version": "3.0.0",
                "scan_date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "target": self.context.target,
                "duration_seconds": round(self.context.stats.duration_seconds, 2),
                "total_requests_sent": self.context.stats.total_requests_sent,
                "total_endpoints_discovered": len(self.context.endpoint_map),
                "total_findings": len(self.context.findings),
                "waf_detected": self.context.waf_info.detected_waf,
            },
            "scope": self.context.scope.model_dump(),
            "waf_info": self.context.waf_info.model_dump(),
            "endpoints": [ep.model_dump() for ep in self.context.endpoint_map.values()],
            "findings": [f.model_dump() for f in self.context.findings]
        }

    def _build_sarif_report(self) -> Dict[str, Any]:
        """Build OASIS SARIF v2.1.0 report for GitHub Code Scanning / CI-CD."""
        rules = []
        results = []
        rule_indices = {}

        severity_level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFORMATIONAL: "none",
        }

        for f in self.context.findings:
            rule_id = f.cwe_id or f.vuln_class.name
            if rule_id not in rule_indices:
                rule_indices[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": f.vuln_class.value,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": severity_level_map.get(f.severity, "warning")
                    },
                    "properties": {
                        "tags": ["security", "OWASP", f.cwe_id],
                        "precision": "high",
                        "cvssScore": str(f.cvss_score),
                        "cvssVector": f.cvss_vector,
                        "remediation": f.remediation
                    }
                })

            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_indices[rule_id],
                "level": severity_level_map.get(f.severity, "warning"),
                "message": {
                    "text": f"[{f.severity.value}] {f.title}: {f.description} (CVSS: {f.cvss_score})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.affected_endpoint
                            }
                        }
                    }
                ]
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "BugScout",
                            "semanticVersion": "3.0.0",
                            "informationUri": "https://github.com/VedantPanchal23/BugScout",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        }

    def _build_markdown_report(self) -> str:
        findings = self.context.findings
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)
        info_count = sum(1 for f in findings if f.severity == Severity.INFORMATIONAL)

        waf_status = self.context.waf_info.detected_waf or "None Detected"

        lines = [
            "# [BugScout] Autonomous Vulnerability Assessment Report",
            "",
            f"**Target:** `{self.context.target}`  ",
            f"**Assessment Date:** `{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}`  ",
            f"**Scan Duration:** `{self.context.stats.duration_seconds:.2f}s`  ",
            f"**WAF Protection:** `{waf_status}`  ",
            f"**Requests Executed:** `{self.context.stats.total_requests_sent}` | **Scope Blocks:** `{self.context.stats.blocked_requests_count}`  ",
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
            f"| [Critical] | {crit_count} |",
            f"| [High] | {high_count} |",
            f"| [Medium] | {med_count} |",
            f"| [Low] | {low_count} |",
            f"| [Informational] | {info_count} |",
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
            lines.append(f"| `{ep.method}` | `{ep.path}` | `{ep.source}` | `{params}` |")

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
                lines.extend([
                    f"### {idx}. [{f.severity.value}] {f.title}",
                    "",
                    f"- **Vulnerability Class:** `{f.vuln_class.value}`",
                    f"- **CWE:** `{f.cwe_id}`",
                    f"- **CVSS 3.1 Base Score:** `{f.cvss_score}` (`{f.cvss_vector}`)",
                    f"- **Confidence:** `{f.confidence.value}`",
                    f"- **Affected Endpoint:** `{f.http_method} {f.affected_endpoint}`",
                    f"- **Target Parameter:** `{f.parameter or 'N/A'}`",
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
                    "```bash",
                    f"{f.reproduction_curl}",
                    "```",
                    "",
                    "#### Technical Evidence",
                    "```",
                    f"{f.evidence}",
                    "```",
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

    def _build_html_dashboard(self, data: Dict[str, Any]) -> str:
        findings = data.get("findings", [])
        meta = data.get("metadata", {})

        crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
        high_count = sum(1 for f in findings if f.get("severity") == "High")
        med_count = sum(1 for f in findings if f.get("severity") == "Medium")
        low_count = sum(1 for f in findings if f.get("severity") == "Low")

        findings_json = json.dumps(findings)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugScout - Vulnerability Assessment Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-main: #0d1117;
            --bg-card: #161b22;
            --border: #30363d;
            --text-primary: #c9d1d9;
            --text-heading: #f0f6fc;
            --crit-color: #f85149;
            --high-color: #d29922;
            --med-color: #e3b341;
            --low-color: #58a6ff;
            --accent: #238636;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-primary);
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .header h1 {{
            color: var(--text-heading);
            margin: 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .badge-status {{
            background: #1f6feb22;
            color: #58a6ff;
            padding: 4px 12px;
            border-radius: 20px;
            border: 1px solid #1f6feb66;
            font-size: 14px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .kpi-num {{
            font-size: 32px;
            font-weight: bold;
            margin: 8px 0;
        }}
        .kpi-crit {{ color: var(--crit-color); }}
        .kpi-high {{ color: var(--high-color); }}
        .kpi-med {{ color: var(--med-color); }}
        .kpi-low {{ color: var(--low-color); }}
        .charts-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 32px;
        }}
        .chart-box {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            height: 280px;
        }}
        .controls {{
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }}
        .search-input {{
            flex: 1;
            padding: 8px 12px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-primary);
            border-radius: 6px;
            min-width: 250px;
        }}
        .filter-btn {{
            padding: 8px 16px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-primary);
            border-radius: 6px;
            cursor: pointer;
        }}
        .filter-btn.active {{
            background: #238636;
            color: white;
            border-color: #2ea043;
        }}
        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }}
        .finding-title {{
            font-size: 16px;
            font-weight: 600;
            color: var(--text-heading);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .badge {{
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge-Critical {{ background: #f8514933; color: var(--crit-color); border: 1px solid var(--crit-color); }}
        .badge-High {{ background: #d2992233; color: var(--high-color); border: 1px solid var(--high-color); }}
        .badge-Medium {{ background: #e3b34133; color: var(--med-color); border: 1px solid var(--med-color); }}
        .badge-Low {{ background: #58a6ff33; color: var(--low-color); border: 1px solid var(--low-color); }}
        .finding-body {{
            padding: 16px;
            border-top: 1px solid var(--border);
            background: #0d111788;
            display: block;
        }}
        pre {{
            background: #0d1117;
            border: 1px solid var(--border);
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            color: #79c0ff;
        }}
        .copy-btn {{
            background: #21262d;
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            cursor: pointer;
            float: right;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>BugScout Assessment Report</h1>
                <p style="margin: 4px 0 0 0; color: #8b949e;">Target: <strong>{meta.get('target')}</strong> | Date: {meta.get('scan_date')} | Duration: {meta.get('duration_seconds')}s</p>
            </div>
            <div class="badge-status">Autonomous Mission Complete</div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div>Total Findings</div>
                <div class="kpi-num">{len(findings)}</div>
            </div>
            <div class="kpi-card">
                <div>Critical Severity</div>
                <div class="kpi-num kpi-crit">{crit_count}</div>
            </div>
            <div class="kpi-card">
                <div>High Severity</div>
                <div class="kpi-num kpi-high">{high_count}</div>
            </div>
            <div class="kpi-card">
                <div>Medium Severity</div>
                <div class="kpi-num kpi-med">{med_count}</div>
            </div>
            <div class="kpi-card">
                <div>Requests / Blocks</div>
                <div class="kpi-num" style="font-size: 24px;">{meta.get('total_requests_sent')} / {self.context.stats.blocked_requests_count}</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-box">
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-box">
                <canvas id="vulnTypeChart"></canvas>
            </div>
        </div>

        <div class="controls">
            <input type="text" id="searchInput" class="search-input" placeholder="Search vulnerability title, endpoint, or CWE...">
            <button class="filter-btn active" onclick="filterSeverity('ALL')">All</button>
            <button class="filter-btn" onclick="filterSeverity('Critical')">Critical</button>
            <button class="filter-btn" onclick="filterSeverity('High')">High</button>
            <button class="filter-btn" onclick="filterSeverity('Medium')">Medium</button>
            <button class="filter-btn" onclick="filterSeverity('Low')">Low</button>
        </div>

        <div id="findingsContainer"></div>
    </div>

    <script>
        const findings = """ + findings_json + """;

        // Charts initialization
        const ctxSev = document.getElementById('severityChart').getContext('2d');
        new Chart(ctxSev, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [""" + str(crit_count) + """, """ + str(high_count) + """, """ + str(med_count) + """, """ + str(low_count) + """],
                    backgroundColor: ['#f85149', '#d29922', '#e3b341', '#58a6ff'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: { display: true, text: 'Vulnerabilities by Severity', color: '#c9d1d9' },
                    legend: { labels: { color: '#c9d1d9' } }
                }
            }
        });

        // Render Findings
        let currentFilter = 'ALL';
        function renderFindings() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const container = document.getElementById('findingsContainer');
            container.innerHTML = '';

            const filtered = findings.filter(f => {
                const matchFilter = currentFilter === 'ALL' || f.severity === currentFilter;
                const matchQuery = !query || f.title.toLowerCase().includes(query) || f.affected_endpoint.toLowerCase().includes(query) || f.cwe_id.toLowerCase().includes(query);
                return matchFilter && matchQuery;
            });

            if (filtered.length === 0) {
                container.innerHTML = '<div style="text-align:center; padding: 40px; color: #8b949e;">No findings match the selected filters.</div>';
                return;
            }

            filtered.forEach((f, idx) => {
                const card = document.createElement('div');
                card.className = 'finding-card';
                card.innerHTML = `
                    <div class="finding-header" onclick="toggleCard('body-` + idx + `')">
                        <div class="finding-title">
                            <span class="badge badge-` + f.severity + `">` + f.severity + `</span>
                            <span>` + f.title + `</span>
                        </div>
                        <div style="font-size: 13px; color: #8b949e;">
                            CVSS: <strong>` + f.cvss_score + `</strong> | CWE: <strong>` + f.cwe_id + `</strong>
                        </div>
                    </div>
                    <div id="body-` + idx + `" class="finding-body">
                        <p><strong>Endpoint:</strong> <code>` + f.http_method + ` ` + f.affected_endpoint + `</code></p>
                        <p><strong>Description:</strong> ` + f.description + `</p>
                        
                        <div style="margin-top: 12px;">
                            <button class="copy-btn" onclick="navigator.clipboard.writeText(encodeURIComponent('` + f.reproduction_curl + `')); this.innerText='Copied!';">Copy cURL</button>
                            <strong>Proof of Concept (cURL):</strong>
                            <pre><code>` + f.reproduction_curl + `</code></pre>
                        </div>
                        
                        <div style="margin-top: 12px;">
                            <strong>Technical Evidence:</strong>
                            <pre><code>` + f.evidence + `</code></pre>
                        </div>

                        <div style="margin-top: 12px;">
                            <strong>Remediation:</strong>
                            <p style="color: #56d364;">` + f.remediation + `</p>
                        </div>
                    </div>
                `;
                container.appendChild(card);
            });
        }

        function toggleCard(id) {
            const el = document.getElementById(id);
            el.style.display = el.style.display === 'none' ? 'block' : 'none';
        }

        function filterSeverity(sev) {
            currentFilter = sev;
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            renderFindings();
        }

        document.getElementById('searchInput').addEventListener('input', renderFindings);
        renderFindings();
    </script>
</body>
</html>"""
        return html

    def _print_rich_summary(self) -> None:
        console = Console(highlight=False)
        findings = self.context.findings

        table = Table(title="BugScout - Mission Findings Summary", header_style="bold cyan")
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
            f"Reports saved to [bold cyan]outputs/VulnerabilityReport.sarif[/bold cyan], [bold cyan]outputs/VulnerabilityReport.html[/bold cyan], [bold cyan]outputs/VulnerabilityReport.md[/bold cyan], and [bold cyan]outputs/VulnerabilityReport.json[/bold cyan]",
            title="Scan Summary",
            border_style="green"
        ))
