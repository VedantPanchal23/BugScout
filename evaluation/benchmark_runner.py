from __future__ import annotations

import os
import json
import time
import threading
import uvicorn
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.pipeline import BugScoutPipeline
from benchmark_lab.server import benchmark_app


class BenchmarkEvaluator:
    """
    Evaluates BugScout against the controlled Ground Truth Security Benchmark Lab.
    Calculates exact confusion matrix metrics:
    - True Positives (TP)
    - False Positives (FP)
    - False Negatives (FN)
    - True Negatives (TN)
    - Precision, Recall, F1 Score, Specificity, and Endpoint Discovery Recall.
    """

    def __init__(self, ground_truth_path: str = "benchmark_lab/ground_truth.json", port: int = 8888):
        self.ground_truth_path = ground_truth_path
        self.port = port
        self.target_url = f"http://127.0.0.1:{port}"
        self.console = Console(highlight=False)

        with open(ground_truth_path, "r", encoding="utf-8-sig") as f:
            self.ground_truth = json.load(f)

    def start_lab_server(self):
        config = uvicorn.Config(benchmark_app, host="127.0.0.1", port=self.port, log_level="error")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        time.sleep(1.0)
        return server

    async def run_evaluation(self) -> Dict[str, Any]:
        self.console.print("\n[bold cyan]================================================================[/bold cyan]")
        self.console.print("[bold white]   BUGSCOUT GROUND-TRUTH SECURITY BENCHMARK & EVALUATION LAB   [/bold white]")
        self.console.print("[bold cyan]================================================================[/bold cyan]\n")

        self.console.print(f"[bold yellow][*] Initializing Ground-Truth Benchmark Lab on {self.target_url}...[/bold yellow]")
        self.start_lab_server()

        self.console.print("[bold yellow][*] Executing Autonomous Multi-Agent Scan against Benchmark Lab...[/bold yellow]\n")
        pipeline = BugScoutPipeline(target_override=self.target_url, max_iterations=2)
        context = await pipeline.run()

        # Evaluate against Ground Truth
        results_summary = self._calculate_metrics(context)
        self._print_evaluation_dashboard(results_summary)

        # Save Evaluation Report
        os.makedirs("outputs", exist_ok=True)
        with open("outputs/BenchmarkEvaluation.json", "w", encoding="utf-8") as f:
            json.dump(results_summary, f, indent=2)

        return results_summary

    def _calculate_metrics(self, context) -> Dict[str, Any]:
        vuln_targets = self.ground_truth.get("vulnerabilities", [])
        decoy_targets = self.ground_truth.get("safe_negative_decoys", [])
        total_known_endpoints = self.ground_truth.get("total_known_endpoints", 25)

        findings = context.findings

        # 1. Evaluate Vulnerabilities (TP & FN)
        tp_list = []
        fn_list = []
        test_case_results = []

        for vt in vuln_targets:
            test_id = vt["test_id"]
            name = vt["name"]
            vuln_class = vt["vuln_class"]
            path = vt["path"]

            matched = False
            detected_finding = None
            for f in findings:
                if f.vuln_class.value == vuln_class and path in f.affected_endpoint:
                    matched = True
                    detected_finding = f
                    break

            if matched:
                tp_list.append(test_id)
                test_case_results.append({
                    "test_id": test_id,
                    "name": name,
                    "target": f"{vt['method']} {path}",
                    "present": "Yes",
                    "detected": "Yes",
                    "result": "TP (True Positive)",
                    "severity": detected_finding.severity.value,
                    "cvss": detected_finding.cvss_score,
                    "confidence": detected_finding.confidence.value
                })
            else:
                fn_list.append(test_id)
                test_case_results.append({
                    "test_id": test_id,
                    "name": name,
                    "target": f"{vt['method']} {path}",
                    "present": "Yes",
                    "detected": "No",
                    "result": "FN (False Negative)",
                    "severity": "N/A",
                    "cvss": 0.0,
                    "confidence": "N/A"
                })

        # 2. Evaluate Safe Negative Decoys (TN & FP)
        fp_list = []
        tn_list = []
        for decoy in decoy_targets:
            test_id = decoy["test_id"]
            name = decoy["name"]
            path = decoy["path"]

            flagged = False
            flagged_finding = None
            for f in findings:
                if path in f.affected_endpoint and "safe" in path.lower():
                    flagged = True
                    flagged_finding = f
                    break

            if flagged:
                fp_list.append(test_id)
                test_case_results.append({
                    "test_id": test_id,
                    "name": name,
                    "target": f"{decoy['method']} {path}",
                    "present": "No (Safe Decoy)",
                    "detected": "Yes (False Alarm)",
                    "result": "FP (False Positive)",
                    "severity": flagged_finding.severity.value,
                    "cvss": flagged_finding.cvss_score,
                    "confidence": flagged_finding.confidence.value
                })
            else:
                tn_list.append(test_id)
                test_case_results.append({
                    "test_id": test_id,
                    "name": name,
                    "target": f"{decoy['method']} {path}",
                    "present": "No (Safe Decoy)",
                    "detected": "No (Rejected)",
                    "result": "TN (True Negative)",
                    "severity": "None",
                    "cvss": 0.0,
                    "confidence": "Rejected"
                })

        tp = len(tp_list)
        fn = len(fn_list)
        fp = len(fp_list)
        tn = len(tn_list)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        endpoints_discovered = len(context.endpoint_map)
        discovery_recall = min(1.0, endpoints_discovered / total_known_endpoints)

        return {
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "true_negatives": tn
            },
            "metrics": {
                "precision": round(precision * 100, 2),
                "recall": round(recall * 100, 2),
                "f1_score": round(f1_score * 100, 2),
                "specificity": round(specificity * 100, 2),
                "endpoint_discovery_recall": round(discovery_recall * 100, 2),
            },
            "scan_stats": {
                "total_requests_sent": context.stats.total_requests_sent,
                "total_endpoints_discovered": endpoints_discovered,
                "total_findings": len(findings),
                "duration_seconds": round(context.stats.duration_seconds, 2)
            },
            "test_cases": test_case_results
        }

    def _print_evaluation_dashboard(self, data: Dict[str, Any]) -> None:
        metrics = data["metrics"]
        cm = data["confusion_matrix"]
        stats = data["scan_stats"]

        self.console.print("\n")
        table = Table(title="BugScout Security Benchmark Lab — Ground Truth Test Matrix (T01 - T10 & Decoys)", header_style="bold cyan")
        table.add_column("Test ID", style="bold yellow", width=8)
        table.add_column("Test Case Name")
        table.add_column("Endpoint", style="dim")
        table.add_column("Present?", justify="center")
        table.add_column("Detected?", justify="center")
        table.add_column("Classification Result", justify="center")

        for tc in data["test_cases"]:
            res = tc["result"]
            res_style = "bold green" if ("TP" in res or "TN" in res) else "bold red"
            table.add_row(
                tc["test_id"],
                tc["name"],
                tc["target"],
                tc["present"],
                tc["detected"],
                f"[{res_style}]{res}[/{res_style}]"
            )

        self.console.print(table)

        # Metrics Panel
        p_color = "bold green" if metrics["precision"] >= 80 else "bold yellow"
        r_color = "bold green" if metrics["recall"] >= 80 else "bold yellow"
        f1_color = "bold green" if metrics["f1_score"] >= 80 else "bold yellow"

        summary_text = (
            f"[bold white]Ground-Truth Empirical Metrics:[/bold white]\n"
            f"  • [bold]True Positives (TP):[/bold] {cm['true_positives']} | [bold]True Negatives (TN):[/bold] {cm['true_negatives']}\n"
            f"  • [bold]False Positives (FP):[/bold] {cm['false_positives']} | [bold]False Negatives (FN):[/bold] {cm['false_negatives']}\n\n"
            f"  • [bold]Precision:[/bold] [{p_color}]{metrics['precision']}%[/{p_color}]  (TP / (TP + FP))\n"
            f"  • [bold]Recall (Sensitivity):[/bold] [{r_color}]{metrics['recall']}%[/{r_color}]  (TP / (TP + FN))\n"
            f"  • [bold]F1 Score:[/bold] [{f1_color}]{metrics['f1_score']}%[/{f1_color}]  (Harmonic Mean)\n"
            f"  • [bold]Specificity (Negative Rejection):[/bold] [bold green]{metrics['specificity']}%[/bold green]  (TN / (TN + FP))\n"
            f"  • [bold]Endpoint Discovery Recall:[/bold] [bold green]{metrics['endpoint_discovery_recall']}%[/bold green] ({stats['total_endpoints_discovered']} endpoints)\n\n"
            f"[dim]Total Requests: {stats['total_requests_sent']} | Scan Duration: {stats['duration_seconds']}s | Output: outputs/BenchmarkEvaluation.json[/dim]"
        )

        self.console.print(Panel(summary_text, title="Academic Benchmark Evaluation Dashboard", border_style="green"))
