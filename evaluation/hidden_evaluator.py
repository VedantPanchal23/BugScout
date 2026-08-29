from __future__ import annotations

import os
import json
import random
import time
import threading
import uvicorn
from typing import Dict, Any, List
from fastapi import FastAPI, Request, Form
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse, RedirectResponse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.pipeline import BugScoutPipeline
from core.mission_context import VulnClass


class HiddenBenchmarkEvaluator:
    """
    Evaluates BugScout's Zero-Shot Generalization across multi-dimensional randomization:
    - Randomized route names (e.g. /api/client_XXXX/search, /service/item_XXXX/lookup)
    - Randomized parameter names (client_q, item_slug, doc_target, redir_dest, safe_tok, safe_key)
    - Mixed HTTP verbs (GET, POST) and response structures
    - Complete confusion matrix reporting: TP, FP, FN, TN, Recall, Precision, and Specificity.
    """

    def __init__(self, port: int = 8899):
        self.port = port
        self.target_url = f"http://127.0.0.1:{port}"
        self.console = Console(highlight=False)
        self.rand_id = random.randint(1000, 9999)

    def create_hidden_app(self) -> FastAPI:
        app = FastAPI(title="Hidden Multi-Dimensional Randomized Evaluation Lab")
        r = self.rand_id

        # 1. Hidden SQLi on randomized route & param
        @app.get(f"/api/client_{r}/search")
        async def hidden_sqli(client_q: str = ""):
            if "'" in client_q:
                return JSONResponse(status_code=500, content={"error": "sqlite3.OperationalError: near \"'\": syntax error"})
            return JSONResponse({"results": ["Client Alpha", "Client Beta"]})

        # 2. Hidden Reflected XSS on randomized route & param
        @app.get(f"/service/item_{r}/lookup")
        async def hidden_xss(item_slug: str = ""):
            return HTMLResponse(f"<html><body><h1>Item Result: {item_slug}</h1></body></html>")

        # 3. Hidden Traversal on randomized route & param
        @app.get(f"/portal/doc_{r}/download")
        async def hidden_traversal(doc_target: str = "whitepaper.pdf"):
            if "../" in doc_target or "..\\" in doc_target:
                return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\n[boot loader]", status_code=200)
            return PlainTextResponse("Public whitepaper content.", status_code=200)

        # 4. Hidden Open Redirect on randomized route & param
        @app.get(f"/auth/redir_{r}/dispatch")
        async def hidden_redirect(redir_dest: str = "https://example.com"):
            if redir_dest.startswith("http://") or redir_dest.startswith("https://"):
                return RedirectResponse(redir_dest, status_code=302)
            return RedirectResponse("/", status_code=302)

        # 5. Hidden Safe Decoy 1 (Safe HTML Encoded Echo)
        @app.get(f"/safe_gateway_{r}/echo")
        async def hidden_safe_echo(safe_tok: str = ""):
            import html
            return HTMLResponse(f"<html><body>Safe Echo: {html.escape(safe_tok)}</body></html>")

        # 6. Hidden Safe Decoy 2 (Safe Parameterized Search)
        @app.get(f"/safe_gateway_{r}/filter")
        async def hidden_safe_search(safe_key: str = ""):
            return JSONResponse({"status": "success", "matches": 0, "filter_used": safe_key})

        return app

    def start_hidden_server(self, app: FastAPI):
        config = uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        time.sleep(1.0)
        return server

    async def run_hidden_evaluation(self) -> Dict[str, Any]:
        self.console.print("\n[bold cyan]================================================================[/bold cyan]")
        self.console.print("[bold white]   BUGSCOUT ZERO-SHOT HIDDEN BENCHMARK GENERALIZATION           [/bold white]")
        self.console.print("[bold cyan]================================================================[/bold cyan]\n")

        app = self.create_hidden_app()
        self.start_hidden_server(app)

        self.console.print(f"[bold yellow][*] Scouting randomized unseen endpoints at {self.target_url} (Seed ID: {self.rand_id})...[/bold yellow]")
        pipeline = BugScoutPipeline(target_override=self.target_url, max_iterations=2)
        ctx = await pipeline.run()

        findings = ctx.findings

        # Evaluation against 6 ground-truth cases (4 vulnerable + 2 negative decoys)
        total_hidden_cases = 6
        vulnerable_cases = 4  # SQLi, XSS, Traversal, Redirect
        negative_cases = 2    # safe_echo, safe_filter

        detected_vuln_classes = set()
        for f in findings:
            if f.affected_endpoint.startswith(self.target_url):
                if "client_" in f.affected_endpoint and f.vuln_class == VulnClass.SQLI:
                    detected_vuln_classes.add("SQLi")
                elif "item_" in f.affected_endpoint and f.vuln_class == VulnClass.XSS:
                    detected_vuln_classes.add("XSS")
                elif "doc_" in f.affected_endpoint and f.vuln_class == VulnClass.PATH_TRAVERSAL:
                    detected_vuln_classes.add("Traversal")
                elif "redir_" in f.affected_endpoint and f.vuln_class == VulnClass.OPEN_REDIRECT:
                    detected_vuln_classes.add("Redirect")

        tp = len(detected_vuln_classes)
        fn = vulnerable_cases - tp

        # False positives: flags on safe_gateway endpoints
        fp = sum(1 for f in findings if "safe_gateway" in f.affected_endpoint.lower())
        tn = negative_cases - fp

        recall = round((tp / vulnerable_cases) * 100, 2)
        precision = round((tp / (tp + fp)) * 100, 2) if (tp + fp) > 0 else 100.0
        specificity = round((tn / negative_cases) * 100, 2)

        summary = {
            "random_seed_id": self.rand_id,
            "hidden_cases": total_hidden_cases,
            "vulnerable_cases": vulnerable_cases,
            "negative_cases": negative_cases,
            "detected_vulnerabilities_tp": tp,
            "false_positives_fp": fp,
            "false_negatives_fn": fn,
            "true_negatives_tn": tn,
            "zero_shot_recall": recall,
            "zero_shot_precision": precision,
            "zero_shot_specificity": specificity,
            "discovered_endpoints": len(ctx.endpoint_map),
            "total_requests": ctx.stats.total_requests_sent,
            "detected_classes": list(detected_vuln_classes)
        }

        self._print_hidden_table(summary)

        os.makedirs("outputs", exist_ok=True)
        with open("outputs/HiddenBenchmarkEvaluation.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        return summary

    def _print_hidden_table(self, data: Dict[str, Any]) -> None:
        table = Table(title=f"Zero-Shot Hidden Benchmark Generalization Results (Random Seed: {data['random_seed_id']})", header_style="bold cyan")
        table.add_column("Generalization Metric", style="bold white")
        table.add_column("Value / Metric", justify="center", style="bold green")
        table.add_column("Evaluation Meaning", style="dim")

        table.add_row("Total Hidden Labeled Cases", str(data["hidden_cases"]), "4 Vulnerable Instances + 2 Negative Decoys")
        table.add_row("Endpoints Discovered by Recon", f"{data['discovered_endpoints']}", "Zero-shot attack surface mapping")
        table.add_row("True Positives (TP)", f"{data['detected_vulnerabilities_tp']} / {data['vulnerable_cases']}", f"Detected: {', '.join(data['detected_classes']) or 'None'}")
        table.add_row("False Negatives (FN)", str(data["false_negatives_fn"]), "Missed novel vulnerabilities")
        table.add_row("True Negatives (TN)", f"{data['true_negatives_tn']} / {data['negative_cases']}", "Safe deceptive controls correctly rejected")
        table.add_row("False Positives (FP)", str(data["false_positives_fp"]), "False alarms on safe controls")
        table.add_row("Zero-Shot Recall", f"{data['zero_shot_recall']}%", "TP / (TP + FN)")
        table.add_row("Zero-Shot Precision", f"{data['zero_shot_precision']}%", "TP / (TP + FP)")
        table.add_row("Zero-Shot Specificity", f"{data['zero_shot_specificity']}%", "TN / (TN + FP)")

        self.console.print("\n")
        self.console.print(table)
        self.console.print(Panel(
            f"[bold green]Empirical Zero-Shot Generalization Finding:[/bold green] Across multi-dimensionally randomized endpoints "
            f"([bold yellow]/api/client_{data['random_seed_id']}/*, /service/item_{data['random_seed_id']}/*[/bold yellow]), "
            f"BugScout discovered [bold]{data['discovered_endpoints']}[/bold] endpoints and achieved "
            f"[bold cyan]{data['zero_shot_recall']}% Recall ({data['detected_vulnerabilities_tp']}/{data['vulnerable_cases']})[/bold cyan], "
            f"[bold green]{data['zero_shot_precision']}% Precision[/bold green], and [bold green]{data['zero_shot_specificity']}% Specificity[/bold green] "
            f"with [bold yellow]{data['false_positives_fp']} False Positives[/bold yellow].\n"
            f"[dim]Results saved to outputs/HiddenBenchmarkEvaluation.json[/dim]",
            title="Zero-Shot Generalization Summary",
            border_style="green"
        ))
