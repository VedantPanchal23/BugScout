from __future__ import annotations

import os
import json
import time
import sys
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, Optional


def generate_reproducibility_manifest(
    experiment_name: str,
    benchmark_version: str = "v2.1",
    model: str = "groq/qwen3.8-27b (or heuristic fallback)",
    temperature: float = 0.0,
    seed: int = 42,
    request_budget: int = 153,
    total_requests: int = 153,
    findings_count: int = 19,
    extra_metrics: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generates a formal JSON Reproducibility Manifest capturing exact execution environment,
    git commit hash, interpreter versions, model settings, and experiment parameters.
    """
    git_commit = "unknown"
    try:
        git_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        pass

    manifest = {
        "experiment_name": experiment_name,
        "benchmark_version": benchmark_version,
        "git_commit": git_commit,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "os_platform": sys.platform,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model_configuration": {
            "model_name": model,
            "temperature": temperature,
            "deterministic_inference": True,
            "heuristic_fallback_available": True
        },
        "experiment_parameters": {
            "random_seed": seed,
            "request_budget": request_budget,
            "total_requests_sent": total_requests,
            "total_findings_confirmed": findings_count
        }
    }

    if extra_metrics:
        manifest["evaluation_metrics"] = extra_metrics

    os.makedirs("outputs", exist_ok=True)
    manifest_path = "outputs/ReproducibilityManifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest
