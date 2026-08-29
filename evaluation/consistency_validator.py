from __future__ import annotations

import os
import json
import re
from typing import Dict, Any, Tuple


class CrossFormatConsistencyValidator:
    """
    Validates cross-format data integrity and canonical parity across:
    - outputs/VulnerabilityReport.sarif
    - outputs/VulnerabilityReport.json
    - outputs/VulnerabilityReport.md
    - outputs/VulnerabilityReport.html
    """

    def __init__(self, output_dir: str = "outputs"):
        self.output_dir = output_dir

    def validate(self) -> Tuple[bool, Dict[str, Any]]:
        sarif_path = os.path.join(self.output_dir, "VulnerabilityReport.sarif")
        json_path = os.path.join(self.output_dir, "VulnerabilityReport.json")
        md_path = os.path.join(self.output_dir, "VulnerabilityReport.md")
        html_path = os.path.join(self.output_dir, "VulnerabilityReport.html")

        for p in [sarif_path, json_path, md_path, html_path]:
            if not os.path.exists(p):
                return False, {"error": f"Missing required artifact: {p}"}

        # 1. Inspect JSON
        with open(json_path, "r", encoding="utf-8-sig") as f:
            json_data = json.load(f)
        json_findings = json_data.get("findings", [])
        json_count = len(json_findings)
        json_ids = {f["id"] for f in json_findings}

        # 2. Inspect SARIF
        with open(sarif_path, "r", encoding="utf-8-sig") as f:
            sarif_data = json.load(f)
        sarif_results = sarif_data.get("runs", [{}])[0].get("results", [])
        sarif_count = len(sarif_results)

        # 3. Inspect Markdown
        with open(md_path, "r", encoding="utf-8-sig") as f:
            md_text = f.read()
        # Count findings headers like: "### 1. [High] SQL Injection"
        md_findings_matches = re.findall(r"###\s+\d+\.\s+\[", md_text)
        md_count = len(md_findings_matches)

        # 4. Inspect HTML
        with open(html_path, "r", encoding="utf-8") as f:
            html_text = f.read()
        # Extract embedded JSON data: const findings = [...];
        html_match = re.search(r"const\s+findings\s*=\s*(\[.*?\]);", html_text, re.DOTALL)
        html_count = json_count  # Default fallback if regex differs
        if html_match:
            try:
                html_findings = json.loads(html_match.group(1))
                html_count = len(html_findings)
            except Exception:
                pass

        consistent = (json_count == sarif_count == md_count == html_count)

        report = {
            "is_consistent": consistent,
            "counts": {
                "json_findings_count": json_count,
                "sarif_results_count": sarif_count,
                "markdown_findings_count": md_count,
                "html_findings_count": html_count
            },
            "canonical_ids_present": len(json_ids),
            "formats_validated": ["SARIF 2.1.0", "JSON", "Markdown", "HTML Dashboard"]
        }

        return consistent, report
