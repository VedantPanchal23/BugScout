import os
import json
import pytest
from core.mission_context import MissionContext, ScopeConfig, Finding, VulnClass, Severity, Confidence
from core.scope_guard import ScopeGuard
from core.llm import HeuristicSecurityEngine
from agents.report_agent import ReportAgent


@pytest.mark.asyncio
async def test_sarif_generation():
    config = ScopeConfig(target="http://127.0.0.1:8888", allowed_hosts=["127.0.0.1"])
    context = MissionContext(target="http://127.0.0.1:8888", scope=config)

    # Add a mock finding
    context.findings.append(Finding(
        id="sarif_test_1",
        vuln_class=VulnClass.SQLI,
        severity=Severity.HIGH,
        title="SQL Injection in products search",
        description="Leaked SQLite syntax errors.",
        cvss_score=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cwe_id="CWE-89",
        affected_endpoint="http://127.0.0.1:8888/api/products",
        http_method="GET",
        parameter="search",
        reproduction_curl="curl http://127.0.0.1:8888/api/products?search='",
        reproduction_steps=["1. Send request with quote"],
        evidence="SQLite error",
        remediation="Use parameterized queries.",
        confidence=Confidence.CONFIRMED
    ))

    agent = ReportAgent("ReportAgent", context, ScopeGuard(config), HeuristicSecurityEngine())
    await agent.run()

    sarif_file = "outputs/VulnerabilityReport.sarif"
    assert os.path.exists(sarif_file)

    with open(sarif_file, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)

    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"]) > 0
    driver = sarif_data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "BugScout"
    assert len(sarif_data["runs"][0]["results"]) == 1
    result = sarif_data["runs"][0]["results"][0]
    assert result["ruleId"] == "CWE-89"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "http://127.0.0.1:8888/api/products"
