import pytest
from core.mission_context import MissionContext, ScopeConfig, Finding, VulnClass, Severity, Confidence, EvidenceLevel
from agents.validation_agent import ValidationAgent


@pytest.mark.asyncio
async def test_validation_agent_evidence_filtering():
    ctx = MissionContext(
        target="http://test.local",
        scope=ScopeConfig(target="http://test.local", allowed_hosts=["test.local"])
    )

    # Add a Level 1 (Weak) finding and a Level 4 (Validated) finding
    f_weak = Finding(
        id="f1",
        vuln_class=VulnClass.SQLI,
        severity=Severity.HIGH,
        title="Weak SQLi Candidate",
        description="Weak signal",
        cvss_score=8.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-89",
        affected_endpoint="http://test.local/api/item",
        http_method="GET",
        reproduction_curl="curl http://test.local/api/item",
        evidence="Small status delta",
        evidence_level=EvidenceLevel.LEVEL_1_SUSPICIOUS,
        remediation="Check queries",
        confidence=Confidence.POTENTIAL
    )

    f_validated = Finding(
        id="f2",
        vuln_class=VulnClass.XSS,
        severity=Severity.MEDIUM,
        title="Confirmed Reflected XSS",
        description="Validated XSS",
        cvss_score=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        cwe_id="CWE-79",
        affected_endpoint="http://test.local/search",
        http_method="GET",
        reproduction_curl="curl http://test.local/search",
        evidence="Reflected <scout_xss_marker>",
        evidence_level=EvidenceLevel.LEVEL_4_VALIDATED,
        remediation="Encode HTML",
        confidence=Confidence.CONFIRMED
    )

    ctx.findings = [f_weak, f_validated]

    agent = ValidationAgent("ValidationAgent", ctx)
    graduated = await agent.run()

    # Assert only the Level 4 finding graduated; Level 1 was rejected
    assert len(graduated) == 1
    assert graduated[0].id == "f2"
    assert graduated[0].why_tested != ""
    assert graduated[0].why_reported != ""
