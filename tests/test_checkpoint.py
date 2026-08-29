import os
import pytest
from core.mission_context import MissionContext, ScopeConfig, Endpoint, Finding, VulnClass, Severity


def test_checkpoint_save_and_resume(tmp_path):
    checkpoint_file = str(tmp_path / "test_checkpoint.json")
    config = ScopeConfig(target="https://example.com", allowed_hosts=["example.com"], checkpoint_path=checkpoint_file)
    context = MissionContext(target="https://example.com", scope=config)

    # Register an endpoint
    ep = Endpoint(id="GET:/api/users", url="https://example.com/api/users", path="/api/users", method="GET")
    context.endpoint_map[ep.id] = ep

    # Register a finding
    f = Finding(
        id="f1",
        vuln_class=VulnClass.SENSITIVE_DATA,
        severity=Severity.CRITICAL,
        title="Exposed .env",
        description="Leaked JWT secrets",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-200",
        affected_endpoint="https://example.com/.env",
        http_method="GET",
        reproduction_curl="curl https://example.com/.env",
        evidence="JWT_SECRET=xyz",
        remediation="Restrict access"
    )
    context.findings.append(f)

    # Save checkpoint
    saved_path = context.save_checkpoint(checkpoint_file)
    assert os.path.exists(saved_path)

    # Load checkpoint
    loaded = MissionContext.load_checkpoint(checkpoint_file)
    assert loaded.target == "https://example.com"
    assert "GET:/api/users" in loaded.endpoint_map
    assert len(loaded.findings) == 1
    assert loaded.findings[0].title == "Exposed .env"
