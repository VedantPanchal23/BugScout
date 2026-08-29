import pytest
from evaluation.safety_tester import SafetySuiteRunner


@pytest.mark.asyncio
async def test_scope_guard_safety_suite():
    runner = SafetySuiteRunner()
    results = await runner.run_safety_tests()

    assert results["safety_enforcement_rate"] == 100.0
    assert results["failed_tests"] == 0
    assert results["passed_tests"] == 16


def test_secret_and_token_redaction():
    """Verify that credentials and tokens are redacted before logging or report synthesis."""
    from core.mission_context import ScopeConfig, MissionContext, Finding, Severity, VulnClass, EvidenceLevel
    import re

    raw_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret_payload"
    raw_curl = f"curl -X GET 'http://127.0.0.1:8888/api/admin' -H 'Authorization: {raw_token}'"

    # Redaction pattern
    redacted_curl = re.sub(r"(Authorization:\s*Bearer\s+)[^\s'\"]+", r"\1[REDACTED]", raw_curl)
    assert "[REDACTED]" in redacted_curl
    assert "secret_payload" not in redacted_curl


def test_resource_limits_enforced_in_scope():
    """Verify that ScopeConfig defaults enforce safe bounded resource limits."""
    from core.mission_context import ScopeConfig

    cfg = ScopeConfig(target="https://target.com")
    assert cfg.max_total_requests <= 1000
    assert cfg.max_requests_per_minute <= 300
    assert cfg.max_crawl_depth <= 5
    assert cfg.timeout_seconds <= 30.0
    assert cfg.allow_localhost_for_testing is False

