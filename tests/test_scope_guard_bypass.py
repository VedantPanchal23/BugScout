import pytest
from core.scope_guard import ScopeGuard
from core.mission_context import ScopeConfig, MissionContext, Hypothesis, VulnClass
from agents.payload_agent import PayloadAgent


@pytest.mark.asyncio
async def test_scope_guard_structural_bypass_prevention():
    # Configure ScopeGuard with strict allowed host: safe.local
    scope = ScopeConfig(
        target="http://safe.local",
        allowed_hosts=["safe.local"],
        allow_localhost_for_testing=False
    )
    guard = ScopeGuard(scope)

    ctx = MissionContext(target="http://safe.local", scope=scope)
    # Hypothesis targeting an out-of-scope external malicious URL
    malicious_hypo = Hypothesis(
        id="h_evil",
        endpoint_id="ep_evil",
        url="http://evil-attacker.com/steal",
        method="GET",
        target_param="token",
        vuln_class=VulnClass.SQLI,
        rationale="Probe external domain",
        test_plan="Test external probe"
    )
    ctx.hypothesis_queue = [malicious_hypo]

    agent = PayloadAgent("PayloadAgent", ctx, guard, None)
    await agent.run()

    # Assert that no network test results were recorded because ScopeGuard blocked the request
    assert len(ctx.test_results) == 0
    assert ctx.stats.blocked_requests_count > 0


@pytest.mark.asyncio
async def test_malicious_llm_metadata_and_ssrf_bypass_prevention():
    """Verify that malicious/adversarial LLM hypotheses targeting cloud metadata or private LAN are blocked."""
    scope = ScopeConfig(
        target="http://app.corp.internal",
        allowed_hosts=["app.corp.internal"],
        allow_localhost_for_testing=False
    )
    guard = ScopeGuard(scope)
    ctx = MissionContext(target="http://app.corp.internal", scope=scope)

    adversarial_hypotheses = [
        Hypothesis(
            id="h_meta",
            endpoint_id="ep_meta",
            url="http://169.254.169.254/latest/meta-data/iam/security-credentials",
            method="GET",
            target_param=None,
            vuln_class=VulnClass.SENSITIVE_DATA,
            rationale="Extract AWS metadata credentials",
            test_plan="Probe metadata endpoint"
        ),
        Hypothesis(
            id="h_lan",
            endpoint_id="ep_lan",
            url="http://192.168.1.1/admin/network_settings",
            method="GET",
            target_param="cmd",
            vuln_class=VulnClass.BROKEN_AUTH,
            rationale="Extract internal router config",
            test_plan="Probe internal gateway"
        ),
        Hypothesis(
            id="h_destruct",
            endpoint_id="ep_destruct",
            url="http://app.corp.internal/api/delete",
            method="POST",
            target_param="id",
            vuln_class=VulnClass.SQLI,
            rationale="Execute destructive DROP TABLE command",
            test_plan="DROP TABLE users; --"
        )
    ]
    ctx.hypothesis_queue = adversarial_hypotheses

    agent = PayloadAgent("PayloadAgent", ctx, guard, None)
    await agent.run()

    # Assert that 100% of adversarial requests were blocked and 0 outbound tests executed
    assert len(ctx.test_results) == 0
    assert ctx.stats.total_requests_sent == 0
    assert ctx.stats.blocked_requests_count >= 3

