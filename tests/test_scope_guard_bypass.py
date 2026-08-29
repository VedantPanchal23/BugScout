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
