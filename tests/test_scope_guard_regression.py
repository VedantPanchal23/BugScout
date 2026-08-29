import pytest
import os
from core.mission_context import ScopeConfig, MissionContext, Hypothesis, VulnClass
from core.scope_guard import ScopeGuard
from agents.payload_agent import PayloadAgent


@pytest.mark.asyncio
async def test_consolidated_scope_guard_network_boundary_invariant(monkeypatch):
    """
    Consolidated Security Boundary Invariant:
    Verifies that no out-of-scope target, private subnet, cloud metadata IP,
    obfuscated IP, userinfo trick, redirect escape, or malicious LLM hypothesis
    can reach the network dispatcher under any environment configuration (including HTTP_PROXY).
    """
    monkeypatch.setenv("HTTP_PROXY", "http://malicious-proxy.attacker.com:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://malicious-proxy.attacker.com:8080")
    monkeypatch.setenv("ALL_PROXY", "socks5://malicious-proxy.attacker.com:1080")

    scope = ScopeConfig(
        target="https://target.corp.internal",
        allowed_hosts=["target.corp.internal"],
        allow_localhost_for_testing=False
    )
    guard = ScopeGuard(scope)
    ctx = MissionContext(target="https://target.corp.internal", scope=scope)

    adversarial_targets = [
        "http://127.0.0.1/admin",
        "http://127.1/debug",
        "http://10.0.0.1/internal",
        "http://172.16.0.1/status",
        "http://192.168.1.1/gateway",
        "http://169.254.169.254/latest/meta-data",
        "http://2130706433/api",
        "http://0x7f000001/api",
        "http://0177.0.0.1/api",
        "http://[::1]/api",
        "http://[::ffff:127.0.0.1]/api",
        "http://[::ffff:192.168.1.1]/api",
        "http://target.corp.internal@127.0.0.1/api",
        "http://target.corp.internal@attacker.org/exfil",
        "http://external-c2.darkweb.onion/leak"
    ]

    hypotheses = [
        Hypothesis(
            id=f"h_{idx}",
            endpoint_id=f"ep_{idx}",
            url=target_url,
            method="GET",
            target_param="q",
            vuln_class=VulnClass.SQLI,
            rationale="Adversarial probe injection",
            test_plan="Test payload"
        )
        for idx, target_url in enumerate(adversarial_targets)
    ]
    ctx.hypothesis_queue = hypotheses

    agent = PayloadAgent("PayloadAgent", ctx, guard, None)
    with pytest.raises(Exception) as exc_info:
        await agent.run()

    assert "ScopeViolationError" in type(exc_info.value).__name__ or "Kill-Switch" in str(exc_info.value)

    # 3. Prove all 15 adversarial URLs are blocked by ScopeGuard URL validation
    for target_url in adversarial_targets:
        valid, reason = guard.validate_url(target_url)
        assert valid is False, f"Expected ScopeGuard to block {target_url}, but got valid=True"

    # 4. Critical Invariants: Zero network calls dispatched, zero test results recorded
    assert len(ctx.test_results) == 0, "No test results should be recorded for out-of-scope targets"
    assert ctx.stats.total_requests_sent == 0, "Zero HTTP requests must be sent across network"
    assert ctx.stats.blocked_requests_count > 0, "Blocked requests must be incremented before kill-switch halt"

    # 5. Validate Redirect Interception
    valid_priv_redir, redir_reason = guard.validate_redirect("https://target.corp.internal/login", "http://127.0.0.1/admin")
    assert valid_priv_redir is False
    assert "Redirect Escape Blocked" in redir_reason

    valid_ext_redir, ext_reason = guard.validate_redirect("https://target.corp.internal/login", "https://attacker.org/steal")
    assert valid_ext_redir is False
    assert "Redirect Escape Blocked" in ext_reason
