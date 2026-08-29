import pytest
import httpx
from unittest.mock import patch
from core.scope_guard import ScopeGuard
from core.mission_context import ScopeConfig, MissionContext, Endpoint, Hypothesis, VulnClass, Severity
from core.llm import HeuristicSecurityEngine
from agents.payload_agent import PayloadAgent
from agents.recon_agent import ReconAgent


@pytest.mark.asyncio
async def test_transport_blocks_private_ipv4_zero_network_traffic():
    scope = ScopeConfig(target="http://example.com", allowed_hosts=["example.com"], allow_localhost_for_testing=False)
    guard = ScopeGuard(scope)

    assert not guard.validate_url("http://10.0.0.1/admin")[0]
    assert not guard.validate_url("http://172.16.0.1/api")[0]
    assert not guard.validate_url("http://192.168.1.1/console")[0]

    context = MissionContext(target="http://example.com", scope=scope)
    context.hypothesis_queue = [
        Hypothesis(
            id="hyp_private",
            endpoint_id="ep_private",
            url="http://10.0.0.1/admin",
            method="GET",
            vuln_class=VulnClass.MISCONFIG,
            confidence_score=0.9,
            rationale="test",
            test_plan="test"
        )
    ]
    agent = PayloadAgent("PayloadAgent", context, guard, HeuristicSecurityEngine())
    with patch.object(httpx.AsyncClient, "request", side_effect=AssertionError("Network request must not be dispatched")):
        await agent.run()

    assert context.stats.total_requests_sent == 0


@pytest.mark.asyncio
async def test_transport_blocks_ipv6_loopback_and_link_local():
    scope = ScopeConfig(target="http://example.com", allowed_hosts=["example.com"], allow_localhost_for_testing=False)
    guard = ScopeGuard(scope)

    assert not guard.validate_url("http://[::1]:8080/debug")[0]
    assert not guard.validate_url("http://[fe80::1]/api")[0]
    assert not guard.validate_url("http://[fc00::1]/internal")[0]
    assert not guard.validate_url("http://[::ffff:127.0.0.1]/status")[0]


@pytest.mark.asyncio
async def test_transport_blocks_cloud_metadata():
    scope = ScopeConfig(target="http://example.com", allowed_hosts=["example.com"])
    guard = ScopeGuard(scope)

    assert not guard.validate_url("http://169.254.169.254/latest/meta-data")[0]
    assert not guard.validate_url("http://metadata.google.internal/computeMetadata/v1/")[0]


@pytest.mark.asyncio
async def test_transport_blocks_decimal_hex_octal_obfuscations():
    scope = ScopeConfig(target="http://example.com", allowed_hosts=["example.com"], allow_localhost_for_testing=False)
    guard = ScopeGuard(scope)

    assert not guard.validate_url("http://2130706433/admin")[0]
    assert not guard.validate_url("http://0x7f000001/api")[0]
    assert not guard.validate_url("http://0177.0.0.1/internal")[0]


@pytest.mark.asyncio
async def test_transport_blocks_userinfo_and_trailing_dots():
    scope = ScopeConfig(target="http://example.com", allowed_hosts=["example.com"], allow_localhost_for_testing=False)
    guard = ScopeGuard(scope)

    assert not guard.validate_url("http://example.com@127.0.0.1/api")[0]
    assert not guard.validate_url("http://user:pass@10.0.0.1/console")[0]
    # Unauthorized trailing-dot host is blocked
    assert not guard.validate_url("http://evil.com.:8080/api")[0]
    # Authorized host with trailing dot is normalized safely
    assert guard.validate_url("http://example.com.:8080/api")[0]


@pytest.mark.asyncio
async def test_transport_blocks_mixed_dns_records():
    scope = ScopeConfig(target="http://example.com", allowed_hosts=["example.com"])
    guard = ScopeGuard(scope)

    mixed_addrinfo = [
        (2, 1, 6, "", ("93.184.216.34", 80)),
        (2, 1, 6, "", ("10.0.0.1", 80))
    ]
    with patch("socket.getaddrinfo", return_value=mixed_addrinfo):
        assert not guard.resolve_and_verify_ip("rebind.attacker.local")[0]


@pytest.mark.asyncio
async def test_transport_blocks_redirect_to_private_and_cross_domain():
    scope = ScopeConfig(target="http://example.com", allowed_hosts=["example.com"], allow_localhost_for_testing=False)
    guard = ScopeGuard(scope)

    assert not guard.validate_redirect("http://example.com/login", "http://127.0.0.1/admin")[0]
    assert not guard.validate_redirect("http://example.com/login", "http://169.254.169.254/latest/meta-data")[0]
    assert not guard.validate_redirect("http://example.com/login", "https://evil-attacker.com/steal")[0]

    assert guard.validate_redirect("http://example.com/login", "/dashboard")[0]
    assert guard.validate_redirect("http://example.com/login", "http://example.com/dashboard")[0]


@pytest.mark.asyncio
async def test_transport_ignores_proxy_environment_variables(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://attacker-proxy.local:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker-proxy.local:8080")
    monkeypatch.setenv("ALL_PROXY", "socks5://attacker-proxy.local:1080")

    scope = ScopeConfig(target="http://127.0.0.1:8888", allow_localhost_for_testing=True)
    guard = ScopeGuard(scope)
    context = MissionContext(target="http://127.0.0.1:8888", scope=scope)

    agent = PayloadAgent("PayloadAgent", context, guard, HeuristicSecurityEngine())
    client = agent._create_client()

    assert not client.trust_env
    assert not client.follow_redirects


@pytest.mark.asyncio
async def test_transport_rejects_destructive_payloads_before_dispatch():
    scope = ScopeConfig(target="http://127.0.0.1:8888", allow_localhost_for_testing=True)
    guard = ScopeGuard(scope)

    assert not guard.validate_payload("'; DROP TABLE users; --")[0]
    assert not guard.validate_payload("; rm -rf / ;")[0]
    assert not guard.validate_payload("&& mkfs.ext4 /dev/sda")[0]
    assert guard.validate_payload("' OR '1'='1")[0]
