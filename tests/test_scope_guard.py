import pytest
from core.mission_context import ScopeConfig
from core.scope_guard import ScopeGuard, ScopeViolationError


def test_scope_guard_allowed_host_and_ports():
    config = ScopeConfig(
        target="https://example.com",
        allowed_hosts=["example.com", "target.com:8443", "*.subdomain.org"],
        allowed_paths=["/api/*", "/login"]
    )
    guard = ScopeGuard(config)

    # Valid host
    valid, reason = guard.validate_url("https://example.com/api/v1/users")
    assert valid is True

    # Valid host with port
    valid, reason = guard.validate_url("https://target.com/login")
    assert valid is True

    # Valid subdomain
    valid, reason = guard.validate_url("https://auth.subdomain.org/api/status")
    assert valid is True

    # Disallowed host
    valid, reason = guard.validate_url("https://attacker.com/api/v1/users")
    assert valid is False
    assert "not in allowed_hosts" in reason


def test_scope_guard_path_normalization_edge_cases():
    config = ScopeConfig(
        target="https://example.com",
        allowed_hosts=["example.com"],
        allowed_paths=["/api/*", "/login"]
    )
    guard = ScopeGuard(config)

    # Normalized path with double slashes
    valid, _ = guard.validate_url("https://example.com//api//users")
    assert valid is True

    # Traversal normalization escaping scope
    valid, reason = guard.validate_url("https://example.com/api/../admin/secret")
    assert valid is False
    assert "not covered by allowed_paths" in reason


def test_scope_guard_private_ip_and_metadata():
    config = ScopeConfig(
        target="https://example.com",
        allowed_hosts=["127.0.0.1", "169.254.169.254", "10.0.0.1"],
        allow_localhost_for_testing=False
    )
    guard = ScopeGuard(config)

    # Localhost blocked by default
    valid, reason = guard.validate_url("http://127.0.0.1/test")
    assert valid is False
    assert "Private / Localhost IP address blocked" in reason

    # Private RFC1918 blocked by default
    valid, reason = guard.validate_url("http://10.0.0.1/api")
    assert valid is False

    # Cloud metadata hard blocked always
    valid, reason = guard.validate_url("http://169.254.169.254/latest/meta-data")
    assert valid is False
    assert "cloud metadata" in reason.lower()


def test_scope_guard_blocked_payloads():
    config = ScopeConfig(
        target="https://example.com",
        allowed_hosts=["example.com"],
        excluded_test_types=["dos", "brute_force"]
    )
    guard = ScopeGuard(config)

    # Excluded test type
    valid, reason = guard.validate_payload("safe_probe", test_type="dos")
    assert valid is False
    assert "excluded in scope" in reason

    # Destructive SQL drop
    valid, reason = guard.validate_payload("1'; DROP TABLE users;--", test_type="sqli")
    assert valid is False
    assert "destructive" in reason.lower() or "keyword detected" in reason.lower()


@pytest.mark.asyncio
async def test_scope_guard_kill_switch():
    config = ScopeConfig(
        target="https://example.com",
        allowed_hosts=["example.com"],
        allowed_paths=["/api/*"]
    )
    guard = ScopeGuard(config)

    # Trigger 9 consecutive blocks
    for _ in range(9):
        valid, _ = await guard.acquire_permission("https://forbidden.com/out-of-scope")
        assert valid is False

    # The 10th consecutive block triggers the hard kill-switch
    with pytest.raises(ScopeViolationError):
        await guard.acquire_permission("https://forbidden.com/out-of-scope")
