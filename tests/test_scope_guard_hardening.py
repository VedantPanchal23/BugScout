import pytest
from core.mission_context import ScopeConfig
from core.scope_guard import ScopeGuard


def test_scope_guard_obfuscation_and_normalization():
    config = ScopeConfig(
        target="https://example.com",
        allowed_hosts=["example.com"],
        allowed_paths=["/api/*", "/login"]
    )
    guard = ScopeGuard(config)

    # Null-byte injection removal
    valid, _ = guard.validate_url("https://example.com/api/users%00.html")
    assert valid is True

    # Double URL encoding resolution (%252e%252e = ..)
    valid, reason = guard.validate_url("https://example.com/api/%252e%252e/admin")
    assert valid is False
    assert "not covered by allowed_paths" in reason

    # Obfuscated integer IP (2130706433 = 127.0.0.1)
    is_priv = guard.is_private_or_restricted_ip("2130706433")
    assert is_priv is True


def test_scope_guard_adversarial_ip_representations():
    """Adversarial testing across decimal, hex, octal, IPv6, and trailing-dot representations."""
    config = ScopeConfig(
        target="https://safe.local",
        allowed_hosts=["safe.local"],
        allow_localhost_for_testing=False
    )
    guard = ScopeGuard(config)

    blocked_vectors = [
        # IPv4
        "127.0.0.1", "127.1", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
        # IPv6
        "::1", "fc00::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:192.168.1.1",
        # Obfuscated representations
        "2130706433", "0x7f000001", "0177.0.0.1", "127.0.0.1.", "169.254.169.254."
    ]

    for vec in blocked_vectors:
        assert guard.is_private_or_restricted_ip(vec) is True, f"Failed to detect restricted IP: {vec}"


def test_scope_guard_adversarial_url_parser_attacks():
    """Adversarial testing against userinfo tricks, trailing dots, and redirect chains."""
    config = ScopeConfig(
        target="https://safe.local",
        allowed_hosts=["safe.local"],
        allow_localhost_for_testing=False
    )
    guard = ScopeGuard(config)

    # 1. Userinfo trick pointing to 127.0.0.1
    valid, reason = guard.validate_url("http://safe.local@127.0.0.1/api")
    assert valid is False

    # 2. Userinfo trick pointing to external evil domain
    valid, reason = guard.validate_url("http://safe.local@evil.com/api")
    assert valid is False

    # 3. Trailing dot on allowed host
    valid, reason = guard.validate_url("https://safe.local./api/items")
    assert valid is True

    # 4. Redirect escape to private IP
    valid, reason = guard.validate_redirect("https://safe.local/login", "http://127.0.0.1/admin")
    assert valid is False
    assert "Redirect Escape Blocked" in reason

    # 5. Redirect escape to external domain
    valid, reason = guard.validate_redirect("https://safe.local/login", "https://attacker.org/exfil")
    assert valid is False
    assert "Redirect Escape Blocked" in reason

