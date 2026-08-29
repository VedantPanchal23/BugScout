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
