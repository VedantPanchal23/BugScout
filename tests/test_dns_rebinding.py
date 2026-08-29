import pytest
from core.scope_guard import ScopeGuard
from core.mission_context import ScopeConfig


def test_dns_rebinding_defense_detection(monkeypatch):
    config = ScopeConfig(
        target="https://public-service.example.com",
        allowed_hosts=["public-service.example.com"],
        allow_localhost_for_testing=False
    )
    guard = ScopeGuard(config)

    # 1. Normal resolution to public IP -> ALLOWED
    def mock_public_getaddrinfo(host, port):
        return [(2, 1, 0, "", ("93.184.216.34", 80))]

    import socket
    monkeypatch.setattr(socket, "getaddrinfo", mock_public_getaddrinfo)
    valid, reason = guard.resolve_and_verify_ip("public-service.example.com")
    assert valid is True

    # 2. DNS Rebinding Attack: domain suddenly resolves to AWS cloud metadata (169.254.169.254) -> BLOCKED
    def mock_rebound_metadata_getaddrinfo(host, port):
        return [(2, 1, 0, "", ("169.254.169.254", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_rebound_metadata_getaddrinfo)
    valid, reason = guard.resolve_and_verify_ip("public-service.example.com")
    assert valid is False
    assert "DNS Rebinding Blocked" in reason

    # 3. DNS Rebinding Attack: domain resolves to internal LAN private IP (192.168.1.1) -> BLOCKED
    def mock_rebound_private_getaddrinfo(host, port):
        return [(2, 1, 0, "", ("192.168.1.1", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_rebound_private_getaddrinfo)
    valid, reason = guard.resolve_and_verify_ip("public-service.example.com")
    assert valid is False
    assert "DNS Rebinding Blocked" in reason
