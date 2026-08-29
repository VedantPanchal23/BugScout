from __future__ import annotations

import asyncio
import ipaddress
import posixpath
import re
import time
import unicodedata
from urllib.parse import urlparse, unquote
from typing import Tuple, Optional

from core.mission_context import ScopeConfig


class ScopeViolationError(Exception):
    """Raised when ScopeGuard triggers a critical halt or kill-switch."""
    pass


class ScopeGuard:
    """
    Cross-cutting ethical and security boundary enforcement layer.
    Every single HTTP request must pass through ScopeGuard before execution.
    Hardened against Unicode normalization, null-byte injections, and obfuscated IPs.
    """

    BLOCKED_PAYLOAD_KEYWORDS = [
        "benchmark(", "sleep(20", "pg_sleep(20", "shutdown", "drop database",
        "drop table", "truncate", "rm -rf", "format c:", "mkfs", ":(){ :|:& };:"
    ]

    CLOUD_METADATA_IPS = [
        "169.254.169.254", "metadata.google.internal", "169.254.169.123",
        "metadata.aws.internal", "100.100.100.200"
    ]

    def __init__(self, config: ScopeConfig):
        self.config = config
        self.consecutive_blocks = 0
        self.max_consecutive_blocks = 10
        self.total_requests = 0
        self.total_blocks = 0
        self.lock = asyncio.Lock()
        self.request_timestamps: list[float] = []

    def is_private_or_restricted_ip(self, host: str) -> bool:
        """Check if host resolves to a private, loopback, link-local, or cloud metadata IP."""
        if not host:
            return False

        # Clean host (handle bracketed IPv6 with port like [2001:db8::1]:8080 or IPv4 host:port)
        host_clean = host.strip()
        if host_clean.startswith("["):
            host_clean = host_clean.split("]")[0].strip("[")
        elif host_clean.count(":") == 1:
            host_clean = host_clean.split(":")[0]

        if host_clean.lower() in ["localhost", "127.0.0.1", "::1", "0.0.0.0", "0", "127.1"]:
            return True

        if host_clean.lower() in self.CLOUD_METADATA_IPS or "metadata" in host_clean.lower():
            return True

        # 1. Try standard IP parsing (handles full IPv4 and IPv6 strings correctly)
        try:
            ip = ipaddress.ip_address(host_clean)
            return (
                ip.is_private or
                ip.is_loopback or
                ip.is_link_local
            )
        except ValueError:
            pass

        # 2. Check 32-bit integer IPv4 representations (e.g. 2130706433 for 127.0.0.1)
        if host_clean.isdigit():
            try:
                num = int(host_clean)
                if 0 <= num <= 0xFFFFFFFF:
                    ip = ipaddress.IPv4Address(num)
                    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            except ValueError:
                pass

        # 3. Check hex representations (e.g. 0x7f000001)
        if host_clean.lower().startswith("0x"):
            try:
                num = int(host_clean, 16)
                if 0 <= num <= 0xFFFFFFFF:
                    ip = ipaddress.IPv4Address(num)
                    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            except ValueError:
                pass

        return False

    def resolve_and_verify_ip(self, host: str) -> Tuple[bool, Optional[str]]:
        """
        DNS Rebinding Defense: Resolves domain name to IP and validates against private subnets
        before network connection. Prevents DNS rebinding SSRF escapes.
        """
        import socket
        host_clean = host.strip()
        if host_clean.startswith("["):
            host_clean = host_clean.split("]")[0].strip("[")
        elif host_clean.count(":") == 1:
            host_clean = host_clean.split(":")[0]

        if self.is_private_or_restricted_ip(host_clean):
            if not self.config.allow_localhost_for_testing:
                return False, f"Private / Localhost IP address blocked by default: {host_clean}"
            return True, None

        # Attempt DNS resolution
        try:
            resolved_ips = socket.getaddrinfo(host_clean, None)
            for item in resolved_ips:
                ip_addr = item[4][0]
                if self.is_private_or_restricted_ip(ip_addr):
                    if not self.config.allow_localhost_for_testing:
                        return False, f"DNS Rebinding Blocked: Host '{host_clean}' resolved to private IP {ip_addr}"
        except Exception:
            pass  # Let normal HTTP client handle unresolved hostnames

        return True, None

    def normalize_path(self, raw_path: str) -> str:
        """Normalize URL path with Unicode NFKC, null-byte stripping, and double-decode."""
        if not raw_path:
            return "/"

        # Unicode NFKC normalization & null-byte stripping
        cleaned = unicodedata.normalize("NFKC", raw_path).replace("\x00", "").replace("%00", "")

        # Double URL-decode to catch %252e%252e%252f
        unquoted = unquote(unquote(cleaned))

        # Collapse multiple slashes
        collapsed = re.sub(r"/+", "/", unquoted)
        normalized = posixpath.normpath(collapsed)
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        if unquoted.endswith("/") and not normalized.endswith("/"):
            normalized += "/"
        return normalized

    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate whether a target URL complies with ethical boundaries."""
        try:
            # Unicode normalize the entire URL string
            url = unicodedata.normalize("NFKC", url).replace("\x00", "").replace("%00", "")
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Malformed URL: {e}"

        if not parsed.scheme or parsed.scheme.lower() not in ["http", "https"]:
            return False, f"Invalid scheme: {parsed.scheme}"

        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname in URL"

        # Check Cloud Metadata protection (Absolute Hard Block)
        if hostname.lower() in self.CLOUD_METADATA_IPS or "metadata" in hostname.lower():
            return False, f"Hard blocked cloud metadata target: {hostname}"

        # Private IP protection & Pre-connect DNS Resolution Verification
        valid_ip, ip_reason = self.resolve_and_verify_ip(hostname)
        if not valid_ip:
            return False, ip_reason

        # Allowed host matching (supports subdomains *.domain.com and host:port)
        if self.config.allowed_hosts:
            host_match = False
            for allowed in self.config.allowed_hosts:
                allowed_clean = allowed.split(":")[0].lower()
                current_clean = hostname.lower()

                if allowed_clean.startswith("*."):
                    domain_suffix = allowed_clean[2:]
                    if current_clean == domain_suffix or current_clean.endswith("." + domain_suffix):
                        host_match = True
                        break
                elif current_clean == allowed_clean:
                    host_match = True
                    break
            if not host_match:
                return False, f"Host '{hostname}' is not in allowed_hosts {self.config.allowed_hosts}"

        # Allowed paths matching with path normalization
        normalized_path = self.normalize_path(parsed.path)
        if self.config.allowed_paths:
            path_match = False
            for pattern in self.config.allowed_paths:
                if pattern in ["/*", "*", "/"]:
                    if pattern == "/" and normalized_path != "/":
                        pass
                    else:
                        path_match = True
                        break
                if pattern.endswith("/*"):
                    prefix = pattern[:-2]
                    if normalized_path == prefix or normalized_path.startswith(prefix + "/"):
                        path_match = True
                        break
                elif pattern.endswith("*"):
                    prefix = pattern[:-1]
                    if normalized_path.startswith(prefix):
                        path_match = True
                        break
                else:
                    if normalized_path == pattern or normalized_path.rstrip("/") == pattern.rstrip("/"):
                        path_match = True
                        break
            if not path_match:
                return False, f"Path '{normalized_path}' is not covered by allowed_paths {self.config.allowed_paths}"

        return True, None

    def validate_redirect(self, original_url: str, redirect_target: str) -> Tuple[bool, Optional[str]]:
        """
        Validate whether following an HTTP 301/302/307/308 redirect location
        remains strictly within in-scope boundaries. Blocks cross-domain escapes.
        """
        from urllib.parse import urljoin
        resolved_url = urljoin(original_url, redirect_target)
        valid, reason = self.validate_url(resolved_url)
        if not valid:
            return False, f"Redirect Escape Blocked: Destination '{resolved_url}' violates scope: {reason}"
        return True, None

    def validate_payload(self, payload: str, test_type: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Validate whether a payload or test type is permitted."""
        if test_type and test_type.lower() in [t.lower() for t in self.config.excluded_test_types]:
            return False, f"Test type '{test_type}' is explicitly excluded in scope configuration"

        lower_payload = payload.lower()
        for kw in self.BLOCKED_PAYLOAD_KEYWORDS:
            if kw in lower_payload:
                return False, f"Potentially destructive keyword detected in payload: '{kw}'"

        return True, None

    async def acquire_permission(self, url: str, payload: str = "", test_type: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate request against URL, payload, rate limit, total limits, and consecutive kill-switch.
        Acquires rate limiter slot asynchronously if valid.
        """
        async with self.lock:
            # 1. Total request limit check
            if self.total_requests >= self.config.max_total_requests:
                self.consecutive_blocks += 1
                self.total_blocks += 1
                return False, f"Total maximum requests limit ({self.config.max_total_requests}) reached"

            # 2. URL validation
            valid_url, url_reason = self.validate_url(url)
            if not valid_url:
                self.consecutive_blocks += 1
                self.total_blocks += 1
                if self.consecutive_blocks >= self.max_consecutive_blocks:
                    raise ScopeViolationError(
                        f"ScopeGuard Kill-Switch Activated: {self.consecutive_blocks} consecutive blocked requests! Last error: {url_reason}"
                    )
                return False, f"URL Scope Block: {url_reason}"

            # 3. Payload validation
            valid_payload, payload_reason = self.validate_payload(payload, test_type)
            if not valid_payload:
                self.consecutive_blocks += 1
                self.total_blocks += 1
                if self.consecutive_blocks >= self.max_consecutive_blocks:
                    raise ScopeViolationError(
                        f"ScopeGuard Kill-Switch Activated: {self.consecutive_blocks} consecutive blocked requests! Last error: {payload_reason}"
                    )
                return False, f"Payload Scope Block: {payload_reason}"

            # Passed checks -> Reset consecutive block counter
            self.consecutive_blocks = 0

            # 4. Token-bucket rate limiting (only enforced for remote targets)
            now = time.time()
            self.request_timestamps = [ts for ts in self.request_timestamps if now - ts < 60.0]
            if not self.config.allow_localhost_for_testing and len(self.request_timestamps) >= self.config.max_requests_per_minute:
                sleep_needed = 60.0 - (now - self.request_timestamps[0]) + 0.05
                if sleep_needed > 0:
                    await asyncio.sleep(sleep_needed)

            self.request_timestamps.append(time.time())
            self.total_requests += 1
            return True, None
