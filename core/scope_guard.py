from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from urllib.parse import urlparse
from typing import Tuple, Optional

from core.mission_context import ScopeConfig


class ScopeViolationError(Exception):
    """Raised when ScopeGuard triggers a critical halt or kill-switch."""
    pass


class ScopeGuard:
    """
    Cross-cutting ethical and security boundary enforcement layer.
    Every single HTTP request must pass through ScopeGuard before execution.
    """

    BLOCKED_PAYLOAD_KEYWORDS = [
        "benchmark(", "sleep(20", "pg_sleep(20", "shutdown", "drop database",
        "drop table", "truncate", "rm -rf", "format c:", "mkfs"
    ]

    CLOUD_METADATA_IPS = ["169.254.169.254", "metadata.google.internal", "169.254.169.123"]

    def __init__(self, config: ScopeConfig):
        self.config = config
        self.consecutive_blocks = 0
        self.max_consecutive_blocks = 10
        self.total_requests = 0
        self.total_blocks = 0
        self.lock = asyncio.Lock()
        self.request_timestamps: list[float] = []

    def is_private_ip(self, hostname: str) -> bool:
        """Check if hostname resolves to a private/loopback IP address."""
        if hostname.lower() in ["localhost", "127.0.0.1", "::1", "0.0.0.0"]:
            return True
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError:
            return False

    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate whether a target URL complies with ethical boundaries."""
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Malformed URL: {e}"

        if not parsed.scheme or parsed.scheme not in ["http", "https"]:
            return False, f"Invalid scheme: {parsed.scheme}"

        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname"

        # Check Cloud Metadata protection
        if hostname.lower() in self.CLOUD_METADATA_IPS or "metadata" in hostname.lower():
            return False, f"Hard blocked cloud metadata target: {hostname}"

        # Private IP protection
        if self.is_private_ip(hostname):
            if not self.config.allow_localhost_for_testing:
                return False, f"Private / Localhost IP address blocked by default: {hostname}"

        # Allowed host matching
        if self.config.allowed_hosts:
            host_match = False
            for allowed in self.config.allowed_hosts:
                if allowed.startswith("*."):
                    domain_suffix = allowed[2:]
                    if hostname == domain_suffix or hostname.endswith("." + domain_suffix):
                        host_match = True
                        break
                elif hostname.lower() == allowed.lower():
                    host_match = True
                    break
            if not host_match:
                return False, f"Host '{hostname}' is not in allowed_hosts {self.config.allowed_hosts}"

        # Allowed paths matching
        path = parsed.path or "/"
        if self.config.allowed_paths:
            path_match = False
            for pattern in self.config.allowed_paths:
                if pattern == "/*" or pattern == "*":
                    path_match = True
                    break
                if pattern.endswith("/*"):
                    prefix = pattern[:-2]
                    # Ensure prefix boundary match: /api/* matches /api/v1 but not /api-secret/
                    if path == prefix or path.startswith(prefix + "/"):
                        path_match = True
                        break
                elif pattern.endswith("*"):
                    prefix = pattern[:-1]
                    if path.startswith(prefix):
                        path_match = True
                        break
                else:
                    if path == pattern or path.rstrip("/") == pattern.rstrip("/"):
                        path_match = True
                        break
            if not path_match:
                return False, f"Path '{path}' is not covered by allowed_paths {self.config.allowed_paths}"

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

            # 4. Token-bucket rate limiting
            now = time.time()
            # Retain only timestamps from the last 60 seconds
            self.request_timestamps = [ts for ts in self.request_timestamps if now - ts < 60.0]
            if len(self.request_timestamps) >= self.config.max_requests_per_minute:
                sleep_needed = 60.0 - (now - self.request_timestamps[0]) + 0.05
                if sleep_needed > 0:
                    await asyncio.sleep(sleep_needed)

            self.request_timestamps.append(time.time())
            self.total_requests += 1
            return True, None
