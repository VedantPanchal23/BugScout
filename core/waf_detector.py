from __future__ import annotations

import random
import logging
from typing import Dict, Optional, Tuple, List
from core.mission_context import WAFInfo

logger = logging.getLogger("BugScout.WAFDetector")


class WAFDetector:
    """
    WAF Detection & Adaptive Politeness Engine:
    - Fingerprints major Web Application Firewalls (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity)
    - Detects active throttling / 429 Too Many Requests / Captcha challenges
    - Dynamically computes adaptive backoff and jitter to evade rate limit blocks
    """

    WAF_SIGNATURES = {
        "Cloudflare": [
            ("header", "cf-ray"),
            ("header", "cf-cache-status"),
            ("header_val", "server", "cloudflare"),
            ("body", "cloudflare-nginx"),
            ("body", "ray id:"),
        ],
        "AWS WAF": [
            ("header", "x-amzn-requestid"),
            ("header", "x-amz-cf-id"),
            ("header_val", "server", "awselb"),
            ("body", "aws-waf"),
        ],
        "Akamai": [
            ("header", "x-akamai-transformed"),
            ("header_val", "server", "akamaighost"),
            ("body", "akamaighost"),
        ],
        "Imperva Incapsula": [
            ("header", "x-iinfo"),
            ("header", "x-cdn"),
            ("body", "_incapsula_resource"),
        ],
        "ModSecurity / OWASP CRS": [
            ("header_val", "server", "mod_security"),
            ("body", "mod_security"),
            ("body", "owasp_crs"),
        ]
    }

    def __init__(self, waf_info: WAFInfo):
        self.waf_info = waf_info
        self.throttle_count = 0

    def analyze_response(self, headers: Dict[str, str], status_code: int, body_snippet: str) -> Tuple[Optional[str], float]:
        """Analyze headers and body to fingerprint active WAF."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body_snippet.lower()

        matched_waf = None
        matched_sigs: List[str] = []

        for waf_name, rules in self.WAF_SIGNATURES.items():
            for rule_type, *args in rules:
                if rule_type == "header":
                    h_name = args[0]
                    if h_name in headers_lower:
                        matched_sigs.append(f"Header: {h_name}")
                        matched_waf = waf_name
                elif rule_type == "header_val":
                    h_name, h_val = args[0], args[1]
                    if h_name in headers_lower and h_val in headers_lower[h_name]:
                        matched_sigs.append(f"Header {h_name}={h_val}")
                        matched_waf = waf_name
                elif rule_type == "body":
                    pattern = args[0]
                    if pattern in body_lower:
                        matched_sigs.append(f"Body: {pattern}")
                        matched_waf = waf_name

        if matched_waf:
            self.waf_info.detected_waf = matched_waf
            self.waf_info.confidence = min(1.0, 0.5 + (0.25 * len(matched_sigs)))
            self.waf_info.signatures_matched = list(set(self.waf_info.signatures_matched + matched_sigs))
            logger.info(f"WAF Detected: [{matched_waf}] (Confidence: {self.waf_info.confidence:.2f})")

        # Adaptive backoff calculation
        adaptive_delay = self._check_throttle(status_code, body_lower)
        return self.waf_info.detected_waf, adaptive_delay

    def _check_throttle(self, status_code: int, body_lower: str) -> float:
        """Check for rate limiting or captcha triggers and calculate backoff delay."""
        if status_code in [429, 503] or ("captcha" in body_lower and status_code == 403):
            self.throttle_count += 1
            self.waf_info.polite_mode_active = True
            # Exponential backoff with random jitter: 1.0s, 2.0s, 4.0s...
            base_delay = min(5.0, 1.0 * (1.5 ** (self.throttle_count - 1)))
            jitter = random.uniform(0.1, 0.5)
            total_delay = base_delay + jitter
            self.waf_info.adaptive_delay_seconds = total_delay
            logger.warning(f"Rate limit / WAF throttle signal detected (HTTP {status_code})! Activating Polite Mode with {total_delay:.2f}s delay.")
            return total_delay

        if self.throttle_count > 0 and status_code == 200:
            # Gradually reduce throttle
            self.throttle_count = max(0, self.throttle_count - 1)
            if self.throttle_count == 0:
                self.waf_info.polite_mode_active = False
                self.waf_info.adaptive_delay_seconds = 0.0

        return 0.0
