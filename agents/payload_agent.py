from __future__ import annotations

import os
import time
import uuid
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx

from agents.base_agent import BaseAgent
from core.mission_context import Hypothesis, TestResult, VulnClass


class PayloadAgent(BaseAgent):
    """
    PayloadAgent crafts and safely fires contextual test payloads:
    - Loads curated non-destructive probe payloads
    - Contextually mutates parameters across query strings, form fields, and headers
    - Strictly routes all requests through ScopeGuard validation and rate limiting
    - Records comprehensive response metrics (status, body snippet, response time)
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.payloads: Dict[str, List[str]] = self._load_payload_dictionaries()

    def _load_payload_dictionaries(self) -> Dict[str, List[str]]:
        payload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "payloads")
        dict_map = {
            "sqli": "sqli.txt",
            "xss": "xss.txt",
            "idor": "idor.txt",
            "ssrf": "ssrf.txt",
            "auth": "auth.txt",
            "misconfig": "misconfig.txt",
        }
        loaded = {}
        for key, fname in dict_map.items():
            fpath = os.path.join(payload_dir, fname)
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    loaded[key] = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            else:
                loaded[key] = []
        return loaded

    async def run(self) -> None:
        self.log(f"Beginning safe payload testing for {len(self.context.hypothesis_queue)} hypotheses...")
        async with httpx.AsyncClient(
            timeout=self.context.scope.timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "BugScout-Autonomous-Agent/1.0 (Ethical Security Scout)"}
        ) as client:
            for hypothesis in self.context.hypothesis_queue:
                await self._test_hypothesis(client, hypothesis)

        self.context.stats.total_tests_executed = len(self.context.test_results)
        self.log(f"Payload testing completed. Executed {len(self.context.test_results)} test probes.")

    async def _test_hypothesis(self, client: httpx.AsyncClient, h: Hypothesis) -> None:
        payload_list = self._select_payloads_for_hypothesis(h)

        for payload in payload_list:
            req_url, req_method, req_headers, req_body = self._build_request(h, payload)

            # ScopeGuard validation & rate limiter
            allowed, block_reason = await self.scope_guard.acquire_permission(
                req_url, payload, test_type=h.vuln_class.value
            )
            if not allowed:
                self.log(f"ScopeGuard intercepted request to {req_url}: {block_reason}", level="WARNING")
                self.context.stats.blocked_requests_count += 1
                continue

            try:
                start_time = time.time()
                if req_method.upper() == "GET":
                    resp = await client.get(req_url, headers=req_headers)
                elif req_method.upper() == "POST":
                    resp = await client.post(req_url, headers=req_headers, json=req_body if isinstance(req_body, dict) else None, data=req_body if isinstance(req_body, str) else None)
                elif req_method.upper() == "PUT":
                    resp = await client.put(req_url, headers=req_headers, json=req_body if isinstance(req_body, dict) else None)
                elif req_method.upper() == "DELETE":
                    resp = await client.delete(req_url, headers=req_headers)
                else:
                    resp = await client.request(req_method, req_url, headers=req_headers)

                elapsed_ms = (time.time() - start_time) * 1000
                self.context.stats.total_requests_sent += 1

                test_result = TestResult(
                    id=str(uuid.uuid4())[:8],
                    hypothesis_id=h.id,
                    endpoint_id=h.endpoint_id,
                    url=req_url,
                    method=req_method,
                    param_tested=h.target_param,
                    payload_sent=payload,
                    request_headers=req_headers,
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body_snippet=resp.text[:1000],
                    response_time_ms=elapsed_ms,
                )
                self.context.test_results.append(test_result)

            except Exception as e:
                self.log(f"Network error probing {req_url}: {e}", level="DEBUG")

    def _select_payloads_for_hypothesis(self, h: Hypothesis) -> List[str]:
        if h.vuln_class == VulnClass.SQLI:
            return self.payloads.get("sqli", ["'", "1' OR '1'='1", "1' AND 1=1 --"])[:5]
        elif h.vuln_class == VulnClass.XSS:
            return self.payloads.get("xss", ["<scout_xss_marker_1>", "\"><scout_xss_marker_2>"])[:4]
        elif h.vuln_class == VulnClass.IDOR:
            return self.payloads.get("idor", ["1", "2", "0", "admin", "99999"])[:4]
        elif h.vuln_class == VulnClass.SSRF:
            return self.payloads.get("ssrf", ["http://127.0.0.1:80/", "http://example.com/canary_probe"])[:2]
        elif h.vuln_class == VulnClass.BROKEN_AUTH:
            return self.payloads.get("auth", ["Bearer null", "admin", "role=admin"])[:3]
        elif h.vuln_class in [VulnClass.MISCONFIG, VulnClass.SENSITIVE_DATA]:
            return [""]
        return ["test_probe"]

    def _build_request(self, h: Hypothesis, payload: str) -> tuple[str, str, dict, Any]:
        url = h.url
        method = h.method.upper()
        headers = {}
        body = None

        if h.target_param:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            if method == "GET":
                qs[h.target_param] = [payload]
                new_query = urlencode(qs, doseq=True)
                new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                return new_url, method, headers, body
            else:
                body = {h.target_param: payload}
                headers["Content-Type"] = "application/json"
                return url, method, headers, body

        # If no target param, e.g. path misconfig or auth probe
        if h.vuln_class == VulnClass.BROKEN_AUTH:
            if "Bearer" in payload:
                headers["Authorization"] = payload
            elif "=" in payload:
                # Add query or body param
                k, v = payload.split("=", 1)
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[k] = [v]
                new_query = urlencode(qs, doseq=True)
                url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        return url, method, headers, body
