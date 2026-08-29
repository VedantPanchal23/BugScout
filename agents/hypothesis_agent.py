from __future__ import annotations

import uuid
from typing import List, Dict, Any
from agents.base_agent import BaseAgent
from core.mission_context import Hypothesis, VulnClass, Endpoint


class HypothesisAgent(BaseAgent):
    """
    HypothesisAgent reasons about the attack surface:
    - Analyzes endpoint structures, HTTP methods, and query/body parameter names
    - Correlates with OWASP Top 10 vulnerability risk vectors
    - Computes confidence scores and ranks the test queue
    - Applies LLM/Heuristic intelligence for prioritized execution
    """

    PARAM_CORRELATIONS = {
        "sqli": [
            "id", "user_id", "product_id", "search", "q", "query", "filter", "sort",
            "order", "limit", "category", "author", "keyword", "select"
        ],
        "xss": [
            "search", "q", "query", "name", "title", "comment", "message", "body",
            "text", "feedback", "author", "tag", "username", "keyword", "input"
        ],
        "idor": [
            "id", "user_id", "account_id", "order_id", "profile_id", "item_id",
            "doc_id", "uid", "record", "uuid", "file_id"
        ],
        "ssrf": [
            "url", "redirect", "dest", "destination", "callback", "webhook", "link",
            "src", "target", "feed", "host", "uri", "image_url", "proxy"
        ],
        "auth": [
            "role", "admin", "token", "auth", "is_admin", "api_key", "secret", "permission"
        ]
    }

    async def run(self) -> None:
        self.log("Evaluating discovered endpoints to generate ranked vulnerability hypotheses...")
        new_hypotheses: List[Hypothesis] = []

        for endpoint_id, ep in self.context.endpoint_map.items():
            ep_hypotheses = self._analyze_endpoint(ep)
            new_hypotheses.extend(ep_hypotheses)

        # Sort hypotheses by confidence descending
        new_hypotheses.sort(key=lambda h: h.confidence_score, reverse=True)

        self.context.hypothesis_queue = new_hypotheses
        self.context.stats.total_hypotheses_generated = len(new_hypotheses)
        self.log(f"Generated {len(new_hypotheses)} prioritized vulnerability hypotheses across {len(self.context.endpoint_map)} endpoints.")

    def _analyze_endpoint(self, ep: Endpoint) -> List[Hypothesis]:
        hypotheses: List[Hypothesis] = []
        path_lower = ep.path.lower()
        all_params = list(set(ep.query_params + ep.body_params))

        # 1. Path-based Misconfiguration & Sensitive Data Analysis
        if any(sens in path_lower for sens in [".env", ".git", "debug", "actuator", "phpinfo", "server-status"]):
            hypotheses.append(Hypothesis(
                id=str(uuid.uuid4())[:8],
                endpoint_id=ep.id,
                url=ep.url,
                method=ep.method,
                vuln_class=VulnClass.MISCONFIG,
                confidence_score=0.95,
                rationale=f"Path '{ep.path}' directly resembles a sensitive debug/environment file or misconfiguration target.",
                test_plan="Send non-destructive probe to check for credential leaks, secret tokens, or internal configurations.",
                iteration=self.context.current_iteration
            ))
            hypotheses.append(Hypothesis(
                id=str(uuid.uuid4())[:8],
                endpoint_id=ep.id,
                url=ep.url,
                method=ep.method,
                vuln_class=VulnClass.SENSITIVE_DATA,
                confidence_score=0.90,
                rationale=f"Exposed path '{ep.path}' may leak environment secrets or internal source code.",
                test_plan="Inspect response headers and body content for API keys, passwords, and private tokens.",
                iteration=self.context.current_iteration
            ))

        # 2. Administrative / Auth Routes
        if any(auth_word in path_lower for auth_word in ["/admin", "/dashboard", "/internal", "/manage", "/settings"]):
            hypotheses.append(Hypothesis(
                id=str(uuid.uuid4())[:8],
                endpoint_id=ep.id,
                url=ep.url,
                method=ep.method,
                vuln_class=VulnClass.BROKEN_AUTH,
                confidence_score=0.85,
                rationale=f"Privileged route '{ep.path}' must enforce strict authentication and role authorization checks.",
                test_plan="Send unauthenticated request and test missing/tampered Authorization headers.",
                iteration=self.context.current_iteration
            ))

        # 3. Parameter-based Analysis
        for param in all_params:
            param_lower = param.lower()

            # SQL Injection hypothesis
            if any(sqli_kw == param_lower or sqli_kw in param_lower for sqli_kw in self.PARAM_CORRELATIONS["sqli"]):
                hypotheses.append(Hypothesis(
                    id=str(uuid.uuid4())[:8],
                    endpoint_id=ep.id,
                    url=ep.url,
                    method=ep.method,
                    target_param=param,
                    vuln_class=VulnClass.SQLI,
                    confidence_score=0.88 if param_lower in ["id", "search", "query", "filter"] else 0.75,
                    rationale=f"Parameter '{param}' is frequently passed directly to backend SQL queries.",
                    test_plan="Inject syntax probe markers and safe boolean/timing payloads to detect database anomalies.",
                    iteration=self.context.current_iteration
                ))

            # XSS hypothesis
            if any(xss_kw == param_lower or xss_kw in param_lower for xss_kw in self.PARAM_CORRELATIONS["xss"]):
                hypotheses.append(Hypothesis(
                    id=str(uuid.uuid4())[:8],
                    endpoint_id=ep.id,
                    url=ep.url,
                    method=ep.method,
                    target_param=param,
                    vuln_class=VulnClass.XSS,
                    confidence_score=0.85 if param_lower in ["q", "search", "name", "comment"] else 0.70,
                    rationale=f"Parameter '{param}' commonly reflects user input in the rendering DOM.",
                    test_plan="Inject unique safe canary probe tokens and verify unescaped reflection.",
                    iteration=self.context.current_iteration
                ))

            # IDOR hypothesis
            if any(idor_kw == param_lower or idor_kw in param_lower for idor_kw in self.PARAM_CORRELATIONS["idor"]):
                hypotheses.append(Hypothesis(
                    id=str(uuid.uuid4())[:8],
                    endpoint_id=ep.id,
                    url=ep.url,
                    method=ep.method,
                    target_param=param,
                    vuln_class=VulnClass.IDOR,
                    confidence_score=0.82 if param_lower in ["id", "user_id", "account_id"] else 0.70,
                    rationale=f"Parameter '{param}' acts as a direct object reference key for resource retrieval.",
                    test_plan="Mutate object identifier and compare unauthorized data access against baseline.",
                    iteration=self.context.current_iteration
                ))

            # SSRF hypothesis
            if any(ssrf_kw == param_lower or ssrf_kw in param_lower for ssrf_kw in self.PARAM_CORRELATIONS["ssrf"]):
                hypotheses.append(Hypothesis(
                    id=str(uuid.uuid4())[:8],
                    endpoint_id=ep.id,
                    url=ep.url,
                    method=ep.method,
                    target_param=param,
                    vuln_class=VulnClass.SSRF,
                    confidence_score=0.86,
                    rationale=f"Parameter '{param}' appears to accept URLs or server endpoints.",
                    test_plan="Test safe canary loopback probe to detect unvalidated backend HTTP fetch.",
                    iteration=self.context.current_iteration
                ))

            # Broken Auth hypothesis
            if any(auth_kw == param_lower or auth_kw in param_lower for auth_kw in self.PARAM_CORRELATIONS["auth"]):
                hypotheses.append(Hypothesis(
                    id=str(uuid.uuid4())[:8],
                    endpoint_id=ep.id,
                    url=ep.url,
                    method=ep.method,
                    target_param=param,
                    vuln_class=VulnClass.BROKEN_AUTH,
                    confidence_score=0.80,
                    rationale=f"Parameter '{param}' controls role or permission level.",
                    test_plan="Tamper with parameter to test privilege escalation without valid administrative session.",
                    iteration=self.context.current_iteration
                ))

        return hypotheses
