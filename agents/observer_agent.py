from __future__ import annotations

import re
import uuid
from typing import List, Dict, Optional, Tuple
from agents.base_agent import BaseAgent
from core.mission_context import TestResult, Finding, VulnClass, Severity, Confidence, Hypothesis, Endpoint


class ObserverAgent(BaseAgent):
    """
    ObserverAgent analyzes test execution outputs and detects vulnerability signals across 10+ vulnerability classes:
    - CORS Misconfiguration (Wildcard/Reflected Origin + Credentials)
    - Missing Critical Security Headers & Clickjacking Exposure
    - GraphQL Schema Introspection Leaks
    - Open URL Redirection
    - Path / Directory Traversal File Leaks
    - Multi-Engine SQL Injection Syntax & Timing Anomaly Detectors
    - Unescaped HTML/DOM Reflection Analysis (XSS)
    - Insecure Direct Object Reference (IDOR)
    - Environment Secrets & Configuration Leaks (.env, tokens)
    - Missing Authentication on Privileged Routes
    - Agentic Replanning Feedback Controller
    """

    SQLI_ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"sqlite3\.operationalerror",
        r"pg_query\(\): query failed",
        r"psycopg2\.errors",
        r"ora-00933",
        r"ora-01756",
        r"microsoft ole db provider for sql server",
        r"syntax error.*sql",
        r"driver.*sql",
        r"invalid input syntax for integer",
    ]

    ENV_PATTERNS = [
        r"[A-Z_0-9]+_KEY\s*=",
        r"[A-Z_0-9]+_SECRET\s*=",
        r"DB_PASSWORD\s*=",
        r"DATABASE_URL\s*=",
        r"JWT_SECRET\s*=",
        r"AWS_ACCESS_KEY_ID\s*=",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"root:.*:0:0:",
        r"daemon:.*:1:1:",
        r"\[boot loader\]",
        r"\[fonts\]",
        r"\[extensions\]",
    ]

    async def run(self) -> None:
        self.log(f"Observer analyzing {len(self.context.test_results)} test execution results...")
        new_findings: List[Finding] = []
        secondary_hypotheses: List[Hypothesis] = []

        # 1. Audit Security Headers per Endpoint
        for ep in self.context.endpoint_map.values():
            header_findings = self._evaluate_endpoint_security_headers(ep)
            new_findings.extend(header_findings)

        # 2. Evaluate Test Results
        for result in self.context.test_results:
            endpoint = self.context.endpoint_map.get(result.endpoint_id)
            findings, next_hypotheses = self._evaluate_result(result, endpoint)
            new_findings.extend(findings)
            secondary_hypotheses.extend(next_hypotheses)

        # Deduplicate findings by (vuln_class, affected_endpoint, parameter)
        seen_keys = set()
        for f in new_findings:
            key = (f.vuln_class, f.affected_endpoint, f.parameter)
            if key not in seen_keys:
                seen_keys.add(key)
                self.context.findings.append(f)
                self.log(f"[FINDING CONFIRMED] {f.severity.value}: {f.title} on {f.affected_endpoint}")

        self.context.stats.total_findings_count = len(self.context.findings)

        # Agentic Replanning: Inject secondary hypotheses for iteration 2 if needed
        if secondary_hypotheses and self.context.current_iteration < self.context.max_iterations:
            self.log(f"Agentic Feedback: Queuing {len(secondary_hypotheses)} secondary hypotheses for deep verification.")
            self.context.hypothesis_queue = secondary_hypotheses
            self.context.replanning_triggered = True
        else:
            self.context.replanning_triggered = False

    def _evaluate_endpoint_security_headers(self, ep: Endpoint) -> List[Finding]:
        findings: List[Finding] = []
        if ep.missing_security_headers and "x-frame-options" in ep.missing_security_headers:
            if "html" in (ep.baseline_body_snippet or "").lower() or ep.path in ["/", "/search", "/login"]:
                findings.append(Finding(
                    id=str(uuid.uuid4())[:8],
                    vuln_class=VulnClass.SECURITY_HEADERS,
                    severity=Severity.LOW,
                    title="Missing Clickjacking Defense (X-Frame-Options)",
                    description=f"Endpoint '{ep.url}' does not set the `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` header, allowing the page to be framed by external malicious domains (Clickjacking).",
                    cvss_score=4.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    cwe_id="CWE-1021",
                    affected_endpoint=ep.url,
                    http_method=ep.method,
                    parameter=None,
                    reproduction_curl=f"curl -i '{ep.url}'",
                    reproduction_steps=[
                        f"1. Send an HTTP GET request to '{ep.url}'.",
                        "2. Inspect the HTTP response headers.",
                        "3. Note the complete absence of `X-Frame-Options` and `Content-Security-Policy: frame-ancestors` headers."
                    ],
                    evidence=f"Missing Headers: {', '.join(ep.missing_security_headers)}",
                    remediation="Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`, and set `Content-Security-Policy: frame-ancestors 'self'`; to protect against clickjacking attacks.",
                    confidence=Confidence.CONFIRMED,
                    iteration_discovered=self.context.current_iteration
                ))
        return findings

    def _evaluate_result(self, res: TestResult, ep: Optional[Endpoint]) -> Tuple[List[Finding], List[Hypothesis]]:
        findings: List[Finding] = []
        secondary: List[Hypothesis] = []

        body_lower = res.response_body_snippet.lower()
        headers_lower = {k.lower(): v for k, v in res.response_headers.items()}

        # 1. CORS Misconfiguration Checks
        acao = headers_lower.get("access-control-allow-origin", "")
        acac = headers_lower.get("access-control-allow-credentials", "")
        if acao and ("evil-attacker.com" in acao or acao == "null" or (acao == "*" and acac.lower() == "true") or ("http" in acao and acac.lower() == "true")):
            res.anomaly_detected = True
            findings.append(Finding(
                id=str(uuid.uuid4())[:8],
                vuln_class=VulnClass.CORS_MISCONFIG,
                severity=Severity.HIGH,
                title="CORS Misconfiguration (Arbitrary Origin Allowed)",
                description=f"Endpoint {res.url} reflects untrusted Origin in `Access-Control-Allow-Origin: {acao}` with credentials allowed (`Access-Control-Allow-Credentials: {acac}`), allowing cross-origin credentialed data exfiltration.",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                cwe_id="CWE-346",
                affected_endpoint=res.url,
                http_method=res.method,
                parameter=None,
                reproduction_curl=self._generate_curl(res),
                reproduction_steps=[
                    f"1. Send an HTTP {res.method} request to '{res.url}' with header `Origin: https://evil-attacker.com`.",
                    "2. Observe `Access-Control-Allow-Origin` and credentials reflection in response."
                ],
                evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                remediation="Do not dynamically mirror untrusted Origin headers. Maintain an explicit whitelist of trusted domains and avoid enabling credentials for wildcard/untrusted origins.",
                confidence=Confidence.CONFIRMED,
                iteration_discovered=self.context.current_iteration
            ))

        # 2. GraphQL Schema Introspection
        if "__schema" in res.response_body_snippet and "types" in res.response_body_snippet:
            res.anomaly_detected = True
            findings.append(Finding(
                id=str(uuid.uuid4())[:8],
                vuln_class=VulnClass.GRAPHQL_INTROSPECTION,
                severity=Severity.MEDIUM,
                title="GraphQL Schema Introspection Enabled",
                description=f"GraphQL endpoint at {res.url} permits unrestricted schema introspection queries (`__schema`), disclosing all backend queries, mutations, types, and internal data structures.",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-200",
                affected_endpoint=res.url,
                http_method=res.method,
                parameter=None,
                reproduction_curl=self._generate_curl(res),
                reproduction_steps=[
                    f"1. Send a POST request to '{res.url}' with payload: `{{\"query\": \"{{ __schema {{ types {{ name }} }} }}\"}}`.",
                    "2. Observe complete database schema and type definitions returned in the JSON response."
                ],
                evidence=f"Response snippet:\n{res.response_body_snippet[:250]}",
                remediation="Disable GraphQL introspection in production environments (e.g., set `introspection: false` in Apollo Server, Yoga, or Strawberry GraphQL config).",
                confidence=Confidence.CONFIRMED,
                iteration_discovered=self.context.current_iteration
            ))

        # 3. Open URL Redirection
        if res.response_status in [301, 302, 303, 307, 308]:
            location_header = headers_lower.get("location", "")
            if "scout_redirect_canary" in location_header or "example.com" in location_header:
                res.anomaly_detected = True
                findings.append(Finding(
                    id=str(uuid.uuid4())[:8],
                    vuln_class=VulnClass.OPEN_REDIRECT,
                    severity=Severity.MEDIUM,
                    title="Open URL Redirection",
                    description=f"Parameter `{res.param_tested}` on {res.url} accepted an external destination and redirected the browser to an unvalidated third-party domain via the `Location: {location_header}` header.",
                    cvss_score=6.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    cwe_id="CWE-601",
                    affected_endpoint=res.url,
                    http_method=res.method,
                    parameter=res.param_tested,
                    reproduction_curl=self._generate_curl(res),
                    reproduction_steps=[
                        f"1. Navigate to '{res.url}' with parameter `{res.param_tested}={res.payload_sent}`.",
                        f"2. Observe HTTP {res.response_status} Redirect response pointing to `{location_header}`."
                    ],
                    evidence=f"Status: {res.response_status}\nLocation: {location_header}",
                    remediation="Validate redirect destinations against a strict server-side domain whitelist or use relative paths only.",
                    confidence=Confidence.CONFIRMED,
                    iteration_discovered=self.context.current_iteration
                ))

        # 4. Path / Directory Traversal
        for trav_pat in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(trav_pat, res.response_body_snippet, re.IGNORECASE):
                res.anomaly_detected = True
                findings.append(Finding(
                    id=str(uuid.uuid4())[:8],
                    vuln_class=VulnClass.PATH_TRAVERSAL,
                    severity=Severity.HIGH,
                    title="Path / Directory Traversal (Local File Inclusion)",
                    description=f"Parameter `{res.param_tested}` on {res.url} leaked sensitive local system files when probed with `{res.payload_sent}`.",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-22",
                    affected_endpoint=res.url,
                    http_method=res.method,
                    parameter=res.param_tested,
                    reproduction_curl=self._generate_curl(res),
                    reproduction_steps=[
                        f"1. Request endpoint '{res.url}' with path traversal payload `{res.payload_sent}`.",
                        "2. Observe local system configuration contents returned in response."
                    ],
                    evidence=f"File leak snippet:\n{res.response_body_snippet[:250]}",
                    remediation="Sanitize file input with `os.path.basename` or validate that canonical paths reside strictly within the intended base directory.",
                    confidence=Confidence.CONFIRMED,
                    iteration_discovered=self.context.current_iteration
                ))
                break

        # 5. SQL Injection Anomaly Checks
        for pattern in self.SQLI_ERROR_PATTERNS:
            if re.search(pattern, body_lower):
                res.anomaly_detected = True
                res.anomaly_type = "Database Error Leak"
                findings.append(Finding(
                    id=str(uuid.uuid4())[:8],
                    vuln_class=VulnClass.SQLI,
                    severity=Severity.HIGH,
                    title="SQL Injection (Error-Based)",
                    description=f"The endpoint at {res.url} leaked database syntax errors when injected with payload `{res.payload_sent}`, indicating unparameterized SQL query execution.",
                    cvss_score=8.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-89",
                    affected_endpoint=res.url,
                    http_method=res.method,
                    parameter=res.param_tested,
                    reproduction_curl=self._generate_curl(res),
                    reproduction_steps=[
                        f"1. Send an HTTP {res.method} request to '{res.url}'.",
                        f"2. Inject SQL probe payload: '{res.payload_sent}' into parameter '{res.param_tested}'.",
                        "3. Observe database error message leaked in the HTTP response body."
                    ],
                    evidence=f"Payload: {res.payload_sent}\nResponse (Status {res.response_status}):\n{res.response_body_snippet[:300]}",
                    remediation="Use parameterized queries / prepared statements (e.g. PDO, SQLAlchemy, or parameterized ORM calls). Never concatenate user input directly into SQL strings.",
                    confidence=Confidence.CONFIRMED,
                    iteration_discovered=self.context.current_iteration
                ))
                break

        # Time-based SQLi
        if res.response_time_ms > 2000 and "sleep" in res.payload_sent.lower():
            res.anomaly_detected = True
            findings.append(Finding(
                id=str(uuid.uuid4())[:8],
                vuln_class=VulnClass.SQLI,
                severity=Severity.HIGH,
                title="Blind SQL Injection (Time-Based)",
                description=f"Endpoint exhibited a significant response delay ({res.response_time_ms:.1f}ms) when receiving time-delayed SQL payload `{res.payload_sent}`.",
                cvss_score=8.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-89",
                affected_endpoint=res.url,
                http_method=res.method,
                parameter=res.param_tested,
                reproduction_curl=self._generate_curl(res),
                reproduction_steps=[
                    f"1. Send HTTP {res.method} request to '{res.url}' with payload: '{res.payload_sent}'.",
                    f"2. Note response delay exceeding 2000ms compared to sub-second baseline."
                ],
                evidence=f"Response Time: {res.response_time_ms:.1f}ms (Baseline < 200ms)",
                remediation="Implement parameterized queries and ensure backend queries do not execute user-controlled expressions.",
                confidence=Confidence.LIKELY,
                iteration_discovered=self.context.current_iteration
            ))

        # 6. XSS Reflection Checks
        if "<scout_xss_marker" in res.response_body_snippet or "alert(1)" in res.response_body_snippet:
            if "<scout_xss_marker_1>" in res.response_body_snippet or "<scout_xss_marker_2>" in res.response_body_snippet:
                res.anomaly_detected = True
                findings.append(Finding(
                    id=str(uuid.uuid4())[:8],
                    vuln_class=VulnClass.XSS,
                    severity=Severity.MEDIUM,
                    title="Reflected Cross-Site Scripting (XSS)",
                    description=f"Injected probe payload `{res.payload_sent}` was reflected verbatim and unencoded in the HTTP response body of {res.url}.",
                    cvss_score=6.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    cwe_id="CWE-79",
                    affected_endpoint=res.url,
                    http_method=res.method,
                    parameter=res.param_tested,
                    reproduction_curl=self._generate_curl(res),
                    reproduction_steps=[
                        f"1. Navigate to '{res.url}'.",
                        f"2. Supply payload '{res.payload_sent}' in parameter '{res.param_tested}'.",
                        "3. Inspect rendered HTML source and observe unescaped probe reflection."
                    ],
                    evidence=f"Reflected snippet:\n{res.response_body_snippet[:300]}",
                    remediation="Contextually encode all user-supplied data before rendering in HTML/DOM (e.g. HTML entity encoding, CSP headers).",
                    confidence=Confidence.CONFIRMED,
                    iteration_discovered=self.context.current_iteration
                ))

        # 7. Environment & Configuration Leaks (.env, debug)
        if res.response_status == 200:
            for env_pat in self.ENV_PATTERNS:
                if re.search(env_pat, res.response_body_snippet, re.IGNORECASE):
                    res.anomaly_detected = True
                    findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        vuln_class=VulnClass.SENSITIVE_DATA,
                        severity=Severity.CRITICAL,
                        title="Exposed Environment & Secret Credentials (.env)",
                        description=f"Publicly accessible environment configuration file at {res.url} leaked sensitive secrets, keys, or database credentials.",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe_id="CWE-200",
                        affected_endpoint=res.url,
                        http_method=res.method,
                        parameter=None,
                        reproduction_curl=self._generate_curl(res),
                        reproduction_steps=[
                            f"1. Send a direct HTTP GET request to '{res.url}'.",
                            "2. Observe raw environment variables and secret tokens in response."
                        ],
                        evidence=f"Secret leak evidence snippet:\n{res.response_body_snippet[:250]}",
                        remediation="Block web server access to hidden files (`.*`), `.env`, and secret config files in NGINX/Apache rules. Move secrets to a dedicated secret store (e.g. Vault, AWS Secrets Manager).",
                        confidence=Confidence.CONFIRMED,
                        iteration_discovered=self.context.current_iteration
                    ))
                    break

        # 8. IDOR Anomaly
        if res.param_tested in ["id", "user_id", "account_id"] and res.response_status == 200:
            if "profile" in res.url.lower() or "user" in res.url.lower():
                if res.payload_sent in ["2", "admin", "100"]:
                    findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        vuln_class=VulnClass.IDOR,
                        severity=Severity.HIGH,
                        title="Insecure Direct Object Reference (IDOR)",
                        description=f"Accessing object ID `{res.payload_sent}` on {res.url} returned unauthorized entity record data without permission checks.",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-639",
                        affected_endpoint=res.url,
                        http_method=res.method,
                        parameter=res.param_tested,
                        reproduction_curl=self._generate_curl(res),
                        reproduction_steps=[
                            f"1. Request profile with parameter '{res.param_tested}={res.payload_sent}'.",
                            "2. Verify that data belonging to another user entity is successfully returned."
                        ],
                        evidence=f"Status 200 OK returned with record payload:\n{res.response_body_snippet[:250]}",
                        remediation="Enforce server-side authorization checks verifying that the requesting session owns the requested resource ID.",
                        confidence=Confidence.LIKELY,
                        iteration_discovered=self.context.current_iteration
                    ))

        # 9. Broken Authentication / Missing Auth
        if "admin" in res.url.lower() and res.response_status == 200:
            if not res.request_headers.get("Authorization") or "null" in res.request_headers.get("Authorization", ""):
                findings.append(Finding(
                    id=str(uuid.uuid4())[:8],
                    vuln_class=VulnClass.BROKEN_AUTH,
                    severity=Severity.HIGH,
                    title="Missing Authentication on Privileged Route",
                    description=f"Privileged administrative endpoint {res.url} is accessible without valid authentication credentials.",
                    cvss_score=8.6,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-306",
                    affected_endpoint=res.url,
                    http_method=res.method,
                    parameter=None,
                    reproduction_curl=self._generate_curl(res),
                    reproduction_steps=[
                        f"1. Send an unauthenticated HTTP GET request to '{res.url}'.",
                        "2. Observe 200 OK response granting access to administrative data."
                    ],
                    evidence=f"Status: {res.response_status}\nBody:\n{res.response_body_snippet[:200]}",
                    remediation="Apply authentication middleware to all administrative endpoints and verify role-based permissions server-side.",
                    confidence=Confidence.CONFIRMED,
                    iteration_discovered=self.context.current_iteration
                ))

        return findings, secondary

    def _generate_curl(self, res: TestResult) -> str:
        cmd = f"curl -i -X {res.method} '{res.url}'"
        for k, v in res.request_headers.items():
            cmd += f" -H '{k}: {v}'"
        return cmd
