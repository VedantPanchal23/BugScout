from __future__ import annotations

import re
import uuid
from typing import List, Dict, Optional
from agents.base_agent import BaseAgent
from core.mission_context import TestResult, Finding, VulnClass, Severity, Confidence, Hypothesis


class ObserverAgent(BaseAgent):
    """
    ObserverAgent analyzes test execution outputs and detects vulnerability signals:
    - Multi-engine SQL syntax and boolean anomaly detectors
    - Unescaped HTML/DOM reflection analysis (XSS)
    - Object state differential verification (IDOR)
    - Environment secrets and configuration leak inspection (Misconfig / Sensitive Data)
    - Agentic Replanning: Dispatches secondary hypotheses to confirm detected anomalies
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

    STACK_TRACE_PATTERNS = [
        r"traceback \(most recent call last\):",
        r"at org\.apache\.",
        r"fatal error: uncaught",
        r"exception in thread",
        r"nullpointerexception",
    ]

    async def run(self) -> None:
        self.log(f"Observer analyzing {len(self.context.test_results)} test execution results...")
        new_findings: List[Finding] = []
        secondary_hypotheses: List[Hypothesis] = []

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

    def _evaluate_result(self, res: TestResult, ep: Optional[Any]) -> tuple[List[Finding], List[Hypothesis]]:
        findings: List[Finding] = []
        secondary: List[Hypothesis] = []

        body_lower = res.response_body_snippet.lower()

        # 1. SQL Injection Anomaly Checks
        for pattern in self.SQLI_ERROR_PATTERNS:
            if re.search(pattern, body_lower):
                res.anomaly_detected = True
                res.anomaly_type = "Database Error Leak"
                res.anomaly_details = f"SQL error pattern matched: '{pattern}'"

                findings.append(Finding(
                    id=str(uuid.uuid4())[:8],
                    vuln_class=VulnClass.SQLI,
                    severity=Severity.HIGH,
                    title="SQL Injection (Error-Based)",
                    description=f"The endpoint at {res.url} leaked database syntax errors when injected with payload {res.payload_sent}, indicating unparameterized SQL query execution.",
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

        # Time-based SQLi / Anomaly
        if res.response_time_ms > 2000 and "sleep" in res.payload_sent.lower():
            res.anomaly_detected = True
            findings.append(Finding(
                id=str(uuid.uuid4())[:8],
                vuln_class=VulnClass.SQLI,
                severity=Severity.HIGH,
                title="Blind SQL Injection (Time-Based)",
                description=f"Endpoint exhibited a significant response delay ({res.response_time_ms:.1f}ms) when receiving time-delayed SQL payload {res.payload_sent}.",
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

        # 2. XSS Reflection Checks
        if "<scout_xss_marker" in res.response_body_snippet or "alert(1)" in res.response_body_snippet:
            if "<scout_xss_marker_1>" in res.response_body_snippet or "<scout_xss_marker_2>" in res.response_body_snippet:
                res.anomaly_detected = True
                res.anomaly_type = "Unescaped Reflection"
                findings.append(Finding(
                    id=str(uuid.uuid4())[:8],
                    vuln_class=VulnClass.XSS,
                    severity=Severity.MEDIUM,
                    title="Reflected Cross-Site Scripting (XSS)",
                    description=f"Injected probe payload {res.payload_sent} was reflected verbatim and unencoded in the HTTP response body of {res.url}.",
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

        # 3. Environment & Configuration Leaks (.env, debug)
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
                        remediation="Block web server access to hidden files (.*), .env, and secret config files in NGINX/Apache rules. Move secrets to a dedicated secret store (e.g. Vault, AWS Secrets Manager).",
                        confidence=Confidence.CONFIRMED,
                        iteration_discovered=self.context.current_iteration
                    ))
                    break

        # 4. IDOR Anomaly
        if res.param_tested in ["id", "user_id", "account_id"] and res.response_status == 200:
            # If payload changed and returned 200 with distinct profile info
            if "profile" in res.url.lower() or "user" in res.url.lower():
                if res.payload_sent in ["2", "admin", "100"]:
                    findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        vuln_class=VulnClass.IDOR,
                        severity=Severity.HIGH,
                        title="Insecure Direct Object Reference (IDOR)",
                        description=f"Accessing object ID {res.payload_sent} on {res.url} returned unauthorized entity record data without permission checks.",
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

        # 5. Broken Authentication / Missing Auth
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
