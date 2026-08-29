from __future__ import annotations

import json
import time
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Confidence(str, Enum):
    CONFIRMED = "Confirmed"
    LIKELY = "Likely"
    POTENTIAL = "Potential"
    FALSE_POSITIVE = "False Positive"


class VulnClass(str, Enum):
    SQLI = "SQL Injection"
    XSS = "Cross-Site Scripting (XSS)"
    IDOR = "Insecure Direct Object Reference (IDOR)"
    SSRF = "Server-Side Request Forgery (SSRF)"
    BROKEN_AUTH = "Broken Authentication / Missing Auth"
    MISCONFIG = "Security Misconfiguration"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    INFO_DISCLOSURE = "Information Disclosure"
    CORS_MISCONFIG = "CORS Misconfiguration"
    SECURITY_HEADERS = "Missing Critical Security Headers / Clickjacking"
    GRAPHQL_INTROSPECTION = "GraphQL Schema Introspection Enabled"
    OPEN_REDIRECT = "Open URL Redirection"
    PATH_TRAVERSAL = "Path / Directory Traversal"


class ScopeConfig(BaseModel):
    target: str
    allowed_hosts: List[str] = Field(default_factory=list)
    allowed_paths: List[str] = Field(default_factory=lambda: ["/*"])
    excluded_test_types: List[str] = Field(default_factory=list)
    max_requests_per_minute: int = 60
    max_total_requests: int = 500
    max_crawl_depth: int = 3
    allow_localhost_for_testing: bool = False
    timeout_seconds: float = 10.0
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    session_cookies: Dict[str, str] = Field(default_factory=dict)
    verify_ssl: bool = True
    max_retries: int = 2
    retry_backoff: float = 0.5


class Endpoint(BaseModel):
    id: str
    url: str
    path: str
    method: str = "GET"
    query_params: List[str] = Field(default_factory=list)
    body_params: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    auth_type: Optional[str] = None
    tech_fingerprint: List[str] = Field(default_factory=list)
    source: str = "crawl"
    baseline_status: Optional[int] = None
    baseline_body_snippet: Optional[str] = None
    baseline_response_time_ms: Optional[float] = None
    security_headers: Dict[str, str] = Field(default_factory=dict)
    missing_security_headers: List[str] = Field(default_factory=list)
    cors_headers: Dict[str, str] = Field(default_factory=dict)
    is_spa_route: bool = False
    is_graphql: bool = False


class Hypothesis(BaseModel):
    id: str
    endpoint_id: str
    url: str
    method: str
    target_param: Optional[str] = None
    vuln_class: VulnClass
    confidence_score: float = 0.5
    rationale: str
    test_plan: str
    iteration: int = 1
    llm_reasoned: bool = False


class TestResult(BaseModel):
    __test__ = False  # Prevent pytest from treating this model as a test suite
    id: str
    hypothesis_id: str
    endpoint_id: str
    url: str
    method: str
    param_tested: Optional[str] = None
    payload_sent: str
    request_headers: Dict[str, str] = Field(default_factory=dict)
    response_status: int
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body_snippet: str
    response_time_ms: float
    anomaly_detected: bool = False
    anomaly_type: Optional[str] = None
    anomaly_details: Optional[str] = None


class Finding(BaseModel):
    id: str
    vuln_class: VulnClass
    severity: Severity
    title: str
    description: str
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    affected_endpoint: str
    http_method: str
    parameter: Optional[str] = None
    reproduction_curl: str
    reproduction_steps: List[str] = Field(default_factory=list)
    evidence: str
    remediation: str
    confidence: Confidence = Confidence.LIKELY
    iteration_discovered: int = 1


class MissionStats(BaseModel):
    total_requests_sent: int = 0
    total_endpoints_discovered: int = 0
    total_hypotheses_generated: int = 0
    total_tests_executed: int = 0
    total_findings_count: int = 0
    blocked_requests_count: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration_seconds: float = 0.0


class MissionContext(BaseModel):
    target: str
    scope: ScopeConfig
    endpoint_map: Dict[str, Endpoint] = Field(default_factory=dict)
    hypothesis_queue: List[Hypothesis] = Field(default_factory=list)
    test_results: List[TestResult] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    stats: MissionStats = Field(default_factory=MissionStats)
    current_iteration: int = 1
    max_iterations: int = 2
    replanning_triggered: bool = False
    agent_logs: List[Dict[str, Any]] = Field(default_factory=list)

    def log_event(self, agent_name: str, message: str, level: str = "INFO") -> None:
        self.agent_logs.append({
            "timestamp": time.time(),
            "agent": agent_name,
            "level": level,
            "message": message
        })

    def save_checkpoint(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(), f, indent=2)

    @classmethod
    def load_checkpoint(cls, path: str) -> MissionContext:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)
