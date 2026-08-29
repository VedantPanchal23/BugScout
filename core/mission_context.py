from __future__ import annotations

import os
import json
import time
from datetime import datetime, timezone
from enum import Enum, IntEnum
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


class EvidenceLevel(IntEnum):
    LEVEL_0_NONE = 0            # No evidence / identical to baseline
    LEVEL_1_SUSPICIOUS = 1      # Suspicious status code or body length delta
    LEVEL_2_ANOMALY = 2         # Behavioral timing/structural anomaly
    LEVEL_3_STRONG = 3          # Strong indicator (database error, unescaped tag)
    LEVEL_4_VALIDATED = 4       # Validated exploit proof / reproducible security impact


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


class AuthConfig(BaseModel):
    login_url: Optional[str] = None
    login_method: str = "POST"
    login_payload: Dict[str, Any] = Field(default_factory=dict)
    token_json_path: Optional[str] = "token"  # e.g., 'access_token' or 'data.token'
    token_header_name: str = "Authorization"
    token_prefix: str = "Bearer "
    cookie_name: Optional[str] = None
    auto_refresh: bool = True
    # Two-identity authorization context for IDOR testing
    user_a_token: Optional[str] = None
    user_b_token: Optional[str] = None


class WAFInfo(BaseModel):
    detected_waf: Optional[str] = None
    confidence: float = 0.0
    signatures_matched: List[str] = Field(default_factory=list)
    polite_mode_active: bool = False
    adaptive_delay_seconds: float = 0.0


class TokenUsageStats(BaseModel):
    llm_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    inference_duration_seconds: float = 0.0


class AuditLogEntry(BaseModel):
    timestamp: str
    agent: str
    action: str
    target: str
    decision: str
    reason: str
    evidence_level: Optional[int] = None


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
    auth: Optional[AuthConfig] = None
    waf_protection: bool = True
    enable_checkpoints: bool = True
    checkpoint_path: str = "outputs/checkpoint.json"


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
    evidence_level: EvidenceLevel = EvidenceLevel.LEVEL_0_NONE


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
    evidence_level: EvidenceLevel = EvidenceLevel.LEVEL_4_VALIDATED
    remediation: str
    confidence: Confidence = Confidence.LIKELY
    confidence_score: float = 0.90
    why_tested: str = ""
    why_reported: str = ""
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
    waf_detected: Optional[str] = None
    checkpoints_saved: int = 0


class ScanManifest(BaseModel):
    scanner_version: str = "3.5.0-academic"
    benchmark_version: str = "2.0-groundtruth"
    model: str = "groq/qwen-3.8-27b"
    scan_start: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_end: Optional[str] = None
    target: str = ""
    scope_allowed_hosts: List[str] = Field(default_factory=list)
    request_count: int = 0
    findings_count: int = 0
    evidence_level_distribution: Dict[str, int] = Field(default_factory=dict)


class MissionContext(BaseModel):
    target: str
    scope: ScopeConfig
    endpoint_map: Dict[str, Endpoint] = Field(default_factory=dict)
    hypothesis_queue: List[Hypothesis] = Field(default_factory=list)
    test_results: List[TestResult] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    waf_info: WAFInfo = Field(default_factory=WAFInfo)
    stats: MissionStats = Field(default_factory=MissionStats)
    token_stats: TokenUsageStats = Field(default_factory=TokenUsageStats)
    audit_trail: List[AuditLogEntry] = Field(default_factory=list)
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

    def record_audit(self, agent: str, action: str, target: str, decision: str, reason: str, evidence_level: Optional[int] = None) -> None:
        entry = AuditLogEntry(
            timestamp=datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
            agent=agent,
            action=action,
            target=target,
            decision=decision,
            reason=reason,
            evidence_level=evidence_level
        )
        self.audit_trail.append(entry)

    def save_checkpoint(self, path: Optional[str] = None) -> str:
        target_path = path or self.scope.checkpoint_path
        os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(), f, indent=2)
        self.stats.checkpoints_saved += 1
        return target_path

    @classmethod
    def load_checkpoint(cls, path: str) -> MissionContext:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        return cls(**data)
