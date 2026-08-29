import pytest
from core.mission_context import TestResult, VulnClass, Severity, Confidence
from core.mission_context import MissionContext, ScopeConfig
from core.scope_guard import ScopeGuard
from core.llm import HeuristicSecurityEngine
from agents.observer_agent import ObserverAgent


def test_observer_detects_sqli_error():
    config = ScopeConfig(target="http://127.0.0.1:8888", allowed_hosts=["127.0.0.1"], allow_localhost_for_testing=True)
    context = MissionContext(target="http://127.0.0.1:8888", scope=config)
    guard = ScopeGuard(config)
    observer = ObserverAgent("ObserverAgent", context, guard, HeuristicSecurityEngine())

    test_res = TestResult(
        id="test1",
        hypothesis_id="h1",
        endpoint_id="GET:/api/products",
        url="http://127.0.0.1:8888/api/products?search='",
        method="GET",
        param_tested="search",
        payload_sent="'",
        response_status=500,
        response_headers={},
        response_body_snippet="sqlite3.OperationalError: near syntax error in query",
        response_time_ms=45.0
    )

    findings, secondary = observer._evaluate_result(test_res, None)
    assert len(findings) == 1
    assert findings[0].vuln_class == VulnClass.SQLI
    assert findings[0].confidence == Confidence.CONFIRMED


def test_observer_detects_xss_reflection():
    config = ScopeConfig(target="http://127.0.0.1:8888", allowed_hosts=["127.0.0.1"], allow_localhost_for_testing=True)
    context = MissionContext(target="http://127.0.0.1:8888", scope=config)
    guard = ScopeGuard(config)
    observer = ObserverAgent("ObserverAgent", context, guard, HeuristicSecurityEngine())

    test_res = TestResult(
        id="test2",
        hypothesis_id="h2",
        endpoint_id="GET:/search",
        url="http://127.0.0.1:8888/search?q=<scout_xss_marker_1>",
        method="GET",
        param_tested="q",
        payload_sent="<scout_xss_marker_1>",
        response_status=200,
        response_headers={"content-type": "text/html"},
        response_body_snippet="<h2>Search Results for: <scout_xss_marker_1></h2>",
        response_time_ms=15.0
    )

    findings, secondary = observer._evaluate_result(test_res, None)
    assert len(findings) == 1
    assert findings[0].vuln_class == VulnClass.XSS
    assert findings[0].confidence == Confidence.CONFIRMED


def test_observer_detects_env_leak():
    config = ScopeConfig(target="http://127.0.0.1:8888", allowed_hosts=["127.0.0.1"], allow_localhost_for_testing=True)
    context = MissionContext(target="http://127.0.0.1:8888", scope=config)
    guard = ScopeGuard(config)
    observer = ObserverAgent("ObserverAgent", context, guard, HeuristicSecurityEngine())

    test_res = TestResult(
        id="test3",
        hypothesis_id="h3",
        endpoint_id="GET:/.env",
        url="http://127.0.0.1:8888/.env",
        method="GET",
        param_tested=None,
        payload_sent="",
        response_status=200,
        response_headers={},
        response_body_snippet="DB_PASSWORD=SuperSecretPass123!\nJWT_SECRET=super-secret-jwt-token",
        response_time_ms=10.0
    )

    findings, secondary = observer._evaluate_result(test_res, None)
    assert len(findings) == 1
    assert findings[0].vuln_class == VulnClass.SENSITIVE_DATA
    assert findings[0].severity == Severity.CRITICAL
