import pytest
from core.mission_context import TestResult, VulnClass, Severity, Confidence, Endpoint
from core.mission_context import MissionContext, ScopeConfig
from core.scope_guard import ScopeGuard
from core.llm import HeuristicSecurityEngine
from agents.observer_agent import ObserverAgent


def test_observer_detects_cors_misconfig():
    config = ScopeConfig(target="http://127.0.0.1:8888", allowed_hosts=["127.0.0.1"], allow_localhost_for_testing=True)
    context = MissionContext(target="http://127.0.0.1:8888", scope=config)
    observer = ObserverAgent("ObserverAgent", context, ScopeGuard(config), HeuristicSecurityEngine())

    test_res = TestResult(
        id="cors1",
        hypothesis_id="h_cors",
        endpoint_id="GET:/api/user/private-data",
        url="http://127.0.0.1:8888/api/user/private-data",
        method="GET",
        param_tested=None,
        payload_sent="https://evil-attacker.com",
        response_status=200,
        response_headers={
            "access-control-allow-origin": "https://evil-attacker.com",
            "access-control-allow-credentials": "true"
        },
        response_body_snippet="{\"status\": \"confidential_data\"}",
        response_time_ms=20.0
    )

    findings, _ = observer._evaluate_result(test_res, None)
    assert len(findings) == 1
    assert findings[0].vuln_class == VulnClass.CORS_MISCONFIG
    assert findings[0].severity == Severity.HIGH


def test_observer_detects_graphql_introspection():
    config = ScopeConfig(target="http://127.0.0.1:8888", allowed_hosts=["127.0.0.1"], allow_localhost_for_testing=True)
    context = MissionContext(target="http://127.0.0.1:8888", scope=config)
    observer = ObserverAgent("ObserverAgent", context, ScopeGuard(config), HeuristicSecurityEngine())

    test_res = TestResult(
        id="gql1",
        hypothesis_id="h_gql",
        endpoint_id="POST:/graphql",
        url="http://127.0.0.1:8888/graphql",
        method="POST",
        param_tested=None,
        payload_sent="{\"query\": \"{ __schema { types { name } } }\"}",
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body_snippet="{\"data\": {\"__schema\": {\"types\": [{\"name\": \"User\"}]}}}",
        response_time_ms=30.0
    )

    findings, _ = observer._evaluate_result(test_res, None)
    assert len(findings) == 1
    assert findings[0].vuln_class == VulnClass.GRAPHQL_INTROSPECTION
    assert findings[0].severity == Severity.MEDIUM


def test_observer_detects_open_redirect():
    config = ScopeConfig(target="http://127.0.0.1:8888", allowed_hosts=["127.0.0.1"], allow_localhost_for_testing=True)
    context = MissionContext(target="http://127.0.0.1:8888", scope=config)
    observer = ObserverAgent("ObserverAgent", context, ScopeGuard(config), HeuristicSecurityEngine())

    test_res = TestResult(
        id="red1",
        hypothesis_id="h_red",
        endpoint_id="GET:/redirect",
        url="http://127.0.0.1:8888/redirect?url=https://example.com/scout_redirect_canary",
        method="GET",
        param_tested="url",
        payload_sent="https://example.com/scout_redirect_canary",
        response_status=302,
        response_headers={"location": "https://example.com/scout_redirect_canary"},
        response_body_snippet="",
        response_time_ms=15.0
    )

    findings, _ = observer._evaluate_result(test_res, None)
    assert len(findings) == 1
    assert findings[0].vuln_class == VulnClass.OPEN_REDIRECT


def test_observer_detects_path_traversal():
    config = ScopeConfig(target="http://127.0.0.1:8888", allowed_hosts=["127.0.0.1"], allow_localhost_for_testing=True)
    context = MissionContext(target="http://127.0.0.1:8888", scope=config)
    observer = ObserverAgent("ObserverAgent", context, ScopeGuard(config), HeuristicSecurityEngine())

    test_res = TestResult(
        id="trav1",
        hypothesis_id="h_trav",
        endpoint_id="GET:/api/download",
        url="http://127.0.0.1:8888/api/download?file=../../../../etc/passwd",
        method="GET",
        param_tested="file",
        payload_sent="../../../../etc/passwd",
        response_status=200,
        response_headers={},
        response_body_snippet="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
        response_time_ms=25.0
    )

    findings, _ = observer._evaluate_result(test_res, None)
    assert len(findings) == 1
    assert findings[0].vuln_class == VulnClass.PATH_TRAVERSAL
    assert findings[0].severity == Severity.HIGH


def test_observer_detects_missing_security_headers():
    config = ScopeConfig(target="http://127.0.0.1:8888", allowed_hosts=["127.0.0.1"], allow_localhost_for_testing=True)
    context = MissionContext(target="http://127.0.0.1:8888", scope=config)
    observer = ObserverAgent("ObserverAgent", context, ScopeGuard(config), HeuristicSecurityEngine())

    ep = Endpoint(
        id="GET:/",
        url="http://127.0.0.1:8888/",
        path="/",
        method="GET",
        missing_security_headers=["x-frame-options", "content-security-policy"],
        baseline_body_snippet="<html><body>Home</body></html>"
    )

    findings = observer._evaluate_endpoint_security_headers(ep)
    assert len(findings) == 1
    assert findings[0].vuln_class == VulnClass.SECURITY_HEADERS
