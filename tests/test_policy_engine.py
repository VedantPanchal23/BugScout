import pytest
from core.policy_engine import PolicyEngine
from core.mission_context import Endpoint, Hypothesis, VulnClass


def test_policy_engine_risk_tier_classification():
    policy = PolicyEngine(max_global_probes=100)

    # 1. High-risk endpoint (contains sensitive parameter "id", "search", "user")
    ep_high = Endpoint(
        id="GET:/api/user/profile",
        url="http://127.0.0.1:8888/api/user/profile",
        path="/api/user/profile",
        method="GET",
        query_params=["id", "user_token"]
    )
    assert policy.calculate_endpoint_risk_tier(ep_high) == "HIGH"
    assert policy.get_max_probes_for_tier("HIGH") == 8

    # 2. Medium-risk endpoint (POST method without sensitive keywords)
    ep_med = Endpoint(
        id="POST:/api/submit",
        url="http://127.0.0.1:8888/api/submit",
        path="/api/submit",
        method="POST",
        body_params=["content"]
    )
    assert policy.calculate_endpoint_risk_tier(ep_med) == "MEDIUM"
    assert policy.get_max_probes_for_tier("MEDIUM") == 4

    # 3. Low-risk endpoint (Static GET page)
    ep_low = Endpoint(
        id="GET:/about",
        url="http://127.0.0.1:8888/about",
        path="/about",
        method="GET"
    )
    assert policy.calculate_endpoint_risk_tier(ep_low) == "LOW"
    assert policy.get_max_probes_for_tier("LOW") == 2


def test_policy_engine_per_endpoint_budget_and_duplicate_pruning():
    policy = PolicyEngine(max_global_probes=5)
    ep = Endpoint(
        id="GET:/search",
        url="http://127.0.0.1:8888/search",
        path="/search",
        method="GET",
        query_params=["q"]
    )
    endpoint_map = {ep.id: ep}

    # Create 10 hypotheses for the same endpoint (should be capped and deduplicated)
    hypotheses = [
        Hypothesis(id="h1", endpoint_id=ep.id, url=ep.url, method="GET", target_param="q", vuln_class=VulnClass.SQLI, rationale="SQL test", test_plan="probe sqli"),
        Hypothesis(id="h2", endpoint_id=ep.id, url=ep.url, method="GET", target_param="q", vuln_class=VulnClass.SQLI, rationale="Duplicate SQL test", test_plan="probe sqli"),
        Hypothesis(id="h3", endpoint_id=ep.id, url=ep.url, method="GET", target_param="q", vuln_class=VulnClass.XSS, rationale="XSS test", test_plan="probe xss"),
        Hypothesis(id="h4", endpoint_id=ep.id, url=ep.url, method="GET", target_param="q", vuln_class=VulnClass.PATH_TRAVERSAL, rationale="Traversal test", test_plan="probe trav"),
        Hypothesis(id="h5", endpoint_id=ep.id, url=ep.url, method="GET", target_param="q", vuln_class=VulnClass.CORS_MISCONFIG, rationale="CORS test", test_plan="probe cors"),
        Hypothesis(id="h6", endpoint_id=ep.id, url=ep.url, method="GET", target_param="q", vuln_class=VulnClass.IDOR, rationale="IDOR test", test_plan="probe idor"),
    ]

    filtered = policy.filter_and_prioritize_hypotheses(hypotheses, endpoint_map)
    
    # Assert duplicate (ep.id, "q", SQLI) was pruned
    sqli_count = sum(1 for h in filtered if h.vuln_class == VulnClass.SQLI)
    assert sqli_count == 1
    # Assert global budget cap enforced
    assert len(filtered) <= 5
