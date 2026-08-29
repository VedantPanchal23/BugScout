import pytest
from core.mission_context import MissionContext, ScopeConfig
from core.scope_guard import ScopeGuard
from core.llm import HeuristicSecurityEngine
from agents.recon_agent import ReconAgent


def test_recon_endpoint_registration():
    config = ScopeConfig(
        target="http://127.0.0.1:8888",
        allowed_hosts=["127.0.0.1"],
        allow_localhost_for_testing=True
    )
    context = MissionContext(target="http://127.0.0.1:8888", scope=config)
    guard = ScopeGuard(config)
    llm = HeuristicSecurityEngine()

    recon = ReconAgent("ReconAgent", context, guard, llm)
    recon._register_endpoint("http://127.0.0.1:8888/api/products?search=phone", method="GET")

    assert "GET:/api/products" in context.endpoint_map
    ep = context.endpoint_map["GET:/api/products"]
    assert "search" in ep.query_params
    assert ep.method == "GET"


def test_recon_js_regex_extraction():
    config = ScopeConfig(
        target="http://127.0.0.1:8888",
        allowed_hosts=["127.0.0.1"],
        allow_localhost_for_testing=True
    )
    context = MissionContext(target="http://127.0.0.1:8888", scope=config)
    guard = ScopeGuard(config)
    llm = HeuristicSecurityEngine()

    recon = ReconAgent("ReconAgent", context, guard, llm)
    sample_js = '''
        const apiUrl = "/api/v1/users?role=admin";
        fetch("/rest/orders/10");
    '''
    recon._extract_endpoints_from_text(sample_js, "http://127.0.0.1:8888/static/app.js")

    assert "GET:/api/v1/users" in context.endpoint_map
    assert "GET:/rest/orders/10" in context.endpoint_map
