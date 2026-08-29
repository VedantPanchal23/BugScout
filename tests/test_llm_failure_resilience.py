import pytest
from core.llm import LLMProvider, HeuristicSecurityEngine
from core.mission_context import MissionContext, ScopeConfig, Endpoint
from agents.hypothesis_agent import HypothesisAgent


class FaultyMockLLM(LLMProvider):
    @property
    def name(self) -> str:
        return "FaultyMockLLM"

    async def generate(self, prompt: str, system_prompt: str = "") -> str:
        # Deliberately return invalid non-JSON output
        return "MALFORMED_NON_JSON_RESPONSE_FROM_FAILING_API"


@pytest.mark.asyncio
async def test_llm_malformed_json_fallback():
    faulty_llm = FaultyMockLLM()
    ctx = MissionContext(
        target="http://test.local",
        scope=ScopeConfig(target="http://test.local", allowed_hosts=["test.local"])
    )

    ep = Endpoint(
        id="ep1",
        url="http://test.local/search?q=test",
        path="/search",
        method="GET",
        query_params=["q"]
    )
    ctx.endpoint_map = {"ep1": ep}

    agent = HypothesisAgent("HypothesisAgent", ctx, None, faulty_llm)
    await agent.run()

    # When LLM fails with invalid JSON, HypothesisAgent falls back to HeuristicSecurityEngine
    assert len(ctx.hypothesis_queue) > 0
    assert ctx.hypothesis_queue[0].target_param == "q"
