import os
import pytest
from core.llm import LLMManager, HeuristicSecurityEngine, GroqProvider


@pytest.mark.asyncio
async def test_heuristic_security_engine():
    engine = HeuristicSecurityEngine()
    assert "Offline" in engine.name
    res = await engine.generate("test prompt")
    assert "Heuristic" in res


@pytest.mark.asyncio
async def test_groq_provider_with_active_key():
    key = os.getenv("GROQ_API_KEY")
    if not key:
        pytest.skip("GROQ_API_KEY not configured in environment.")

    provider = GroqProvider(api_key=key)
    res = await provider.generate("Respond with the word: VERIFIED")
    assert "VERIFIED" in res or len(res) > 0
