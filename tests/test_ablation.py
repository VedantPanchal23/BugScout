import pytest
from evaluation.ablation_study import AblationStudyRunner


@pytest.mark.asyncio
async def test_4_tier_ablation_study():
    runner = AblationStudyRunner(port=8892)
    results = await runner.run_ablation_study()

    assert "tier_1_rules_only" in results
    assert "tier_2_rules_llm" in results
    assert "tier_3_llm_replanning" in results
    assert "tier_4_full_bugscout" in results
