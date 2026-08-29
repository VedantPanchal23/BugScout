import pytest
from evaluation.ablation_study import AblationStudyRunner


@pytest.mark.asyncio
async def test_4_tier_ablation_study():
    runner = AblationStudyRunner(port=8892)
    results = await runner.run_ablation_study()

    assert "system_1_rules_only" in results
    assert "system_2_rules_llm" in results
    assert "system_3_llm_replanning" in results
    assert "system_4_full_bugscout" in results
