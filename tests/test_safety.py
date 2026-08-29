import pytest
from evaluation.safety_tester import SafetySuiteRunner


@pytest.mark.asyncio
async def test_scope_guard_safety_suite():
    runner = SafetySuiteRunner()
    results = await runner.run_safety_tests()

    assert results["safety_enforcement_rate"] == 100.0
    assert results["failed_tests"] == 0
    assert results["passed_tests"] >= 14
