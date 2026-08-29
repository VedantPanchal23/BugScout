import pytest
from evaluation.benchmark_runner import BenchmarkEvaluator


@pytest.mark.asyncio
async def test_ground_truth_benchmark_metrics():
    evaluator = BenchmarkEvaluator(port=8890)
    results = await evaluator.run_evaluation()

    metrics = results["metrics"]
    cm = results["confusion_matrix"]

    # Assert Ground Truth Precision and Recall thresholds
    assert cm["true_positives"] >= 8
    assert cm["false_positives"] <= 1
    assert metrics["precision"] >= 85.0
    assert metrics["recall"] >= 85.0
    assert metrics["f1_score"] >= 85.0
    assert metrics["specificity"] >= 90.0
