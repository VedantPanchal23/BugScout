import pytest
from evaluation.benchmark_runner import BenchmarkEvaluator


@pytest.mark.asyncio
async def test_ground_truth_benchmark_metrics():
    evaluator = BenchmarkEvaluator(port=8890)
    results = await evaluator.run_evaluation()

    metrics = results["metrics"]
    cm = results["confusion_matrix"]

    # Assert Ground Truth Precision and Recall thresholds on 60+ benchmark
    assert cm["true_positives"] >= 15
    assert cm["false_positives"] <= 3
    assert metrics["precision"] >= 80.0
    assert metrics["recall"] >= 65.0
    assert metrics["f1_score"] >= 75.0
    assert metrics["specificity"] >= 85.0
