import pytest
import json
import os
import math
import hashlib
from evaluation.benchmark_runner import BenchmarkEvaluator
from evaluation.hidden_evaluator import HiddenBenchmarkEvaluator


@pytest.mark.asyncio
async def test_ground_truth_benchmark_metrics():
    evaluator = BenchmarkEvaluator(port=8890)
    results = await evaluator.run_evaluation()

    metrics = results["metrics"]
    cm = results["confusion_matrix"]
    categories = results["category_breakdown"]

    tp = cm["true_positives"]
    tn = cm["true_negatives"]
    fp = cm["false_positives"]
    fn = cm["false_negatives"]
    total = cm["total_evaluated_cases"]

    # 1. Fundamental Accounting Assertions
    positives = tp + fn
    negatives = tn + fp
    assert positives == 27, f"Expected 27 positive cases, got {positives}"
    assert negatives == 19, f"Expected 19 negative cases, got {negatives}"
    assert total == 46, f"Expected 46 total evaluated cases, got {total}"
    assert tp + tn + fp + fn == total, "Confusion matrix sum must equal total cases"

    # 2. Mathematical Metric Derivation Assertions
    expected_prec = round((tp / (tp + fp)) * 100, 2)
    expected_rec = round((tp / (tp + fn)) * 100, 2)
    expected_spec = round((tn / (tn + fp)) * 100, 2)
    expected_f1 = round((2 * (tp / (tp + fp)) * (tp / (tp + fn)) / ((tp / (tp + fp)) + (tp / (tp + fn)))) * 100, 2)

    assert abs(metrics["precision"] - expected_prec) < 0.01, f"Precision mismatch: {metrics['precision']} vs {expected_prec}"
    assert abs(metrics["recall"] - expected_rec) < 0.01, f"Recall mismatch: {metrics['recall']} vs {expected_rec}"
    assert abs(metrics["specificity"] - expected_spec) < 0.01, f"Specificity mismatch: {metrics['specificity']} vs {expected_spec}"
    assert abs(metrics["f1_score"] - expected_f1) < 0.01, f"F1 score mismatch: {metrics['f1_score']} vs {expected_f1}"

    # 3. Category Breakdown Accounting Parity
    sum_cat_present = sum(val["present"] for val in categories.values())
    sum_cat_detected = sum(val["detected"] for val in categories.values())
    sum_cat_decoys = sum(val["decoys"] for val in categories.values())
    sum_cat_fp = sum(val["false_positives"] for val in categories.values())

    assert sum_cat_present == positives, f"Category positives sum {sum_cat_present} != {positives}"
    assert sum_cat_detected == tp, f"Category detected sum {sum_cat_detected} != {tp}"
    assert sum_cat_decoys == negatives, f"Category decoys sum {sum_cat_decoys} != {negatives}"
    assert sum_cat_fp == fp, f"Category FP sum {sum_cat_fp} != {fp}"

    # 4. Reproducibility Manifest Parity
    manifest_path = "outputs/ReproducibilityManifest.json"
    assert os.path.exists(manifest_path), "Manifest file must exist"
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["experiment"]["id"] == "primary_46_case_benchmark"
    assert manifest["dataset"]["total_cases"] == 46
    assert manifest["confusion_matrix"]["true_positives"] == tp
    assert manifest["confusion_matrix"]["true_negatives"] == tn
    assert manifest["confusion_matrix"]["false_positives"] == fp
    assert manifest["confusion_matrix"]["false_negatives"] == fn
    assert manifest["metrics"]["precision"] == metrics["precision"]
    assert manifest["metrics"]["recall"] == metrics["recall"]
    expected_hash = hashlib.sha256(open("benchmark_lab/ground_truth.json", "rb").read()).hexdigest()
    assert manifest["dataset"]["ground_truth_hash"] == expected_hash


@pytest.mark.asyncio
async def test_hidden_benchmark_isolation():
    """Verify that running the hidden benchmark does not mutate or alter primary benchmark ground truth."""
    with open("benchmark_lab/ground_truth.json", "r", encoding="utf-8") as f:
        before_gt = json.load(f)

    hidden_evaluator = HiddenBenchmarkEvaluator(port=8891)
    hidden_results = await hidden_evaluator.run_hidden_evaluation()

    with open("benchmark_lab/ground_truth.json", "r", encoding="utf-8") as f:
        after_gt = json.load(f)

    assert before_gt == after_gt, "Hidden benchmark must not mutate primary benchmark ground truth"
    assert hidden_results["hidden_cases"] == 6
    assert hidden_results["confusion_matrix"]["true_positives"] + hidden_results["confusion_matrix"]["false_negatives"] == 4
    assert hidden_results["confusion_matrix"]["true_negatives"] + hidden_results["confusion_matrix"]["false_positives"] == 2


