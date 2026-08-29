import pytest
from evaluation.consistency_validator import CrossFormatConsistencyValidator


def test_cross_format_consistency():
    validator = CrossFormatConsistencyValidator()
    is_valid, report = validator.validate()

    assert is_valid is True
    counts = report["counts"]
    assert counts["json_findings_count"] == counts["sarif_results_count"]
    assert counts["json_findings_count"] == counts["markdown_findings_count"]
    assert counts["json_findings_count"] == counts["html_findings_count"]
