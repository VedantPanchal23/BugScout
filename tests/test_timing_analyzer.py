import pytest
from core.timing_analyzer import StatisticalTimingAnalyzer


def test_statistical_timing_analyzer_genuine_delay():
    analyzer = StatisticalTimingAnalyzer(delay_threshold_seconds=2.0, min_z_score=3.0)
    baseline_samples = [0.045, 0.052, 0.048, 0.050, 0.047]

    # Fast probe (0.051s) -> Should NOT trigger delay
    delayed, conf, details = analyzer.analyze_timing_anomaly(baseline_samples, 0.051)
    assert delayed is False
    assert conf == 0.0

    # Genuine time delay probe (2.45s) -> Exceeds 2.0s threshold and > 3 sigma -> Triggered
    delayed, conf, details = analyzer.analyze_timing_anomaly(baseline_samples, 2.45)
    assert delayed is True
    assert conf > 0.8
    assert details["z_score"] >= 3.0
    assert details["is_statistically_delayed"] is True


def test_statistical_timing_analyzer_jitter_rejection():
    analyzer = StatisticalTimingAnalyzer(delay_threshold_seconds=2.0, min_z_score=3.0)
    baseline_samples = [0.20, 0.35, 0.25, 0.40]

    # Minor network spike (0.85s) -> Does not reach 2.0s threshold -> Rejected
    delayed, conf, details = analyzer.analyze_timing_anomaly(baseline_samples, 0.85)
    assert delayed is False
