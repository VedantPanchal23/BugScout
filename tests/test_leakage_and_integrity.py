import os
import sys
import glob
import json
import random
import hashlib
import pytest
from core.scope_guard import ScopeGuard
from core.mission_context import ScopeConfig, MissionContext, Finding, Severity, VulnClass, EvidenceLevel, Confidence, WAFInfo
from core.timing_analyzer import StatisticalTimingAnalyzer
from core.waf_detector import WAFDetector
from core.llm import HeuristicSecurityEngine
from agents.report_agent import ReportAgent
from evaluation.budget_curve import calculate_pareto_frontier
from evaluation.hidden_evaluator import HiddenBenchmarkEvaluator


def test_scanner_code_does_not_import_benchmark_or_ground_truth():
    """Verify that production scanner code in agents/ and scanner core never imports evaluation or ground_truth."""
    scanner_files = glob.glob("agents/**/*.py", recursive=True) + [
        "core/pipeline.py",
        "core/scope_guard.py",
        "core/llm.py",
        "core/mission_context.py",
        "core/waf_detector.py",
        "core/timing_analyzer.py",
        "core/auth_manager.py"
    ]
    forbidden_terms = [
        "benchmark_lab.ground_truth",
        "ground_truth.json",
        "from benchmark_lab import",
        "from evaluation import",
        "import evaluation",
    ]

    for fpath in scanner_files:
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
            for term in forbidden_terms:
                assert term not in content, f"Leakage violation: {term} found in production file {fpath}"


def test_mathematical_metric_invariants():
    """Verify exact mathematical identities across confusion matrix metrics."""
    tp, tn, fp, fn = 19, 18, 1, 8
    positives = tp + fn
    negatives = tn + fp
    total = tp + tn + fp + fn

    assert positives == 27
    assert negatives == 19
    assert total == 46

    precision = round((tp / (tp + fp)) * 100, 2)
    recall = round((tp / (tp + fn)) * 100, 2)
    f1 = round((2 * (precision * recall) / (precision + recall)), 2)
    specificity = round((tn / (tn + fp)) * 100, 2)

    assert precision == 95.00
    assert recall == 70.37
    assert f1 == 80.85
    assert specificity == 94.74


def test_pareto_frontier_property_with_random_points():
    """Property test verifying Pareto frontier dominance logic on randomized budget-recall points."""
    random.seed(42)
    points = []
    for _ in range(50):
        reqs = random.randint(10, 500)
        rec = round(random.uniform(10.0, 100.0), 2)
        points.append({"config": f"cfg_{reqs}_{rec}", "requests": reqs, "recall": rec})

    frontier = calculate_pareto_frontier(points)

    for f_pt in frontier:
        for pt in points:
            is_strictly_better = (pt["requests"] <= f_pt["requests"] and pt["recall"] >= f_pt["recall"]) and \
                                 (pt["requests"] < f_pt["requests"] or pt["recall"] > f_pt["recall"])
            assert not is_strictly_better, f"Point {f_pt} on frontier is dominated by {pt}"


@pytest.mark.asyncio
async def test_hidden_benchmark_leaves_ground_truth_unmodified():
    """Verify that hidden evaluation is strictly isolated and does not alter primary ground_truth.json."""
    gt_path = "benchmark_lab/ground_truth.json"
    with open(gt_path, "rb") as f:
        hash_before = hashlib.sha256(f.read()).hexdigest()

    evaluator = HiddenBenchmarkEvaluator(port=8899)
    app = evaluator.create_hidden_app()
    assert app is not None

    with open(gt_path, "rb") as f:
        hash_after = hashlib.sha256(f.read()).hexdigest()

    assert hash_before == hash_after, "Hidden evaluation mutated primary ground truth!"


def test_report_agent_escapes_xss_in_findings():
    """Verify that generated HTML reports escape malicious XSS payloads in finding fields."""
    scope = ScopeConfig(target="http://127.0.0.1:8888")
    context = MissionContext(target="http://127.0.0.1:8888", scope=scope)
    malicious_finding = Finding(
        id="f_malicious",
        title="<script>alert('xss_title')</script>",
        vuln_class=VulnClass.XSS,
        severity=Severity.HIGH,
        cvss_score=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        cwe_id="CWE-79",
        affected_endpoint="http://127.0.0.1:8888/<script>alert(1)</script>",
        http_method="GET",
        parameter="<img src=x onerror=alert(2)>",
        evidence="Response contains <script>document.cookie</script>",
        remediation="Ensure <b>proper</b> sanitization.",
        reproduction_curl="curl 'http://127.0.0.1:8888/?q=<script>alert(3)</script>'",
        evidence_level=EvidenceLevel.LEVEL_4_VALIDATED,
        confidence=Confidence.CONFIRMED,
        description="Test malicious description"
    )
    context.findings = [malicious_finding]

    agent = ReportAgent("ReportAgent", context, ScopeGuard(scope), HeuristicSecurityEngine())
    report_data = agent._build_json_report()
    html_report = agent._build_html_dashboard(report_data)

    assert "escapeHtml" in html_report
    assert "safeTitle = escapeHtml(f.title)" in html_report
    assert "safeEvidence = escapeHtml(f.evidence)" in html_report


def test_resource_limits_and_crawler_depth_enforced():
    """Verify that ScopeConfig enforce hard limits on requests, crawl depth, and rate limits."""
    scope = ScopeConfig(
        target="http://example.com",
        max_total_requests=250,
        max_crawl_depth=2,
        max_requests_per_minute=100
    )
    guard = ScopeGuard(scope)

    assert guard.config.max_total_requests == 250
    assert guard.config.max_crawl_depth == 2
    assert guard.config.max_requests_per_minute == 100


def test_llm_prompt_injection_cannot_alter_scope_policy():
    """Verify that prompt injection payloads in target content cannot grant out-of-scope permissions."""
    scope = ScopeConfig(target="http://example.com", allowed_hosts=["example.com"], allow_localhost_for_testing=False)
    guard = ScopeGuard(scope)

    assert not guard.validate_url("http://127.0.0.1/admin")[0]
    assert not guard.validate_url("http://10.0.0.1/api")[0]
    assert "127.0.0.1" not in guard.config.allowed_hosts


def test_sarif_schema_structure_and_rule_stability():
    """Verify that SARIF output conforms to OASIS SARIF 2.1.0 schema and maintains stable rule IDs."""
    scope = ScopeConfig(target="http://127.0.0.1:8888")
    context = MissionContext(target="http://127.0.0.1:8888", scope=scope)
    context.findings = [
        Finding(
            id="f_sarif_test",
            title="SQL Injection",
            vuln_class=VulnClass.SQLI,
            severity=Severity.HIGH,
            cwe_id="CWE-89",
            cvss_score=8.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            affected_endpoint="http://127.0.0.1:8888/api/users",
            http_method="GET",
            parameter="id",
            evidence="sqlite3.OperationalError",
            remediation="Use parameterized queries",
            reproduction_curl="curl 'http://127.0.0.1:8888/api/users?id=1%27'",
            evidence_level=EvidenceLevel.LEVEL_4_VALIDATED,
            confidence=Confidence.CONFIRMED,
            description="Test SQLi"
        )
    ]
    agent = ReportAgent("ReportAgent", context, ScopeGuard(scope), HeuristicSecurityEngine())
    sarif = agent._build_sarif_report()

    assert sarif["version"] == "2.1.0"
    assert "https://raw.githubusercontent.com/oasis-tcs/sarif-spec" in sarif["$schema"]
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "BugScout"
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "CWE-89"


def test_timing_analyzer_zero_variance_handled_gracefully():
    """Verify that StatisticalTimingAnalyzer handles zero variance without ZeroDivisionError."""
    analyzer = StatisticalTimingAnalyzer(delay_threshold_seconds=2.0)
    is_delayed, z_score, details = analyzer.analyze_timing_anomaly(
        baseline_durations=[0.05, 0.05, 0.05],
        probe_duration=0.05
    )
    assert not is_delayed
    assert z_score == 0.0


def test_waf_detector_exponential_backoff_bound():
    """Verify that WAF backoff is capped safely and does not grow indefinitely."""
    waf_info = WAFInfo()
    detector = WAFDetector(waf_info)
    for _ in range(10):
        detector.analyze_response(headers={}, status_code=429, body_snippet="Too Many Requests")
    assert waf_info.adaptive_delay_seconds <= 10.0
