import pytest
from core.mission_context import WAFInfo
from core.waf_detector import WAFDetector


def test_waf_detector_fingerprints():
    waf_info = WAFInfo()
    detector = WAFDetector(waf_info)

    # Cloudflare detection
    headers = {"server": "cloudflare", "cf-ray": "8b9213876-SJC"}
    detected, delay = detector.analyze_response(headers, 200, "<html>Cloudflare</html>")
    assert detected == "Cloudflare"
    assert waf_info.confidence >= 0.75
    assert delay == 0.0

    # AWS WAF detection
    waf_info_aws = WAFInfo()
    detector_aws = WAFDetector(waf_info_aws)
    headers_aws = {"x-amzn-requestid": "12345-67890", "server": "awselb/2.0"}
    detected_aws, _ = detector_aws.analyze_response(headers_aws, 200, "")
    assert detected_aws == "AWS WAF"


def test_waf_detector_adaptive_throttling():
    waf_info = WAFInfo()
    detector = WAFDetector(waf_info)

    # Status 429 Too Many Requests triggers Polite Mode
    _, delay = detector.analyze_response({}, 429, "Too Many Requests")
    assert delay > 0.0
    assert waf_info.polite_mode_active is True
    assert waf_info.adaptive_delay_seconds > 0.0
