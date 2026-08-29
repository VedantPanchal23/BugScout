import os
import time
import pytest
import threading
import uvicorn
from core.pipeline import BugScoutPipeline
from core.mission_context import VulnClass
from mock_target.server import app


@pytest.fixture(scope="module")
def live_mock_server():
    config = uvicorn.Config(app, host="127.0.0.1", port=8888, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.0)
    yield


@pytest.mark.asyncio
async def test_full_autonomous_pipeline(live_mock_server):
    pipeline = BugScoutPipeline(config_path="config/scope.yaml", max_iterations=1)
    context = await pipeline.run()

    assert context.stats.total_endpoints_discovered >= 4
    assert context.stats.total_requests_sent > 0
    assert len(context.findings) >= 3

    # Assert findings cover key OWASP classes
    vuln_classes = [f.vuln_class for f in context.findings]
    assert VulnClass.SQLI in vuln_classes
    assert VulnClass.XSS in vuln_classes
    assert VulnClass.SENSITIVE_DATA in vuln_classes or VulnClass.MISCONFIG in vuln_classes

    # Check generated report files
    assert os.path.exists("outputs/VulnerabilityReport.md")
    assert os.path.exists("outputs/VulnerabilityReport.json")
