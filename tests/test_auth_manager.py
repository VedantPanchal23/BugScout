import pytest
import uvicorn
import threading
import time
from core.mission_context import AuthConfig
from core.auth_manager import AuthManager
from mock_target.server import app


@pytest.fixture(scope="module")
def live_auth_server():
    config = uvicorn.Config(app, host="127.0.0.1", port=8889, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.0)
    yield


@pytest.mark.asyncio
async def test_auth_manager_preflight_login(live_auth_server):
    auth_cfg = AuthConfig(
        login_url="http://127.0.0.1:8889/api/auth/login",
        login_method="POST",
        login_payload={"username": "admin", "password": "secret_password"},
        token_json_path="token",
        token_header_name="Authorization",
        token_prefix="Bearer "
    )
    auth_mgr = AuthManager(auth_cfg)
    assert auth_mgr.is_configured() is True

    headers, cookies = await auth_mgr.authenticate()
    assert "Authorization" in headers
    assert headers["Authorization"] == "Bearer jwt_token_demo_9876"
    assert auth_mgr.active_token == "jwt_token_demo_9876"
