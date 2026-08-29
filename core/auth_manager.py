from __future__ import annotations

import logging
from typing import Dict, Any, Optional, Tuple
import httpx
from core.mission_context import AuthConfig

logger = logging.getLogger("BugScout.AuthManager")


class AuthManager:
    """
    Dynamic Authentication & Session Lifecycle Manager:
    - Pre-flight automated authentication (JWT, OAuth, Form-based, Session Cookie)
    - Token path resolution (e.g. 'access_token', 'data.token')
    - Automatic token refresh upon encountering HTTP 401 Unauthorized responses
    """

    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config
        self.active_token: Optional[str] = None
        self.active_headers: Dict[str, str] = {}
        self.active_cookies: Dict[str, str] = {}

    def is_configured(self) -> bool:
        return self.config is not None and bool(self.config.login_url)

    async def authenticate(self, client: Optional[httpx.AsyncClient] = None) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Perform login and extract authorization tokens / cookies."""
        if not self.is_configured() or not self.config:
            return {}, {}

        login_url = self.config.login_url
        method = self.config.login_method.upper()
        payload = self.config.login_payload

        logger.info(f"Authenticating against login endpoint: {login_url} [{method}]")

        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
            should_close = True

        try:
            if method == "POST":
                resp = await client.post(login_url, json=payload)
            else:
                resp = await client.get(login_url, params=payload)

            if resp.status_code in [200, 201]:
                # 1. Extract JSON Token
                if self.config.token_json_path:
                    try:
                        data = resp.json()
                        token_val = self._extract_nested_key(data, self.config.token_json_path)
                        if token_val:
                            self.active_token = str(token_val)
                            header_val = f"{self.config.token_prefix}{self.active_token}"
                            self.active_headers[self.config.token_header_name] = header_val
                            logger.info(f"Successfully extracted auth token from {self.config.token_json_path}")
                    except Exception as e:
                        logger.debug(f"JSON token extraction failed: {e}")

                # 2. Extract Session Cookies
                for cookie_key, cookie_val in resp.cookies.items():
                    self.active_cookies[cookie_key] = cookie_val

                if self.config.cookie_name and self.config.cookie_name in resp.cookies:
                    self.active_cookies[self.config.cookie_name] = resp.cookies[self.config.cookie_name]

                return self.active_headers, self.active_cookies
            else:
                logger.warning(f"Authentication failed with status {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.error(f"Error during authentication request: {e}")
        finally:
            if should_close:
                await client.aclose()

        return self.active_headers, self.active_cookies

    async def handle_response(self, client: httpx.AsyncClient, status_code: int) -> bool:
        """Handle 401 Unauthorized by re-authenticating if auto_refresh is enabled."""
        if status_code == 401 and self.is_configured() and self.config and self.config.auto_refresh:
            logger.info("Encountered 401 Unauthorized: Triggering session re-authentication...")
            headers, cookies = await self.authenticate(client)
            return bool(headers or cookies)
        return False

    def _extract_nested_key(self, data: Any, path: str) -> Optional[Any]:
        keys = path.split(".")
        curr = data
        for k in keys:
            if isinstance(curr, dict) and k in curr:
                curr = curr[k]
            else:
                return None
        return curr
