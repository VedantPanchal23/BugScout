from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set, Dict, List
import httpx
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
import warnings

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

from agents.base_agent import BaseAgent
from core.mission_context import Endpoint


class ReconAgent(BaseAgent):
    """
    ReconAgent maps the target attack surface:
    - robots.txt & sitemap.xml parsing
    - OpenAPI / Swagger documentation inspection (JSON/YAML)
    - GraphQL endpoint discovery & introspection testing
    - SPA client-side routing and JS API regex mining
    - Security headers audit & CORS baseline probing
    - Tech stack fingerprinting & baseline response recording
    """

    COMMON_SENSITIVE_PATHS = [
        "/.env", "/.git/HEAD", "/debug/config", "/actuator/health",
        "/api-docs", "/openapi.json", "/swagger.json", "/phpinfo.php",
        "/graphql", "/api/graphql", "/query", "/redirect", "/api/download"
    ]

    API_REGEX_PATTERNS = [
        r'["\'](/api/[a-zA-Z0-9_\-\/]+(?:\?[a-zA-Z0-9_\-=&]*)?)["\']',
        r'["\'](/v[1-9]/[a-zA-Z0-9_\-\/]+(?:\?[a-zA-Z0-9_\-=&]*)?)["\']',
        r'["\'](/rest/[a-zA-Z0-9_\-\/]+(?:\?[a-zA-Z0-9_\-=&]*)?)["\']',
        r'["\'](/search(?:\?[a-zA-Z0-9_\-=&]*)?)["\']',
        r'["\'](/graphql(?:\?[a-zA-Z0-9_\-=&]*)?)["\']',
        r'["\'](/redirect(?:\?[a-zA-Z0-9_\-=&]*)?)["\']',
    ]

    SPA_ROUTE_PATTERNS = [
        r'path:\s*["\'](/[a-zA-Z0-9_\-\/:]+)["\']',
        r'route:\s*["\'](/[a-zA-Z0-9_\-\/:]+)["\']',
        r'<Route\s+[^>]*path=["\'](/[a-zA-Z0-9_\-\/:]+)["\']',
    ]

    SECURITY_HEADER_NAMES = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]

    async def run(self) -> None:
        self.log(f"Starting Deep Reconnaissance on target: {self.context.target}")
        base_url = self.context.target.rstrip("/")
        visited_urls: Set[str] = set()

        headers = dict(self.context.scope.custom_headers)
        cookies = dict(self.context.scope.session_cookies)

        async with httpx.AsyncClient(
            timeout=self.context.scope.timeout_seconds,
            verify=self.context.scope.verify_ssl,
            follow_redirects=False,
            trust_env=False,
            headers=headers,
            cookies=cookies
        ) as client:
            # 1. Root probe, Tech stack fingerprinting, Security headers, CORS
            await self._fingerprint_and_baseline(client, base_url)

            # 2. Check robots.txt
            await self._check_robots_txt(client, base_url)

            # 3. Check sitemap.xml
            await self._check_sitemap_xml(client, base_url)

            # 4. Check OpenAPI / Swagger specs
            await self._check_openapi_specs(client, base_url)

            # 5. Check well-known sensitive & GraphQL endpoints
            await self._check_common_endpoints(client, base_url)

            # 6. Crawl web pages starting from base URL
            await self._crawl_target(client, base_url, visited_urls, depth=0)

        self.context.stats.total_endpoints_discovered = len(self.context.endpoint_map)
        self.log(f"Deep Recon completed. Discovered {len(self.context.endpoint_map)} endpoints in scope.")

    def _register_endpoint(
        self,
        url: str,
        method: str = "GET",
        query_params: List[str] = None,
        body_params: List[str] = None,
        source: str = "crawl",
        status: int = None,
        snippet: str = None,
        response_time_ms: float = None,
        tech: List[str] = None,
        sec_headers: Dict[str, str] = None,
        missing_sec_headers: List[str] = None,
        cors_headers: Dict[str, str] = None,
        is_spa: bool = False,
        is_graphql: bool = False,
    ) -> Endpoint:
        parsed = urlparse(url)
        path = parsed.path or "/"
        endpoint_id = f"{method}:{path}"

        if query_params is None:
            query_params = list(parse_qs(parsed.query).keys())

        if endpoint_id not in self.context.endpoint_map:
            endpoint = Endpoint(
                id=endpoint_id,
                url=url,
                path=path,
                method=method,
                query_params=query_params or [],
                body_params=body_params or [],
                headers={},
                tech_fingerprint=tech or [],
                source=source,
                baseline_status=status,
                baseline_body_snippet=snippet,
                baseline_response_time_ms=response_time_ms,
                security_headers=sec_headers or {},
                missing_security_headers=missing_sec_headers or [],
                cors_headers=cors_headers or {},
                is_spa_route=is_spa,
                is_graphql=is_graphql or ("/graphql" in path.lower()),
            )
            self.context.endpoint_map[endpoint_id] = endpoint
            self.log(f"Discovered Endpoint [{method}] {path} via {source}")
            return endpoint
        else:
            existing = self.context.endpoint_map[endpoint_id]
            for q in (query_params or []):
                if q not in existing.query_params:
                    existing.query_params.append(q)
            for b in (body_params or []):
                if b not in existing.body_params:
                    existing.body_params.append(b)
            if is_graphql:
                existing.is_graphql = True
            return existing

    async def _fingerprint_and_baseline(self, client: httpx.AsyncClient, base_url: str) -> None:
        allowed, reason = await self.scope_guard.acquire_permission(base_url)
        if not allowed:
            self.log(f"Root request blocked by ScopeGuard: {reason}", level="WARNING")
            return

        try:
            # Baseline probe with CORS origin test
            resp = await client.get(base_url, headers={"Origin": "https://evil-attacker.com"})
            self.context.stats.total_requests_sent += 1

            tech = []
            for header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
                if header in resp.headers:
                    tech.append(f"{header}: {resp.headers[header]}")

            soup = BeautifulSoup(resp.text, "html.parser")
            meta_gen = soup.find("meta", attrs={"name": "generator"})
            if meta_gen and meta_gen.get("content"):
                tech.append(f"Generator: {meta_gen['content']}")

            # Inspect security headers
            sec_headers = {}
            missing_sec_headers = []
            resp_lower_headers = {k.lower(): v for k, v in resp.headers.items()}
            for sec_name in self.SECURITY_HEADER_NAMES:
                if sec_name in resp_lower_headers:
                    sec_headers[sec_name] = resp_lower_headers[sec_name]
                else:
                    missing_sec_headers.append(sec_name)

            # CORS headers
            cors_headers = {k: v for k, v in resp.headers.items() if k.lower().startswith("access-control-")}

            self._register_endpoint(
                url=base_url,
                method="GET",
                source="root_probe",
                status=resp.status_code,
                snippet=resp.text[:200],
                response_time_ms=resp.elapsed.total_seconds() * 1000,
                tech=tech,
                sec_headers=sec_headers,
                missing_sec_headers=missing_sec_headers,
                cors_headers=cors_headers,
            )
        except Exception as e:
            self.log(f"Error inspecting root endpoint: {e}", level="WARNING")

    async def _check_robots_txt(self, client: httpx.AsyncClient, base_url: str) -> None:
        url = urljoin(base_url, "/robots.txt")
        allowed, _ = await self.scope_guard.acquire_permission(url)
        if not allowed:
            return

        try:
            resp = await client.get(url)
            self.context.stats.total_requests_sent += 1
            if resp.status_code == 200:
                self.log("Discovered robots.txt! Extracting paths...")
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            target_path = parts[1].strip()
                            if target_path and target_path != "/":
                                full_url = urljoin(base_url, target_path)
                                self._register_endpoint(full_url, source="robots.txt")
        except Exception as e:
            self.log(f"robots.txt check failed: {e}", level="DEBUG")

    async def _check_sitemap_xml(self, client: httpx.AsyncClient, base_url: str) -> None:
        url = urljoin(base_url, "/sitemap.xml")
        allowed, _ = await self.scope_guard.acquire_permission(url)
        if not allowed:
            return

        try:
            resp = await client.get(url)
            self.context.stats.total_requests_sent += 1
            if resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", ""):
                root = ET.fromstring(resp.text)
                for loc in root.findall(".//{*}loc"):
                    if loc.text:
                        self._register_endpoint(loc.text.strip(), source="sitemap.xml")
        except Exception as e:
            self.log(f"sitemap.xml check failed: {e}", level="DEBUG")

    async def _check_openapi_specs(self, client: httpx.AsyncClient, base_url: str) -> None:
        candidates = ["/openapi.json", "/swagger.json", "/api-docs", "/api/openapi.json"]
        for path in candidates:
            url = urljoin(base_url, path)
            allowed, _ = await self.scope_guard.acquire_permission(url)
            if not allowed:
                continue
            try:
                resp = await client.get(url)
                self.context.stats.total_requests_sent += 1
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "paths" in data:
                            self.log(f"Discovered OpenAPI schema at {path}!")
                            for api_path, methods in data["paths"].items():
                                for http_method, details in methods.items():
                                    if http_method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                                        full_url = urljoin(base_url, api_path)
                                        params = [p.get("name") for p in details.get("parameters", []) if p.get("name")]
                                        self._register_endpoint(
                                            full_url,
                                            method=http_method.upper(),
                                            query_params=params,
                                            source="openapi_spec"
                                        )
                    except Exception:
                        pass
            except Exception:
                pass

    async def _check_common_endpoints(self, client: httpx.AsyncClient, base_url: str) -> None:
        for path in self.COMMON_SENSITIVE_PATHS:
            url = urljoin(base_url, path)
            allowed, _ = await self.scope_guard.acquire_permission(url)
            if not allowed:
                continue
            try:
                resp = await client.get(url, headers={"Origin": "https://evil-attacker.com"})
                self.context.stats.total_requests_sent += 1
                if resp.status_code in [200, 301, 302, 401, 403, 405]:
                    cors_headers = {k: v for k, v in resp.headers.items() if k.lower().startswith("access-control-")}
                    is_graphql = "/graphql" in path.lower() or "/query" in path.lower()
                    self._register_endpoint(
                        url,
                        method="GET",
                        source="sensitive_path_probe",
                        status=resp.status_code,
                        snippet=resp.text[:200],
                        response_time_ms=resp.elapsed.total_seconds() * 1000,
                        cors_headers=cors_headers,
                        is_graphql=is_graphql
                    )
            except Exception:
                pass

    async def _crawl_target(self, client: httpx.AsyncClient, current_url: str, visited: Set[str], depth: int) -> None:
        if depth > self.context.scope.max_crawl_depth or current_url in visited:
            return
        visited.add(current_url)

        allowed, _ = await self.scope_guard.acquire_permission(current_url)
        if not allowed:
            return

        try:
            resp = await client.get(current_url)
            self.context.stats.total_requests_sent += 1

            # Handle Redirects strictly through ScopeGuard validation
            if resp.status_code in [301, 302, 303, 307, 308] and "location" in resp.headers:
                redir_target = resp.headers["location"]
                allowed_redir, _ = self.scope_guard.validate_redirect(current_url, redir_target)
                if allowed_redir:
                    full_redir = urljoin(current_url, redir_target)
                    self._register_endpoint(full_redir, method="GET", source="crawler_redirect")
                    if full_redir not in visited and depth + 1 <= self.context.scope.max_crawl_depth:
                        await self._crawl_target(client, full_redir, visited, depth + 1)

            # Only invoke BeautifulSoup if response contains HTML tags
            if "<html" in resp.text.lower() or "<body" in resp.text.lower() or "<form" in resp.text.lower() or "<a " in resp.text.lower() or "<script" in resp.text.lower():
                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract Links <a href>
                for a in soup.find_all("a", href=True):
                    link = urljoin(current_url, a["href"])
                    valid_url, _ = self.scope_guard.validate_url(link)
                    if valid_url:
                        self._register_endpoint(link, method="GET", source="crawler_link")
                        if link not in visited and depth + 1 <= self.context.scope.max_crawl_depth:
                            await self._crawl_target(client, link, visited, depth + 1)

            # Extract Forms <form action method>
            for form in soup.find_all("form"):
                action = form.get("action") or current_url
                form_url = urljoin(current_url, action)
                form_method = (form.get("method") or "GET").upper()
                inputs = [inp.get("name") for inp in form.find_all(["input", "textarea", "select"]) if inp.get("name")]
                if form_method == "GET":
                    self._register_endpoint(form_url, method="GET", query_params=inputs, source="crawler_form")
                else:
                    self._register_endpoint(form_url, method=form_method, body_params=inputs, source="crawler_form")

            # Extract JS Scripts <script src> & inline scripts
            for script in soup.find_all("script"):
                if script.get("src"):
                    js_url = urljoin(current_url, script["src"])
                    valid_js, _ = self.scope_guard.validate_url(js_url)
                    if valid_js:
                        await self._mine_js_endpoints(client, js_url)
                elif script.string:
                    self._extract_endpoints_from_text(script.string, current_url)

        except Exception as e:
            self.log(f"Crawl error on {current_url}: {e}", level="DEBUG")

    async def _mine_js_endpoints(self, client: httpx.AsyncClient, js_url: str) -> None:
        allowed, _ = await self.scope_guard.acquire_permission(js_url)
        if not allowed:
            return
        try:
            resp = await client.get(js_url)
            self.context.stats.total_requests_sent += 1
            if resp.status_code == 200:
                self._extract_endpoints_from_text(resp.text, js_url)
        except Exception:
            pass

    def _extract_endpoints_from_text(self, text: str, source_url: str) -> None:
        # API Routes
        for pattern in self.API_REGEX_PATTERNS:
            for match in re.findall(pattern, text):
                full_url = urljoin(source_url, match)
                valid, _ = self.scope_guard.validate_url(full_url)
                if valid:
                    self._register_endpoint(full_url, method="GET", source="js_regex_mining")

        # Client-side SPA routes
        for spa_pat in self.SPA_ROUTE_PATTERNS:
            for match in re.findall(spa_pat, text):
                # Clean route parameters like /user/:id -> /user/1
                cleaned_path = re.sub(r':([a-zA-Z0-9_]+)', '1', match)
                full_url = urljoin(source_url, cleaned_path)
                valid, _ = self.scope_guard.validate_url(full_url)
                if valid:
                    self._register_endpoint(full_url, method="GET", source="spa_route_miner", is_spa=True)
