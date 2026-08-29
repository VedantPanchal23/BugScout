from __future__ import annotations

import html
import os
import uvicorn
from fastapi import FastAPI, Response, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

benchmark_app = FastAPI(
    title="BugScout Security Benchmark Lab",
    description="Ground-truth security testbed with controlled vulnerabilities and safe negative decoys.",
    version="1.0.0"
)


# ============================================================================
# 1. ROOT & RECONNAISSANCE DISCOVERY (T04, T11, T12, T13)
# ============================================================================

@benchmark_app.get("/", response_class=HTMLResponse)
async def index():
    # T04: Deliberately missing X-Frame-Options and CSP
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>BugScout Benchmark Target</title>
        <meta name="generator" content="FastAPI Benchmark / Python 3.11">
    </head>
    <body>
        <h1>BugScout Security Benchmark Lab</h1>
        <nav>
            <ul>
                <!-- Vulnerable Endpoints -->
                <li><a href="/search?q=test">Search (XSS - T02)</a></li>
                <li><a href="/api/products?search=phone">Products (SQLi - T01)</a></li>
                <li><a href="/api/user/profile?id=1">Profile (IDOR - T06)</a></li>
                <li><a href="/api/user/private-data">Private Data (CORS - T03)</a></li>
                <li><a href="/api/admin/dashboard">Admin Dashboard (Broken Auth - T10)</a></li>
                <li><a href="/redirect?url=https://example.com">Redirect (Open Redirect - T07)</a></li>
                <li><a href="/api/download?file=receipt.pdf">Download (Path Traversal - T08)</a></li>

                <!-- Safe Negative Decoys -->
                <li><a href="/safe-headers">Safe Headers (T04-N)</a></li>
                <li><a href="/safe-echo?name=Alice">Safe Echo (T02-N)</a></li>
                <li><a href="/api/safe-search?q=phone">Safe Search (T01-N)</a></li>
                <li><a href="/api/safe-cors">Safe CORS (T03-N)</a></li>
                <li><a href="/api/safe-profile?id=1">Safe Profile (T06-N)</a></li>
                <li><a href="/safe-redirect?url=/home">Safe Redirect (T07-N)</a></li>
                <li><a href="/api/safe-download?file=doc.txt">Safe Download (T08-N)</a></li>
                <li><a href="/safe-info">Safe Info (T09-N)</a></li>
                <li><a href="/api/admin/secure">Safe Admin (T10-N)</a></li>
            </ul>
        </nav>
        <script src="/static/bundle.js"></script>
        <script>
            // T11: API Route Discovery in JS
            fetch('/api/v1/internal-status');
            // T12: SPA Route Mining in JS
            const routes = [
                { path: "/settings/security", component: "SecuritySettings" },
                { path: "/user/orders", component: "UserOrders" }
            ];
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@benchmark_app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    # T13: Recon via robots.txt
    return "User-agent: *\nDisallow: /admin/\nDisallow: /debug/config\nDisallow: /.env\nDisallow: /graphql\nDisallow: /safe-graphql\n"


@benchmark_app.get("/sitemap.xml", response_class=Response)
async def sitemap(request: Request):
    # T13: Recon via sitemap.xml
    base = str(request.base_url).rstrip("/")
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>{base}/</loc></url>
        <url><loc>{base}/search</loc></url>
        <url><loc>{base}/api/products</loc></url>
        <url><loc>{base}/api/safe-search</loc></url>
        <url><loc>{base}/safe-echo</loc></url>
    </urlset>
    """
    return Response(content=xml, media_type="application/xml")


# ============================================================================
# 2. VULNERABLE ENDPOINTS (T01 - T10)
# ============================================================================

# T01: SQL Injection (Vulnerable)
@benchmark_app.get("/api/products")
async def products_endpoint(search: str = ""):
    if "'" in search or "1=1" in search or "OR" in search:
        if "'" in search and "1=1" not in search:
            return PlainTextResponse(
                "500 Internal Server Error: sqlite3.OperationalError: near \"syntax error in query\" at line 1",
                status_code=500
            )
        return JSONResponse(content=[
            {"id": 1, "name": "Laptop Pro", "price": 1299.99},
            {"id": 2, "name": "Smartphone Ultra", "price": 899.99}
        ])
    return JSONResponse(content=[{"id": 1, "name": f"Product matching {search}", "price": 49.99}])


# T02: Reflected XSS (Vulnerable)
@benchmark_app.get("/search", response_class=HTMLResponse)
async def search_endpoint(q: str = ""):
    return HTMLResponse(content=f"<html><body><h2>Search Results for: {q}</h2></body></html>")


# T03: CORS Misconfiguration (Vulnerable)
@benchmark_app.get("/api/user/private-data")
@benchmark_app.options("/api/user/private-data")
async def cors_vulnerable_endpoint(request: Request):
    origin = request.headers.get("Origin") or "https://evil-attacker.com"
    headers = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
    }
    return JSONResponse(content={"secret": "confidential_user_token_987"}, headers=headers)


# T05: GraphQL Introspection (Vulnerable)
@benchmark_app.post("/graphql")
@benchmark_app.get("/graphql")
async def graphql_endpoint(request: Request):
    return JSONResponse(content={
        "data": {
            "__schema": {
                "types": [{"name": "User"}, {"name": "CreditCard"}, {"name": "Query"}]
            }
        }
    })


# T06: IDOR (Vulnerable)
@benchmark_app.get("/api/user/profile")
async def profile_endpoint(id: str = "1"):
    profiles = {
        "1": {"id": 1, "username": "alice", "role": "user"},
        "2": {"id": 2, "username": "bob_admin", "email": "bob@corp.internal", "role": "admin"},
        "admin": {"id": 0, "username": "root_admin", "role": "superadmin"}
    }
    return JSONResponse(content=profiles.get(id, {"id": id, "username": f"user_{id}"}))


# T07: Open Redirect (Vulnerable)
@benchmark_app.get("/redirect")
async def open_redirect_endpoint(url: str = "https://example.com"):
    return RedirectResponse(url=url, status_code=302)


# T08: Path Traversal (Vulnerable)
@benchmark_app.get("/api/download")
async def path_traversal_endpoint(file: str = "receipt.pdf"):
    if ".." in file or "etc" in file or "win.ini" in file:
        return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:\n[boot loader]\n", status_code=200)
    return PlainTextResponse(f"Simulated file content for {file}", status_code=200)


# T09: Sensitive Credential Leak (Vulnerable)
@benchmark_app.get("/.env", response_class=PlainTextResponse)
async def env_file():
    return "DB_PASSWORD=SuperSecretPass123!\nJWT_SECRET=super-secret-jwt-token-9988\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"


# T10: Broken Authentication (Vulnerable)
@benchmark_app.get("/api/admin/dashboard")
async def admin_dashboard(request: Request):
    return JSONResponse(content={"status": "admin_access_granted", "metrics": {"revenue": "$450,000"}})


# ============================================================================
# 3. SAFE NEGATIVE DECOYS (T01-N - T10-N)
# ============================================================================

# T01-N: Safe Parameterized Search (Decoy)
@benchmark_app.get("/api/safe-search")
async def safe_search_endpoint(q: str = ""):
    # Safely handles quotes and SQL probes without leaking database syntax errors
    return JSONResponse(content={"query": q, "results": [], "status": "safe_parameterized_execution"})


# T02-N: Safe HTML Encoded Echo (Decoy)
@benchmark_app.get("/safe-echo", response_class=HTMLResponse)
async def safe_echo_endpoint(name: str = ""):
    safe_name = html.escape(name)
    return HTMLResponse(content=f"<html><body><h2>Hello, {safe_name}</h2></body></html>")


# T03-N: Safe Whitelisted CORS (Decoy)
@benchmark_app.get("/api/safe-cors")
async def safe_cors_endpoint():
    headers = {"Access-Control-Allow-Origin": "https://trusted-domain.corp"}
    return JSONResponse(content={"status": "safe_cors"}, headers=headers)


# T04-N: Safe Hardened Security Headers (Decoy)
@benchmark_app.get("/safe-headers", response_class=HTMLResponse)
async def safe_headers_endpoint():
    headers = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff"
    }
    return HTMLResponse(content="<html><body>Hardened Page</body></html>", headers=headers)


# T05-N: Safe Production GraphQL (Decoy)
@benchmark_app.post("/safe-graphql")
async def safe_graphql_endpoint():
    return JSONResponse(
        content={"errors": [{"message": "GraphQL schema introspection is disabled in production."}]},
        status_code=400
    )


# T06-N: Safe Authorized Profile (Decoy)
@benchmark_app.get("/api/safe-profile")
async def safe_profile_endpoint(id: str = "1", request: Request = None):
    # Returns 403 Forbidden if accessing other user IDs without ownership
    if id != "1":
        return JSONResponse(content={"error": "Access Denied: Session does not own requested resource."}, status_code=403)
    return JSONResponse(content={"id": 1, "username": "alice", "status": "authorized"})


# T07-N: Safe Whitelisted Redirect (Decoy)
@benchmark_app.get("/safe-redirect")
async def safe_redirect_endpoint(url: str = "/home"):
    # Only allows relative paths; rejects third-party external origins and protocol-relative //
    if url.startswith("http://") or url.startswith("https://") or url.startswith("//") or "://" in url:
        return RedirectResponse(url="/home", status_code=302)
    return RedirectResponse(url=url, status_code=302)


# T08-N: Safe Sanitized File Download (Decoy)
@benchmark_app.get("/api/safe-download")
async def safe_download_endpoint(file: str = "doc.txt"):
    safe_name = os.path.basename(file)
    return PlainTextResponse(f"Safe contents of {safe_name}", status_code=200)


# T09-N: Safe Public Metadata (Decoy)
@benchmark_app.get("/safe-info")
async def safe_info_endpoint():
    return JSONResponse(content={"application": "Benchmark Lab", "status": "healthy", "version": "1.0"})


# T10-N: Safe Protected Admin Route (Decoy)
@benchmark_app.get("/api/admin/secure")
async def safe_admin_endpoint(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or "Bearer secret_admin_token" not in auth_header:
        return JSONResponse(content={"error": "Unauthorized: Valid token required"}, status_code=401)
    return JSONResponse(content={"status": "admin_granted"})


# Recon target
@benchmark_app.get("/api/v1/internal-status")
async def internal_status():
    return JSONResponse(content={"system": "ok", "uptime": 3600})


@benchmark_app.get("/debug/config")
async def debug_config():
    return JSONResponse(content={"debug": True, "env": "benchmark"})


def run_benchmark_server(host: str = "127.0.0.1", port: int = 8888):
    uvicorn.run(benchmark_app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    run_benchmark_server()
