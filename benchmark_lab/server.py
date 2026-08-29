from __future__ import annotations

import html
import os
import json
import uvicorn
from fastapi import FastAPI, Response, Request, Form
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

benchmark_app = FastAPI(
    title="BugScout Security Benchmark Lab (Academic Edition)",
    description="Ground-truth security testbed with multi-variant vulnerabilities, deceptive negative decoys, 2-user IDOR, and multi-framework routers.",
    version="3.0.0"
)

from benchmark_lab.multi_framework_adapter import get_multi_framework_router
benchmark_app.include_router(get_multi_framework_router())


# ============================================================================
# 1. ROOT & RECONNAISSANCE ATTACK SURFACE (T04, T11, T12, T13)
# ============================================================================

@benchmark_app.get("/", response_class=HTMLResponse)
async def index():
    # HDR-01 (T04): Deliberately missing X-Frame-Options and CSP
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>BugScout Benchmark Lab v2.0</title>
        <meta name="generator" content="FastAPI Benchmark / Python 3.11">
    </head>
    <body>
        <h1>BugScout Academic Security Benchmark Lab v2.0</h1>
        <nav>
            <ul>
                <!-- Vulnerable Multi-Variant Endpoints -->
                <li><a href="/search?q=test">Search (XSS-01)</a></li>
                <li><a href="/profile/view?user=alice">Profile View (XSS-02)</a></li>
                <li><a href="/app/config?theme=dark">App Config (XSS-03)</a></li>
                <li><a href="/api/products?search=laptop">Products (SQLi-01)</a></li>
                <li><a href="/api/orders?id=101">Orders (SQLi-04)</a></li>
                <li><a href="/api/analytics?metric=views">Analytics (SQLi-05)</a></li>
                <li><a href="/api/user/profile?id=1">Profile (IDOR-01)</a></li>
                <li><a href="/api/v2/orders?order_id=501">Invoice (IDOR-02)</a></li>
                <li><a href="/api/user/private-data">Private Data (CORS-01)</a></li>
                <li><a href="/api/v2/user-session">User Session (CORS-02)</a></li>
                <li><a href="/api/v2/cors-null">CORS Null (CORS-03)</a></li>
                <li><a href="/api/admin/dashboard">Admin Dashboard (AUTH-01)</a></li>
                <li><a href="/api/v2/admin/config">Admin Config (AUTH-02)</a></li>
                <li><a href="/redirect?url=https://example.com">Redirect (RED-01)</a></li>
                <li><a href="/goto?dest=https://attacker.org">Goto (RED-02)</a></li>
                <li><a href="/api/download?file=receipt.pdf">Download (TRAV-01)</a></li>
                <li><a href="/api/v2/read-log?path=app.log">Read Log (TRAV-02)</a></li>
                <li><a href="/api/v2/system-file?name=config.ini">System File (TRAV-03)</a></li>

                <!-- Safe Negative Decoys -->
                <li><a href="/safe-headers">Safe Headers (HDR-N01)</a></li>
                <li><a href="/safe-echo?name=Alice">Safe Echo (XSS-N01)</a></li>
                <li><a href="/api/safe-json?q=test">Safe JSON (XSS-N02)</a></li>
                <li><a href="/api/safe-search?q=phone">Safe Search (SQLi-N01)</a></li>
                <li><a href="/api/safe-products?desc=phone">Safe Syntax Text (SQLi-N02)</a></li>
                <li><a href="/api/safe-cors">Safe CORS (CORS-N01)</a></li>
                <li><a href="/api/safe-cors-no-creds">Safe CORS No Creds (CORS-N02)</a></li>
                <li><a href="/api/safe-profile?id=1">Safe Profile (IDOR-N01)</a></li>
                <li><a href="/api/public-catalog?item_id=42">Public Catalog (IDOR-N02)</a></li>
                <li><a href="/safe-redirect?url=/home">Safe Redirect (RED-N01)</a></li>
                <li><a href="/safe-goto?dest=/settings">Safe Goto (RED-N02)</a></li>
                <li><a href="/api/safe-download?file=doc.txt">Safe Download (TRAV-N01)</a></li>
                <li><a href="/api/safe-docs?doc=guide.pdf">Safe Docs (TRAV-N02)</a></li>
                <li><a href="/safe-info">Safe Info (SEC-N01)</a></li>
                <li><a href="/api/admin/secure">Safe Admin (AUTH-N01)</a></li>
                <li><a href="/api/admin/invalid-token">Safe Invalid Auth (AUTH-N02)</a></li>
                <li><a href="/api/admin/expired-token">Safe Expired Auth (AUTH-N03)</a></li>
                <li><a href="/api/admin/user-role">Safe Role Auth (AUTH-N04)</a></li>
            </ul>
        </nav>
        <script src="/static/bundle.js"></script>
        <script>
            // T11: API Route Discovery in JS
            fetch('/api/v1/internal-status');
            fetch('/api/v2/items');
            fetch('/api/v2/search');
            // T12: SPA Route Mining in JS
            const routes = [
                { path: "/settings/security", component: "SecuritySettings" },
                { path: "/user/orders", component: "UserOrders" },
                { path: "/catalog/item", component: "CatalogItem" }
            ];
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@benchmark_app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return "User-agent: *\nDisallow: /admin/\nDisallow: /debug/config\nDisallow: /.env\nDisallow: /config.json\nDisallow: /graphql\nDisallow: /safe-graphql\nDisallow: /catalog/item\nDisallow: /portal/view\nDisallow: /legacy/read\n"


@benchmark_app.get("/sitemap.xml", response_class=Response)
async def sitemap(request: Request):
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
# 2. VULNERABLE MULTI-VARIANT ENDPOINTS (SQLi, XSS, CORS, Traversal, Redirect)
# ============================================================================

# SQLi-01: GET search parameter
@benchmark_app.get("/api/products")
async def products_endpoint(search: str = ""):
    if "'" in search or "1=1" in search or "OR" in search:
        if "'" in search and "1=1" not in search:
            return PlainTextResponse("500 Internal Server Error: sqlite3.OperationalError: near \"syntax error in query\" at line 1", status_code=500)
        return JSONResponse(content=[{"id": 1, "name": "Laptop Pro", "price": 1299.99}])
    return JSONResponse(content=[{"id": 1, "name": f"Product matching {search}", "price": 49.99}])


# SQLi-02: POST Form parameter
@benchmark_app.post("/api/v2/search")
async def post_search_endpoint(request: Request):
    body_text = (await request.body()).decode("utf-8", errors="ignore")
    if "'" in body_text:
        return PlainTextResponse("500 Internal Server Error: sqlite3.OperationalError: near 'syntax error'", status_code=500)
    return JSONResponse(content={"results": [body_text]})


# SQLi-03: POST JSON Body filter
class FilterRequest(BaseModel):
    filter: str = ""

@benchmark_app.post("/api/v2/items")
async def json_items_endpoint(req: FilterRequest):
    if "'" in req.filter:
        return PlainTextResponse("500 Internal Server Error: sqlite3.OperationalError: syntax error near filter", status_code=500)
    return JSONResponse(content={"items": [{"id": 1, "filter": req.filter}]})


# SQLi-04: Numeric ID parameter
@benchmark_app.get("/api/orders")
async def orders_numeric_sqli(id: str = "101"):
    if "'" in id or "1=1" in id:
        return PlainTextResponse("500 Internal Server Error: sqlite3.OperationalError: near 'syntax error'", status_code=500)
    return JSONResponse(content={"order_id": id, "total": 199.50})


# SQLi-05: Order By / Time-based delay
@benchmark_app.get("/api/analytics")
async def analytics_sqli(metric: str = "views"):
    if "'" in metric or "SLEEP" in metric or "WAITFOR" in metric:
        return PlainTextResponse("500 Internal Server Error: sqlite3.OperationalError: near metric syntax", status_code=500)
    return JSONResponse(content={"metric": metric, "value": 4200})


# XSS-01: HTML Body Reflection
@benchmark_app.get("/search", response_class=HTMLResponse)
async def search_endpoint(q: str = ""):
    return HTMLResponse(content=f"<html><body><h2>Search Results for: {q}</h2></body></html>")


# XSS-02: Attribute Context Reflection (value="...")
@benchmark_app.get("/profile/view", response_class=HTMLResponse)
async def profile_attr_xss(user: str = "alice"):
    return HTMLResponse(content=f'<html><body><input type="text" name="user" value="{user}"></body></html>')


# XSS-03: JavaScript Context Reflection
@benchmark_app.get("/app/config", response_class=HTMLResponse)
async def script_context_xss(theme: str = "dark"):
    return HTMLResponse(content=f'<html><head><script>const currentTheme = "{theme}";</script></head><body>Theme Config</body></html>')


# CORS-01: Wildcard + Credentials
@benchmark_app.get("/api/user/private-data")
@benchmark_app.options("/api/user/private-data")
async def cors_wildcard_endpoint(request: Request):
    origin = request.headers.get("Origin") or "https://attacker.org"
    return JSONResponse(
        content={"secret": "confidential_user_token_987"},
        headers={"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}
    )


# CORS-02: Reflected Origin + Credentials
@benchmark_app.get("/api/v2/user-session")
async def cors_reflected_endpoint(request: Request):
    origin = request.headers.get("Origin") or "https://evil.example"
    return JSONResponse(
        content={"session": "active_sess_3321"},
        headers={"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}
    )


# CORS-03: Null Origin Allowed
@benchmark_app.get("/api/v2/cors-null")
async def cors_null_endpoint():
    return JSONResponse(
        content={"data": "unprotected_null_origin"},
        headers={"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"}
    )


# IDOR-01: Two-Identity Profile Access (User A accesses User B)
@benchmark_app.get("/api/user/profile")
async def profile_idor(id: str = "1", request: Request = None):
    auth_header = request.headers.get("Authorization", "")
    # User A token is 'Bearer token_user_a', but accessing id=2 returns Bob's private admin profile
    profiles = {
        "1": {"id": 1, "username": "alice", "role": "user", "email": "alice@corp.internal"},
        "2": {"id": 2, "username": "bob_admin", "role": "admin", "ssn": "999-00-1234"},
    }
    return JSONResponse(content=profiles.get(id, {"id": id, "username": f"user_{id}"}))


# IDOR-02: Order Invoice Lookup (User A accesses User B order)
@benchmark_app.get("/api/v2/orders")
async def orders_idor(order_id: str = "501"):
    return JSONResponse(content={"order_id": order_id, "customer_ssn": "000-12-3456", "total": 999.00})


# AUTH-01: Unauthenticated Admin Dashboard
@benchmark_app.get("/api/admin/dashboard")
async def admin_dashboard():
    return JSONResponse(content={"status": "admin_access_granted", "metrics": {"revenue": "$450,000"}})


# AUTH-02: Missing Token Admin Config
@benchmark_app.get("/api/v2/admin/config")
async def admin_config():
    return JSONResponse(content={"status": "admin_access_granted", "jwt_secret": "insecure_admin_key"})


# TRAV-01: Standard Path Traversal
@benchmark_app.get("/api/download")
async def path_traversal_endpoint(file: str = "receipt.pdf"):
    if ".." in file or "etc" in file or "win.ini" in file:
        return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:\n[boot loader]\n", status_code=200)
    return PlainTextResponse(f"Simulated file content for {file}", status_code=200)


# TRAV-02: Encoded Path Traversal
@benchmark_app.get("/api/v2/read-log")
async def encoded_path_traversal(path: str = "app.log"):
    if ".." in path or "%2e" in path or "etc" in path:
        return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\n", status_code=200)
    return PlainTextResponse(f"Log contents for {path}", status_code=200)


# TRAV-03: Windows Traversal
@benchmark_app.get("/api/v2/system-file")
async def windows_path_traversal(name: str = "config.ini"):
    if "win.ini" in name or ".." in name:
        return PlainTextResponse("[boot loader]\ntimeout=30\ndefault=multi(0)\n", status_code=200)
    return PlainTextResponse("System file OK", status_code=200)


# RED-01: Open Redirect Query Param
@benchmark_app.get("/redirect")
async def open_redirect_endpoint(url: str = "https://example.com"):
    return RedirectResponse(url=url, status_code=302)


# RED-02: Open Redirect Goto Param
@benchmark_app.get("/goto")
async def goto_redirect_endpoint(dest: str = "https://attacker.org"):
    return RedirectResponse(url=dest, status_code=302)


# SEC-01: Exposed .env file
@benchmark_app.get("/.env", response_class=PlainTextResponse)
async def env_file():
    return "DB_PASSWORD=SuperSecretPass123!\nJWT_SECRET=super-secret-jwt-token-9988\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"


# SEC-02: Exposed config.json
@benchmark_app.get("/config.json")
async def config_json():
    return JSONResponse(content={"api_key": "live_sk_99381928312", "stripe_secret": "sk_test_51Nz812"})


# GQL-01: GraphQL Schema Introspection
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


# ============================================================================
# 3. DECEPTIVE NEGATIVE DECOYS (Stress-Testing Evidence Discrimination)
# ============================================================================

# SQLi-N01: Parameterized Safe Search
@benchmark_app.get("/api/safe-search")
async def safe_search_endpoint(q: str = ""):
    return JSONResponse(content={"query": q, "results": [], "status": "safe_parameterized_execution"})


# SQLi-N02: Deceptive Text Decoy (Returns text 'syntax error' safely in JSON)
@benchmark_app.get("/api/safe-products")
async def safe_products_text_decoy(desc: str = ""):
    return JSONResponse(content={"description": desc, "warning": "Notice: product syntax error checks passed cleanly without database execution."})


# XSS-N01: Safe HTML-escaped Echo
@benchmark_app.get("/safe-echo", response_class=HTMLResponse)
async def safe_echo_endpoint(name: str = ""):
    safe_name = html.escape(name)
    return HTMLResponse(content=f"<html><body><h2>Hello, {safe_name}</h2></body></html>")


# XSS-N02: Safe JSON Reflection (application/json)
@benchmark_app.get("/api/safe-json")
async def safe_json_endpoint(q: str = ""):
    return JSONResponse(content={"query": q, "format": "json_escaped"})


# CORS-N01: Static Whitelisted Origin
@benchmark_app.get("/api/safe-cors")
async def safe_cors_endpoint():
    return JSONResponse(content={"status": "safe_cors"}, headers={"Access-Control-Allow-Origin": "https://trusted-domain.corp"})


# CORS-N02: Wildcard Without Credentials
@benchmark_app.get("/api/safe-cors-no-creds")
async def safe_cors_no_creds():
    return JSONResponse(content={"public": "data"}, headers={"Access-Control-Allow-Origin": "*"})


# IDOR-N01: Session-Validated Profile (Returns 403 on ID Mismatch)
@benchmark_app.get("/api/safe-profile")
async def safe_profile_endpoint(id: str = "1"):
    if id != "1":
        return JSONResponse(content={"error": "Access Denied: Session does not own requested resource."}, status_code=403)
    return JSONResponse(content={"id": 1, "username": "alice", "status": "authorized"})


# IDOR-N02: Intentionally Public Item Lookup
@benchmark_app.get("/api/public-catalog")
async def public_catalog_endpoint(item_id: str = "42"):
    return JSONResponse(content={"item_id": item_id, "title": f"Public Catalog Product #{item_id}", "access": "public"})


# AUTH-N01: Anonymous request returns 401
@benchmark_app.get("/api/admin/secure")
async def safe_admin_endpoint(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or "Bearer secret_admin_token" not in auth_header:
        return JSONResponse(content={"error": "Unauthorized: Valid admin token required"}, status_code=401)
    return JSONResponse(content={"status": "admin_granted"})


# AUTH-N02: Invalid token returns 401
@benchmark_app.get("/api/admin/invalid-token")
async def safe_invalid_auth_endpoint(request: Request):
    return JSONResponse(content={"error": "Invalid token signature"}, status_code=401)


# AUTH-N03: Expired token returns 401
@benchmark_app.get("/api/admin/expired-token")
async def safe_expired_auth_endpoint(request: Request):
    return JSONResponse(content={"error": "Token expired at timestamp"}, status_code=401)


# AUTH-N04: Normal user token returns 403 Forbidden
@benchmark_app.get("/api/admin/user-role")
async def safe_user_role_auth_endpoint(request: Request):
    return JSONResponse(content={"error": "Forbidden: Requires role 'admin', user has role 'standard'"}, status_code=403)


# TRAV-N01: Sanitized File Download with os.path.basename
@benchmark_app.get("/api/safe-download")
async def safe_download_endpoint(file: str = "doc.txt"):
    safe_name = os.path.basename(file)
    return PlainTextResponse(f"Safe contents of {safe_name}", status_code=200)


# TRAV-N02: Whitelisted Document Download
@benchmark_app.get("/api/safe-docs")
async def safe_docs_endpoint(doc: str = "guide.pdf"):
    allowed = ["guide.pdf", "manual.pdf", "terms.txt"]
    if doc not in allowed:
        return PlainTextResponse("File not found in document directory.", status_code=404)
    return PlainTextResponse(f"Contents of {doc}", status_code=200)


# RED-N01: Whitelisted Relative-Only Redirect
@benchmark_app.get("/safe-redirect")
async def safe_redirect_endpoint(url: str = "/home"):
    if url.startswith("http://") or url.startswith("https://") or url.startswith("//") or "://" in url:
        return RedirectResponse(url="/home", status_code=302)
    return RedirectResponse(url=url, status_code=302)


# RED-N02: Internal Domain Whitelist
@benchmark_app.get("/safe-goto")
async def safe_goto_endpoint(dest: str = "/settings"):
    if "attacker.org" in dest or "evil.com" in dest:
        return RedirectResponse(url="/settings", status_code=302)
    return RedirectResponse(url=dest, status_code=302)


# SEC-N01: Safe Public Metadata
@benchmark_app.get("/safe-info")
async def safe_info_endpoint():
    return JSONResponse(content={"application": "Benchmark Lab", "status": "healthy", "version": "2.0.0"})


# GQL-N01: Production GraphQL with Introspection Disabled
@benchmark_app.post("/safe-graphql")
async def safe_graphql_endpoint():
    return JSONResponse(content={"errors": [{"message": "GraphQL schema introspection is disabled in production."}]}, status_code=400)


# HDR-N01: Hardened Headers (X-Frame-Options: DENY & CSP)
@benchmark_app.get("/safe-headers", response_class=HTMLResponse)
async def safe_headers_endpoint():
    headers = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff"
    }
    return HTMLResponse(content="<html><body>Hardened Page</body></html>", headers=headers)


# ============================================================================
# 4. UNSEEN / GENERALIZATION BENCHMARK CASES
# ============================================================================

@benchmark_app.get("/catalog/item")
async def unseen_sqli(query: str = "item1"):
    if "'" in query:
        return PlainTextResponse("500 Internal Server Error: sqlite3.OperationalError: near 'syntax error'", status_code=500)
    return JSONResponse(content={"item": query})


@benchmark_app.get("/portal/view", response_class=HTMLResponse)
async def unseen_xss(name: str = "guest"):
    return HTMLResponse(content=f"<html><body>Portal View: {name}</body></html>")


@benchmark_app.get("/legacy/read")
async def unseen_traversal(doc: str = "readme.txt"):
    if ".." in doc:
        return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\n", status_code=200)
    return PlainTextResponse(f"Reading legacy {doc}", status_code=200)


@benchmark_app.get("/api/v1/internal-status")
async def internal_status():
    return JSONResponse(content={"system": "ok", "uptime": 7200})


@benchmark_app.get("/debug/config")
async def debug_config():
    return JSONResponse(content={"debug": True, "env": "benchmark_v2"})


def run_benchmark_server(host: str = "127.0.0.1", port: int = 8888):
    uvicorn.run(benchmark_app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    run_benchmark_server()
