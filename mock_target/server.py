from __future__ import annotations

import uvicorn
from fastapi import FastAPI, Response, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, RedirectResponse

app = FastAPI(
    title="BugScout Test Target (Deliberately Vulnerable App)",
    description="Safe local test application designed for verifying BugScout autonomous security agents.",
    version="2.0.0"
)


@app.get("/", response_class=HTMLResponse)
async def index():
    # Deliberately missing X-Frame-Options and CSP headers
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>BugScout Vulnerable Target Store</title>
        <meta name="generator" content="FastAPI / Python 3.11">
    </head>
    <body>
        <h1>Welcome to Vulnerable Target Store</h1>
        <p>This application is for authorized academic security testing only.</p>
        <nav>
            <ul>
                <li><a href="/search?q=gadgets">Search Catalog</a></li>
                <li><a href="/api/products?search=phone">API Products</a></li>
                <li><a href="/api/user/profile?id=1">User Profile</a></li>
                <li><a href="/api/user/private-data">Private Data (CORS)</a></li>
                <li><a href="/api/admin/dashboard">Admin Dashboard</a></li>
                <li><a href="/redirect?url=https://example.com">Redirect Gateway</a></li>
                <li><a href="/api/download?file=receipt.pdf">Download Document</a></li>
            </ul>
        </nav>
        <script src="/static/app.js"></script>
        <script>
            // Inline API fetch calls and SPA client routes
            fetch('/api/v1/recommendations?category=electronics');
            const routes = [
                { path: "/user/orders", component: "OrdersView" },
                { path: "/settings/security", component: "SecurityView" }
            ];
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return "User-agent: *\nDisallow: /admin/\nDisallow: /debug/\nDisallow: /.env\nDisallow: /graphql\n"


@app.get("/sitemap.xml", response_class=Response)
async def sitemap():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>http://127.0.0.1:8888/</loc></url>
        <url><loc>http://127.0.0.1:8888/search</loc></url>
        <url><loc>http://127.0.0.1:8888/api/products</loc></url>
        <url><loc>http://127.0.0.1:8888/api/user/private-data</loc></url>
    </urlset>
    """
    return Response(content=xml, media_type="application/xml")


@app.get("/search", response_class=HTMLResponse)
async def search_endpoint(q: str = ""):
    # Deliberately vulnerable to Reflected XSS
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h2>Search Results for: {q}</h2>
        <p>No products matched your search term.</p>
        <a href="/">Back to Home</a>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/api/products")
async def products_endpoint(search: str = ""):
    # Deliberately vulnerable to SQLi simulation
    if "'" in search or "1=1" in search or "OR" in search:
        if "'" in search and "1=1" not in search:
            return PlainTextResponse(
                "500 Internal Server Error: sqlite3.OperationalError: near \"syntax error in query\" at line 1",
                status_code=500
            )
        return JSONResponse(content=[
            {"id": 1, "name": "Laptop Pro", "price": 1299.99},
            {"id": 2, "name": "Smartphone Ultra", "price": 899.99},
            {"id": 3, "name": "Secret Enterprise Server", "price": 99999.00}
        ])

    return JSONResponse(content=[{"id": 1, "name": f"Product matching {search}", "price": 49.99}])


@app.get("/api/user/profile")
async def profile_endpoint(id: str = "1"):
    # Deliberately vulnerable to IDOR
    profiles = {
        "1": {"id": 1, "username": "alice", "email": "alice@example.com", "role": "user"},
        "2": {"id": 2, "username": "bob_admin", "email": "bob_admin@company.corp", "role": "admin", "api_token": "token_admin_98765"},
        "admin": {"id": 0, "username": "root_admin", "email": "admin@company.corp", "role": "superadmin"}
    }
    profile = profiles.get(id, {"id": id, "username": f"user_{id}", "email": f"user{id}@example.com"})
    return JSONResponse(content=profile)


@app.get("/api/user/private-data")
@app.options("/api/user/private-data")
async def cors_vulnerable_endpoint(request: Request):
    # Deliberately vulnerable to CORS Misconfiguration (Reflects Origin + Credentials True)
    origin = request.headers.get("Origin") or "https://evil-attacker.com"
    headers = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type"
    }
    return JSONResponse(content={
        "status": "confidential_user_data",
        "balance": "$94,200.00",
        "ssn_last4": "8842",
        "email": "executive_vip@corp.internal"
    }, headers=headers)


@app.post("/graphql")
@app.get("/graphql")
async def graphql_endpoint(request: Request):
    # Deliberately vulnerable to GraphQL Introspection
    return JSONResponse(content={
        "data": {
            "__schema": {
                "types": [
                    {"name": "User", "kind": "OBJECT"},
                    {"name": "CreditCard", "kind": "OBJECT"},
                    {"name": "InternalSecretKey", "kind": "OBJECT"},
                    {"name": "Query", "kind": "OBJECT"}
                ],
                "queryType": {"name": "Query"}
            }
        }
    })


@app.get("/redirect")
async def open_redirect_endpoint(url: str = "https://example.com"):
    # Deliberately vulnerable to Open URL Redirection
    return RedirectResponse(url=url, status_code=302)


@app.get("/api/download")
async def path_traversal_endpoint(file: str = "receipt.pdf"):
    # Deliberately vulnerable to Path Traversal simulation
    if ".." in file or "etc" in file or "win.ini" in file:
        return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n[boot loader]\n[fonts]\n", status_code=200)
    return PlainTextResponse(f"Simulated file content for {file}", status_code=200)


@app.get("/api/proxy")
async def proxy_endpoint(url: str = ""):
    # Deliberately vulnerable to SSRF probe simulation
    if "127.0.0.1" in url or "localhost" in url:
        return JSONResponse(content={"status": "fetched", "target": url, "response": "Internal Service OK"})
    return JSONResponse(content={"status": "error", "message": "Invalid host"})


@app.get("/api/admin/dashboard")
async def admin_dashboard(request: Request):
    # Deliberately missing authorization checks
    auth_header = request.headers.get("Authorization")
    return JSONResponse(content={
        "status": "admin_access_granted",
        "auth_received": auth_header or "None",
        "system_metrics": {"total_users": 1500, "total_revenue": "$450,000", "active_sessions": 84}
    })


@app.get("/.env", response_class=PlainTextResponse)
async def env_file():
    return "DB_PASSWORD=SuperSecretPass123!\nJWT_SECRET=super-secret-jwt-token-9988\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDEBUG=True\n"


@app.get("/debug/config")
async def debug_config():
    return JSONResponse(content={
        "debug": True,
        "database": {"host": "127.0.0.1", "port": 5432, "name": "production_db"},
        "api_version": "v2.0.0-dev"
    })


def run_target(host: str = "127.0.0.1", port: int = 8888):
    """Run target server directly."""
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    run_target()
