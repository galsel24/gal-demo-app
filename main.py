import time
from typing import Optional
from fastapi import FastAPI, Request, Response, Form, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Arcadia Demo Portal - F5 XC Workshop",
    description="Multi-purpose demo app for F5 Distributed Cloud WAF, Bot, API & Delivery labs",
    version="1.0.0"
)

# ---------------------------------------------------------
# Models for API Validation
# ---------------------------------------------------------
class TransferRequest(BaseModel):
    source_account: str = Field(..., example="ACC-100293")
    target_account: str = Field(..., example="ACC-994821")
    amount: float = Field(..., gt=0, example=250.00)
    currency: str = Field("USD", pattern="^(USD|EUR|ILS)$", example="USD")

# ---------------------------------------------------------
# Web Frontend Pages
# ---------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def home_page(request: Request):
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "Unknown")
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Arcadia Financial - F5 XC Demo</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; background: #0f172a; color: #f8fafc; }}
            nav {{ background: #1e293b; padding: 1rem 2rem; border-bottom: 2px solid #3b82f6; display: flex; justify-content: space-between; align-items: center; }}
            .container {{ max-width: 900px; margin: 2rem auto; padding: 1rem; }}
            .card {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); }}
            h2 {{ color: #60a5fa; margin-top: 0; }}
            a {{ color: #38bdf8; text-decoration: none; font-weight: 500; }}
            a:hover {{ text-decoration: underline; }}
            input, button {{ padding: 0.5rem; margin-top: 0.5rem; border-radius: 4px; border: 1px solid #475569; }}
            input {{ width: 280px; background: #0f172a; color: white; }}
            button {{ background: #2563eb; color: white; font-weight: bold; cursor: pointer; border: none; }}
            button:hover {{ background: #1d4ed8; }}
            code {{ background: #334155; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; }}
        </style>
    </head>
    <body>
        <nav>
            <h2 style="margin:0;">🛡️ Arcadia Financial Core Portal</h2>
            <div>Detected Client IP: <code>{client_ip}</code></div>
        </nav>
        <div class="container">
            <div class="card">
                <h2>1. HTTP Delivery & Inspection</h2>
                <p>Verify traffic steering, routing rules, TLS offloading, and mTLS headers passed by F5 XC.</p>
                <ul>
                    <li><a href="/headers">🔍 Inspect Request Headers & mTLS Identity</a></li>
                    <li><a href="/cache-test">⚡ CDN & Caching Verification</a></li>
                </ul>
            </div>

            <div class="card">
                <h2>2. WAAP & Security Verification (WAF & Bots)</h2>
                <p>Test WAF signatures, Threat Campaigns, and Bot Protection policies:</p>
                <form action="/login" method="post" style="margin-bottom: 1rem;">
                    <strong>Login Endpoint (Bot Defense & Brute Force Target):</strong><br>
                    <input type="text" name="username" placeholder="Username (e.g. admin)" required><br>
                    <input type="password" name="password" placeholder="Password" required><br>
                    <button type="submit">Submit Login</button>
                </form>
                <form action="/search" method="get">
                    <strong>Search Endpoint (WAF Attack Vector - SQLi / XSS):</strong><br>
                    <input type="text" name="query" placeholder="Search accounts (e.g. ' OR 1=1 --)" required><br>
                    <button type="submit">Execute Search</button>
                </form>
            </div>

            <div class="card">
                <h2>3. API Security & Discovery</h2>
                <p>Swagger-documented APIs vs. hidden shadow endpoints:</p>
                <ul>
                    <li><a href="/api/v1/accounts">📜 GET /api/v1/accounts (Documented)</a></li>
                    <li><a href="/api/v1/sensitive-data">🔒 GET /api/v1/sensitive-data (Data Leakage Demo)</a></li>
                    <li><a href="/api/v1/internal-debug">🕵️ GET /api/v1/internal-debug (Shadow API - Undocumented)</a></li>
                    <li><a href="/docs" target="_blank">📖 Open Interactive Swagger UI</a></li>
                </ul>
            </div>

            <div class="card">
                <h2>4. Troubleshooting & Latency Simulator</h2>
                <p>Simulate backend failures to test F5 XC dashboards and alerts:</p>
                <ul>
                    <li><a href="/simulate/502">💥 Trigger Bad Gateway (HTTP 502)</a></li>
                    <li><a href="/simulate/500">💥 Trigger Internal Server Error (HTTP 500)</a></li>
                    <li><a href="/simulate/latency?seconds=3">⏱️ Simulate 3-Second Backend Latency</a></li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """

# ---------------------------------------------------------
# Delivery, mTLS & Headers Inspection
# ---------------------------------------------------------
@app.get("/headers", response_class=HTMLResponse)
async def inspect_headers(request: Request):
    headers_rows = "".join([f"<tr><td style='padding:6px;border:1px solid #334155;'><strong>{k}</strong></td><td style='padding:6px;border:1px solid #334155;color:#38bdf8;'>{v}</td></tr>" for k, v in request.headers.items()])
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Headers & TLS Inspection</title></head>
    <body style="background:#0f172a;color:#f8fafc;font-family:sans-serif;padding:2rem;">
        <a href="/" style="color:#38bdf8;">← Back to Home</a>
        <h2>🔍 HTTP Headers Received by Backend (Origin)</h2>
        <p>Notice headers injected or altered by F5 XC (e.g., <code>X-Forwarded-For</code>, custom routing headers, or Client mTLS subject headers):</p>
        <table style="border-collapse:collapse;width:100%;max-width:850px;background:#1e293b;">
            <tr style="background:#334155;"><th>Header Name</th><th>Value</th></tr>
            {headers_rows}
        </table>
    </body>
    </html>
    """

# ---------------------------------------------------------
# CDN & Caching Verification
# ---------------------------------------------------------
@app.get("/cache-test")
async def cache_test(response: Response):
    response.headers["Cache-Control"] = "public, max-age=120"
    response.headers["X-Origin-Timestamp"] = str(time.time())
    return {
        "status": "success",
        "message": "If CDN caching is enabled on F5 XC LB, consecutive requests will show the SAME timestamp and XC Cache HIT header.",
        "server_generated_timestamp": time.time(),
        "cache_control": "public, max-age=120"
    }

# ---------------------------------------------------------
# WAF & Bot Targets
# ---------------------------------------------------------
@app.post("/login")
async def login_endpoint(username: str = Form(...), password: str = Form(...)):
    return {
        "status": "authentication_attempt",
        "user_received": username,
        "note": "If an attack or bot was detected, F5 XC WAF/Bot Defense will block this before reaching origin."
    }

@app.get("/search")
async def search_endpoint(query: str):
    return {
        "search_query": query,
        "results_found": 3,
        "message": f"Results for '{query}' returned successfully."
    }

# ---------------------------------------------------------
# Documented APIs
# ---------------------------------------------------------
@app.get("/api/v1/accounts")
async def get_accounts():
    return [
        {"account_id": "ACC-100293", "type": "Checking", "balance": 15420.50, "currency": "USD"},
        {"account_id": "ACC-994821", "type": "Savings", "balance": 98200.00, "currency": "USD"}
    ]

@app.post("/api/v1/transfer")
async def make_transfer(payload: TransferRequest):
    return {
        "transaction_id": f"TXN-{int(time.time())}",
        "status": "APPROVED",
        "details": payload.model_dump()
    }

@app.get("/api/v1/sensitive-data")
async def get_sensitive_data():
    return {
        "account_holder": "Jane Doe",
        "ssn": "123-45-6789",
        "credit_card": "4111-2221-8899-4455",
        "warning": "This endpoint serves sensitive PII/PCI data to test F5 XC data masking and sensitive endpoint tagging."
    }

# ---------------------------------------------------------
# Shadow API (Intentionally Omitted from OpenAPI spec)
# ---------------------------------------------------------
@app.get("/api/v1/internal-debug", tags=["Internal"])
async def internal_debug_endpoint():
    return {
        "service": "core-banking",
        "debug_mode": True,
        "cluster_node": "node-04b",
        "shadow_api_status": "This route is NOT declared in openapi_spec.json to trigger F5 XC API Discovery Shadow API detection!"
    }

# ---------------------------------------------------------
# Troubleshooting & Error Simulator
# ---------------------------------------------------------
@app.get("/simulate/502")
async def simulate_bad_gateway():
    raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Simulated 502 Bad Gateway response from Origin.")

@app.get("/simulate/500")
async def simulate_internal_error():
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Simulated 500 Internal Server Error.")

@app.get("/simulate/latency")
async def simulate_latency(seconds: int = 3):
    sleep_time = min(max(seconds, 1), 10)
    time.sleep(sleep_time)
    return {
        "delayed_seconds": sleep_time,
        "message": f"Successfully delayed response by {sleep_time} seconds to simulate upstream latency."
    }
