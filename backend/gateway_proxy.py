"""
SENTINEL Standalone Deception Gateway Proxy
Mirrors the exact NGINX auth_request dynamic routing pipeline:
Client -> Gateway -> Risk Evaluation (/gateway/evaluate) -> Real App OR Decoy Honeynet App
"""
from __future__ import annotations
import argparse
import sys
from typing import Any, Dict
import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import Response as StarletteResponse

app = FastAPI(title="SENTINEL Deception Reverse-Proxy Gateway")

BACKEND_BASE_URL = "http://127.0.0.1:8000"


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def deception_gateway_proxy(full_path: str, request: Request):
    """
    Reverse proxy entry point:
    1. Evaluates client IP and risk using SENTINEL internal auth_request.
    2. Routes to Real (/demo/real/{path}) or Decoy (/demo/decoy/{path}).
    3. Streams response back with security telemetry headers.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    # Respect forwarded headers if present
    x_forwarded = request.headers.get("x-forwarded-for")
    if x_forwarded:
        client_ip = x_forwarded.split(",")[0].strip()

    req_path = f"/{full_path}" if not full_path.startswith("/") else full_path
    req_method = request.method

    target_service = "real"
    risk_score = 0.0

    async with httpx.AsyncClient(base_url=BACKEND_BASE_URL, timeout=5.0) as client:
        # Step 1: Gateway Subrequest (NGINX auth_request equivalent)
        try:
            auth_eval = await client.get(
                "/api/gateway/evaluate",
                headers={
                    "x-original-uri": req_path,
                    "x-original-method": req_method,
                    "x-real-ip": client_ip,
                    "x-forwarded-for": client_ip,
                },
            )
            if auth_eval.status_code == 200:
                route_decision = auth_eval.headers.get("x-sentinel-route", "real")
                target_service = route_decision
                risk_score = float(auth_eval.headers.get("x-sentinel-risk", "0.0"))
        except Exception:
            # Safe fallback to real application on evaluation failure
            target_service = "real"

        # Step 2: Rewrite destination based on threat evaluation
        if target_service == "decoy":
            upstream_path = f"/demo/decoy{req_path}"
        else:
            upstream_path = f"/demo/real{req_path}"

        # Step 3: Forward request payload to upstream target
        body = await request.body()
        forward_headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
        forward_headers["x-real-ip"] = client_ip
        forward_headers["x-forwarded-for"] = client_ip

        try:
            upstream_resp = await client.request(
                method=req_method,
                url=upstream_path,
                headers=forward_headers,
                content=body,
                params=dict(request.query_params),
            )
            resp_content = upstream_resp.content
            resp_status = upstream_resp.status_code
            resp_headers = dict(upstream_resp.headers)
        except httpx.HTTPError as err:
            return StarletteResponse(
                content=f'{{"error": "Gateway Upstream Failure: {str(err)}"}}',
                status_code=502,
                media_type="application/json",
            )

    # Attach gateway telemetry headers
    resp_headers["X-Sentinel-Gateway"] = "active"
    resp_headers["X-Sentinel-Routed-To"] = target_service
    resp_headers["X-Sentinel-Evaluated-Risk"] = str(risk_score)

    # Strip hop-by-hop headers
    for h in ("content-encoding", "transfer-encoding", "connection"):
        resp_headers.pop(h, None)

    return StarletteResponse(
        content=resp_content,
        status_code=resp_status,
        headers=resp_headers,
        media_type=upstream_resp.headers.get("content-type", "application/json"),
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL Deception Gateway")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8088, help="Port to listen on (default: 8088)")
    args = parser.parse_args()

    print(f"[*] Starting SENTINEL Deception Gateway on {args.host}:{args.port}")
    print(f"[*] Upstream Backend: {BACKEND_BASE_URL}")
    print(f"[*] Gateway Routing: 0-30 Real | 31-70 Challenge | 71-100 Decoy")
    uvicorn.run("gateway_proxy:app", host=args.host, port=args.port, log_level="info")
