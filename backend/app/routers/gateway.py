from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy import desc, func, select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.db import get_db
from app.models import Attacker, GatewayRequestLog, FunctionTargetEvent
from app.services.gateway import evaluate_gateway_routing, extract_client_ip
from app.demo_apps.real_app import router as real_app_router
from app.demo_apps.decoy_app import router as decoy_app_router

router = APIRouter(prefix="/gateway", tags=["Deception Gateway & Dynamic Routing"])


class TrafficSimulateIn(BaseModel):
    src_ip: str
    path: str = "/auth/login"
    method: str = "POST"


class ResetVisitorIn(BaseModel):
    src_ip: Optional[str] = None


@router.post("/reset_visitor")
async def reset_visitor(
    request: Request,
    payload: Optional[ResetVisitorIn] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Controlled Demo Reset:
    Resets the visitor's risk score and clears their function targeting events,
    allowing an external tester to demonstrate normal -> suspicious -> diversion again from scratch.
    """
    remote_addr = request.client.host if request.client else "127.0.0.1"
    target_ip = (payload.src_ip if payload and payload.src_ip else None) or extract_client_ip(dict(request.headers), remote_addr)

    stmt = select(Attacker).where(Attacker.ip == target_ip)
    res = await db.execute(stmt)
    atk = res.scalar_one_or_none()
    if atk:
        atk.risk_score = 0.0
        atk.function_risk_score = 0.0
        atk.risk_band = "low"
        atk.highest_risk_function = None
        atk.targeted_functions = []
        atk.status = "active"

    del_stmt = delete(FunctionTargetEvent).where(FunctionTargetEvent.src_ip == target_ip)
    await db.execute(del_stmt)
    await db.commit()

    return {
        "status": "reset_complete",
        "ip": target_ip,
        "new_risk_score": 0.0,
        "message": f"Visitor {target_ip} threat profile successfully reset to 0. Next request routes to Real Application.",
    }


@router.get("/evaluate")
async def evaluate_nginx_auth_request(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    NGINX auth_request compatible evaluation endpoint.
    NGINX makes an internal subrequest to this endpoint before routing traffic.
    Sets 'X-Sentinel-Route' and returns HTTP 200 (allow) or HTTP 403 (decoy divert).
    """
    headers = dict(request.headers)
    remote_addr = request.client.host if request.client else "127.0.0.1"
    client_ip = extract_client_ip(headers, remote_addr)
    target_path = headers.get("x-original-uri") or headers.get("X-Original-URI") or "/"
    target_method = headers.get("x-original-method") or headers.get("X-Original-Method") or "GET"

    decision, score, reason, meta = await evaluate_gateway_routing(
        db=db,
        client_ip=client_ip,
        path=target_path,
        method=target_method,
    )
    await db.commit()

    # Set response headers for NGINX to inspect
    response.headers["X-Sentinel-Route"] = decision
    response.headers["X-Sentinel-Risk"] = str(score)
    response.headers["X-Sentinel-Client-IP"] = client_ip
    response.headers["X-Sentinel-Reason"] = reason[:200]

    return {
        "status": "evaluated",
        "route": decision,
        "risk_score": score,
        "reason": reason,
        "client_ip": client_ip,
    }


@router.get("/stats")
async def get_gateway_stats(db: AsyncSession = Depends(get_db)):
    """
    Returns aggregated metrics and recent routing logs for the Gateway SOC dashboard.
    """
    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)

    # 1. Total request counts by routed_to
    stmt_routes = (
        select(GatewayRequestLog.routed_to, func.count(GatewayRequestLog.id))
        .group_by(GatewayRequestLog.routed_to)
    )
    routes_res = await db.execute(stmt_routes)
    routes_dict = {row[0]: int(row[1]) for row in routes_res.all()}

    real_count = routes_dict.get("real", 0)
    decoy_count = routes_dict.get("decoy", 0)
    challenge_count = routes_dict.get("challenge", 0)
    blocked_count = routes_dict.get("blocked", 0)
    total_requests = real_count + decoy_count + challenge_count + blocked_count

    # 2. Distinct diverted attackers
    stmt_diverted = (
        select(func.count(func.distinct(GatewayRequestLog.src_ip)))
        .where(GatewayRequestLog.routed_to == "decoy")
    )
    diverted_res = await db.execute(stmt_diverted)
    diverted_attackers_count = int(diverted_res.scalar() or 0)

    # 3. Average response time
    stmt_avg_time = select(func.avg(GatewayRequestLog.response_time_ms))
    avg_time_res = await db.execute(stmt_avg_time)
    avg_response_time = round(float(avg_time_res.scalar() or 0.0), 2)

    # 4. Recent routing decisions
    stmt_recent = (
        select(GatewayRequestLog)
        .order_by(desc(GatewayRequestLog.timestamp))
        .limit(25)
    )
    recent_res = await db.execute(stmt_recent)
    recent_logs = [
        {
            "id": log.id,
            "src_ip": log.src_ip,
            "method": log.method,
            "path": log.path,
            "routed_to": log.routed_to,
            "risk_score": log.risk_score,
            "decision_reason": log.decision_reason,
            "response_time_ms": log.response_time_ms,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        }
        for log in recent_res.scalars().all()
    ]

    return {
        "gateway_status": "operational",
        "total_requests": total_requests,
        "real_traffic_count": real_count,
        "decoy_traffic_count": decoy_count,
        "challenge_traffic_count": challenge_count,
        "blocked_traffic_count": blocked_count,
        "diverted_attackers_count": diverted_attackers_count,
        "average_response_time_ms": avg_response_time,
        "routing_policy": {
            "real_threshold": "0 - 30",
            "challenge_threshold": "31 - 70",
            "decoy_threshold": "71 - 100",
        },
        "recent_decisions": recent_logs,
    }


@router.post("/simulate_traffic")
async def simulate_gateway_traffic(
    body: TrafficSimulateIn,
    db: AsyncSession = Depends(get_db),
):
    """
    Test endpoint for simulating a visitor accessing the gateway and evaluating
    whether they reach the Real Demo or are diverted to the Decoy.
    """
    decision, score, reason, meta = await evaluate_gateway_routing(
        db=db,
        client_ip=body.src_ip,
        path=body.path,
        method=body.method,
    )
    await db.commit()

    target_app_url = f"/demo/{decision}{body.path}"
    return {
        "status": "success",
        "client_ip": body.src_ip,
        "routed_to": decision,
        "risk_score": score,
        "decision_reason": reason,
        "dispatched_url": target_app_url,
    }


@router.get("/nginx-config")
async def get_nginx_configuration_template():
    """
    Returns the production NGINX reverse-proxy configuration template
    integrating auth_request with SENTINEL.
    """
    conf = """# SENTINEL Deception Gateway NGINX Configuration
# Dynamic Risk-Based Routing: Real vs Decoy Isolation

upstream sentinel_backend {
    server 127.0.0.1:8000;
    keepalive 32;
}

upstream real_application {
    server 127.0.0.1:8000; # Routes to /demo/real
}

upstream decoy_honeypot {
    server 127.0.0.1:8000; # Routes to /demo/decoy
}

server {
    listen 80;
    server_name sentinel.internal;

    # Trust only known upstream proxies
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    # 1. Gateway Risk Evaluation Subrequest
    location = /_sentinel_auth {
        internal;
        proxy_pass http://sentinel_backend/gateway/evaluate;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_connect_timeout 2s;
        proxy_read_timeout 2s;
    }

    # 2. Protected Gateway Entry Point
    location / {
        auth_request /_sentinel_auth;
        auth_request_set $sentinel_route $upstream_http_x_sentinel_route;
        auth_request_set $sentinel_risk $upstream_http_x_sentinel_risk;

        # Fallback to Real application if auth evaluation is unavailable
        error_page 500 502 503 504 = @fallback_real;

        # Divert to Decoy if threat threshold exceeded
        if ($sentinel_route = "decoy") {
            rewrite ^/(.*)$ /demo/decoy/$1 break;
            proxy_pass http://decoy_honeypot;
        }

        # Otherwise route to Real Application
        rewrite ^/(.*)$ /demo/real/$1 break;
        proxy_pass http://real_application;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location @fallback_real {
        rewrite ^/(.*)$ /demo/real/$1 break;
        proxy_pass http://real_application;
    }
}
"""
    return Response(content=conf, media_type="text/plain")

