from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy import desc, func, select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.db import get_db
from app.models import (
    Attacker,
    GatewayRequestLog,
    FunctionTargetEvent,
    VisitorSessionRisk,
    ObservedBehaviourEvent,
    AccountRiskHistory,
)
from app.services.gateway import evaluate_gateway_routing, extract_client_ip
from app.services.behaviour_risk import (
    record_behaviour_event,
    compute_behaviour_risk_score,
    get_configured_allocations,
    BEHAVIOUR_CATEGORIES,
)
from app.demo_apps.real_app import router as real_app_router
from app.demo_apps.decoy_app import router as decoy_app_router

router = APIRouter(prefix="/gateway", tags=["Deception Gateway & Dynamic Routing"])


class TrafficSimulateIn(BaseModel):
    src_ip: str
    path: str = "/auth/login"
    method: str = "POST"


class ResetVisitorIn(BaseModel):
    src_ip: Optional[str] = None


class ResetSessionIn(BaseModel):
    session_id: str


@router.post("/reset_visitor")
async def reset_visitor(
    request: Request,
    payload: Optional[ResetVisitorIn] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Controlled Demo Reset:
    Resets the visitor's risk score and clears their function targeting events and behaviour records,
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

    # Reset visitor session risk records
    sess_stmt = select(VisitorSessionRisk).where(VisitorSessionRisk.src_ip == target_ip)
    sess_res = await db.execute(sess_stmt)
    for sess in sess_res.scalars().all():
        sess.risk_score = 0.0
        sess.previous_risk_score = 0.0
        sess.risk_classification = "NORMAL"
        sess.category_scores = {}
        sess.active_categories = []
        sess.independent_categories_count = 0
        sess.reason_codes = []
        sess.current_route = "real"
        sess.is_diverted = False
        sess.diverted_at = None
        sess.diversion_reason = None
        sess.routing_transitions = []

    del_stmt = delete(FunctionTargetEvent).where(FunctionTargetEvent.src_ip == target_ip)
    await db.execute(del_stmt)

    del_beh_stmt = delete(ObservedBehaviourEvent).where(ObservedBehaviourEvent.src_ip == target_ip)
    await db.execute(del_beh_stmt)

    await db.commit()

    return {
        "status": "reset_complete",
        "ip": target_ip,
        "new_risk_score": 0.0,
        "message": f"Visitor {target_ip} threat profile successfully reset to 0. Next request routes to Real Application.",
    }


@router.post("/reset_session")
async def reset_session_endpoint(
    payload: ResetSessionIn,
    db: AsyncSession = Depends(get_db),
):
    """
    Resets an isolated demonstration session without deleting real visitor telemetry.
    """
    target_sid = payload.session_id.strip()
    if not target_sid:
        raise HTTPException(status_code=400, detail="session_id cannot be empty")

    from app.demo_apps.real_app import REVOKED_SESSIONS, REVOKED_TOKENS
    REVOKED_SESSIONS.discard(target_sid)

    # Delete observed behaviour events ONLY for this session
    del_stmt = delete(ObservedBehaviourEvent).where(ObservedBehaviourEvent.session_id == target_sid)
    await db.execute(del_stmt)

    # Reset VisitorSessionRisk record ONLY for this session
    sess_stmt = select(VisitorSessionRisk).where(VisitorSessionRisk.session_id == target_sid)
    sess_res = await db.execute(sess_stmt)
    sess = sess_res.scalar_one_or_none()
    if sess:
        # Reconcile attacker IP profile for demo isolation
        atk_stmt = select(Attacker).where(Attacker.ip == sess.src_ip)
        atk_res = await db.execute(atk_stmt)
        atk = atk_res.scalar_one_or_none()
        if atk:
            atk.risk_score = 0.0
            atk.function_risk_score = 0.0
            atk.risk_band = "low"
            atk.status = "active"

        sess.risk_score = 0.0
        sess.previous_risk_score = 0.0
        sess.risk_classification = "NORMAL"
        sess.category_scores = {}
        sess.active_categories = []
        sess.independent_categories_count = 0
        sess.reason_codes = []
        sess.current_route = "real"
        sess.is_diverted = False
        sess.diverted_at = None
        sess.diversion_reason = None
        sess.routing_transitions = []
        sess.last_seen = datetime.now(timezone.utc)

    await db.commit()

    return {
        "status": "reset_complete",
        "session_id": target_sid,
        "new_risk_score": 0.0,
        "message": f"Demonstration session {target_sid} reset successfully. Real visitor telemetry preserved.",
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
    session_id = (
        headers.get("x-session-id")
        or headers.get("X-Session-ID")
        or request.cookies.get("sentinel_session")
        or f"sess_{client_ip.replace(':', '_')}"
    )

    decision, score, reason, meta = await evaluate_gateway_routing(
        db=db,
        client_ip=client_ip,
        path=target_path,
        method=target_method,
        session_id=session_id,
    )
    await db.commit()

    # Set response headers for NGINX to inspect
    response.headers["X-Sentinel-Route"] = decision
    response.headers["X-Sentinel-Risk"] = str(score)
    response.headers["X-Sentinel-Client-IP"] = client_ip
    response.headers["X-Sentinel-Session"] = session_id
    response.headers["X-Sentinel-Reason"] = reason[:200]

    return {
        "status": "evaluated",
        "route": decision,
        "risk_score": score,
        "session_id": session_id,
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

    # 5. Diverted visitor sessions
    stmt_sess_div = select(func.count(VisitorSessionRisk.id)).where(VisitorSessionRisk.is_diverted == True)
    div_sess_res = await db.execute(stmt_sess_div)
    diverted_sessions_count = int(div_sess_res.scalar() or 0)

    return {
        "gateway_status": "operational",
        "total_requests": total_requests,
        "real_traffic_count": real_count,
        "decoy_traffic_count": decoy_count,
        "challenge_traffic_count": challenge_count,
        "blocked_traffic_count": blocked_count,
        "diverted_attackers_count": diverted_attackers_count,
        "diverted_sessions_count": diverted_sessions_count,
        "average_response_time_ms": avg_response_time,
        "routing_policy": {
            "real_threshold": "0 - 29",
            "challenge_threshold": "30 - 69",
            "decoy_threshold": "70 - 100",
            "safeguard": "Minimum 2 independent categories required for automatic decoy diversion",
        },
        "point_allocations": get_configured_allocations(),
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


class BehaviourEventIn(BaseModel):
    session_id: str
    src_ip: str
    category: str
    endpoint: str = ""
    event_type: str = "probe"
    evidence: str = ""
    account_email: Optional[str] = None
    is_simulated: bool = False


@router.post("/behaviour_event")
async def ingest_behaviour_event_api(
    payload: BehaviourEventIn,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingests an observed behaviour event, recomputes rolling 0-100 risk score,
    and updates session/routing states with safeguards.
    """
    result = await record_behaviour_event(
        db=db,
        session_id=payload.session_id,
        src_ip=payload.src_ip,
        category=payload.category,
        endpoint=payload.endpoint,
        event_type=payload.event_type,
        evidence=payload.evidence,
        account_email=payload.account_email,
        is_simulated=payload.is_simulated,
    )
    await db.commit()
    return result


@router.get("/sessions")
async def list_visitor_sessions(
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns active visitor sessions with continuously updated 0-100 behaviour scores.
    """
    stmt = (
        select(VisitorSessionRisk)
        .order_by(desc(VisitorSessionRisk.last_seen))
        .limit(limit)
    )
    res = await db.execute(stmt)
    sessions = res.scalars().all()
    return {
        "total": len(sessions),
        "point_allocations": get_configured_allocations(),
        "categories": BEHAVIOUR_CATEGORIES,
        "sessions": [
            {
                "session_id": s.session_id,
                "src_ip": s.src_ip,
                "account_email": s.account_email,
                "risk_score": s.risk_score,
                "previous_risk_score": s.previous_risk_score,
                "risk_classification": s.risk_classification,
                "category_scores": s.category_scores,
                "active_categories": s.active_categories,
                "independent_categories_count": s.independent_categories_count,
                "reason_codes": s.reason_codes,
                "current_route": s.current_route,
                "is_diverted": s.is_diverted,
                "diverted_at": s.diverted_at.isoformat() if s.diverted_at else None,
                "diversion_reason": s.diversion_reason,
                "routing_transitions": s.routing_transitions or [],
                "request_count": s.request_count,
                "first_seen": s.first_seen.isoformat() if s.first_seen else None,
                "last_seen": s.last_seen.isoformat() if s.last_seen else None,
            }
            for s in sessions
        ],
    }


@router.get("/session/{session_id}")
async def get_visitor_session_risk(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns full behaviour breakdown, 0-100 score, severity mappings, transition history,
    and post-diversion decoy interactions for a session.
    """
    stmt = select(VisitorSessionRisk).where(VisitorSessionRisk.session_id == session_id)
    res = await db.execute(stmt)
    sess = res.scalar_one_or_none()
    if not sess:
        raise HTTPException(status_code=404, detail="Visitor session not found")

    # Fetch post-diversion decoy interactions
    decoy_interactions = []
    if sess.is_diverted:
        decoy_stmt = (
            select(FunctionTargetEvent)
            .where(
                FunctionTargetEvent.src_ip == sess.src_ip,
                FunctionTargetEvent.honeypot_source == "decoy_app",
            )
            .order_by(desc(FunctionTargetEvent.timestamp))
            .limit(20)
        )
        decoy_res = await db.execute(decoy_stmt)
        decoy_interactions = [
            {
                "id": ev.id,
                "target_function": ev.target_function,
                "target_endpoint": ev.target_endpoint,
                "attack_type": ev.attack_type,
                "severity": ev.severity,
                "result": ev.result,
                "evidence": ev.evidence,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            }
            for ev in decoy_res.scalars().all()
        ]

    return {
        "session_id": sess.session_id,
        "src_ip": sess.src_ip,
        "account_email": sess.account_email,
        "risk_score": sess.risk_score,
        "previous_risk_score": sess.previous_risk_score,
        "risk_classification": sess.risk_classification,
        "category_scores": sess.category_scores,
        "active_categories": sess.active_categories,
        "independent_categories_count": sess.independent_categories_count,
        "reason_codes": sess.reason_codes,
        "current_route": sess.current_route,
        "is_diverted": sess.is_diverted,
        "diverted_at": sess.diverted_at.isoformat() if sess.diverted_at else None,
        "diversion_reason": sess.diversion_reason,
        "routing_transitions": sess.routing_transitions or [],
        "decoy_interactions": decoy_interactions,
        "decoy_interactions_count": len(decoy_interactions),
        "request_count": sess.request_count,
        "first_seen": sess.first_seen.isoformat() if sess.first_seen else None,
        "last_seen": sess.last_seen.isoformat() if sess.last_seen else None,
    }

