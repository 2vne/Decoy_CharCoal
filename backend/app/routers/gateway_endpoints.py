from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.models import Gateway, VisitorSessionRisk
from app.services.gateway import extract_client_ip
from app.services.behaviour_risk import record_behaviour_event
from app.services.gateway_lifecycle import on_gateway_attack, is_in_watch_mode

router = APIRouter(tags=["Protected Gateways Traffic"])


def _get_client_info(request: Request):
    remote_addr = request.client.host if request.client else "127.0.0.1"
    client_ip = extract_client_ip(dict(request.headers), remote_addr)
    sess_id = request.headers.get("x-session-id") or request.cookies.get("session_id") or f"sess_{client_ip.replace(':', '_')}"
    return client_ip, sess_id


async def _check_gateway_availability(gateway_id: str, db: AsyncSession) -> Gateway:
    stmt = select(Gateway).where(Gateway.id == gateway_id)
    res = await db.execute(stmt)
    gw = res.scalar_one_or_none()
    if not gw:
        raise HTTPException(status_code=404, detail=f"Gateway '{gateway_id}' not found")

    if gw.status == "taken_down":
        raise HTTPException(
            status_code=503,
            detail=f"503 Service Unavailable: Gateway '{gw.name}' has been taken down for incident containment.",
            headers={"X-Gateway-Status": "taken_down"},
        )
    if gw.status == "fixing":
        raise HTTPException(
            status_code=503,
            detail=f"503 Service Unavailable: Gateway '{gw.name}' is offline while active security remediation is in progress.",
            headers={"X-Gateway-Status": "fixing"},
        )

    return gw


# ---------------- PAYMENT GATEWAY (/api/payment) ----------------

@router.api_route("/payment", methods=["GET", "POST", "PUT", "DELETE"])
@router.api_route("/payment/{subpath:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def payment_gateway_proxy(
    request: Request,
    subpath: str = "",
    db: AsyncSession = Depends(get_db),
):
    """
    Traffic router for Payment Gateway (/api/payment):
    Checks gateway availability (503 if taken_down or fixing).
    Monitors for suspicious manipulation or attack patterns.
    Triggers gateway lifecycle transition to 'attacked' (or 'reattack_after_restore') when risk >= 51.
    """
    gw = await _check_gateway_availability("payment", db)
    client_ip, session_id = _get_client_info(request)

    # In watch mode, apply threshold drop
    in_watch, _ = is_in_watch_mode(gw)

    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="ignore")

    # Inspect for attack patterns or simulated payloads
    is_malicious = (
        request.method in ("POST", "PUT") and
        ("manipulate" in subpath.lower() or "bypass" in body_text.lower() or "override" in body_text.lower() or "hack" in body_text.lower() or "' OR " in body_text or "token" in subpath.lower() or "charge" in subpath.lower() or "exploit" in body_text.lower())
    ) or ("attack" in subpath.lower()) or (request.headers.get("x-simulate-attack") == "true")

    # Check if header or query explicitly sets risk
    force_attack = request.query_params.get("attack") == "true" or is_malicious

    if force_attack:
        now = datetime.now(timezone.utc)
        risk_result = await record_behaviour_event(
            db=db,
            session_id=session_id,
            src_ip=client_ip,
            category="payment_gateway",
            endpoint=f"/api/payment/{subpath}" if subpath else "/api/payment",
            event_type="payment_manipulation",
            evidence=f"Payment transaction tampering / unauthorized authorization on {request.url.path}",
            is_critical=True,
            critical_reason="Payment gateway authorization tampering attempt",
            now=now,
        )
        current_risk = risk_result.get("risk_score", 65.0)
        # If risk >= 51 or critical, trigger gateway attack auto-rule
        if current_risk >= 51.0 or is_malicious:
            attack_req = {
                "path": request.url.path,
                "method": request.method,
                "src_ip": client_ip,
                "payload": body_text[:500],
                "headers": dict(request.headers),
            }
            await on_gateway_attack(gw, current_risk, attack_req, db, now=now)
            await db.commit()

        raise HTTPException(
            status_code=402,
            detail="Payment Authorization Failed: Security policy violation detected. Transaction rejected.",
            headers={"X-Gateway-Status": gw.status, "X-Sentinel-Risk": str(current_risk)},
        )

    return {
        "gateway": gw.name,
        "status": gw.status,
        "is_watch_mode": in_watch,
        "message": "Payment gateway operational.",
    }


# ---------------- AUTH GATEWAY (/api/auth) ----------------

@router.api_route("/auth", methods=["GET", "POST"])
@router.api_route("/auth/{subpath:path}", methods=["GET", "POST"])
async def auth_gateway_proxy(
    request: Request,
    subpath: str = "",
    db: AsyncSession = Depends(get_db),
):
    """
    Traffic router for Authentication Gateway (/api/auth).
    Checks gateway availability (503 if taken_down or fixing).
    """
    gw = await _check_gateway_availability("auth", db)
    client_ip, session_id = _get_client_info(request)
    in_watch, _ = is_in_watch_mode(gw)

    return {
        "gateway": gw.name,
        "status": gw.status,
        "is_watch_mode": in_watch,
        "message": "Authentication gateway operational.",
    }

