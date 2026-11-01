from __future__ import annotations
from datetime import datetime, timezone, timedelta
import ipaddress
import time
from typing import Any, Dict, Optional, Tuple
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.models import Attacker, GatewayRequestLog, VisitorSessionRisk
from app.services.broadcast import broadcast
from app.services.behaviour_risk import evaluate_routing_decision

# Trusted proxy networks (e.g. localhost, private GCP VPC)
TRUSTED_PROXIES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def extract_client_ip(headers: Dict[str, str], remote_addr: str) -> str:
    """
    Safely resolves the true client IP from forwarded headers.
    Only trusts X-Forwarded-For / X-Real-IP if received from trusted proxy infrastructure.
    """
    is_trusted = False
    try:
        remote_ip_obj = ipaddress.ip_address(remote_addr)
        is_trusted = any(remote_ip_obj in net for net in TRUSTED_PROXIES)
    except ValueError:
        is_trusted = False

    if is_trusted:
        x_forwarded = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For")
        if x_forwarded:
            first_ip = x_forwarded.split(",")[0].strip()
            try:
                ipaddress.ip_address(first_ip)
                return first_ip
            except ValueError:
                pass

        x_real = headers.get("x-real-ip") or headers.get("X-Real-IP")
        if x_real:
            try:
                ipaddress.ip_address(x_real.strip())
                return x_real.strip()
            except ValueError:
                pass

    return remote_addr


async def evaluate_gateway_routing(
    db: AsyncSession,
    client_ip: str,
    path: str = "/",
    method: str = "GET",
    session_id: Optional[str] = None,
) -> Tuple[str, float, str, Dict[str, Any]]:
    """
    Evaluates dynamic risk-based routing for an incoming request using
    continuous 0-100 behaviour risk scoring and independent-category safeguards:
    Returns (decision, risk_score, reason, telemetry_metadata)
    - 0-29: 'real' (Low risk - Real Application)
    - 30-49: 'real' (Medium risk - Real Application with enhanced monitoring)
    - 50-69: 'challenge' / 'real' (Elevated risk - Additional scrutiny)
    - 70-100: 'decoy' (High risk - Divert to isolated decoy honeypot application)
      Subject to independent-category safeguard (requires >= 2 independent categories)
    """
    start_time = time.time()
    now = datetime.now(timezone.utc)

    # 1. Resolve active session identifier
    active_session_id = session_id or f"sess_{client_ip.replace(':', '_')}"

    # 2. Check VisitorSessionRisk
    sess_stmt = select(VisitorSessionRisk).where(VisitorSessionRisk.session_id == active_session_id)
    sess_res = await db.execute(sess_stmt)
    sess = sess_res.scalar_one_or_none()

    # 3. Check Attacker profile for IP-level indicators
    stmt = select(Attacker).where(Attacker.ip == client_ip)
    res = await db.execute(stmt)
    attacker = res.scalar_one_or_none()

    sess_score = sess.risk_score if sess else 0.0
    atk_score = attacker.risk_score if attacker else 0.0
    fn_score = attacker.function_risk_score if attacker else 0.0

    # Unified risk score: considers session behaviour, IP risk, and function intelligence
    score = round(min(100.0, max(sess_score, atk_score, fn_score)), 2)

    active_cats = list(sess.active_categories if sess else [])
    if attacker and attacker.targeted_functions:
        cat_map = {
            "auth_login": "login_failures",
            "auth_otp": "otp_failures",
            "auth_reset": "password_reset",
            "admin_access": "admin_access",
            "secrets_env": "secrets_probing",
            "database_api": "database_access",
        }
        for tf in attacker.targeted_functions:
            mapped = cat_map.get(tf)
            if mapped and mapped not in active_cats:
                active_cats.append(mapped)

    independent_count = len([c for c in active_cats if c != "combined_patterns"])
    is_diverted = sess.is_diverted if sess else False

    # Independent category safeguard:
    # If a score is >= 70, require evidence from at least 2 independent categories
    # or established honeypot attacker / emergency policy.
    has_sufficient_evidence = (
        independent_count >= settings.decoy_min_independent_categories
        or (attacker and (attacker.risk_score >= 71.0 or attacker.function_risk_score >= 71.0))
        or settings.emergency_single_vector_divert
    )

    if is_diverted:
        decision = "decoy"
        reason = (sess.diversion_reason if sess else None) or "Session previously diverted to isolated honeypot; real application access prohibited."
    elif score >= settings.decoy_routing_threshold:
        if has_sufficient_evidence:
            decision = "decoy"
            cats_str = ", ".join([c for c in active_cats if c != "combined_patterns"]) or "multi-vector attack pattern"
            reason = f"Diverted to DECOY: Threat score {score:.1f}/100 confirmed by independent evidence ({cats_str})."
        else:
            cats_str = ", ".join(active_cats)
            decision = "real"
            reason = f"Elevated Scrutiny on REAL application: Threat score {score:.1f}/100 exceeds threshold but lacks confirmation from at least {settings.decoy_min_independent_categories} independent categories (active: {cats_str}). Safeguard prevented false-positive decoy routing."
    elif score >= 50.0:
        decision = "challenge"
        reason = f"Challenge / Scrutiny applied: Elevated risk score {score:.1f}/100 detected from previous activity."
    elif score >= 30.0:
        decision = "challenge"
        reason = f"Allowed to REAL application with enhanced monitoring: Risk score {score:.1f}/100."
    else:
        decision = "real"
        reason = f"Allowed to REAL application: Low risk score {score:.1f}/100 within legitimate tolerance."

    if sess:
        sess.risk_score = max(sess.risk_score, score)
        if decision == "decoy" and not sess.is_diverted:
            sess.is_diverted = True
            sess.diverted_at = now
            sess.current_route = "decoy"
            sess.diversion_reason = reason
            transitions = list(sess.routing_transitions or [])
            transitions.append({
                "transition": "REAL → DECOY",
                "session_id": active_session_id,
                "src_ip": client_ip,
                "score": score,
                "reason": reason,
                "timestamp": now.isoformat(),
            })
            sess.routing_transitions = transitions

    targeted_funcs = active_cats

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    # 2. Persist gateway telemetry log
    gateway_log = GatewayRequestLog(
        src_ip=client_ip,
        method=method,
        path=path,
        routed_to=decision,
        risk_score=score,
        decision_reason=reason,
        status_code=200 if decision != "blocked" else 403,
        response_time_ms=elapsed_ms,
        timestamp=now,
    )
    db.add(gateway_log)
    await db.flush()

    # 3. Broadcast live gateway telemetry over WebSocket
    try:
        await broadcast("gateway_routing", {
            "id": gateway_log.id,
            "src_ip": client_ip,
            "method": method,
            "path": path,
            "routed_to": decision,
            "risk_score": score,
            "decision_reason": reason,
            "response_time_ms": elapsed_ms,
            "timestamp": now.isoformat(),
        })
    except Exception:
        pass

    metadata = {
        "client_ip": client_ip,
        "risk_score": score,
        "decision": decision,
        "reason": reason,
        "targeted_functions": targeted_funcs,
        "elapsed_ms": elapsed_ms,
    }

    return decision, score, reason, metadata

