from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.models import Gateway, AdvisoryStepStatus, Incident
from app.services.broadcast import broadcast
from app.services.audit import record_audit


GATEWAY_CATEGORY_MAP = {
    "payment": ["payment_gateway", "payment_manipulation", "checkout"],
    "auth": ["authentication_login", "two_factor_otp", "login_failures", "otp_failures", "password_reset"],
    "admin": ["admin_panel", "admin_access", "admin_escalation"],
}


def is_in_watch_mode(gw: Gateway, now: Optional[datetime] = None) -> Tuple[bool, float]:
    """
    Returns (is_active, remaining_seconds) for the gateway watch window.
    """
    now_utc = now or datetime.now(timezone.utc)
    if not gw.watch_until:
        return False, 0.0
    wu = gw.watch_until if gw.watch_until.tzinfo else gw.watch_until.replace(tzinfo=timezone.utc)
    rem = (wu - now_utc).total_seconds()
    if rem > 0:
        return True, round(rem, 1)
    return False, 0.0


async def check_gateway_reattack(
    gw: Gateway,
    now: Optional[datetime] = None,
) -> bool:
    """
    Checks if a new attack constitutes a RE-ATTACK after restore:
    Triggered if gateway status is currently 'restored' and now < watch_until,
    OR within REATTACK_WINDOW_MIN (default 60 min) of restored_at.
    """
    now_utc = now or datetime.now(timezone.utc)
    is_watch, _ = is_in_watch_mode(gw, now_utc)
    if gw.status == "restored" and is_watch:
        return True

    if gw.restored_at:
        ra = gw.restored_at if gw.restored_at.tzinfo else gw.restored_at.replace(tzinfo=timezone.utc)
        diff_min = (now_utc - ra).total_seconds() / 60.0
        if diff_min <= float(settings.reattack_window_min):
            return True

    return False


async def on_gateway_attack(
    gw: Gateway,
    risk_score: float,
    attack_request: Dict[str, Any],
    db: AsyncSession,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Auto-rule when a request with risk >= 51 hits the gateway:
    - Checks for reattack_after_restore
    - Transitions gateway status to 'attacked'
    - Appends attack request to last_attack_sequence
    - Records status history
    - Escalates incident severity if reattack
    - Broadcasts live WebSocket event
    """
    now_utc = now or datetime.now(timezone.utc)
    is_reattack = await check_gateway_reattack(gw, now_utc)

    if is_reattack:
        gw.reattack_after_restore = True
        gw.reattack_count = (gw.reattack_count or 0) + 1

    old_status = gw.status
    gw.status = "attacked"
    gw.updated_at = now_utc

    # Append to status history
    history = list(gw.status_history or [])
    note = f"Automated attack detection: risk score {risk_score:.1f}"
    if is_reattack:
        note += f" [RE-ATTACK #{gw.reattack_count} after restore!]"
    history.append({
        "status": "attacked",
        "timestamp": now_utc.isoformat(),
        "note": note,
        "actor": "system_auto",
        "risk_score": risk_score,
        "is_reattack": is_reattack,
    })
    gw.status_history = history

    # Append to last attack sequence (cap at last 20 requests)
    seq = list(gw.last_attack_sequence or [])
    seq.append({
        "timestamp": now_utc.isoformat(),
        "path": attack_request.get("path", gw.endpoint_prefix),
        "method": attack_request.get("method", "POST"),
        "payload": attack_request.get("payload", {}),
        "headers": attack_request.get("headers", {}),
        "src_ip": attack_request.get("src_ip", "unknown"),
        "risk_score": risk_score,
    })
    gw.last_attack_sequence = seq[-20:]

    # Reset last verify result on new attack
    gw.last_verify_result = None

    await db.flush()

    # If re-attack, escalate open incidents linked to this gateway/target
    if is_reattack:
        inc_stmt = (
            select(Incident)
            .where(Incident.status.in_(["new", "investigating"]))
            .order_by(Incident.created_at.desc())
        )
        inc_res = await db.execute(inc_stmt)
        for inc in inc_res.scalars().all():
            inc.title = f"[ESCALATED: RE-ATTACK] {inc.title}"
            inc_history = list(inc.status_history or [])
            inc_history.append({
                "status": inc.status,
                "ts": now_utc.isoformat(),
                "note": f"Incident escalated: Gateway '{gw.name}' re-attacked after restore (count={gw.reattack_count}).",
            })
            inc.status_history = inc_history

    # Broadcast WebSocket notification
    event_payload = {
        "gateway_id": gw.id,
        "name": gw.name,
        "status": gw.status,
        "previous_status": old_status,
        "risk_score": risk_score,
        "is_reattack": is_reattack,
        "reattack_count": gw.reattack_count,
        "timestamp": now_utc.isoformat(),
    }
    try:
        await broadcast("gateway_status_update", event_payload)
        if is_reattack:
            await broadcast("gateway_reattack", event_payload)
    except Exception:
        pass

    return event_payload


async def check_safe_to_reopen(
    gw: Gateway,
    db: AsyncSession,
) -> Tuple[bool, List[str]]:
    """
    Safe to reopen indicator stays AMBER (False) until:
    1. Verification passes (last_verify_result['status'] == 'passed').
    2. Any required before_reopening steps are done or verified.
    """
    reasons = []

    # 1. Verification check
    if not gw.last_verify_result:
        reasons.append("Hardening verification replay has not been executed yet.")
    elif gw.last_verify_result.get("status") != "passed":
        reasons.append(f"Hardening verification failed: {gw.last_verify_result.get('details', 'Tripwire still triggered')}")

    # 2. Steps check
    step_stmt = select(AdvisoryStepStatus).where(
        AdvisoryStepStatus.gateway_id == gw.id,
    )
    step_res = await db.execute(step_stmt)
    steps = step_res.scalars().all()
    pending_steps = [s.step_id for s in steps if s.status == "pending"]
    if pending_steps:
        reasons.append(f"{len(pending_steps)} remediation step(s) still pending.")

    is_safe = len(reasons) == 0
    return is_safe, reasons

