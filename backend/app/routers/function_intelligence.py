from __future__ import annotations
import asyncio
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.db import get_db
from app.models import Attacker, FunctionTargetEvent
from app.schemas import FunctionTargetEventIn, FunctionTargetEventOut
from app.services.function_intelligence import (
    FUNCTION_METADATA,
    compute_bounded_function_risk,
    record_function_targeting,
    sanitize_text,
    execute_demo_action,
    execute_demo_recon_sequence,
    stop_demo_simulation,
    reset_demo_session,
    get_demo_status,
)
from app.services.ingest import get_or_create_attacker

router = APIRouter(prefix="/intelligence/functions", tags=["Function Intelligence"])


def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> None:
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid X-API-Key")


@router.get("", response_model=Dict[str, Any])
async def list_function_events(
    attacker_id: Optional[int] = Query(None, description="Filter by attacker ID"),
    target_function: Optional[str] = Query(None, description="Filter by function key"),
    is_simulated: Optional[bool] = Query(None, description="Filter by simulation status"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(FunctionTargetEvent).order_by(desc(FunctionTargetEvent.timestamp)).limit(limit)
    if attacker_id:
        stmt = stmt.where(FunctionTargetEvent.attacker_id == attacker_id)
    if target_function:
        stmt = stmt.where(FunctionTargetEvent.target_function == target_function)
    if is_simulated is not None:
        stmt = stmt.where(FunctionTargetEvent.is_simulated == is_simulated)

    res = await db.execute(stmt)
    items = res.scalars().all()

    return {
        "count": len(items),
        "events": [
            FunctionTargetEventOut(
                id=e.id,
                attacker_id=e.attacker_id,
                src_ip=e.src_ip,
                target_function=e.target_function,
                target_endpoint=sanitize_text(e.target_endpoint),
                attack_type=e.attack_type,
                severity=e.severity,
                result=e.result,
                attempts=e.attempts,
                honeypot_source=e.honeypot_source,
                evidence=sanitize_text(e.evidence),
                confidence=e.confidence,
                is_simulated=e.is_simulated,
                timestamp=e.timestamp.isoformat() if e.timestamp else None,
            )
            for e in items
        ],
    }


@router.get("/stats")
async def get_function_intelligence_stats(db: AsyncSession = Depends(get_db)):
    # 1. Total attempts per function
    stmt_counts = (
        select(FunctionTargetEvent.target_function, func.sum(FunctionTargetEvent.attempts))
        .group_by(FunctionTargetEvent.target_function)
    )
    counts_res = await db.execute(stmt_counts)
    counts_dict = {row[0]: int(row[1]) for row in counts_res.all()}

    # 2. Separate observed vs simulated counts
    stmt_sim_counts = (
        select(FunctionTargetEvent.is_simulated, func.sum(FunctionTargetEvent.attempts))
        .group_by(FunctionTargetEvent.is_simulated)
    )
    sim_res = await db.execute(stmt_sim_counts)
    sim_dict = {bool(row[0]): int(row[1]) for row in sim_res.all()}
    observed_count = sim_dict.get(False, 0)
    simulated_count = sim_dict.get(True, 0)
    total_events = observed_count + simulated_count

    most_targeted = []
    for fn_key, meta in FUNCTION_METADATA.items():
        count = counts_dict.get(fn_key, 0)
        most_targeted.append({
            "key": fn_key,
            "name": meta["name"],
            "category": meta["category"],
            "weight": settings.function_weights.get(fn_key, meta["default_weight"]),
            "attempts": count,
        })
    most_targeted.sort(key=lambda x: x["attempts"], reverse=True)

    functions_map = {
        fn_key: {
            "name": meta["name"],
            "category": meta["category"],
            "weight": settings.function_weights.get(fn_key, meta["default_weight"]),
            "attempts": counts_dict.get(fn_key, 0),
        }
        for fn_key, meta in FUNCTION_METADATA.items()
    }

    # 3. Top attackers by function risk score
    stmt_atks = (
        select(Attacker)
        .where(Attacker.function_risk_score > 0)
        .order_by(desc(Attacker.function_risk_score))
        .limit(10)
    )
    atks_res = await db.execute(stmt_atks)
    top_attackers = []
    for a in atks_res.scalars().all():
        bk = a.function_risk_breakdown or {}
        top_attackers.append({
            "id": a.id,
            "ip": a.ip,
            "function_risk_score": a.function_risk_score,
            "targeted_functions": a.targeted_functions or [],
            "risk_band": a.risk_band,
            "explanation": sanitize_text(bk.get("explanation", "")),
            "confidence": bk.get("confidence", 0.8),
            "time_window_seconds": bk.get("time_window_seconds", 0.0),
            "is_simulated": bk.get("is_simulated", False),
        })

    # 4. Recent attack sequences
    stmt_seq = (
        select(FunctionTargetEvent)
        .order_by(desc(FunctionTargetEvent.timestamp))
        .limit(20)
    )
    seq_res = await db.execute(stmt_seq)
    recent_sequence = [
        {
            "id": e.id,
            "attacker_id": e.attacker_id,
            "src_ip": e.src_ip,
            "function": e.target_function,
            "function_name": FUNCTION_METADATA.get(e.target_function, {}).get("name", e.target_function),
            "endpoint": sanitize_text(e.target_endpoint),
            "severity": e.severity,
            "confidence": e.confidence,
            "is_simulated": e.is_simulated,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "evidence": sanitize_text(e.evidence),
        }
        for e in seq_res.scalars().all()
    ]

    return {
        "metadata": FUNCTION_METADATA,
        "functions": functions_map,
        "total_targeted_events": total_events,
        "observed_events_count": observed_count,
        "simulated_events_count": simulated_count,
        "most_targeted_functions": most_targeted,
        "top_attackers": top_attackers,
        "recent_sequences": recent_sequence,
        "behavioural_windows_seconds": settings.behavioural_windows,
        "thresholds": settings.function_risk_thresholds,
    }


@router.post("/simulate", dependencies=[Depends(verify_api_key)])
async def simulate_function_targeting(
    body: FunctionTargetEventIn,
    db: AsyncSession = Depends(get_db),
):
    """
    Simulates a function targeting event and recalculates Level-2 bounded score.
    Requires X-API-Key authentication. Explicitly marks the event as simulated
    so it does NOT pollute real attacker statistics or permanent risk scores.
    """
    now = body.timestamp or datetime.now(timezone.utc)
    if body.target_function not in FUNCTION_METADATA:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target_function '{body.target_function}'. Valid functions: {list(FUNCTION_METADATA.keys())}",
        )

    attacker = await get_or_create_attacker(db, body.src_ip, now)
    fn_ev = await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function=body.target_function,
        target_endpoint=body.target_endpoint or f"/api/{body.target_function}",
        attack_type=body.attack_type or "probe",
        severity=body.severity or "high",
        result=body.result or "intercepted",
        attempts=body.attempts or 1,
        honeypot_source=body.honeypot_source or "simulation",
        evidence=body.evidence or f"[Simulated] Controlled injection targeting {body.target_function}",
        confidence=body.confidence or 1.0,
        is_simulated=True,
        event_timestamp=now,
    )
    await db.commit()

    return {
        "status": "success",
        "event_id": fn_ev.id,
        "attacker_id": attacker.id,
        "src_ip": attacker.ip,
        "target_function": fn_ev.target_function,
        "confidence": fn_ev.confidence,
        "is_simulated": True,
        "function_risk_score": attacker.function_risk_score,
        "breakdown": attacker.function_risk_breakdown,
    }


# --------------------------------------------------------------------------
# Manual Function Intelligence Demonstration Controls
# --------------------------------------------------------------------------
from pydantic import BaseModel


class DemoActionRequest(BaseModel):
    action: str  # "normal", "repeated", "sensitive_probe"
    session_id: Optional[str] = "demo_fn_session_interactive"
    target_function: Optional[str] = "auth_login"


class DemoReconRequest(BaseModel):
    session_id: Optional[str] = "demo_fn_session_interactive"


class DemoStopRequest(BaseModel):
    session_id: Optional[str] = "demo_fn_session_interactive"


class DemoResetRequest(BaseModel):
    session_id: Optional[str] = "demo_fn_session_interactive"


@router.post("/demo/action")
async def trigger_demo_action(
    body: DemoActionRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Executes a controlled manual synthetic function targeting action:
    - 'normal': Legitimate single-attempt access
    - 'repeated': Repeated attempt bursts for the same function (attempts increment)
    - 'sensitive_probe': Probing sensitive secrets/config or admin functions
    """
    try:
        res = await execute_demo_action(
            db=db,
            action=body.action,
            session_id=body.session_id,
            target_function=body.target_function,
        )

        # Trigger PagerDuty Phone Call & Multi-Channel Incident Alert whenever an attack is clicked
        if body.action in ("repeated", "sensitive_probe", "sensitive") or body.target_function in ("secrets_env", "admin_access", "payment_gateway", "database_api"):
            try:
                from app.services.alert_dispatcher import dispatch_function_intel_live_alert
                asyncio.create_task(
                    dispatch_function_intel_live_alert(
                        action=body.action,
                        target_function=res.get("target_function") or body.target_function or "auth_login",
                        session_id=body.session_id,
                        attempts=res.get("attempts", 1),
                        evidence=res.get("explanation", ""),
                    )
                )
            except Exception as e:
                logger.warning(f"Failed to dispatch demo attack alert: {e}")

        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to execute demonstration action: {e}")


@router.post("/demo/recon")
async def trigger_demo_recon(
    body: Optional[DemoReconRequest] = None,
):
    """
    Triggers an asynchronous multi-step sequence across 4 distinct functions:
    Login -> OTP -> Admin -> Database Core, activating sequence synergies.
    """
    session_id = body.session_id if body else "demo_fn_session_interactive"
    try:
        from app.services.alert_dispatcher import dispatch_function_intel_live_alert
        asyncio.create_task(
            dispatch_function_intel_live_alert(
                action="recon",
                target_function="database_api",
                session_id=session_id,
                attempts=4,
                evidence="Multi-Function Reconnaissance Synergy targeting Login -> OTP -> Admin -> Database",
            )
        )
    except Exception as e:
        logger.warning(f"Failed to dispatch recon alert: {e}")
    return await execute_demo_recon_sequence(session_id=session_id)


@router.post("/demo/stop")
async def trigger_demo_stop(
    body: Optional[DemoStopRequest] = None,
):
    """
    Immediately stops any ongoing multi-function reconnaissance sequence.
    """
    session_id = body.session_id if body else "demo_fn_session_interactive"
    return stop_demo_simulation(session_id=session_id)


@router.post("/demo/reset")
async def trigger_demo_reset(
    body: Optional[DemoResetRequest] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Resets the isolated synthetic demonstration session back to 0.
    Deletes simulated demo events only. Genuine observed telemetry is preserved.
    """
    session_id = body.session_id if body else "demo_fn_session_interactive"
    return await reset_demo_session(db=db, session_id=session_id)


@router.get("/demo/status")
async def get_demo_session_status(
    session_id: str = Query("demo_fn_session_interactive"),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns current state of the isolated demo session:
    whether simulation is running, attempt counters, and risk score.
    """
    return await get_demo_status(db=db, session_id=session_id)

