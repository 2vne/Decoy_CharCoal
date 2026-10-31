from __future__ import annotations
from datetime import datetime, timezone
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
