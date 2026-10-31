from __future__ import annotations
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.models import AuditLog, Event
from app.schemas import AuditLogOut
from app.services.integrity import compute_raw_hash, verify_event_raw_hash

router = APIRouter()


@router.get("/audit", response_model=List[AuditLogOut])
async def list_audit_logs(
    entity_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    res = await db.execute(stmt)
    logs = res.scalars().all()

    return [
        AuditLogOut(
            id=log.id,
            entity_type=log.entity_type,
            entity_id=log.entity_id,
            action=log.action,
            actor=log.actor,
            details=log.details or {},
            timestamp=log.timestamp.isoformat() if log.timestamp else "",
        )
        for log in logs
    ]


@router.get("/events/{event_id}/integrity")
async def verify_event_integrity(
    event_id: str,
    db: AsyncSession = Depends(get_db),
):
    # Support numeric id or string event_id
    if event_id.isdigit():
        stmt = select(Event).where((Event.id == int(event_id)) | (Event.event_id == event_id))
    else:
        stmt = select(Event).where(Event.event_id == event_id)

    res = await db.execute(stmt)
    event = res.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    is_valid_raw = verify_event_raw_hash(event)
    recalculated_raw = compute_raw_hash(event.raw or {}, event.event_id)

    return {
        "event_id": event.event_id,
        "id": event.id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "raw_hash": event.raw_hash,
        "chain_hash": event.chain_hash,
        "prev_hash": event.prev_hash,
        "integrity_verified": is_valid_raw or (event.raw_hash is None),
        "tamper_detected": not is_valid_raw and event.raw_hash is not None,
        "recalculated_hash": recalculated_raw,
    }

