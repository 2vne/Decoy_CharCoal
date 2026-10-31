from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Block, Incident
from app.services.broadcast import broadcast

VALID_STATUSES = ["new", "investigating", "contained", "resolved"]


async def update_incident_status(
    db: AsyncSession,
    incident_id: int,
    new_status: str,
    note: str = "",
    assignee: Optional[str] = None,
) -> Optional[Incident]:
    if new_status not in VALID_STATUSES:
        return None

    stmt = select(Incident).where(Incident.id == incident_id)
    res = await db.execute(stmt)
    incident = res.scalar_one_or_none()
    if not incident:
        return None

    now = datetime.now(timezone.utc)
    incident.status = new_status
    incident.updated_at = now

    history = list(incident.status_history or [])
    history.append({
        "status": new_status,
        "ts": now.isoformat(),
        "note": note or f"Status changed to {new_status}",
    })
    incident.status_history = history

    if assignee:
        incident.assignee = assignee

    # If transitioned to resolved or contained, compute TTR if block verified
    if new_status in ("contained", "resolved") and incident.ttr_seconds is None and incident.attacker_id:
        stmt_blk = select(Block).where(
            Block.attacker_id == incident.attacker_id,
            Block.verified_at.isnot(None),
        ).order_by(Block.verified_at.asc())
        blk_res = await db.execute(stmt_blk)
        first_blk = blk_res.scalar_one_or_none()
        if first_blk and first_blk.verified_at and incident.created_at:
            t_created = incident.created_at if incident.created_at.tzinfo else incident.created_at.replace(tzinfo=timezone.utc)
            t_ver = first_blk.verified_at if first_blk.verified_at.tzinfo else first_blk.verified_at.replace(tzinfo=timezone.utc)
            incident.ttr_seconds = round(max(0.0, (t_ver - t_created).total_seconds()), 2)

    await db.flush()

    try:
        await broadcast("incident", {
            "id": incident.id,
            "status": incident.status,
            "title": incident.title,
            "assignee": incident.assignee,
            "updated_at": incident.updated_at.isoformat(),
        })
    except Exception:
        pass

    return incident


async def add_incident_note(
    db: AsyncSession,
    incident_id: int,
    text: str,
    author: str = "analyst",
) -> Optional[Incident]:
    stmt = select(Incident).where(Incident.id == incident_id)
    res = await db.execute(stmt)
    incident = res.scalar_one_or_none()
    if not incident:
        return None

    now = datetime.now(timezone.utc)
    notes = list(incident.notes or [])
    notes.append({
        "text": text,
        "author": author,
        "ts": now.isoformat(),
    })
    incident.notes = notes
    incident.updated_at = now
    await db.flush()
    return incident

