from __future__ import annotations
import logging
from typing import Any, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.db import get_db
from app.models import Event
from app.schemas import EventIn
from app.services.ingest import ingest_event

router = APIRouter()
logger = logging.getLogger(__name__)


def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> None:
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid X-API-Key")


@router.post("/events", dependencies=[Depends(verify_api_key)])
async def post_events(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    body = await request.json()
    items = body if isinstance(body, list) else [body]

    results = []
    for raw_item in items:
        try:
            ev_in = EventIn.model_validate(raw_item)
            res = await ingest_event(db, ev_in)
            results.append(res)
        except Exception as e:
            logger.error(f"Error ingesting event: {e}", exc_info=True)
            results.append({"status": "error", "error": str(e)})

    await db.commit()
    return {"processed": len(results), "results": results}


@router.get("/events")
async def list_events(
    severity: Optional[str] = Query(None),
    honeypot: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    cursor: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Event).order_by(Event.id.desc())

    if honeypot:
        stmt = stmt.where(Event.honeypot == honeypot)

    if q:
        q_wild = f"%{q}%"
        stmt = stmt.where(
            or_(
                Event.src_ip.like(q_wild),
                Event.command.like(q_wild),
                Event.username.like(q_wild),
                Event.event_type.like(q_wild),
            )
        )

    if cursor:
        stmt = stmt.where(Event.id < cursor)

    stmt = stmt.limit(limit)
    res = await db.execute(stmt)
    events = res.scalars().all()

    data = []
    for e in events:
        data.append({
            "id": e.id,
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "received_at": e.received_at.isoformat() if e.received_at else None,
            "honeypot": e.honeypot,
            "decoy_type": e.decoy_type,
            "src_ip": e.src_ip,
            "src_port": e.src_port,
            "dst_port": e.dst_port,
            "session_id": e.session_id,
            "event_type": e.event_type,
            "username": e.username,
            "command": e.command,
            "url": e.url,
            "file_hash": e.file_hash,
            "attacker_id": e.attacker_id,
            "normalised": e.normalised or {},
            "raw": e.raw or {},
        })

    next_cursor = events[-1].id if len(events) == limit else None
    return {"events": data, "next_cursor": next_cursor, "count": len(data)}
