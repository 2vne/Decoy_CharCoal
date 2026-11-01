from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.models import Attacker, Block, Event, Incident
from app.services.health import get_honeypot_health

router = APIRouter()


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "MIRAGE SOC", "version": "1.0.0"}


@router.get("/honeypots/health")
async def get_hp_health(db: AsyncSession = Depends(get_db)):
    health_list = await get_honeypot_health(db)
    return {"honeypots": health_list}


@router.get("/overview")
async def get_overview(db: AsyncSession = Depends(get_db)):
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    total_events = (await db.execute(select(func.count(Event.id)))).scalar_one() or 0
    total_attackers = (await db.execute(select(func.count(Attacker.id)))).scalar_one() or 0
    total_incidents = (await db.execute(select(func.count(Incident.id)))).scalar_one() or 0

    active_blocks = (await db.execute(
        select(func.count(Block.id)).where(Block.status.in_(["active", "pending"]))
    )).scalar_one() or 0

    events_today = (await db.execute(
        select(func.count(Event.id)).where(Event.received_at >= today_start)
    )).scalar_one() or 0

    # Band counts
    band_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    band_res = await db.execute(select(Attacker.risk_band, func.count(Attacker.id)).group_by(Attacker.risk_band))
    for band, count in band_res.all():
        if band in band_counts:
            band_counts[band] = count

    hp_health = await get_honeypot_health(db)
    honeypots_healthy = sum(1 for h in hp_health if h["status"] == "running")

    return {
        "total_events": total_events,
        "total_attackers": total_attackers,
        "total_incidents": total_incidents,
        "active_blocks": active_blocks,
        "band_counts": band_counts,
        "events_today": events_today,
        "honeypots_healthy": honeypots_healthy,
    }

