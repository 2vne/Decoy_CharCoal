from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Event


async def get_replay_sequence(db: AsyncSession, attacker_id: int) -> List[Dict[str, Any]]:
    stmt = (
        select(Event)
        .where(
            Event.attacker_id == attacker_id,
            Event.event_type == "command",
        )
        .order_by(Event.timestamp.asc())
    )
    res = await db.execute(stmt)
    events = res.scalars().all()

    sequence = []
    prev_time = None

    for ev in events:
        ts = ev.timestamp if ev.timestamp.tzinfo else ev.timestamp.replace(tzinfo=timezone.utc)
        delay_ms = 0
        if prev_time is not None:
            delta = (ts - prev_time).total_seconds()
            delay_ms = max(50, min(8000, int(delta * 1000)))
        else:
            delay_ms = 100

        sequence.append({
            "event_id": ev.event_id,
            "timestamp": ts.isoformat(),
            "command": ev.command or "",
            "username": ev.username or "root",
            "honeypot": ev.honeypot,
            "delay_ms": delay_ms,
        })
        prev_time = ts

    return sequence

