from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Alert

DEDUP_WINDOW_SECONDS = 60


async def get_or_create_alert(
    db: AsyncSession,
    src_ip: str,
    event_type: str,
    honeypot: str,
    event_uuid: str,
    attacker_id: Optional[int],
    classification: Optional[str] = None,
) -> Tuple[Alert, bool]:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=DEDUP_WINDOW_SECONDS)

    stmt = select(Alert).where(
        Alert.src_ip == src_ip,
        Alert.event_type == event_type,
        Alert.honeypot == honeypot,
        Alert.last_seen >= window_start,
    ).order_by(Alert.last_seen.desc()).limit(1)

    res = await db.execute(stmt)
    existing = res.scalar_one_or_none()

    if existing:
        existing.count += 1
        existing.alerts_suppressed += 1
        existing.last_seen = now
        ids = list(existing.event_ids or [])
        if event_uuid not in ids:
            ids.append(event_uuid)
        existing.event_ids = ids
        if classification and not existing.classification:
            existing.classification = classification
        await db.flush()
        return existing, False

    alert = Alert(
        attacker_id=attacker_id,
        src_ip=src_ip,
        honeypot=honeypot,
        event_type=event_type,
        classification=classification,
        count=1,
        first_seen=now,
        last_seen=now,
        alerts_suppressed=0,
        event_ids=[event_uuid],
    )
    db.add(alert)
    await db.flush()
    return alert, True


async def get_total_suppressed(db: AsyncSession) -> int:
    stmt = select(func.sum(Alert.alerts_suppressed))
    res = await db.execute(stmt)
    total = res.scalar_one_or_none()
    return int(total or 0)

