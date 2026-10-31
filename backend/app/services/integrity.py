from __future__ import annotations
import hashlib
import json
from typing import Any, Dict, Optional, Tuple
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Event


def compute_raw_hash(raw_data: Dict[str, Any], event_id: str) -> str:
    serialized = json.dumps(raw_data, sort_keys=True, default=str)
    payload = f"{event_id}:{serialized}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


async def compute_chain_hash_for_event(
    db: AsyncSession,
    raw_hash: str,
    event_id: str,
    timestamp_str: str,
) -> Tuple[str, str]:
    """
    Returns (chain_hash, prev_hash).
    Uses the latest inserted event's chain_hash as prev_hash (genesis hash if first).
    """
    stmt = (
        select(Event.chain_hash)
        .where(Event.chain_hash.isnot(None))
        .order_by(desc(Event.id))
        .limit(1)
    )
    res = await db.execute(stmt)
    latest_chain_hash = res.scalar_one_or_none()
    prev_hash = latest_chain_hash or "0" * 64

    combo = f"{prev_hash}:{raw_hash}:{event_id}:{timestamp_str}".encode("utf-8")
    chain_hash = hashlib.sha256(combo).hexdigest()
    return chain_hash, prev_hash


def verify_event_raw_hash(event: Event) -> bool:
    if not event.raw_hash:
        return False
    expected = compute_raw_hash(event.raw or {}, event.event_id)
    return expected == event.raw_hash

