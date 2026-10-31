from __future__ import annotations
from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import AuditLog

logger = logging.getLogger(__name__)


async def record_audit(
    db: AsyncSession,
    entity_type: str,
    entity_id: str | int,
    action: str,
    actor: str = "system",
    details: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    entry = AuditLog(
        entity_type=entity_type,
        entity_id=str(entity_id),
        action=action,
        actor=actor,
        details=details or {},
        timestamp=datetime.now(timezone.utc),
    )
    db.add(entry)
    await db.flush()
    return entry

