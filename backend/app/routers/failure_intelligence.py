from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.models import GatewayIncident
from app.services.failure_intelligence import record_gateway_failure

router = APIRouter(prefix="/intelligence/failures", tags=["Gateway Failure Intelligence"])


class FailureRecordIn(BaseModel):
    endpoint: str
    error_code: int = 502
    error_details: str = "Bad Gateway"
    related_attacker_ip: Optional[str] = None
    related_function: Optional[str] = None
    severity: str = "high"


@router.get("")
async def list_gateway_failures(
    status: Optional[str] = Query(None, description="Filter by status (active, recurring, resolved)"),
    endpoint: Optional[str] = Query(None, description="Filter by endpoint"),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(GatewayIncident).order_by(desc(GatewayIncident.last_failure_ts)).limit(limit)
    if status:
        stmt = stmt.where(GatewayIncident.status == status)
    if endpoint:
        stmt = stmt.where(GatewayIncident.endpoint.contains(endpoint))

    res = await db.execute(stmt)
    items = res.scalars().all()

    return {
        "count": len(items),
        "incidents": [
            {
                "id": inc.id,
                "incident_uuid": inc.incident_uuid,
                "endpoint": inc.endpoint,
                "status": inc.status,
                "severity": inc.severity,
                "error_code": inc.error_code,
                "first_failure_ts": inc.first_failure_ts.isoformat() if inc.first_failure_ts else None,
                "detection_ts": inc.detection_ts.isoformat() if inc.detection_ts else None,
                "last_failure_ts": inc.last_failure_ts.isoformat() if inc.last_failure_ts else None,
                "recovery_ts": inc.recovery_ts.isoformat() if inc.recovery_ts else None,
                "recurrence_count": inc.recurrence_count,
                "related_attacker_ip": inc.related_attacker_ip,
                "related_function": inc.related_function,
                "error_details": inc.error_details,
                "ai_investigation": inc.ai_investigation,
            }
            for inc in items
        ],
    }


@router.get("/{incident_id}")
async def get_gateway_failure_details(incident_id: int, db: AsyncSession = Depends(get_db)):
    stmt = select(GatewayIncident).where(GatewayIncident.id == incident_id)
    res = await db.execute(stmt)
    inc = res.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Gateway incident not found")

    return {
        "id": inc.id,
        "incident_uuid": inc.incident_uuid,
        "endpoint": inc.endpoint,
        "status": inc.status,
        "severity": inc.severity,
        "error_code": inc.error_code,
        "first_failure_ts": inc.first_failure_ts.isoformat() if inc.first_failure_ts else None,
        "last_failure_ts": inc.last_failure_ts.isoformat() if inc.last_failure_ts else None,
        "recovery_ts": inc.recovery_ts.isoformat() if inc.recovery_ts else None,
        "recurrence_count": inc.recurrence_count,
        "related_attacker_ip": inc.related_attacker_ip,
        "related_function": inc.related_function,
        "error_details": inc.error_details,
        "ai_investigation": inc.ai_investigation,
    }


@router.post("/record")
async def record_failure_endpoint(
    body: FailureRecordIn,
    db: AsyncSession = Depends(get_db),
):
    incident = await record_gateway_failure(
        db=db,
        endpoint=body.endpoint,
        error_code=body.error_code,
        error_details=body.error_details,
        related_attacker_ip=body.related_attacker_ip,
        related_function=body.related_function,
        severity=body.severity,
    )
    await db.commit()

    return {
        "status": "success",
        "incident_uuid": incident.incident_uuid,
        "recurrence_count": incident.recurrence_count,
        "severity": incident.severity,
        "ai_investigation": incident.ai_investigation,
    }


@router.post("/{incident_id}/resolve")
async def resolve_failure_incident(incident_id: int, db: AsyncSession = Depends(get_db)):
    stmt = select(GatewayIncident).where(GatewayIncident.id == incident_id)
    res = await db.execute(stmt)
    inc = res.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Gateway incident not found")

    inc.status = "resolved"
    inc.recovery_ts = datetime.now(timezone.utc)
    await db.commit()

    return {
        "status": "resolved",
        "incident_uuid": inc.incident_uuid,
        "recovery_ts": inc.recovery_ts.isoformat(),
    }

