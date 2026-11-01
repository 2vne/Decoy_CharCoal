from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.models import AdvisoryStepStatus, Incident
from app.services.remediation import generate_remediation_advisory
from app.services.playbook_loader import get_all_playbooks

router = APIRouter(tags=["Remediation Advisor"])


class StepStatusUpdateIn(BaseModel):
    status: str  # pending | done | skipped
    note: Optional[str] = None
    incident_id: Optional[str] = None
    gateway_id: Optional[str] = None


@router.get("/incidents/{incident_id}/advisory")
async def get_incident_advisory(
    incident_id: int,
    refresh: bool = Query(False, description="Force fresh advisory computation"),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns suggested fixes and the full remediation plan for the specified incident.
    """
    stmt = select(Incident).where(Incident.id == incident_id)
    res = await db.execute(stmt)
    inc = res.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    advisory = await generate_remediation_advisory(
        incident=inc,
        db=db,
        force_refresh=refresh,
    )

    # Attach current step execution statuses
    step_stmt = select(AdvisoryStepStatus).where(
        (AdvisoryStepStatus.incident_id == str(incident_id)) |
        (AdvisoryStepStatus.incident_id.is_(None))
    )
    step_res = await db.execute(step_stmt)
    statuses = {s.step_id: s.status for s in step_res.scalars().all()}
    advisory["step_statuses"] = statuses

    return advisory


@router.post("/incidents/{incident_id}/advisory/refresh")
async def refresh_incident_advisory(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Forces recalculation of the remediation advisory, clearing any cached state.
    """
    stmt = select(Incident).where(Incident.id == incident_id)
    res = await db.execute(stmt)
    inc = res.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    advisory = await generate_remediation_advisory(
        incident=inc,
        db=db,
        force_refresh=True,
    )
    return advisory


@router.post("/advisory/steps/{step_id}/status")
async def update_step_status(
    step_id: str,
    payload: StepStatusUpdateIn,
    db: AsyncSession = Depends(get_db),
):
    """
    Updates the execution status of an individual remediation step (pending | done | skipped).
    """
    valid_statuses = {"pending", "done", "skipped"}
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Status must be one of {valid_statuses}")

    now = datetime.now(timezone.utc)
    stmt = select(AdvisoryStepStatus).where(AdvisoryStepStatus.step_id == step_id)
    if payload.incident_id:
        stmt = stmt.where(AdvisoryStepStatus.incident_id == str(payload.incident_id))
    if payload.gateway_id:
        stmt = stmt.where(AdvisoryStepStatus.gateway_id == str(payload.gateway_id))

    res = await db.execute(stmt)
    rec = res.scalar_one_or_none()

    if not rec:
        rec = AdvisoryStepStatus(
            step_id=step_id,
            incident_id=str(payload.incident_id) if payload.incident_id else None,
            gateway_id=str(payload.gateway_id) if payload.gateway_id else None,
            status=payload.status,
            note=payload.note,
            updated_at=now,
        )
        db.add(rec)
    else:
        rec.status = payload.status
        if payload.note is not None:
            rec.note = payload.note
        rec.updated_at = now

    await db.commit()

    return {
        "step_id": step_id,
        "status": rec.status,
        "note": rec.note,
        "updated_at": rec.updated_at.isoformat(),
    }


@router.get("/advisory/summary")
async def get_advisory_summary(db: AsyncSession = Depends(get_db)):
    """
    Returns top recurring fixes and recommended playbooks across all incidents and gateways.
    """
    # Group completed vs pending steps
    stmt = select(AdvisoryStepStatus)
    res = await db.execute(stmt)
    all_statuses = res.scalars().all()

    playbooks = get_all_playbooks()
    recurring_steps: Dict[str, Dict[str, Any]] = {}

    for pb_id, pb in playbooks.items():
        for act in pb.immediate_actions + pb.before_reopening + pb.long_term_fixes:
            if act.step not in recurring_steps:
                recurring_steps[act.step] = {
                    "step": act.step,
                    "playbook_id": pb_id,
                    "playbook_title": pb.title,
                    "frequency": 1,
                    "why": act.why,
                }
            else:
                recurring_steps[act.step]["frequency"] += 1

    sorted_fixes = sorted(recurring_steps.values(), key=lambda x: x["frequency"], reverse=True)[:8]

    done_count = sum(1 for s in all_statuses if s.status == "done")
    pending_count = sum(1 for s in all_statuses if s.status == "pending")

    return {
        "top_recurring_fixes": sorted_fixes,
        "metrics": {
            "total_tracked_steps": len(all_statuses),
            "completed_steps": done_count,
            "pending_steps": pending_count,
            "available_playbooks": len(playbooks),
        },
    }

