from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.models import ResponseAction
from app.schemas import ActionApproveIn, ActionRejectIn, ResponseActionOut
from app.services.audit import record_audit
from app.services.broadcast import broadcast
from app.services.enforcer import request_block

router = APIRouter()


@router.get("/actions", response_model=List[ResponseActionOut])
async def list_actions(
    status: Optional[str] = Query(None, description="Filter by action status"),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ResponseAction).order_by(desc(ResponseAction.created_at))
    if status:
        stmt = stmt.where(ResponseAction.status == status)
    res = await db.execute(stmt)
    actions = res.scalars().all()

    return [
        ResponseActionOut(
            id=a.id,
            attacker_id=a.attacker_id,
            incident_id=a.incident_id,
            block_id=a.block_id,
            action_type=a.action_type,
            target_ip=a.target_ip,
            status=a.status,
            reason=a.reason,
            duration_seconds=a.duration_seconds,
            approver=a.approver,
            created_at=a.created_at.isoformat() if a.created_at else None,
            approved_at=a.approved_at.isoformat() if a.approved_at else None,
            rejected_at=a.rejected_at.isoformat() if a.rejected_at else None,
            executed_at=a.executed_at.isoformat() if a.executed_at else None,
            verified_at=a.verified_at.isoformat() if a.verified_at else None,
            rolled_back_at=a.rolled_back_at.isoformat() if a.rolled_back_at else None,
            details=a.details or {},
        )
        for a in actions
    ]


@router.post("/actions/{action_id}/approve")
async def approve_action(
    action_id: int,
    body: ActionApproveIn = ActionApproveIn(),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ResponseAction).where(ResponseAction.id == action_id)
    res = await db.execute(stmt)
    action = res.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    if action.status not in ("proposed", "pending"):
        return {"status": action.status, "message": f"Action is already {action.status}"}

    now = datetime.now(timezone.utc)
    action.status = "approved"
    action.approver = body.approver
    action.approved_at = now
    if body.duration_seconds:
        action.duration_seconds = body.duration_seconds

    # Execute firewall block
    blk = await request_block(
        db=db,
        ip=action.target_ip,
        attacker_id=action.attacker_id,
        ttl_seconds=action.duration_seconds,
        requested_by=body.approver,
    )
    if blk:
        action.block_id = blk.id
        action.status = "verified"
        action.executed_at = now
        action.verified_at = now

    await record_audit(
        db=db,
        entity_type="action",
        entity_id=action.id,
        action="approve_and_execute",
        actor=body.approver,
        details={"target_ip": action.target_ip, "duration": action.duration_seconds},
    )

    await db.commit()

    try:
        await broadcast("action", {
            "id": action.id,
            "action_type": action.action_type,
            "target_ip": action.target_ip,
            "status": action.status,
            "approver": action.approver,
        })
    except Exception:
        pass

    return {
        "status": action.status,
        "action_id": action.id,
        "target_ip": action.target_ip,
        "block_id": action.block_id,
        "approver": action.approver,
    }


@router.post("/actions/{action_id}/reject")
async def reject_action(
    action_id: int,
    body: ActionRejectIn = ActionRejectIn(),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ResponseAction).where(ResponseAction.id == action_id)
    res = await db.execute(stmt)
    action = res.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    now = datetime.now(timezone.utc)
    action.status = "rejected"
    action.approver = body.approver
    action.rejected_at = now
    if body.reason:
        action.reason = f"{action.reason} [Rejected: {body.reason}]"

    await record_audit(
        db=db,
        entity_type="action",
        entity_id=action.id,
        action="reject",
        actor=body.approver,
        details={"target_ip": action.target_ip, "reason": body.reason},
    )

    await db.commit()

    try:
        await broadcast("action", {
            "id": action.id,
            "action_type": action.action_type,
            "target_ip": action.target_ip,
            "status": "rejected",
            "approver": action.approver,
        })
    except Exception:
        pass

    return {
        "status": "rejected",
        "action_id": action.id,
        "target_ip": action.target_ip,
        "approver": action.approver,
    }

