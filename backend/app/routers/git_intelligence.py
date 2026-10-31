from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.models import CommitAttribution, GatewayIncident
from app.services.git_intelligence import correlate_commits_for_incident, get_local_git_commits
from app.services.notifications import send_resend_email

router = APIRouter(prefix="/intelligence/git", tags=["GitHub & Commit Intelligence"])


class CorrelateRequest(BaseModel):
    incident_id: int
    affected_function: Optional[str] = ""
    affected_endpoint: Optional[str] = ""


class NotifyTeamRequest(BaseModel):
    attribution_id: int
    notes: Optional[str] = "Human analyst approved investigation lead dispatch"


@router.get("/commits")
async def list_git_commits(
    incident_id: Optional[int] = Query(None, description="Filter by related incident ID"),
    limit: int = Query(25, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns recorded commit attributions or raw local git history.
    """
    if incident_id:
        stmt = (
            select(CommitAttribution)
            .where(CommitAttribution.incident_id == incident_id)
            .order_by(desc(CommitAttribution.commit_ts))
            .limit(limit)
        )
        res = await db.execute(stmt)
        items = res.scalars().all()
        return {
            "incident_id": incident_id,
            "count": len(items),
            "attributions": [
                {
                    "id": a.id,
                    "commit_hash": a.commit_hash,
                    "short_hash": a.commit_hash[:8],
                    "author_name": a.author_name,
                    "author_email": a.author_email,
                    "commit_msg": a.commit_msg,
                    "commit_ts": a.commit_ts.isoformat() if a.commit_ts else None,
                    "changed_files": a.changed_files,
                    "assigned_team": a.assigned_team,
                    "confidence": a.confidence,
                    "explanation": a.correlation_explanation,
                }
                for a in items
            ],
        }

    # Otherwise return live local commits
    commits = get_local_git_commits(max_count=limit)
    return {
        "count": len(commits),
        "commits": [
            {
                **c,
                "short_hash": c["commit_hash"][:8],
                "commit_ts": c["commit_ts"].isoformat() if c["commit_ts"] else None,
            }
            for c in commits
        ],
    }


@router.post("/correlate")
async def correlate_incident_commits(
    body: CorrelateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Triggers automated Git history correlation for an incident window.
    """
    stmt = select(GatewayIncident).where(GatewayIncident.id == body.incident_id)
    res = await db.execute(stmt)
    inc = res.scalar_one_or_none()

    affected_func = body.affected_function or (inc.related_function if inc else "")
    affected_ep = body.affected_endpoint or (inc.endpoint if inc else "")
    inc_ts = inc.first_failure_ts if inc else datetime.now(timezone.utc)

    attributions = await correlate_commits_for_incident(
        db=db,
        incident_id=body.incident_id,
        affected_function=affected_func or "",
        affected_endpoint=affected_ep or "",
        incident_start_ts=inc_ts,
    )
    await db.commit()

    return {
        "status": "success",
        "incident_id": body.incident_id,
        "leads_found": len(attributions),
        "leads": [
            {
                "id": a.id,
                "short_hash": a.commit_hash[:8],
                "author": a.author_name,
                "team": a.assigned_team,
                "confidence": a.confidence,
                "explanation": a.correlation_explanation,
            }
            for a in attributions
        ],
    }


@router.post("/notify_team")
async def notify_responsible_team(
    body: NotifyTeamRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Dispatches a human-approved notification to the responsible team lead.
    """
    stmt = select(CommitAttribution).where(CommitAttribution.id == body.attribution_id)
    res = await db.execute(stmt)
    attr = res.scalar_one_or_none()
    if not attr:
        raise HTTPException(status_code=404, detail="Commit attribution lead not found")

    # Send email notification via existing Resend / notification integration
    subject = f"[SENTINEL Investigation Lead] Team {attr.assigned_team.upper()} Triage Request"
    body_text = (
        f"SENTINEL Investigation Lead Review:\n\n"
        f"Team: {attr.assigned_team}\n"
        f"Commit: {attr.commit_hash[:8]} by {attr.author_name}\n"
        f"Subject: {attr.commit_msg}\n\n"
        f"Evidence & Explanation:\n{attr.correlation_explanation}\n\n"
        f"Analyst Notes:\n{body.notes}\n"
    )
    email_res = await send_resend_email(subject, body_text)

    return {
        "status": "notified",
        "team": attr.assigned_team,
        "commit": attr.commit_hash[:8],
        "email_status": email_res,
        "message": f"Triage lead dispatched to {attr.assigned_team} team.",
    }

