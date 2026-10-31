from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.db import get_db
from app.models import Attacker, Event, Incident, KillChainMapping, MitreMapping, ResponseAction
from app.services.ai_investigation import run_ai_investigation
from app.services.incidents import add_incident_note, update_incident_status
from app.services.reports import generate_incident_pdf

router = APIRouter()


def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> None:
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid X-API-Key")


def _format_incident(i: Incident) -> dict:
    return {
        "id": i.id,
        "attacker_id": i.attacker_id,
        "title": i.title,
        "status": i.status,
        "status_history": i.status_history or [],
        "assignee": i.assignee,
        "notes": i.notes or [],
        "root_cause": i.root_cause or {},
        "blast_radius": i.blast_radius or {},
        "ttd_seconds": i.ttd_seconds,
        "ttr_seconds": i.ttr_seconds,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
        "risk_score_at_creation": i.risk_score_at_creation,
        "ai_investigation": i.ai_investigation,
    }


@router.get("/incidents")
async def list_incidents(db: AsyncSession = Depends(get_db)):
    stmt = select(Incident).order_by(Incident.created_at.desc())
    res = await db.execute(stmt)
    incidents = res.scalars().all()
    return {"incidents": [_format_incident(i) for i in incidents], "count": len(incidents)}


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: int, db: AsyncSession = Depends(get_db)):
    stmt = select(Incident).where(Incident.id == incident_id)
    res = await db.execute(stmt)
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _format_incident(incident)


@router.patch("/incidents/{incident_id}", dependencies=[Depends(verify_api_key)])
async def patch_incident(
    incident_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    body = await request.json()
    new_status = body.get("status")
    assignee = body.get("assignee")
    note = body.get("note", "")

    if new_status:
        incident = await update_incident_status(db, incident_id, new_status, note, assignee)
    else:
        stmt = select(Incident).where(Incident.id == incident_id)
        incident = (await db.execute(stmt)).scalar_one_or_none()
        if incident and assignee is not None:
            incident.assignee = assignee
            await db.flush()

    await db.commit()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found or invalid transition")

    return _format_incident(incident)


@router.post("/incidents/{incident_id}/notes", dependencies=[Depends(verify_api_key)])
async def post_incident_note(
    incident_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    body = await request.json()
    text = body.get("text", "")
    author = body.get("author", "analyst")

    if not text:
        raise HTTPException(status_code=400, detail="Note text cannot be empty")

    incident = await add_incident_note(db, incident_id, text, author)
    await db.commit()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return _format_incident(incident)


@router.get("/incidents/{incident_id}/investigation")
async def get_incident_investigation(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
):
    try:
        inv = await run_ai_investigation(db, incident_id, force_refresh=False)
        await db.commit()
        return inv
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/incidents/{incident_id}/investigate")
async def trigger_incident_investigate(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
):
    try:
        inv = await run_ai_investigation(db, incident_id, force_refresh=True)
        await db.commit()
        return inv
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/incidents/{incident_id}/report")
async def download_incident_report(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Incident).where(Incident.id == incident_id)
    incident = (await db.execute(stmt)).scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    attacker = None
    events = []
    mitre_list = []
    kc_list = []
    actions = []

    if incident.attacker_id:
        attacker = (await db.execute(select(Attacker).where(Attacker.id == incident.attacker_id))).scalar_one_or_none()
        events = list((await db.execute(select(Event).where(Event.attacker_id == incident.attacker_id).order_by(Event.timestamp.asc()).limit(30))).scalars().all())
        mitre_list = list((await db.execute(select(MitreMapping).where(MitreMapping.attacker_id == incident.attacker_id))).scalars().all())
        kc_list = list((await db.execute(select(KillChainMapping).where(KillChainMapping.attacker_id == incident.attacker_id))).scalars().all())
        actions = list((await db.execute(select(ResponseAction).where(ResponseAction.attacker_id == incident.attacker_id))).scalars().all())

    pdf_bytes = generate_incident_pdf(
        incident=incident,
        attacker=attacker,
        events=events,
        mitre_list=mitre_list,
        kc_list=kc_list,
        actions=actions,
    )

    filename = f"sentinel_incident_{incident_id}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
