from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.db import get_db
from app.models import Attacker, Block, Event, Incident, KillChainMapping, MitreMapping, Relationship
from app.services.enforcer import request_block, request_unblock
from app.services.geo import get_geo
from app.services.replay import get_replay_sequence

router = APIRouter()


def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> None:
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid X-API-Key")


@router.get("/attackers")
async def list_attackers(db: AsyncSession = Depends(get_db)):
    stmt = select(Attacker).order_by(Attacker.risk_score.desc())
    res = await db.execute(stmt)
    attackers = res.scalars().all()

    items = []
    for a in attackers:
        geo = await get_geo(a.ip)
        items.append({
            "id": a.id,
            "ip": a.ip,
            "risk_score": a.risk_score,
            "risk_band": a.risk_band,
            "geo": geo,
            "is_repeat": a.is_repeat,
            "fingerprint": a.fingerprint,
            "honeypots_touched": a.honeypots_touched or [],
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "status": a.status,
            "intent": a.intent,
            "total_events": a.total_events,
        })

    return {"attackers": items, "count": len(items)}


@router.get("/attackers/{attacker_id}")
async def get_attacker(attacker_id: int, db: AsyncSession = Depends(get_db)):
    stmt = select(Attacker).where(Attacker.id == attacker_id)
    res = await db.execute(stmt)
    a = res.scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="Attacker not found")

    geo = await get_geo(a.ip)

    # MITRE mappings
    stmt_mitre = select(MitreMapping).where(MitreMapping.attacker_id == attacker_id)
    mitre_rows = (await db.execute(stmt_mitre)).scalars().all()
    mitre = [
        {
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "tactic": m.tactic,
            "evidence_event_ids": m.evidence_event_ids or [],
        }
        for m in mitre_rows
    ]

    # Kill Chain
    stmt_kc = select(KillChainMapping).where(KillChainMapping.attacker_id == attacker_id)
    kc_rows = (await db.execute(stmt_kc)).scalars().all()
    killchain = [
        {
            "phase": k.phase,
            "evidence_event_ids": k.evidence_event_ids or [],
        }
        for k in kc_rows
    ]

    # Related attackers
    stmt_rels = select(Relationship).where(
        or_(Relationship.attacker_a_id == attacker_id, Relationship.attacker_b_id == attacker_id)
    )
    rel_rows = (await db.execute(stmt_rels)).scalars().all()
    related_ids = set()
    for r in rel_rows:
        related_ids.add(r.attacker_a_id)
        related_ids.add(r.attacker_b_id)
    related_ids.discard(attacker_id)

    related_attackers = []
    if related_ids:
        stmt_other = select(Attacker).where(Attacker.id.in_(related_ids))
        other_atks = (await db.execute(stmt_other)).scalars().all()
        for o in other_atks:
            other_geo = await get_geo(o.ip)
            related_attackers.append({
                "id": o.id,
                "ip": o.ip,
                "risk_score": o.risk_score,
                "risk_band": o.risk_band,
                "geo": other_geo,
                "intent": o.intent,
            })

    # Blocks
    stmt_blk = select(Block).where(Block.attacker_id == attacker_id)
    blk_rows = (await db.execute(stmt_blk)).scalars().all()
    blocks = [
        {
            "id": b.id,
            "ip": b.ip,
            "status": b.status,
            "ttl_seconds": b.ttl_seconds,
            "requested_at": b.requested_at.isoformat() if b.requested_at else None,
            "verified_at": b.verified_at.isoformat() if b.verified_at else None,
            "expires_at": b.expires_at.isoformat() if b.expires_at else None,
            "rolled_back_at": b.rolled_back_at.isoformat() if b.rolled_back_at else None,
        }
        for b in blk_rows
    ]

    # Incidents
    stmt_inc = select(Incident).where(Incident.attacker_id == attacker_id)
    inc_rows = (await db.execute(stmt_inc)).scalars().all()
    incidents = [
        {
            "id": i.id,
            "title": i.title,
            "status": i.status,
            "created_at": i.created_at.isoformat() if i.created_at else None,
            "risk_score_at_creation": i.risk_score_at_creation,
        }
        for i in inc_rows
    ]

    return {
        "id": a.id,
        "ip": a.ip,
        "first_seen": a.first_seen.isoformat() if a.first_seen else None,
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        "total_events": a.total_events,
        "honeypots_touched": a.honeypots_touched or [],
        "ports": a.ports or [],
        "usernames": a.usernames or [],
        "passwords": a.passwords or [],
        "commands": a.commands or [],
        "urls": a.urls or [],
        "hashes": a.hashes or [],
        "sessions": a.sessions or [],
        "is_repeat": a.is_repeat,
        "status": a.status,
        "fingerprint": a.fingerprint,
        "feature_vector": a.feature_vector or {},
        "risk_score": a.risk_score,
        "risk_band": a.risk_band,
        "risk_factors": a.risk_factors or [],
        "risk_history": a.risk_history or [],
        "intent": a.intent,
        "intent_evidence": a.intent_evidence or [],
        "is_anomaly": a.is_anomaly,
        "anomaly_score": a.anomaly_score,
        "geo": geo,
        "mitre": mitre,
        "killchain": killchain,
        "related_attackers": related_attackers,
        "blocks": blocks,
        "incidents": incidents,
    }


@router.get("/attackers/{attacker_id}/timeline")
async def get_attacker_timeline(attacker_id: int, db: AsyncSession = Depends(get_db)):
    stmt_atk = select(Attacker.id).where(Attacker.id == attacker_id)
    if not (await db.execute(stmt_atk)).scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Attacker not found")

    stmt = select(Event).where(Event.attacker_id == attacker_id).order_by(Event.timestamp.asc())
    events = (await db.execute(stmt)).scalars().all()

    timeline = []
    for e in events:
        timeline.append({
            "id": e.id,
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "honeypot": e.honeypot,
            "decoy_type": e.decoy_type,
            "event_type": e.event_type,
            "command": e.command,
            "username": e.username,
            "url": e.url,
            "dst_port": e.dst_port,
        })

    return {"attacker_id": attacker_id, "timeline": timeline}


@router.get("/attackers/{attacker_id}/replay")
async def get_replay(attacker_id: int, db: AsyncSession = Depends(get_db)):
    stmt_atk = select(Attacker.id).where(Attacker.id == attacker_id)
    if not (await db.execute(stmt_atk)).scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Attacker not found")

    seq = await get_replay_sequence(db, attacker_id)
    return {"attacker_id": attacker_id, "sequence": seq}


@router.post("/attackers/{attacker_id}/block", dependencies=[Depends(verify_api_key)])
async def block_attacker_endpoint(attacker_id: int, db: AsyncSession = Depends(get_db)):
    stmt = select(Attacker).where(Attacker.id == attacker_id)
    attacker = (await db.execute(stmt)).scalar_one_or_none()
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")

    block = await request_block(
        db=db,
        ip=attacker.ip,
        attacker_id=attacker.id,
        ttl_seconds=600,
        requested_by="analyst_manual",
    )
    await db.commit()

    if block is None:
        raise HTTPException(status_code=400, detail="Cannot block safe IP or internal subnet")

    return {
        "status": "blocked",
        "block_id": block.id,
        "ip": attacker.ip,
        "ttl_seconds": block.ttl_seconds,
    }


@router.post("/attackers/{attacker_id}/unblock", dependencies=[Depends(verify_api_key)])
async def unblock_attacker_endpoint(attacker_id: int, db: AsyncSession = Depends(get_db)):
    stmt = select(Attacker).where(Attacker.id == attacker_id)
    attacker = (await db.execute(stmt)).scalar_one_or_none()
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")

    unblocked = await request_unblock(db=db, ip=attacker.ip)
    await db.commit()

    return {"status": "unblocked" if unblocked else "not_found", "ip": attacker.ip}


@router.get("/relationships")
async def get_relationships(db: AsyncSession = Depends(get_db)):
    stmt = select(Relationship).order_by(Relationship.id.desc())
    rels = (await db.execute(stmt)).scalars().all()

    # Prefetch attacker IPs
    stmt_atks = select(Attacker.id, Attacker.ip)
    ip_map = dict((await db.execute(stmt_atks)).all())

    results = []
    for r in rels:
        results.append({
            "id": r.id,
            "attacker_a_id": r.attacker_a_id,
            "attacker_b_id": r.attacker_b_id,
            "attacker_a_ip": ip_map.get(r.attacker_a_id, "Unknown"),
            "attacker_b_ip": ip_map.get(r.attacker_b_id, "Unknown"),
            "rel_type": r.rel_type,
            "weight": r.weight,
            "evidence": r.evidence or [],
            "created_at": r.created_at.isoformat() if r.created_at else None,
        })

    return {"relationships": results, "count": len(results)}
