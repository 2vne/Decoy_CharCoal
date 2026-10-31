from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.models import Block

router = APIRouter()


@router.get("/blocks")
async def list_blocks(db: AsyncSession = Depends(get_db)):
    stmt = select(Block).order_by(Block.requested_at.desc())
    res = await db.execute(stmt)
    blocks = res.scalars().all()

    data = []
    for b in blocks:
        data.append({
            "id": b.id,
            "ip": b.ip,
            "attacker_id": b.attacker_id,
            "requested_by": b.requested_by,
            "ttl_seconds": b.ttl_seconds,
            "status": b.status,
            "mock": b.mock,
            "requested_at": b.requested_at.isoformat() if b.requested_at else None,
            "verified_at": b.verified_at.isoformat() if b.verified_at else None,
            "expires_at": b.expires_at.isoformat() if b.expires_at else None,
            "rolled_back_at": b.rolled_back_at.isoformat() if b.rolled_back_at else None,
        })

    return {"blocks": data, "count": len(data)}

