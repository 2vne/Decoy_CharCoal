from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.services.metrics import compute_metrics

router = APIRouter()


@router.get("/metrics")
async def get_metrics(db: AsyncSession = Depends(get_db)):
    return await compute_metrics(db)

