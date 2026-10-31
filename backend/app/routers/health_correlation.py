from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.services.health_correlation import get_health_correlation_data

router = APIRouter()


@router.get("/health-correlation")
async def get_health_correlation(db: AsyncSession = Depends(get_db)):
    return await get_health_correlation_data(db)

