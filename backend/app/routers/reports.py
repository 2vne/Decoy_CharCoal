from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.services.adaptive_deception import get_adaptive_deception_advisories
from app.services.reports import generate_summary_report_data

router = APIRouter()


@router.get("/reports/summary")
async def get_reports_summary(db: AsyncSession = Depends(get_db)):
    return await generate_summary_report_data(db)


@router.get("/adaptive-deception")
async def get_adaptive_deception(db: AsyncSession = Depends(get_db)):
    return {"advisories": await get_adaptive_deception_advisories(db)}

