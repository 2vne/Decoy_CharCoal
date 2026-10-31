from __future__ import annotations
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.schemas import ExposureAssetOut
from app.services.exposure import evaluate_exposure_budget, update_exposure_asset_threshold

router = APIRouter()


@router.get("/exposure", response_model=List[ExposureAssetOut])
async def get_exposure_budget(db: AsyncSession = Depends(get_db)):
    results = await evaluate_exposure_budget(db)
    await db.commit()
    return [ExposureAssetOut(**r) for r in results]


@router.put("/exposure", response_model=List[ExposureAssetOut])
async def update_exposure_budget(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    body = await request.json()
    updates = body.get("assets", [])
    for item in updates:
        asset_id = item.get("id")
        threshold = item.get("threshold")
        if asset_id is not None and threshold is not None:
            await update_exposure_asset_threshold(db, int(asset_id), float(threshold))

    results = await evaluate_exposure_budget(db)
    await db.commit()
    return [ExposureAssetOut(**r) for r in results]

