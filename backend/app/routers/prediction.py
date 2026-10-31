from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.schemas import PredictionOut
from app.services.prediction import predict_attacker_propagation

router = APIRouter()


@router.get("/attackers/{attacker_id}/prediction", response_model=PredictionOut)
async def get_attacker_propagation_prediction(
    attacker_id: int,
    db: AsyncSession = Depends(get_db),
):
    try:
        pred = await predict_attacker_propagation(db, attacker_id)
        return PredictionOut(**pred)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

