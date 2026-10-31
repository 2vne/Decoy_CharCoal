from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.schemas import WhatIfOut, WhatIfRequest
from app.services.whatif import simulate_whatif

router = APIRouter()


@router.post("/whatif", response_model=WhatIfOut)
async def whatif_simulation(
    body: WhatIfRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await simulate_whatif(
            db=db,
            attacker_id=body.attacker_id,
            action=body.action,
            at_stage=body.at_stage,
        )
        return WhatIfOut(**result)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

