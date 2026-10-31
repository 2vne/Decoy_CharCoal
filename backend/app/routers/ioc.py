from __future__ import annotations
from typing import Literal
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.services.ioc import extract_iocs, format_iocs_csv, format_iocs_stix

router = APIRouter()


@router.get("/ioc")
async def export_iocs(
    format: Literal["json", "csv", "stix"] = Query("json", description="Export format"),
    db: AsyncSession = Depends(get_db),
):
    iocs = await extract_iocs(db)

    if format == "csv":
        csv_data = format_iocs_csv(iocs)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="sentinel_iocs.csv"'},
        )
    elif format == "stix":
        stix_bundle = format_iocs_stix(iocs)
        return stix_bundle
    else:
        return {"iocs": iocs, "count": len(iocs)}

