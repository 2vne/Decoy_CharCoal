from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Attacker, Event, ExposureAsset

DEFAULT_ASSETS = [
    {
        "name": "Core Customer Database",
        "asset_type": "database",
        "honeypot_link": "opencanary",
        "criticality": "critical",
        "threshold": 60.0,
    },
    {
        "name": "Substation Modbus PLC-01",
        "asset_type": "scada_plc",
        "honeypot_link": "conpot",
        "criticality": "critical",
        "threshold": 50.0,
    },
    {
        "name": "Engineering Bastion Jumpbox",
        "asset_type": "ssh_bastion",
        "honeypot_link": "cowrie",
        "criticality": "high",
        "threshold": 75.0,
    },
    {
        "name": "Internal Active Directory DC",
        "asset_type": "internal_ad",
        "honeypot_link": "dionaea",
        "criticality": "critical",
        "threshold": 65.0,
    },
]


async def ensure_exposure_assets(db: AsyncSession) -> List[ExposureAsset]:
    stmt = select(ExposureAsset)
    res = await db.execute(stmt)
    assets = list(res.scalars().all())

    if not assets:
        for da in DEFAULT_ASSETS:
            asset = ExposureAsset(
                name=da["name"],
                asset_type=da["asset_type"],
                honeypot_link=da["honeypot_link"],
                criticality=da["criticality"],
                exposure_score=15.0,
                threshold=da["threshold"],
                breached=False,
                last_evaluated=datetime.now(timezone.utc),
            )
            db.add(asset)
        await db.flush()
        stmt2 = select(ExposureAsset)
        assets = list((await db.execute(stmt2)).scalars().all())

    return assets


async def evaluate_exposure_budget(db: AsyncSession) -> List[Dict[str, Any]]:
    assets = await ensure_exposure_assets(db)
    now = datetime.now(timezone.utc)
    results: List[Dict[str, Any]] = []

    for asset in assets:
        # Calculate exposure based on attackers touching this honeypot
        stmt_atks = select(func.max(Attacker.risk_score)).where(
            Attacker.honeypots_touched.contains(asset.honeypot_link)
        )
        max_risk = (await db.execute(stmt_atks)).scalar() or 0.0

        stmt_events = select(func.count(Event.id)).where(Event.honeypot == asset.honeypot_link)
        event_count = (await db.execute(stmt_events)).scalar() or 0

        # Weighted exposure score (0-100)
        calc_score = round(min(100.0, max_risk * 0.75 + min(25.0, event_count * 1.5)), 1)
        asset.exposure_score = max(5.0, calc_score)
        asset.breached = asset.exposure_score >= asset.threshold
        asset.last_evaluated = now

        results.append({
            "id": asset.id,
            "name": asset.name,
            "asset_type": asset.asset_type,
            "honeypot_link": asset.honeypot_link,
            "criticality": asset.criticality,
            "exposure_score": asset.exposure_score,
            "threshold": asset.threshold,
            "breached": asset.breached,
            "last_evaluated": asset.last_evaluated.isoformat(),
        })

    await db.flush()
    return results


async def update_exposure_asset_threshold(db: AsyncSession, asset_id: int, threshold: float) -> ExposureAsset:
    stmt = select(ExposureAsset).where(ExposureAsset.id == asset_id)
    res = await db.execute(stmt)
    asset = res.scalar_one_or_none()
    if not asset:
        raise ValueError(f"Exposure asset #{asset_id} not found")

    asset.threshold = threshold
    asset.breached = asset.exposure_score >= threshold
    await db.flush()
    return asset

