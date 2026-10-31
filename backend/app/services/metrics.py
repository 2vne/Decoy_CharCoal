from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import Any, Dict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Alert, Attacker, Event, Incident


async def compute_metrics(db: AsyncSession) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)

    # 1. TTD / TTR averages and last 20
    stmt_inc = select(Incident).order_by(Incident.created_at.desc()).limit(20)
    inc_res = await db.execute(stmt_inc)
    incidents = inc_res.scalars().all()

    last_20_ttd = [round(i.ttd_seconds, 1) for i in incidents if i.ttd_seconds is not None]
    last_20_ttr = [round(i.ttr_seconds, 1) for i in incidents if i.ttr_seconds is not None]

    ttd_avg = round(sum(last_20_ttd) / len(last_20_ttd), 1) if last_20_ttd else None
    ttr_avg = round(sum(last_20_ttr) / len(last_20_ttr), 1) if last_20_ttr else None

    # 2. Total alerts suppressed
    stmt_supp = select(func.sum(Alert.alerts_suppressed))
    supp_res = await db.execute(stmt_supp)
    alerts_suppressed = int(supp_res.scalar_one_or_none() or 0)

    # 3. Band counts
    band_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    stmt_bands = select(Attacker.risk_band, func.count(Attacker.id)).group_by(Attacker.risk_band)
    band_res = await db.execute(stmt_bands)
    for band, count in band_res.all():
        if band in band_counts:
            band_counts[band] = count

    # 4. Events over time (last 24 hours in 1-hour buckets)
    events_over_time = []
    for h in range(23, -1, -1):
        start = now - timedelta(hours=h + 1)
        end = now - timedelta(hours=h)
        stmt_ev = select(func.count(Event.id)).where(Event.received_at >= start, Event.received_at < end)
        ev_res = await db.execute(stmt_ev)
        count = ev_res.scalar_one() or 0
        events_over_time.append({
            "hour": start.strftime("%H:00"),
            "count": count,
        })

    # 5. Top honeypots
    stmt_hp = select(Event.honeypot, func.count(Event.id)).group_by(Event.honeypot).order_by(func.count(Event.id).desc()).limit(8)
    hp_res = await db.execute(stmt_hp)
    top_honeypots = [{"honeypot": hp, "count": count} for hp, count in hp_res.all()]

    # 6. Top attack types
    stmt_types = select(Event.event_type, func.count(Event.id)).group_by(Event.event_type).order_by(func.count(Event.id).desc()).limit(8)
    types_res = await db.execute(stmt_types)
    top_attack_types = [{"event_type": et, "count": count} for et, count in types_res.all()]

    return {
        "ttd_avg": ttd_avg,
        "ttr_avg": ttr_avg,
        "alerts_suppressed": alerts_suppressed,
        "band_counts": band_counts,
        "events_over_time": events_over_time,
        "top_honeypots": top_honeypots,
        "top_attack_types": top_attack_types,
        "last_20_ttd": last_20_ttd,
        "last_20_ttr": last_20_ttr,
    }

