from __future__ import annotations
from typing import Any, Dict, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Attacker, Event, KillChainMapping

STAGE_ORDER = [
    "recon",
    "brute_force",
    "privilege_escalation",
    "malware_staging",
    "lateral_movement",
]

STAGE_RISK_WEIGHTS = {
    "recon": 10.0,
    "brute_force": 25.0,
    "privilege_escalation": 20.0,
    "malware_staging": 25.0,
    "lateral_movement": 20.0,
}


async def simulate_whatif(
    db: AsyncSession,
    attacker_id: int,
    action: str,  # block, delay, none
    at_stage: str,  # recon, brute_force, privilege_escalation, malware_staging, lateral_movement
) -> Dict[str, Any]:
    stmt = select(Attacker).where(Attacker.id == attacker_id)
    res = await db.execute(stmt)
    attacker = res.scalar_one_or_none()
    if not attacker:
        raise ValueError(f"Attacker #{attacker_id} not found")

    # Fetch actual kill chain mappings
    kc_stmt = select(KillChainMapping).where(KillChainMapping.attacker_id == attacker_id)
    kc_mappings = (await db.execute(kc_stmt)).scalars().all()
    actual_phases = {m.phase for m in kc_mappings}

    # Fetch events
    ev_stmt = select(Event).where(Event.attacker_id == attacker_id).order_by(Event.timestamp.asc())
    events = (await db.execute(ev_stmt)).scalars().all()

    stage_idx = STAGE_ORDER.index(at_stage) if at_stage in STAGE_ORDER else 0
    actual_risk = attacker.risk_score

    stages_avoided: List[str] = []
    counterfactual_comparison: List[Dict[str, Any]] = []

    if action == "block":
        # All stages after at_stage are prevented
        for idx, stage in enumerate(STAGE_ORDER):
            was_executed = stage in actual_phases or idx <= stage_idx
            if idx <= stage_idx:
                counterfactual_comparison.append({
                    "stage": stage,
                    "actual_status": "executed" if was_executed else "skipped",
                    "counterfactual_status": "executed",
                    "difference": "Baseline allowed telemetry",
                })
            else:
                if was_executed:
                    stages_avoided.append(stage)
                counterfactual_comparison.append({
                    "stage": stage,
                    "actual_status": "executed" if was_executed else "not_reached",
                    "counterfactual_status": "prevented",
                    "difference": f"Blocked by automated firewall enforcement at stage '{at_stage}'",
                })

        # Calculate projected risk
        accumulated_risk = sum(STAGE_RISK_WEIGHTS[s] for s in STAGE_ORDER[: stage_idx + 1])
        projected_risk = min(actual_risk, max(5.0, accumulated_risk))
        risk_reduction = max(0.0, actual_risk - projected_risk)
        reduction_pct = round((risk_reduction / actual_risk * 100), 1) if actual_risk > 0 else 0.0

        estimated_impact = (
            f"Enforcing '{action}' at '{at_stage}' prevents {len(stages_avoided)} attack phase(s) "
            f"({', '.join(stages_avoided) if stages_avoided else 'subsequent propagation'}). "
            f"Reduces adversary risk velocity by {reduction_pct}% and prevents lateral reach into internal decoys."
        )

    elif action == "delay":
        projected_risk = round(actual_risk * 0.65, 1)
        reduction_pct = 35.0
        stages_avoided = ["lateral_movement"] if "lateral_movement" in actual_phases else []
        estimated_impact = (
            f"Applying tarpit rate-limiting at '{at_stage}' extends attacker dwell-time requirement by 8x. "
            f"Deters automated script engines and reduces threat velocity score to {projected_risk}."
        )
        for stage in STAGE_ORDER:
            counterfactual_comparison.append({
                "stage": stage,
                "actual_status": "executed" if stage in actual_phases else "not_reached",
                "counterfactual_status": "throttled",
                "difference": "Execution latency increased by 800ms per payload",
            })
    else:  # none
        projected_risk = actual_risk
        reduction_pct = 0.0
        estimated_impact = "No containment applied. Attack progression reaches maximum blast radius."
        for stage in STAGE_ORDER:
            counterfactual_comparison.append({
                "stage": stage,
                "actual_status": "executed" if stage in actual_phases else "not_reached",
                "counterfactual_status": "unmitigated",
                "difference": "No intervention",
            })

    return {
        "attacker_id": attacker.id,
        "ip": attacker.ip,
        "action_simulated": action,
        "at_stage": at_stage,
        "actual_risk": actual_risk,
        "projected_risk": projected_risk,
        "risk_reduction_pct": reduction_pct,
        "stages_avoided": stages_avoided,
        "estimated_impact": estimated_impact,
        "counterfactual_comparison": counterfactual_comparison,
    }

