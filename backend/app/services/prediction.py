from __future__ import annotations
from typing import Any, Dict, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Attacker, KillChainMapping

DECOY_CATALOG = {
    "cowrie": {"service": "SSH Bastion Decoy", "port": 22, "type": "external"},
    "opencanary": {"service": "Corporate Web Admin & MySQL", "port": 8080, "type": "internal"},
    "dionaea": {"service": "Windows SMB & MS-RPC Server", "port": 445, "type": "internal"},
    "conpot": {"service": "Substation SCADA PLC (Modbus)", "port": 502, "type": "internal"},
}


async def predict_attacker_propagation(
    db: AsyncSession,
    attacker_id: int,
) -> Dict[str, Any]:
    stmt = select(Attacker).where(Attacker.id == attacker_id)
    res = await db.execute(stmt)
    attacker = res.scalar_one_or_none()
    if not attacker:
        raise ValueError(f"Attacker #{attacker_id} not found")

    touched = set(attacker.honeypots_touched or [])

    # Fetch latest kill chain stage
    kc_stmt = select(KillChainMapping.phase).where(KillChainMapping.attacker_id == attacker_id).order_by(KillChainMapping.id.desc()).limit(1)
    current_phase = (await db.execute(kc_stmt)).scalar_one_or_none() or "recon"

    ranked_targets: List[Dict[str, Any]] = []

    # Heuristic transition graph
    if "cowrie" in touched and "opencanary" not in touched:
        ranked_targets.append({
            "decoy": "opencanary",
            "service": DECOY_CATALOG["opencanary"]["service"],
            "port": DECOY_CATALOG["opencanary"]["port"],
            "probability": 0.82,
            "rationale": "Adversaries with SSH foothold routinely spray stolen credentials into internal HTTP/DB administration portals.",
        })
    if "cowrie" in touched and "dionaea" not in touched:
        ranked_targets.append({
            "decoy": "dionaea",
            "service": DECOY_CATALOG["dionaea"]["service"],
            "port": DECOY_CATALOG["dionaea"]["port"],
            "probability": 0.68,
            "rationale": "High likelihood of automated lateral SMB worm propagation (EternalBlue / PsExec techniques) across port 445.",
        })
    if "conpot" not in touched:
        prob = 0.55 if ("dionaea" in touched or "opencanary" in touched) else 0.28
        ranked_targets.append({
            "decoy": "conpot",
            "service": DECOY_CATALOG["conpot"]["service"],
            "port": DECOY_CATALOG["conpot"]["port"],
            "probability": prob,
            "rationale": "Deep lateral traversal towards operational technology / Modbus sensors if segmentation is breached.",
        })

    # Default fallback if all touched
    if not ranked_targets:
        ranked_targets.append({
            "decoy": "conpot",
            "service": "Modbus Function Code Injection",
            "port": 502,
            "probability": 0.91,
            "rationale": "Host has touched all sensor tiers. Predicted action is ICS register overwrite and payload execution.",
        })

    # Sort descending by probability
    ranked_targets.sort(key=lambda x: x["probability"], reverse=True)

    return {
        "attacker_id": attacker.id,
        "ip": attacker.ip,
        "current_stage": current_phase,
        "observed_honeypots": list(touched),
        "likely_next_targets": ranked_targets,
    }

