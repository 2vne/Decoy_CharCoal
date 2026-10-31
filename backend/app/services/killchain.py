from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import KillChainMapping

PHASES = [
    "Reconnaissance",
    "Delivery",
    "Exploitation",
    "Installation",
    "C2",
    "Actions on Objectives",
]


def map_event_to_phases(
    event_type: str,
    command: Optional[str],
    decoy_type: str,
    classification: Optional[str],
) -> List[str]:
    phases = []
    cmd = (command or "").lower()

    if event_type == "scan" or classification == "port_scan":
        phases.append("Reconnaissance")

    if event_type in ("login_failed", "connect") or classification == "brute_force":
        phases.append("Delivery")

    if event_type in ("login_success", "exploit") or classification == "suspicious_login":
        phases.append("Exploitation")

    if event_type in ("file_download", "file_upload") or classification == "malware_attempt":
        phases.append("Installation")

    if event_type == "command" and cmd:
        if any(k in cmd for k in ["wget", "curl", "tftp", "chmod +x"]):
            phases.append("Installation")
        if any(k in cmd for k in ["crontab", "rc.local", "systemctl"]):
            phases.append("Installation")
        if any(k in cmd for k in ["bash -i", "/dev/tcp", "nc ", "python -c"]):
            phases.append("C2")
        if any(k in cmd for k in ["whoami", "id", "uname", "ls", "cat /etc"]):
            phases.append("Reconnaissance")

    if decoy_type == "internal" or classification == "lateral_movement":
        phases.append("Actions on Objectives")

    out = []
    for p in phases:
        if p in PHASES and p not in out:
            out.append(p)
    return out


async def update_killchain_for_attacker(
    db: AsyncSession,
    attacker_id: int,
    event_uuid: str,
    event_type: str,
    command: Optional[str],
    decoy_type: str,
    classification: Optional[str],
) -> List[Dict[str, Any]]:
    phases = map_event_to_phases(event_type, command, decoy_type, classification)
    now = datetime.now(timezone.utc)

    for phase in phases:
        stmt = select(KillChainMapping).where(
            KillChainMapping.attacker_id == attacker_id,
            KillChainMapping.phase == phase,
        )
        res = await db.execute(stmt)
        existing = res.scalar_one_or_none()

        if existing:
            ev_list = list(existing.evidence_event_ids or [])
            if event_uuid not in ev_list:
                ev_list.append(event_uuid)
                existing.evidence_event_ids = ev_list
                existing.updated_at = now
        else:
            mapping = KillChainMapping(
                attacker_id=attacker_id,
                phase=phase,
                evidence_event_ids=[event_uuid],
                created_at=now,
                updated_at=now,
            )
            db.add(mapping)

    await db.flush()

    stmt = select(KillChainMapping).where(KillChainMapping.attacker_id == attacker_id)
    all_res = await db.execute(stmt)
    return [
        {
            "phase": k.phase,
            "evidence_event_ids": k.evidence_event_ids,
        }
        for k in all_res.scalars().all()
    ]

