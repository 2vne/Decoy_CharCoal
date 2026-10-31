from __future__ import annotations
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import MitreMapping

TECHNIQUES = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1222": {"name": "File Permissions Modification", "tactic": "Defense Evasion"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
}


def map_event_to_techniques(
    event_type: str,
    command: Optional[str],
    decoy_type: str,
    classification: Optional[str],
) -> List[str]:
    techniques = []
    cmd = (command or "").lower()

    if event_type == "login_failed" or classification == "brute_force":
        techniques.append("T1110")

    if event_type == "login_success":
        techniques.append("T1078")

    if event_type == "scan" or classification == "port_scan":
        techniques.append("T1046")

    if decoy_type == "internal" or classification == "lateral_movement":
        techniques.append("T1021")

    if event_type == "command" and cmd:
        if any(k in cmd for k in ["whoami", "id", "uname"]):
            techniques.append("T1082")
        if any(k in cmd for k in ["cat /etc/passwd", " w ", "last", "who"]):
            techniques.append("T1087")
        if any(k in cmd for k in ["ls", "find", "dir"]):
            techniques.append("T1083")
        if any(k in cmd for k in ["wget", "curl", "tftp", "fetch"]):
            techniques.append("T1105")
        if "chmod +x" in cmd:
            techniques.append("T1222")
        if any(k in cmd for k in ["crontab", "rc.local", "systemctl enable"]):
            techniques.append("T1053")

    # preserve unique order
    out = []
    for t in techniques:
        if t in TECHNIQUES and t not in out:
            out.append(t)
    return out


async def update_mitre_for_attacker(
    db: AsyncSession,
    attacker_id: int,
    event_uuid: str,
    event_type: str,
    command: Optional[str],
    decoy_type: str,
    classification: Optional[str],
) -> List[Dict[str, Any]]:
    tech_ids = map_event_to_techniques(event_type, command, decoy_type, classification)

    for tech_id in tech_ids:
        stmt = select(MitreMapping).where(
            MitreMapping.attacker_id == attacker_id,
            MitreMapping.technique_id == tech_id,
        )
        res = await db.execute(stmt)
        existing = res.scalar_one_or_none()

        if existing:
            ev_list = list(existing.evidence_event_ids or [])
            if event_uuid not in ev_list:
                ev_list.append(event_uuid)
                existing.evidence_event_ids = ev_list
        else:
            meta = TECHNIQUES[tech_id]
            mapping = MitreMapping(
                attacker_id=attacker_id,
                technique_id=tech_id,
                technique_name=meta["name"],
                tactic=meta["tactic"],
                evidence_event_ids=[event_uuid],
            )
            db.add(mapping)

    await db.flush()

    stmt = select(MitreMapping).where(MitreMapping.attacker_id == attacker_id)
    all_res = await db.execute(stmt)
    return [
        {
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "tactic": m.tactic,
            "evidence_event_ids": m.evidence_event_ids,
        }
        for m in all_res.scalars().all()
    ]

