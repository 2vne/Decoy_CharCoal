from __future__ import annotations
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
import httpx
from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.models import Attacker, Event, Incident, KillChainMapping, MitreMapping, Relationship
from app.services.audit import record_audit

logger = logging.getLogger(__name__)


async def gather_investigation_context(db: AsyncSession, incident: Incident) -> Dict[str, Any]:
    attacker_id = incident.attacker_id
    attacker: Optional[Attacker] = None
    events: List[Event] = []
    mitre_list: List[MitreMapping] = []
    kc_list: List[KillChainMapping] = []
    related_attackers: List[Dict[str, Any]] = []

    if attacker_id:
        # Attacker
        att_res = await db.execute(select(Attacker).where(Attacker.id == attacker_id))
        attacker = att_res.scalar_one_or_none()

        # Events
        ev_stmt = (
            select(Event)
            .where(Event.attacker_id == attacker_id)
            .order_by(Event.timestamp.asc())
            .limit(50)
        )
        ev_res = await db.execute(ev_stmt)
        events = list(ev_res.scalars().all())

        # MITRE
        m_stmt = select(MitreMapping).where(MitreMapping.attacker_id == attacker_id)
        m_res = await db.execute(m_stmt)
        mitre_list = list(m_res.scalars().all())

        # Kill Chain
        kc_stmt = select(KillChainMapping).where(KillChainMapping.attacker_id == attacker_id)
        kc_res = await db.execute(kc_stmt)
        kc_list = list(kc_res.scalars().all())

        # Relationships
        rel_stmt = (
            select(Relationship)
            .where(or_(Relationship.attacker_a_id == attacker_id, Relationship.attacker_b_id == attacker_id))
            .limit(10)
        )
        rel_res = await db.execute(rel_stmt)
        for r in rel_res.scalars().all():
            other_id = r.attacker_b_id if r.attacker_a_id == attacker_id else r.attacker_a_id
            other_att = (await db.execute(select(Attacker.ip).where(Attacker.id == other_id))).scalar_one_or_none()
            related_attackers.append({
                "related_ip": other_att or f"ID:{other_id}",
                "rel_type": r.rel_type,
                "weight": r.weight,
                "evidence": r.evidence,
            })

    return {
        "incident": incident,
        "attacker": attacker,
        "events": events,
        "mitre": mitre_list,
        "kill_chain": kc_list,
        "related": related_attackers,
    }


def generate_template_investigation(context: Dict[str, Any]) -> Dict[str, Any]:
    incident: Incident = context["incident"]
    attacker: Optional[Attacker] = context.get("attacker")
    events: List[Event] = context.get("events", [])
    mitre: List[MitreMapping] = context.get("mitre", [])
    related: List[Dict[str, Any]] = context.get("related", [])

    ip = attacker.ip if attacker else "Unknown"
    score = attacker.risk_score if attacker else incident.risk_score_at_creation
    intent = attacker.intent if attacker else "unknown"
    honeypots = list(attacker.honeypots_touched or []) if attacker else []
    commands = list(attacker.commands or []) if attacker else []

    # Evidence list
    evidence_items = []
    for ev in events[-10:]:
        evidence_items.append({
            "event_id": ev.event_id,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else "",
            "honeypot": ev.honeypot,
            "event_type": ev.event_type,
            "command": ev.command,
            "significance": f"Observed {ev.event_type} on {ev.honeypot}:{ev.dst_port or 'N/A'}",
        })

    # What happened
    hp_summary = ", ".join(honeypots) if honeypots else "multiple decoy sensors"
    cmd_summary = f" Commands executed include '{commands[0]}'" if commands else ""
    what_happened = (
        f"Attacker {ip} initiated hostile deception probes against {hp_summary}. "
        f"The host conducted automated reconnaissance and attempted authentication compromise.{cmd_summary}. "
        f"Behavioral telemetry identified intent as '{intent}' with an aggregated risk velocity of {score:.0f}/100."
    )

    # Why dangerous
    danger_factors = []
    if "internal" in str(incident.blast_radius):
        danger_factors.append("adversary touched high-value internal decoy services representing lateral movement")
    if commands:
        danger_factors.append("interactive command execution observed including persistence/payload retrieval")
    if mitre:
        t_names = [m.technique_name for m in mitre[:3]]
        danger_factors.append(f"mapped to critical MITRE ATT&CK techniques: {', '.join(t_names)}")
    if related:
        danger_factors.append(f"correlated with {len(related)} other hostile nodes via shared credentials or fingerprints")

    if not danger_factors:
        danger_factors.append("exhibits persistent automated brute force and service probing velocity")

    why_dangerous = (
        f"High severity breach threat. Specifically, {'; '.join(danger_factors)}. "
        f"Unmitigated progression presents immediate exposure to credential harvesting and lateral propagation."
    )

    # Recommended actions
    recommended = [
        f"Enforce immediate edge firewall block on {ip} for 600s with automated verification",
        f"Isolate decoy credentials used ({', '.join(list(attacker.passwords or [])[:3]) or 'observed passes'}) across production directories",
    ]
    if "conpot" in honeypots or "dionaea" in honeypots:
        recommended.append("Audit OT/ICS and SMB ingress rules against perimeter perimeter logs")
    if related:
        recommended.append(f"Place coordinated cluster IPs on active sentinel watchlist ({len(related)} related hosts)")

    return {
        "incident_id": incident.id,
        "what_happened": what_happened,
        "why_dangerous": why_dangerous,
        "evidence_list": evidence_items,
        "confidence": 0.94 if len(events) >= 5 else 0.82,
        "recommended_actions": recommended,
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "model_used": "template_fallback",
    }


async def run_ai_investigation(db: AsyncSession, incident_id: int, force_refresh: bool = False) -> Dict[str, Any]:
    stmt = select(Incident).where(Incident.id == incident_id)
    res = await db.execute(stmt)
    incident = res.scalar_one_or_none()
    if not incident:
        raise ValueError(f"Incident #{incident_id} not found")

    # If already cached and not force_refresh
    if incident.ai_investigation and not force_refresh:
        return incident.ai_investigation

    ctx = await gather_investigation_context(db, incident)

    # Check if OpenAI is configured and not in mock mode
    investigation_data: Dict[str, Any]
    if settings.openai_api_key and not settings.mock_mode:
        try:
            investigation_data = await _call_openai_investigation(ctx)
        except Exception as e:
            logger.warning(f"OpenAI investigation call failed ({e}); falling back to template engine")
            investigation_data = generate_template_investigation(ctx)
    else:
        investigation_data = generate_template_investigation(ctx)

    # Store cache on incident
    incident.ai_investigation = investigation_data
    await record_audit(
        db=db,
        entity_type="incident",
        entity_id=incident.id,
        action="ai_investigation_generated",
        actor="ai_investigator",
        details={"confidence": investigation_data.get("confidence"), "model": investigation_data.get("model_used")},
    )
    await db.flush()
    return investigation_data


async def _call_openai_investigation(context: Dict[str, Any]) -> Dict[str, Any]:
    incident: Incident = context["incident"]
    attacker: Optional[Attacker] = context.get("attacker")
    events: List[Event] = context.get("events", [])
    mitre: List[MitreMapping] = context.get("mitre", [])

    prompt_summary = {
        "incident_id": incident.id,
        "attacker_ip": attacker.ip if attacker else "N/A",
        "risk_score": attacker.risk_score if attacker else 80.0,
        "intent": attacker.intent if attacker else "reconnaissance",
        "honeypots": list(attacker.honeypots_touched or []) if attacker else [],
        "commands": list(attacker.commands or [])[:10] if attacker else [],
        "mitre_techniques": [f"{m.technique_id} - {m.technique_name}" for m in mitre],
        "recent_event_ids": [ev.event_id for ev in events[-10:]],
    }

    system_prompt = (
        "You are an expert SOC Level 3 Cyber Threat Investigator analyzing deception telemetry from Sentinel SOC. "
        "Return valid JSON matching this exact structure:\n"
        "{\n"
        '  "what_happened": "Clear factual narrative of the attack sequence",\n'
        '  "why_dangerous": "Specific blast radius and operational risk factors",\n'
        '  "evidence_list": [{"event_id": "...", "significance": "..."}],\n'
        '  "confidence": 0.95,\n'
        '  "recommended_actions": ["Action 1", "Action 2"]\n'
        "}"
    )

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": settings.openai_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Investigate this incident telemetry:\n{json.dumps(prompt_summary)}"},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.2,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        raw_json = resp.json()["choices"][0]["message"]["content"]
        parsed = json.loads(raw_json)
        parsed["incident_id"] = incident.id
        parsed["cached_at"] = datetime.now(timezone.utc).isoformat()
        parsed["model_used"] = settings.openai_model
        return parsed

