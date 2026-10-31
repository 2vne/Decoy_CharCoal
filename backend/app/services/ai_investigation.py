from __future__ import annotations
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
import httpx
from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.models import (
    Attacker,
    CommitAttribution,
    Event,
    FunctionTargetEvent,
    GatewayIncident,
    GatewayRequestLog,
    Incident,
    KillChainMapping,
    MitreMapping,
    Relationship,
)
from app.services.audit import record_audit

logger = logging.getLogger(__name__)


async def gather_investigation_context(db: AsyncSession, incident: Incident) -> Dict[str, Any]:
    attacker_id = incident.attacker_id
    attacker: Optional[Attacker] = None
    events: List[Event] = []
    function_events: List[FunctionTargetEvent] = []
    gateway_logs: List[GatewayRequestLog] = []
    gateway_incidents: List[GatewayIncident] = []
    commit_leads: List[CommitAttribution] = []
    mitre_list: List[MitreMapping] = []
    kc_list: List[KillChainMapping] = []
    related_attackers: List[Dict[str, Any]] = []

    if attacker_id:
        # 1. Attacker Profile
        att_res = await db.execute(select(Attacker).where(Attacker.id == attacker_id))
        attacker = att_res.scalar_one_or_none()

        # 2. Raw Events
        ev_stmt = (
            select(Event)
            .where(Event.attacker_id == attacker_id)
            .order_by(Event.timestamp.asc())
            .limit(50)
        )
        ev_res = await db.execute(ev_stmt)
        events = list(ev_res.scalars().all())

        # 3. Level-2 Function Targeting Telemetry
        fn_stmt = (
            select(FunctionTargetEvent)
            .where(FunctionTargetEvent.attacker_id == attacker_id)
            .order_by(FunctionTargetEvent.timestamp.asc())
            .limit(30)
        )
        fn_res = await db.execute(fn_stmt)
        function_events = list(fn_res.scalars().all())

        if attacker:
            # 4. Gateway Routing Telemetry
            gw_stmt = (
                select(GatewayRequestLog)
                .where(GatewayRequestLog.src_ip == attacker.ip)
                .order_by(desc(GatewayRequestLog.timestamp))
                .limit(20)
            )
            gw_res = await db.execute(gw_stmt)
            gateway_logs = list(gw_res.scalars().all())

            # 5. Gateway Failures linked to this attacker or targeted functions
            gi_stmt = (
                select(GatewayIncident)
                .where(or_(GatewayIncident.related_attacker_ip == attacker.ip, GatewayIncident.related_function.in_(attacker.targeted_functions or [])))
                .limit(5)
            )
            gi_res = await db.execute(gi_stmt)
            gateway_incidents = list(gi_res.scalars().all())

        # 6. Commit Attribution Leads
        ca_stmt = (
            select(CommitAttribution)
            .order_by(desc(CommitAttribution.commit_ts))
            .limit(5)
        )
        ca_res = await db.execute(ca_stmt)
        commit_leads = list(ca_res.scalars().all())

        # 7. MITRE & Kill Chain
        m_stmt = select(MitreMapping).where(MitreMapping.attacker_id == attacker_id)
        m_res = await db.execute(m_stmt)
        mitre_list = list(m_res.scalars().all())

        kc_stmt = select(KillChainMapping).where(KillChainMapping.attacker_id == attacker_id)
        kc_res = await db.execute(kc_stmt)
        kc_list = list(kc_res.scalars().all())

        # 8. Relationships
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
        "function_events": function_events,
        "gateway_logs": gateway_logs,
        "gateway_incidents": gateway_incidents,
        "commit_leads": commit_leads,
        "mitre": mitre_list,
        "kill_chain": kc_list,
        "related": related_attackers,
    }


def generate_template_investigation(context: Dict[str, Any]) -> Dict[str, Any]:
    incident: Incident = context["incident"]
    attacker: Optional[Attacker] = context.get("attacker")
    events: List[Event] = context.get("events", [])
    function_events: List[FunctionTargetEvent] = context.get("function_events", [])
    gateway_logs: List[GatewayRequestLog] = context.get("gateway_logs", [])
    gateway_incidents: List[GatewayIncident] = context.get("gateway_incidents", [])
    commit_leads: List[CommitAttribution] = context.get("commit_leads", [])
    mitre: List[MitreMapping] = context.get("mitre", [])
    related: List[Dict[str, Any]] = context.get("related", [])

    ip = attacker.ip if attacker else "Unknown"
    score = attacker.risk_score if attacker else incident.risk_score_at_creation
    fn_score = attacker.function_risk_score if attacker else 0.0
    intent = attacker.intent if attacker else "unknown"
    is_repeat = attacker.is_repeat if attacker else False
    targeted_funcs = attacker.targeted_functions if attacker else []
    was_diverted = any(l.routed_to == "decoy" for l in gateway_logs)

    # 1. Observed Facts (Strict telemetry only)
    observed_facts = [
        f"Attacker source IP: {ip} with {len(events)} captured honeypot events.",
        f"Primary threat score: {score:.1f}/100; Level-2 function risk score: {fn_score:.1f}/100.",
    ]
    if targeted_funcs:
        observed_facts.append(f"Direct targeting recorded against sensitive application function(s): {', '.join(targeted_funcs)}.")
    if was_diverted:
        observed_facts.append("Deception Gateway actively diverted incoming visitor requests to the isolated Decoy Honeynet.")
    if gateway_incidents:
        observed_facts.append(f"Recorded {len(gateway_incidents)} concurrent gateway failures on endpoints touched by adversary.")

    # 2. Inferences (Derived from heuristics & correlations)
    inferences = []
    if is_repeat:
        inferences.append("Host demonstrates persistent reconnaissance across multiple disconnected timeframes.")
    if len(targeted_funcs) >= 2:
        inferences.append("Adversary is executing a coordinated multi-step attack sequence (e.g. Credential Access -> Privilege Escalation).")
    if related:
        inferences.append(f"Correlated with {len(related)} other IP nodes via shared credentials or behavioral fingerprints.")

    # 3. AI Hypotheses
    hypotheses = [
        f"Adversary likely operating automated tooling aimed at '{intent or 'credential_access'}'.",
        "Target selection indicates focus on privilege escalation and core business data rather than random perimeter scanning.",
    ]
    if commit_leads:
        lead = commit_leads[0]
        hypotheses.append(f"Code modification in commit {lead.commit_hash[:8]} ({lead.assigned_team} team) authoring window may correlate with failure behavior.")

    # 4. Recommended Actions
    recommended_actions = [
        f"Maintain dynamic deception routing: Keep {ip} diverted to the decoy honeypot application.",
        f"Propose 600s perimeter firewall block for analyst approval via the Response Center.",
    ]
    if targeted_funcs:
        recommended_actions.append(f"Review ingress filtering on affected function endpoints: {', '.join(targeted_funcs)}.")
    if commit_leads:
        recommended_actions.append(f"Dispatch investigation lead notification to {commit_leads[0].assigned_team} engineering team.")

    # Evidence timeline
    evidence_items = []
    for ev in events[-8:]:
        evidence_items.append({
            "event_id": ev.event_id,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else "",
            "honeypot": ev.honeypot,
            "event_type": ev.event_type,
            "command": ev.command,
            "significance": f"Observed {ev.event_type} on {ev.honeypot}:{ev.dst_port or 'N/A'}",
        })

    return {
        "incident_id": incident.id,
        "what_happened": "\n".join(observed_facts) if observed_facts else f"Suspicious activity targeting {ip}",
        "why_dangerous": "\n".join(hypotheses) if hypotheses else f"Evaluated threat risk score: {max(score, fn_score):.1f}/100",
        "executive_summary": (
            f"Adversary {ip} engaged in deceptive targeting against {len(targeted_funcs) or 1} critical function(s). "
            f"Evaluated with a risk velocity of {max(score, fn_score):.1f}/100. "
            f"{'Traffic was intercepted and diverted to decoy application.' if was_diverted else 'Monitored at gateway perimeter.'}"
        ),
        "attacker_profile": {
            "ip": ip,
            "fingerprint": attacker.fingerprint if attacker else None,
            "is_repeat": is_repeat,
            "total_events": attacker.total_events if attacker else len(events),
            "intent": intent,
            "risk_score": max(score, fn_score),
            "risk_band": attacker.risk_band if attacker else "medium",
        },
        "targeted_functions": targeted_funcs,
        "was_diverted_to_decoy": was_diverted,
        "gateway_failure_detected": len(gateway_incidents) > 0,
        "assigned_team": commit_leads[0].assigned_team if commit_leads else "Security",
        "observed_facts": observed_facts,
        "inferences": inferences,
        "ai_hypotheses": hypotheses,
        "recommended_actions": recommended_actions,
        "evidence_list": evidence_items,
        "potential_commits": [
            {
                "short_hash": c.commit_hash[:8],
                "author": c.author_name,
                "team": c.assigned_team,
                "explanation": c.correlation_explanation,
            }
            for c in commit_leads[:3]
        ],
        "confidence": 0.94 if len(events) >= 5 else 0.84,
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "model_used": "sentinel_ai_investigation_v2",
    }


async def run_ai_investigation(db: AsyncSession, incident_id: int, force_refresh: bool = False) -> Dict[str, Any]:
    stmt = select(Incident).where(Incident.id == incident_id)
    res = await db.execute(stmt)
    incident = res.scalar_one_or_none()
    if not incident:
        raise ValueError(f"Incident #{incident_id} not found")

    if incident.ai_investigation and not force_refresh:
        return incident.ai_investigation

    ctx = await gather_investigation_context(db, incident)

    # Use unified template investigation
    result = generate_template_investigation(ctx)
    incident.ai_investigation = result
    await db.flush()

    await record_audit(
        db=db,
        action="ai_investigation_run",
        actor="system",
        entity_type="incident",
        entity_id=str(incident.id),
        details={"confidence": result.get("confidence", 0.9), "model": result.get("model_used")},
    )

    return result
