from __future__ import annotations
import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import (
    Attacker,
    Event,
    Incident,
    Gateway,
    CommitAttribution,
    ObservedBehaviourEvent,
    AdvisoryStepStatus,
)
from app.services.playbook_loader import match_playbooks, get_all_playbooks, PlaybookModel

logger = logging.getLogger("sentinel.remediation")

# Cache mapping key -> (hash, advisory_data)
_ADVISORY_CACHE: Dict[str, Tuple[str, Dict[str, Any]]] = {}

DISCLAIMER_TEXT = "AI suggestion, human review required"
MANDATORY_CAVEATS = [
    "Restoring a service without fixing the likely root cause invites a repeat attack.",
    "Reopen service in stages according to the staged reopen plan.",
    "Maintain heightened monitoring during the active watch window.",
    "AI suggestion, human review required before executing any remediation step.",
]


def mask_secrets(value: Any) -> Any:
    """
    Sanitizes strings and nested structures, masking passwords, bearer tokens, and keys.
    """
    if isinstance(value, str):
        masked = re.sub(r'(?i)(password|secret|token|api_?key|auth)[:=]\s*["\']?([^"\'\s&]+)', r'\1=[MASKED]', value)
        masked = re.sub(r'Bearer\s+[A-Za-z0-9_\-\.]+', 'Bearer [MASKED]', masked)
        masked = re.sub(r'(SK[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,})', '[MASKED_KEY]', masked)
        return masked
    elif isinstance(value, dict):
        result = {}
        for k, v in value.items():
            if re.search(r'(?i)(password|secret|token|api_?key|auth)', str(k)) and isinstance(v, str):
                result[k] = '[MASKED]'
            else:
                result[k] = mask_secrets(v)
        return result
    elif isinstance(value, list):
        return [mask_secrets(item) for item in value]
    return value


def _compute_input_hash(payload: Dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def build_evidence_table(
    events: List[Any],
    categories: List[str],
    mitre_techniques: List[str],
) -> Dict[str, List[str]]:
    """
    Maps category/technique keys to relevant event IDs.
    """
    evidence_table: Dict[str, List[str]] = {}

    for cat in categories:
        evidence_table[cat] = []
    for tech in mitre_techniques:
        evidence_table[tech] = []

    for ev in events:
        ev_id = getattr(ev, "event_id", None) or str(getattr(ev, "id", ""))
        cat = getattr(ev, "category", None) or getattr(ev, "event_type", None)
        if cat and cat in evidence_table:
            if ev_id not in evidence_table[cat]:
                evidence_table[cat].append(ev_id)

        # Raw or normalised checks for MITRE
        raw = getattr(ev, "raw", {}) or {}
        technique = raw.get("mitre_technique")
        if technique and technique in evidence_table:
            if ev_id not in evidence_table[technique]:
                evidence_table[technique].append(ev_id)

    return evidence_table


def generate_template_advisory(
    matched_playbooks: List[PlaybookModel],
    attacker_ip: str,
    risk_score: float,
    is_reattack: bool,
    evidence_table: Dict[str, List[str]],
    suggested_owner: Optional[str] = None,
    gateway_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Deterministic template advisory conforming strictly to the requested schema.
    Used in MOCK_MODE or when OpenAI calls fail / timeout.
    """
    likely_causes = []
    immediate_actions = []
    before_reopening = []
    staged_reopen_plan = []
    monitoring_after_restore = []
    long_term_fixes = []

    seen_immediate: set = set()
    seen_before: set = set()
    seen_monitoring: set = set()
    seen_long_term: set = set()
    all_evidence_ids: List[str] = []

    for ev_ids in evidence_table.values():
        all_evidence_ids.extend(ev_ids)
    all_evidence_ids = list(dict.fromkeys(all_evidence_ids))[:10]

    for pb in matched_playbooks:
        # Determine likely cause with confidence
        conf = 0.95 if pb.id == "pb_reattack_after_restore" else (0.85 if pb.severity == "critical" else 0.75)
        cause_text = f"Likely {pb.title.lower()} exploitation"
        if gateway_name:
            cause_text += f" targeting {gateway_name}"
        if is_reattack and pb.id == "pb_reattack_after_restore":
            cause_text = f"Likely persistent re-attack on {gateway_name or 'gateway'} prior to complete vulnerability remediation"

        # Find matching evidence IDs
        pb_ev_ids = []
        for trigger_cat in pb.trigger.categories:
            pb_ev_ids.extend(evidence_table.get(trigger_cat, []))
        for trigger_tech in pb.trigger.mitre_techniques:
            pb_ev_ids.extend(evidence_table.get(trigger_tech, []))
        pb_ev_ids = list(dict.fromkeys(pb_ev_ids)) or all_evidence_ids[:3]

        likely_causes.append({
            "text": cause_text,
            "confidence": round(conf, 2),
            "evidence_event_ids": pb_ev_ids,
            "playbook_id": pb.id,
        })

        # Immediate actions
        for act in pb.immediate_actions:
            if act.step not in seen_immediate:
                seen_immediate.add(act.step)
                immediate_actions.append({
                    "step": act.step,
                    "why": act.why,
                    "playbook_id": pb.id,
                    "evidence_event_ids": pb_ev_ids,
                })

        # Before reopening
        for act in pb.before_reopening:
            if act.step not in seen_before:
                seen_before.add(act.step)
                before_reopening.append({
                    "step": act.step,
                    "why": act.why,
                    "playbook_id": pb.id,
                    "evidence_event_ids": pb_ev_ids,
                })

        # Staged reopen plan (use highest severity playbook's staged reopen)
        if not staged_reopen_plan and pb.staged_reopen:
            for phase in pb.staged_reopen:
                staged_reopen_plan.append({
                    "phase": phase.phase,
                    "traffic_percent": phase.traffic_percent,
                    "exit_criteria": phase.exit_criteria,
                })

        # Monitoring after restore
        for act in pb.monitoring_after_restore:
            if act.step not in seen_monitoring:
                seen_monitoring.add(act.step)
                monitoring_after_restore.append({
                    "step": act.step,
                    "why": act.why,
                    "playbook_id": pb.id,
                })

        # Long term fixes
        for act in pb.long_term_fixes:
            if act.step not in seen_long_term:
                seen_long_term.add(act.step)
                long_term_fixes.append({
                    "step": act.step,
                    "why": act.why,
                    "playbook_id": pb.id,
                })

    # Default staged reopen if not covered
    if not staged_reopen_plan:
        staged_reopen_plan = [
            {"phase": "Canary Verification", "traffic_percent": 10, "exit_criteria": "Zero tripwire hits and error rate < 0.1% for 15 min"},
            {"phase": "Controlled Ramp", "traffic_percent": 50, "exit_criteria": "Telemetry stability verified for 30 min"},
            {"phase": "Full Production Reopen", "traffic_percent": 100, "exit_criteria": "Watch mode active with threshold protection"},
        ]

    reattack_level = "CRITICAL" if is_reattack else ("HIGH" if risk_score >= 70 else "MEDIUM")
    reattack_reasons = []
    if is_reattack:
        reattack_reasons.append("Adversary re-attacked service within the post-restore observation window.")
    if risk_score >= 70:
        reattack_reasons.append("Attacker risk score exceeds critical diversion thresholds.")
    reattack_reasons.append("Automated tooling or persistent script may retry until vulnerability is patched.")

    advisory = {
        "disclaimer": DISCLAIMER_TEXT,
        "source": "TEMPLATE (MOCK)",
        "confidence": 0.90 if is_reattack else 0.85,
        "likely_causes": likely_causes,
        "immediate_actions": immediate_actions,
        "before_reopening": before_reopening,
        "staged_reopen_plan": staged_reopen_plan,
        "monitoring_after_restore": monitoring_after_restore,
        "long_term_fixes": long_term_fixes,
        "reattack_risk": {
            "level": reattack_level,
            "reasons": reattack_reasons,
        },
        "caveats": list(MANDATORY_CAVEATS),
        "suggested_owner": suggested_owner,
    }
    return advisory


async def generate_remediation_advisory(
    incident: Optional[Incident] = None,
    gateway: Optional[Gateway] = None,
    db: Optional[AsyncSession] = None,
    force_refresh: bool = False,
) -> Dict[str, Any]:
    """
    Main entry point for generating a Remediation Advisory for an incident or gateway.
    Handles playbook matching, evidence correlation, LLM tailoring with schema validation,
    fallback to deterministic template, and caching.
    """
    target_id = f"inc_{incident.id}" if incident else (f"gw_{gateway.id}" if gateway else "general")

    # 1. Gather context
    attacker_ip = "unknown"
    risk_score = 50.0
    is_reattack = False
    categories_hit: List[str] = []
    mitre_techniques: List[str] = []
    raw_events: List[Any] = []
    suggested_owner: Optional[str] = None
    gateway_name: Optional[str] = gateway.name if gateway else None

    if gateway:
        is_reattack = bool(gateway.reattack_after_restore)
        if gateway.id == "payment":
            categories_hit.extend(["payment_gateway", "payment_manipulation"])
        elif gateway.id == "auth":
            categories_hit.extend(["authentication_login", "two_factor_otp", "login_failures"])
        elif gateway.id == "admin":
            categories_hit.extend(["admin_panel", "admin_access"])

    if incident and db:
        risk_score = float(incident.risk_score_at_creation or 75.0)
        # Fetch related attacker
        if incident.attacker_id:
            atk_res = await db.execute(select(Attacker).where(Attacker.id == incident.attacker_id))
            atk = atk_res.scalar_one_or_none()
            if atk:
                attacker_ip = atk.ip
                if atk.factors:
                    categories_hit.extend([f.get("factor") for f in atk.factors if isinstance(f, dict)])

        # Fetch recent events for incident
        ev_stmt = (
            select(Event)
            .where(Event.src_ip == attacker_ip)
            .order_by(desc(Event.timestamp))
            .limit(50)
        )
        ev_res = await db.execute(ev_stmt)
        raw_events = list(ev_res.scalars().all())

        # Check for Git Attribution (suggested owner / last modified by)
        attr_stmt = (
            select(CommitAttribution)
            .where(CommitAttribution.incident_id == incident.id)
            .order_by(desc(CommitAttribution.confidence))
            .limit(1)
        )
        attr_res = await db.execute(attr_stmt)
        attribution = attr_res.scalar_one_or_none()
        if attribution:
            suggested_owner = f"Last modified by: {attribution.author_name} ({attribution.author_email}) in commit {attribution.commit_hash[:8]}"

    if not suggested_owner and gateway:
        suggested_owner = f"Assigned team: {gateway.owner_team.replace('_', ' ').title()}"

    # Match playbooks
    matched_pbs = match_playbooks(
        categories=categories_hit,
        mitre_techniques=mitre_techniques,
        is_reattack=is_reattack,
    )

    # Build evidence table
    evidence_table = build_evidence_table(raw_events, categories_hit, mitre_techniques)

    # Compute cache key
    input_state = {
        "target_id": target_id,
        "risk_score": risk_score,
        "is_reattack": is_reattack,
        "playbook_ids": [p.id for p in matched_pbs],
        "events_count": len(raw_events),
        "gateway_status": gateway.status if gateway else None,
        "suggested_owner": suggested_owner,
    }
    input_hash = _compute_input_hash(input_state)

    if not force_refresh and target_id in _ADVISORY_CACHE:
        cached_hash, cached_advisory = _ADVISORY_CACHE[target_id]
        if cached_hash == input_hash:
            return cached_advisory

    # Generate template advisory as base
    template_advisory = generate_template_advisory(
        matched_playbooks=matched_pbs,
        attacker_ip=attacker_ip,
        risk_score=risk_score,
        is_reattack=is_reattack,
        evidence_table=evidence_table,
        suggested_owner=suggested_owner,
        gateway_name=gateway_name,
    )

    final_advisory = template_advisory

    # If OpenAI is configured and not in mock_mode, call LLM to tailor and reorder
    if settings.openai_api_key and not settings.mock_mode:
        try:
            valid_pb_ids = {p.id for p in matched_pbs}
            prompt_context = {
                "attacker_ip": attacker_ip,
                "risk_score": risk_score,
                "is_reattack": is_reattack,
                "gateway_name": gateway_name,
                "matched_playbooks": [
                    {
                        "id": p.id,
                        "title": p.title,
                        "immediate_actions": [{"step": a.step, "why": a.why} for a in p.immediate_actions],
                        "before_reopening": [{"step": a.step, "why": a.why} for a in p.before_reopening],
                        "staged_reopen": [{"phase": s.phase, "traffic_percent": s.traffic_percent, "exit_criteria": s.exit_criteria} for s in p.staged_reopen],
                        "monitoring_after_restore": [{"step": a.step, "why": a.why} for a in p.monitoring_after_restore],
                        "long_term_fixes": [{"step": a.step, "why": a.why} for a in p.long_term_fixes],
                    }
                    for p in matched_pbs
                ],
                "suggested_owner": suggested_owner,
                "recent_logs": [
                    mask_secrets(getattr(ev, "raw", {}) or getattr(ev, "command", "") or getattr(ev, "url", ""))
                    for ev in raw_events[:20]
                ],
            }

            system_instructions = (
                "You are the SENTINEL Remediation Advisor. You turn incidents and gateway telemetry into suggested fixes.\n"
                "NON-NEGOTIABLE RULES:\n"
                "1. SUGGESTIONS ONLY. Output label: 'AI suggestion, human review required'.\n"
                "2. Do not assert an unverified root cause. Use 'likely' and give confidence.\n"
                "3. Never claim a person caused the breach. Use 'last modified by'.\n"
                "4. You may only tailor, reorder, and explain playbook steps. You may NOT add steps whose playbook_id is missing from the matched playbooks.\n"
                "5. Always include in caveats: Restoring a service without fixing the likely root cause invites a repeat attack; reopen in stages; keep heightened monitoring after restore.\n"
                "6. Return strictly a JSON object conforming to the schema."
            )

            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {settings.openai_api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": settings.openai_model,
                        "messages": [
                            {"role": "system", "content": system_instructions},
                            {"role": "user", "content": json.dumps(prompt_context)},
                        ],
                        "response_format": {"type": "json_object"},
                        "temperature": 0.2,
                    },
                )
                if res.status_code == 200:
                    data = res.json()
                    content = data["choices"][0]["message"]["content"]
                    parsed = json.loads(content)

                    # Validate that all returned steps reference an existing playbook_id
                    all_steps_valid = True
                    for section in ["immediate_actions", "before_reopening", "monitoring_after_restore", "long_term_fixes"]:
                        for item in parsed.get(section, []):
                            if item.get("playbook_id") not in valid_pb_ids:
                                all_steps_valid = False
                                break

                    if all_steps_valid:
                        parsed["disclaimer"] = DISCLAIMER_TEXT
                        parsed["source"] = "OPENAI"
                        # Ensure mandatory caveats are present
                        caveats = set(parsed.get("caveats", []))
                        for mc in MANDATORY_CAVEATS:
                            caveats.add(mc)
                        parsed["caveats"] = list(caveats)
                        final_advisory = parsed
                        logger.info("Successfully generated OpenAI-tailored remediation advisory.")
                    else:
                        logger.warning("OpenAI output contained steps without valid playbook_id. Falling back to template.")
                else:
                    logger.warning(f"OpenAI call returned status {res.status_code}. Falling back to template.")
        except Exception as e:
            logger.warning(f"OpenAI call failed or timed out ({e}). Falling back to template advisory.")

    # Cache result
    _ADVISORY_CACHE[target_id] = (input_hash, final_advisory)
    return final_advisory
