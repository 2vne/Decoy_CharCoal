from __future__ import annotations
from datetime import datetime, timezone, timedelta
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import GatewayIncident
from app.services.broadcast import broadcast


def generate_failure_investigation(
    endpoint: str,
    error_code: int,
    error_details: str,
    recurrence_count: int,
    related_function: Optional[str] = None,
    related_attacker_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generates explainable AI root-cause analysis for gateway and endpoint failures.
    Strictly separates observed facts, hypotheses, and recommended response steps.
    """
    observed_facts = [
        f"HTTP error status {error_code} recorded on endpoint {endpoint}.",
        f"Recurrence counter: {recurrence_count} historical failure cycles detected on this endpoint.",
    ]
    if related_attacker_ip:
        observed_facts.append(f"Concurrent suspicious traffic originating from IP {related_attacker_ip}.")
    if related_function:
        observed_facts.append(f"Affected endpoint maps directly to critical system function: '{related_function}'.")

    # Domain hypotheses based on error status
    hypotheses = []
    log_targets = ["/var/log/nginx/error.log", "/var/log/sentinel/backend.log"]
    team = "backend"

    if error_code in (502, 504):
        hypotheses.append("Upstream application process hung, crashed, or was overwhelmed by heavy payload volume.")
        hypotheses.append("FastAPI worker socket timeout or connection pool exhaustion.")
        log_targets.append("/var/log/syslog (OOM-killer checks)")
    elif error_code == 503:
        hypotheses.append("Service temporarily unavailable due to thread starvation or unhandled upstream dependency timeout.")
    elif error_code == 429:
        hypotheses.append("Rate-limiting threshold tripped by aggressive automated scanner or credential brute-force.")
        team = "security"
    elif error_code == 401 or error_code == 403:
        hypotheses.append("Authentication subsystem failure or invalid credential validation sequence.")
        team = "security"

    if related_function == "payment_gateway":
        team = "payments"
    elif related_function in ("database_api", "secrets_env"):
        team = "database" if related_function == "database_api" else "devops"

    recommended_actions = [
        {"action": "Inspect Upstream Logs", "details": f"Review {', '.join(log_targets)} for fatal stack traces around incident window."},
        {"action": "Team Assignment", "details": f"Dispatch triage notification to the {team.upper()} engineering team."},
    ]

    if recurrence_count >= 2:
        recommended_actions.append({
            "action": "Investigate Recent Code Commits",
            "details": f"Endpoint has failed {recurrence_count} times. Check recent Git commits touching {endpoint}.",
        })
        recommended_actions.append({
            "action": "Consider Secret / Credential Rotation",
            "details": "If failure was triggered by credential stuffing or config leak, rotate relevant API tokens immediately.",
        })

    return {
        "observed_facts": observed_facts,
        "hypotheses": hypotheses,
        "logs_to_inspect": log_targets,
        "recommended_team": team,
        "recommended_actions": recommended_actions,
        "requires_secret_rotation": recurrence_count >= 2 and related_function in ("secrets_env", "payment_gateway"),
        "confidence": min(0.95, round(0.70 + 0.08 * recurrence_count, 2)),
    }


async def record_gateway_failure(
    db: AsyncSession,
    endpoint: str,
    error_code: int = 502,
    error_details: str = "",
    related_attacker_ip: Optional[str] = None,
    related_function: Optional[str] = None,
    severity: str = "high",
    event_timestamp: Optional[datetime] = None,
) -> GatewayIncident:
    """
    Ingests or updates a gateway failure incident.
    Detects recurrence if the endpoint previously experienced failures.
    """
    ts = event_timestamp or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    # Check for recent active or resolved incident on same endpoint (last 72h)
    cutoff = ts - timedelta(hours=72)
    stmt = (
        select(GatewayIncident)
        .where(GatewayIncident.endpoint == endpoint, GatewayIncident.first_failure_ts >= cutoff)
        .order_by(desc(GatewayIncident.last_failure_ts))
    )
    res = await db.execute(stmt)
    existing = res.scalars().first()

    if existing and existing.status in ("active", "mitigated", "resolved"):
        # Recurrence detected!
        existing.recurrence_count += 1
        existing.last_failure_ts = ts
        existing.status = "recurring"
        existing.severity = "critical" if existing.recurrence_count >= 2 else "high"
        existing.error_details = error_details or existing.error_details
        if related_attacker_ip:
            existing.related_attacker_ip = related_attacker_ip
        if related_function:
            existing.related_function = related_function

        investigation = generate_failure_investigation(
            endpoint=endpoint,
            error_code=error_code,
            error_details=existing.error_details,
            recurrence_count=existing.recurrence_count,
            related_function=existing.related_function,
            related_attacker_ip=existing.related_attacker_ip,
        )
        existing.ai_investigation = investigation
        incident = existing
    else:
        # New Incident
        inc_uuid = f"gw-inc-{uuid.uuid4().hex[:8]}"
        investigation = generate_failure_investigation(
            endpoint=endpoint,
            error_code=error_code,
            error_details=error_details,
            recurrence_count=1,
            related_function=related_function,
            related_attacker_ip=related_attacker_ip,
        )
        incident = GatewayIncident(
            incident_uuid=inc_uuid,
            endpoint=endpoint,
            status="active",
            severity=severity,
            error_code=error_code,
            first_failure_ts=ts,
            detection_ts=ts,
            last_failure_ts=ts,
            recurrence_count=1,
            related_attacker_ip=related_attacker_ip,
            related_function=related_function,
            error_details=error_details,
            evidence={"initial_error": error_code, "details": error_details[:200]},
            ai_investigation=investigation,
        )
        db.add(incident)

    await db.flush()

    # Broadcast gateway failure alert over live WebSocket
    try:
        await broadcast("gateway_incident", {
            "id": incident.id,
            "incident_uuid": incident.incident_uuid,
            "endpoint": incident.endpoint,
            "status": incident.status,
            "severity": incident.severity,
            "error_code": incident.error_code,
            "recurrence_count": incident.recurrence_count,
            "related_function": incident.related_function,
            "related_attacker_ip": incident.related_attacker_ip,
            "timestamp": ts.isoformat(),
        })
    except Exception:
        pass

    return incident

