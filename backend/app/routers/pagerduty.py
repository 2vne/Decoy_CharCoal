from __future__ import annotations
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import get_db
from app.services.pagerduty import pagerduty_manager

router = APIRouter(prefix="/pagerduty", tags=["PagerDuty Integration"])


@router.get("/status")
async def get_pagerduty_status() -> Dict[str, Any]:
    """Returns the operational status, responder configuration, and incident counts."""
    return pagerduty_manager.get_status()


@router.get("/incidents")
async def list_pagerduty_incidents() -> Dict[str, Any]:
    """Returns the active and recent PagerDuty incidents correlated by session/dedup_key."""
    incidents = pagerduty_manager.get_all_incidents()
    return {
        "incidents": incidents,
        "count": len(incidents),
        "status": pagerduty_manager.get_status(),
    }


@router.post("/test")
async def test_pagerduty_notification(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Triggers an explicit test notification to verify PagerDuty connectivity,
    responder routing, and event delivery.
    """
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    operator = body.get("operator", "soc_lead")
    responder_phone = settings.pagerduty_phone or "9372185727"
    responder_email = settings.authority_email or "danishsjain@gmail.com"

    test_dedup_key = f"sentinel_test_verification_{int(request.state.__dict__.get('time', 0)) or 'soc'}"

    incident = await pagerduty_manager.trigger_or_update_incident(
        dedup_key=test_dedup_key,
        summary="[SIMULATED] Sentinel SOC: On-Call Responder Verification Alert",
        severity="error",
        source=f"sentinel:test:{operator}",
        component="soc_verification",
        incident_class="integration_test",
        custom_details={
            "operator": operator,
            "test_purpose": "Verify on-call routing, phone escalation, and email alerting",
            "configured_phone": responder_phone,
            "configured_email": responder_email,
        },
        session_id="test_verification_session",
        src_ip=request.client.host if request.client else "127.0.0.1",
        is_simulated=True,
        category="verification_test",
        db=db,
    )

    return {
        "status": "success",
        "message": "PagerDuty verification incident dispatched successfully.",
        "incident": incident,
        "responder": {
            "phone": responder_phone,
            "email": responder_email,
        },
    }


@router.post("/incidents/{dedup_key}/acknowledge")
async def acknowledge_incident(dedup_key: str, request: Request) -> Dict[str, Any]:
    """Acknowledges an open PagerDuty incident."""
    operator = "soc_operator"
    try:
        body = await request.json()
        operator = body.get("operator", "soc_operator")
    except Exception:
        pass

    incident = await pagerduty_manager.acknowledge_incident(dedup_key, ack_by=operator)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found for dedup_key")

    return {
        "status": "acknowledged",
        "incident": incident,
    }


@router.post("/incidents/{dedup_key}/resolve")
async def resolve_incident(dedup_key: str, request: Request) -> Dict[str, Any]:
    """Resolves an open PagerDuty incident."""
    operator = "soc_operator"
    reason = "Threat mitigated and decoy session isolated"
    try:
        body = await request.json()
        operator = body.get("operator", "soc_operator")
        reason = body.get("reason", reason)
    except Exception:
        pass

    incident = await pagerduty_manager.resolve_incident(dedup_key, resolved_by=operator, reason=reason)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found for dedup_key")

    return {
        "status": "resolved",
        "incident": incident,
    }

