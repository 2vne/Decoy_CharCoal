from __future__ import annotations
import asyncio
from datetime import datetime, timezone
import hashlib
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid
import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import NotificationLog
from app.services.broadcast import broadcast

logger = logging.getLogger("sentinel.pagerduty")

PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

PRIORITY_LEVELS = {
    "P1": 4,
    "P2": 3,
    "P3": 2,
    "P4": 1,
}

SEVERITY_TO_PRIORITY = {
    "critical": "P1",
    "error": "P2",
    "warning": "P3",
    "info": "P4",
}

PRIORITY_TO_SEVERITY = {
    "P1": "critical",
    "P2": "error",
    "P3": "warning",
    "P4": "info",
}


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PagerDutyManager:
    """
    Production-grade PagerDuty Incident Lifecycle Manager for SENTINEL:
    - Session-based incident correlation & deduplication via deterministic `dedup_key`.
    - Priority-based escalation (P1 Critical -> P2 Error -> P3 Warning -> P4 Info).
    - Prevents incident storms by updating open incidents on repeat actions.
    - Idempotency guards for Launch Control and manual triggers.
    - Local in-memory and database persistence.
    - Non-blocking asynchronous delivery with safe retries and simulated fallback.
    - Real-time WebSocket broadcasting to SOC Dashboard.
    """

    def __init__(self):
        # In-memory incident registry keyed by dedup_key
        self._incidents: Dict[str, Dict[str, Any]] = {}
        # Idempotency cache: hash -> expiration timestamp (monotonic seconds)
        self._idempotency_cache: Dict[str, float] = {}
        # Statistics
        self._total_triggers: int = 0
        self._last_event_ts: Optional[str] = None
        self._last_status_message: str = "Initialized"

    def _cleanup_idempotency(self) -> None:
        now = time.monotonic()
        expired = [k for k, exp in self._idempotency_cache.items() if exp < now]
        for k in expired:
            self._idempotency_cache.pop(k, None)

    def check_idempotency(self, idempotency_key: str, window_seconds: float = 60.0) -> bool:
        """Returns True if this key is a duplicate within the active window."""
        self._cleanup_idempotency()
        now = time.monotonic()
        if idempotency_key in self._idempotency_cache:
            return True
        self._idempotency_cache[idempotency_key] = now + window_seconds
        return False

    def classify_decoy_priority(
        self,
        category: str,
        endpoint: str,
        is_honeytoken: bool = False,
    ) -> Tuple[str, str]:
        """
        Maps decoy interaction parameters to (priority, severity):
        P1 critical: Honeytokens, payment manipulation, database core dumps.
        P2 error: Admin consoles, repeated auth/OTP failures.
        P3 warning: Password reset, suspicious probing/scans.
        P4 info: Low-risk reconnaissance.
        """
        cat_lower = (category or "").lower()
        ep_lower = (endpoint or "").lower()

        if (
            is_honeytoken
            or "honeytoken" in cat_lower
            or "secrets_env" in cat_lower
            or ".env" in ep_lower
            or "payment" in cat_lower
            or "payment" in ep_lower
            or "checkout" in ep_lower
            or "database" in cat_lower
            or "database" in ep_lower
            or "db_dump" in cat_lower
            or "sql" in ep_lower
        ):
            return "P1", "critical"

        if (
            "admin" in cat_lower
            or "admin" in ep_lower
            or "auth_otp" in cat_lower
            or "auth_login" in cat_lower
            or "login" in ep_lower
            or ".git" in ep_lower
        ):
            return "P2", "error"

        if "reset" in cat_lower or "reset" in ep_lower or "recon" in cat_lower:
            return "P3", "warning"

        return "P4", "info"

    async def _post_pagerduty_api(
        self,
        event_action: str,
        dedup_key: str,
        summary: Optional[str] = None,
        severity: str = "critical",
        source: str = "sentinel",
        component: str = "sentinel_soc",
        group: str = "security_operations",
        incident_class: str = "honeypot_alert",
        custom_details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Sends request to PagerDuty Events API v2 with retries and safe fallbacks.
        When routing key is unset or in mock mode, safely records as simulated.
        """
        routing_key = settings.pagerduty_routing_key

        if not routing_key or settings.mock_mode:
            logger.info(
                f"[PagerDuty Simulated] Action: {event_action}, dedup_key: {dedup_key}, "
                f"severity: {severity}, summary: {summary}"
            )
            return {"status": "simulated", "http_code": 200, "message": "Simulated delivery"}

        payload_body: Dict[str, Any] = {
            "routing_key": routing_key,
            "event_action": event_action,
            "dedup_key": dedup_key,
        }

        if event_action == "trigger":
            payload_body["payload"] = {
                "summary": summary or "MIRAGE Security Incident",
                "source": source,
                "severity": severity,
                "timestamp": utc_iso(),
                "component": component,
                "group": group,
                "class": incident_class,
                "custom_details": custom_details or {},
            }

        # Safe retries with exponential backoff (bounded up to 2 retries, 4.0s timeout)
        for attempt in range(1, 3):
            try:
                async with httpx.AsyncClient(timeout=4.0) as client:
                    resp = await client.post(PAGERDUTY_EVENTS_URL, json=payload_body)
                    if resp.status_code in (200, 201, 202):
                        return {
                            "status": "delivered",
                            "http_code": resp.status_code,
                            "response": resp.json() if resp.text else {},
                        }
                    else:
                        logger.warning(
                            f"PagerDuty API returned {resp.status_code} (attempt {attempt}): {resp.text[:140]}"
                        )
            except Exception as exc:
                logger.warning(f"PagerDuty HTTP request error (attempt {attempt}): {exc}")
                if attempt < 2:
                    await asyncio.sleep(0.5)

        return {"status": "failed", "http_code": 500, "message": "Failed after retries"}

    async def trigger_or_update_incident(
        self,
        dedup_key: str,
        summary: str,
        severity: str = "critical",
        source: str = "sentinel",
        component: str = "deception_gateway",
        incident_class: str = "malicious_probing",
        custom_details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        src_ip: Optional[str] = None,
        is_simulated: bool = False,
        category: Optional[str] = None,
        db: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """
        Core Deduplication and Incident Lifecycle Engine:
        - If an incident with dedup_key is already open:
            * Does NOT create duplicate ticket.
            * Updates existing incident, appends event breadcrumbs, increments counter.
            * Escalates severity if the new event has higher priority (e.g. P3 -> P1).
        - If new incident:
            * Creates tracked incident ticket.
        - Delivers trigger update to PagerDuty Events API v2.
        - Broadcasts `pagerduty_incident` to SOC Dashboard.
        """
        now_ts = utc_iso()
        self._total_triggers += 1
        self._last_event_ts = now_ts

        # Determine priority and severity
        priority = SEVERITY_TO_PRIORITY.get(severity, "P2")

        # Format title with [SIMULATED] tag if simulated
        clean_title = summary
        if is_simulated and not clean_title.startswith("[SIMULATED]"):
            clean_title = f"[SIMULATED] {clean_title}"

        responder_phone = settings.pagerduty_phone or "9372185727"
        responder_email = settings.authority_email or "danishsjain@gmail.com"

        merged_details = {
            "responder_phone": responder_phone,
            "responder_email": responder_email,
            "session_id": session_id or "N/A",
            "src_ip": src_ip or "N/A",
            "category": category or "general",
            "is_simulated": is_simulated,
            **(custom_details or {}),
        }

        # Check existing incident by dedup_key
        existing = self._incidents.get(dedup_key)
        if existing and existing.get("status") in ("triggered", "acknowledged"):
            # Existing incident: update & correlate
            current_priority = existing.get("priority", "P3")
            current_level = PRIORITY_LEVELS.get(current_priority, 1)
            new_level = PRIORITY_LEVELS.get(priority, 1)

            # Escalate priority if higher
            if new_level > current_level:
                existing["priority"] = priority
                existing["severity"] = severity
                existing["title"] = clean_title  # reflect escalated danger in title

            existing["event_count"] = existing.get("event_count", 1) + 1
            existing["updated_at"] = now_ts
            existing["status"] = "triggered"  # re-trigger unacknowledged if new attack event arrives
            existing["history"].insert(
                0,
                {
                    "timestamp": now_ts,
                    "action": "event_correlated",
                    "summary": clean_title,
                    "severity": severity,
                    "priority": priority,
                    "details": merged_details,
                },
            )
            incident_record = existing
            is_new = False
        else:
            # Create new incident record
            incident_id = f"PD-{uuid.uuid4().hex[:8].upper()}"
            incident_record = {
                "id": incident_id,
                "dedup_key": dedup_key,
                "title": clean_title,
                "severity": severity,
                "priority": priority,
                "status": "triggered",
                "session_id": session_id or "unknown_session",
                "src_ip": src_ip or "127.0.0.1",
                "triggering_event": clean_title,
                "category": category or "honeypot",
                "component": component,
                "event_count": 1,
                "is_simulated": is_simulated,
                "created_at": now_ts,
                "updated_at": now_ts,
                "responder_phone": responder_phone,
                "responder_email": responder_email,
                "history": [
                    {
                        "timestamp": now_ts,
                        "action": "incident_created",
                        "summary": clean_title,
                        "severity": severity,
                        "priority": priority,
                        "details": merged_details,
                    }
                ],
                "details": merged_details,
            }
            self._incidents[dedup_key] = incident_record
            is_new = True

        # PagerDuty API delivery
        api_result = await self._post_pagerduty_api(
            event_action="trigger",
            dedup_key=dedup_key,
            summary=incident_record["title"],
            severity=incident_record["severity"],
            source=source,
            component=component,
            incident_class=incident_class,
            custom_details={
                **merged_details,
                "incident_id": incident_record["id"],
                "event_count": incident_record["event_count"],
            },
        )
        incident_record["delivery_status"] = api_result.get("status", "simulated")
        self._last_status_message = f"{'Created' if is_new else 'Updated'} incident {dedup_key} ({incident_record['priority']})"

        # Persist log to database if db session provided
        if db:
            try:
                log_entry = NotificationLog(
                    target_ip=src_ip or "127.0.0.1",
                    channel="pagerduty",
                    severity=incident_record["severity"],
                    recipient=responder_phone,
                    payload={
                        "dedup_key": dedup_key,
                        "incident_id": incident_record["id"],
                        "title": incident_record["title"],
                        "priority": incident_record["priority"],
                        "status": incident_record["status"],
                        "event_count": incident_record["event_count"],
                        "delivery": api_result,
                    },
                    status=api_result.get("status", "simulated"),
                    created_at=datetime.now(timezone.utc),
                )
                db.add(log_entry)
                await db.commit()
            except Exception as e:
                logger.debug(f"Failed to commit NotificationLog: {e}")
                await db.rollback()

        # Real-time WebSocket broadcast to SOC dashboard
        try:
            await broadcast(
                "pagerduty_incident",
                {
                    "action": "created" if is_new else "updated",
                    "incident": incident_record,
                    "stats": self.get_status(),
                    "status": self.get_status(),
                },
            )
        except Exception:
            pass

        return incident_record

    async def acknowledge_incident(self, dedup_key: str, ack_by: str = "soc_operator") -> Optional[Dict[str, Any]]:
        """Acknowledges an open incident in local registry and upstream PagerDuty."""
        incident = self._incidents.get(dedup_key)
        if not incident:
            return None

        now_ts = utc_iso()
        incident["status"] = "acknowledged"
        incident["updated_at"] = now_ts
        incident["history"].insert(
            0,
            {
                "timestamp": now_ts,
                "action": "acknowledged",
                "by": ack_by,
            },
        )

        api_res = await self._post_pagerduty_api(
            event_action="acknowledge",
            dedup_key=dedup_key,
        )
        incident["delivery_status"] = api_res.get("status", "simulated")

        try:
            await broadcast(
                "pagerduty_incident",
                {
                    "action": "acknowledged",
                    "incident": incident,
                    "stats": self.get_status(),
                    "status": self.get_status(),
                },
            )
        except Exception:
            pass

        return incident

    async def resolve_incident(
        self,
        dedup_key: str,
        resolved_by: str = "soc_operator",
        reason: str = "Threat contained and isolated",
    ) -> Optional[Dict[str, Any]]:
        """Resolves an open incident in local registry and upstream PagerDuty."""
        incident = self._incidents.get(dedup_key)
        if not incident:
            return None

        now_ts = utc_iso()
        incident["status"] = "resolved"
        incident["updated_at"] = now_ts
        incident["history"].insert(
            0,
            {
                "timestamp": now_ts,
                "action": "resolved",
                "by": resolved_by,
                "reason": reason,
            },
        )

        api_res = await self._post_pagerduty_api(
            event_action="resolve",
            dedup_key=dedup_key,
        )
        incident["delivery_status"] = api_res.get("status", "simulated")

        try:
            await broadcast(
                "pagerduty_incident",
                {
                    "action": "resolved",
                    "incident": incident,
                    "stats": self.get_status(),
                    "status": self.get_status(),
                },
            )
        except Exception:
            pass

        return incident

    def get_incident(self, dedup_key: str) -> Optional[Dict[str, Any]]:
        return self._incidents.get(dedup_key)

    def get_all_incidents(self) -> List[Dict[str, Any]]:
        return sorted(
            list(self._incidents.values()),
            key=lambda x: x.get("created_at", ""),
            reverse=True,
        )

    def get_status(self) -> Dict[str, Any]:
        routing_key = settings.pagerduty_routing_key or ""
        key_configured = bool(routing_key.strip())
        preview = (
            f"{routing_key[:4]}...{routing_key[-4:]}"
            if key_configured and len(routing_key) >= 8
            else ("configured" if key_configured else "not_configured")
        )

        incidents = list(self._incidents.values())
        open_count = sum(1 for i in incidents if i.get("status") in ("triggered", "acknowledged"))
        p1_count = sum(1 for i in incidents if i.get("priority") == "P1" and i.get("status") != "resolved")

        return {
            "routing_key_configured": key_configured,
            "routing_key_preview": preview,
            "responder_phone": settings.pagerduty_phone or "9372185727",
            "responder_email": settings.authority_email or "danishsjain@gmail.com",
            "total_incidents": len(incidents),
            "open_incidents": open_count,
            "p1_active": p1_count,
            "last_event_ts": self._last_event_ts,
            "last_status_message": self._last_status_message,
            "service_mode": "operational" if key_configured and not settings.mock_mode else "simulated_local",
        }

    def clear_incidents(self) -> None:
        """For testing cleanup."""
        self._incidents.clear()
        self._idempotency_cache.clear()
        self._total_triggers = 0
        self._last_event_ts = None


# Module-level singleton instance
pagerduty_manager = PagerDutyManager()


async def dispatch_decoy_pagerduty_alert(
    session_id: str,
    src_ip: str,
    endpoint: str,
    method: str,
    category: str,
    is_honeytoken: bool = False,
    sanitized_evidence: str = "",
    user_agent: Optional[str] = None,
    is_simulated: bool = False,
) -> Dict[str, Any]:
    """
    Non-blocking decoy alert dispatcher:
    - Derives deterministic correlation dedup_key from session_id.
    - Classifies priority: P1 for honeytokens/payments/database, P2 for admin/auth, etc.
    - Updates open session incident instead of spamming duplicates.
    """
    dedup_key = f"sentinel_decoy_{session_id}"
    priority, severity = pagerduty_manager.classify_decoy_priority(category, endpoint, is_honeytoken)

    title_map = {
        "P1": f"CRITICAL Decoy Breach: {category.replace('_', ' ').title()} - {endpoint}",
        "P2": f"HIGH Decoy Probe: {category.replace('_', ' ').title()} - {endpoint}",
        "P3": f"SUSPICIOUS Decoy Probe: {category.replace('_', ' ').title()} - {endpoint}",
        "P4": f"Decoy Observation: {category.replace('_', ' ').title()} - {endpoint}",
    }
    title = title_map.get(priority, f"Decoy Interaction Alert: {category}")

    custom_details = {
        "endpoint": endpoint,
        "method": method,
        "interaction_category": category,
        "is_honeytoken": is_honeytoken,
        "evidence_snippet": sanitized_evidence[:200] if sanitized_evidence else "None",
        "user_agent": user_agent or "Unknown",
    }

    return await pagerduty_manager.trigger_or_update_incident(
        dedup_key=dedup_key,
        summary=title,
        severity=severity,
        source=f"sentinel:decoy:{src_ip}",
        component="decoy_honeypot",
        incident_class="deception_tripwire",
        custom_details=custom_details,
        session_id=session_id,
        src_ip=src_ip,
        is_simulated=is_simulated,
        category=category,
    )


async def dispatch_launch_control_pagerduty_alert(
    scenario: str,
    operator: str = "soc_operator",
    launch_id: Optional[str] = None,
    speed: float = 1.0,
    is_simulated: bool = True,
) -> Dict[str, Any]:
    """
    Non-blocking Launch Control alert dispatcher:
    - Generates dedup_key per scenario and launch execution.
    - Idempotency guard prevents duplicate incident storms on double-clicking.
    - Tags [SIMULATED] in title and payload.
    - Priority P1 for full-chain / multivector / ransomware, P2 for others.
    """
    clean_scenario = scenario.strip().lower()
    token = launch_id or f"{clean_scenario}_{int(time.time() // 30)}"
    dedup_key = f"sentinel_launch_{token}"

    # Check idempotency within 60s
    idempotency_hash = hashlib.md5(f"{clean_scenario}_{operator}_{launch_id or ''}".encode()).hexdigest()
    if pagerduty_manager.check_idempotency(idempotency_hash, window_seconds=60.0):
        logger.info(f"Duplicate Launch Control alert suppressed by idempotency guard: {dedup_key}")
        existing = pagerduty_manager.get_incident(dedup_key)
        if existing:
            return existing

    # Scenario priority mapping
    critical_scenarios = {"full_chain", "multivector_apt", "multi_vector", "ransomware", "data_exfil"}
    if clean_scenario in critical_scenarios or "apt" in clean_scenario or "chain" in clean_scenario:
        priority = "P1"
        severity = "critical"
    else:
        priority = "P2"
        severity = "error"

    scenario_name = scenario.replace("_", " ").title()
    title = f"[SIMULATED] Launch Control: Attack Scenario '{scenario_name}' Activated"

    custom_details = {
        "scenario": scenario,
        "operator": operator,
        "simulation_speed": speed,
        "launch_id": launch_id or token,
        "action_required": "Operator triage on MIRAGE SOC Live Monitoring",
    }

    return await pagerduty_manager.trigger_or_update_incident(
        dedup_key=dedup_key,
        summary=title,
        severity=severity,
        source=f"sentinel:launch_control:{operator}",
        component="launch_control",
        incident_class="attack_simulation",
        custom_details=custom_details,
        session_id=f"launch_{token}",
        src_ip="127.0.0.1",
        is_simulated=True,
        category="attack_simulation",
    )


async def dispatch_function_intel_pagerduty_alert(
    action: str,
    target_function: str,
    session_id: str = "demo_fn_session_interactive",
    src_ip: str = "198.51.100.99",
    attempts: int = 1,
    evidence: str = "",
    is_simulated: bool = True,
) -> Dict[str, Any]:
    """
    Function Intelligence Alert Dispatcher:
    - Generates unique dedup_key per attack trigger so PagerDuty fires a fresh critical incident and calls the phone.
    - Escalates with priority P1 / severity critical.
    - Sends to PagerDuty Events API v2.
    - Broadcasts pagerduty_incident over WebSockets so the SOC Dashboard updates in real time.
    """
    clean_action = (action or "attack").strip().lower()
    fn_name = target_function.replace("_", " ").title()
    ts = int(time.time() * 10)
    dedup_key = f"sentinel_fn_{target_function}_{ts}"

    priority = "P1"
    severity = "critical"

    action_label = {
        "sensitive_probe": "Sensitive Probe Breach",
        "sensitive": "Sensitive Function Probe",
        "repeated": f"Repeated Attack Burst ({attempts} attempts)",
        "recon": "Multi-Function Reconnaissance Synergy",
    }.get(clean_action, f"Exploit: {clean_action}")

    title = f"[CRITICAL ATTACK] Function Intelligence: {action_label} on {fn_name}"

    custom_details = {
        "action": clean_action,
        "target_function": target_function,
        "function_name": fn_name,
        "attempts": attempts,
        "session_id": session_id,
        "src_ip": src_ip,
        "evidence": evidence or f"Function-level exploit attempt triggered on {fn_name}",
        "call_target": settings.pagerduty_phone or "9372185727",
        "action_required": "Emergency voice call dispatched to on-call responder",
    }

    return await pagerduty_manager.trigger_or_update_incident(
        dedup_key=dedup_key,
        summary=title,
        severity=severity,
        source=f"sentinel:fn_intel:{src_ip}",
        component="function_intelligence",
        incident_class="active_function_attack",
        custom_details=custom_details,
        session_id=session_id,
        src_ip=src_ip,
        is_simulated=is_simulated,
        category="function_targeting",
    )

