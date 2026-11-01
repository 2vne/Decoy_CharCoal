"""
Sentinel Autonomous Alert Dispatcher.

Monitors live application telemetry (Function Intelligence, Real/Decoy App interactions,
Gateway behaviour events) and autonomously dispatches real-time alerts without manual intervention.
"""
from __future__ import annotations
import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy import select

from app.config import settings
from app.db import AsyncSessionLocal
from app.models import Attacker
from app.services.notifications import route_and_dispatch_notification
from app.services.pagerduty import pagerduty_manager

logger = logging.getLogger(__name__)

# Debounce cache: key -> timestamp of last alert dispatch
_DEBOUNCE_CACHE: Dict[str, float] = {}
DEBOUNCE_COOLDOWN = 15.0  # Cooldown per session+function in seconds


async def trigger_autonomous_attack_alert(
    src_ip: str,
    target_function: str,
    target_endpoint: str = "",
    attack_type: str = "probe",
    severity: str = "critical",
    score: float = 0.0,
    evidence: str = "",
    is_simulated: bool = False,
    session_id: Optional[str] = None,
    is_critical: bool = False,
    category: Optional[str] = None,
) -> None:
    """
    Executes autonomous multi-channel alert dispatch for detected attacks:
    1. Debounces rapid duplicate triggers within DEBOUNCE_COOLDOWN.
    2. Instantly updates PagerDuty Manager, forwards to PagerDuty Events API v2,
       and broadcasts `pagerduty_incident` over WebSockets to the SOC Dashboard.
    3. Concurrently dispatches external alerts via Resend Email, Twilio Voice Call,
       Twilio SMS, and Telegram.
    """
    now = time.time()
    endpoint_clean = target_endpoint or target_function
    dedup_token = f"{session_id or src_ip}:{target_function}"

    last_dispatched = _DEBOUNCE_CACHE.get(dedup_token, 0.0)
    if now - last_dispatched < DEBOUNCE_COOLDOWN:
        logger.debug(f"[AUTO-ALERT] Debounced rapid trigger for {dedup_token}")
        return

    _DEBOUNCE_CACHE[dedup_token] = now

    # Priority determination
    is_p1 = (
        severity == "critical"
        or is_critical
        or score >= 60.0
        or any(k in str(target_function).lower() for k in ["secret", "admin", "payment", "database", "bypass", "dump"])
        or any(k in str(endpoint_clean).lower() for k in [".env", ".git", "admin", "payment", "config"])
    )
    pd_priority = "P1" if is_p1 else "P2"
    pd_sev = "critical" if is_p1 else "error"
    sim_tag = "[SIMULATED] " if is_simulated else ""
    summary = f"{sim_tag}[{pd_priority}] Real-Time Attack Detected: {target_function.replace('_', ' ').title()} - {endpoint_clean}"
    if score > 0:
        summary += f" (Risk: {score:.0f})"

    dedup_key = f"sentinel_attack_{session_id or src_ip.replace('.', '_')}"

    custom_details = {
        "dedup_key": dedup_key,
        "target_function": target_function,
        "endpoint": endpoint_clean,
        "attack_type": attack_type,
        "evidence": (evidence or "Live malicious pattern detected")[:250],
        "risk_score": score,
        "src_ip": src_ip,
        "session_id": session_id,
        "is_simulated": is_simulated,
        "category": category or target_function,
    }

    # Step 1: PagerDuty Manager & SOC WebSocket Broadcast
    try:
        await pagerduty_manager.trigger_or_update_incident(
            dedup_key=dedup_key,
            summary=summary,
            severity=pd_sev,
            source=f"sentinel:attack:{src_ip}",
            component="function_intelligence",
            incident_class="active_threat_targeting",
            custom_details=custom_details,
            session_id=session_id or f"atk_{src_ip}",
            src_ip=src_ip,
            is_simulated=is_simulated,
            category=category or target_function,
        )
        logger.info(f"[AUTO-ALERT] PagerDuty incident triggered/updated for {dedup_key}")
    except Exception as e:
        logger.warning(f"[AUTO-ALERT] PagerDuty dispatch failed: {e}")

    # Step 2: External Notifications (Resend Email, Twilio Call/SMS, Telegram)
    try:
        async with AsyncSessionLocal() as db_session:
            async with db_session.begin():
                res = await db_session.execute(select(Attacker).where(Attacker.ip == src_ip))
                attacker = res.scalar_one_or_none()
                if not attacker:
                    attacker = Attacker(
                        ip=src_ip,
                        status="watchlist",
                        risk_score=max(score, 65.0),
                        risk_band="high" if is_p1 else "medium",
                        total_events=1,
                        honeypots_touched=[target_function],
                        sessions=[session_id] if session_id else [],
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                    )
                    db_session.add(attacker)
                    await db_session.flush()
                else:
                    attacker.risk_score = max(attacker.risk_score or 0.0, score)
                    if target_function not in (attacker.honeypots_touched or []):
                        h = list(attacker.honeypots_touched or [])
                        h.append(target_function)
                        attacker.honeypots_touched = h
                    await db_session.flush()

                notif_title = f"CRITICAL: Sentinel Attack Detected - {target_function}"
                notif_msg = (
                    f"Active security breach attempt on endpoint: {endpoint_clean}\n"
                    f"Target Function: {target_function}\n"
                    f"Attacker IP: {src_ip}\n"
                    f"Session ID: {session_id or 'unknown'}\n"
                    f"Risk Score: {score:.0f}/100\n"
                    f"Evidence: {evidence[:200]}"
                )
                await route_and_dispatch_notification(
                    db=db_session,
                    attacker=attacker,
                    severity="critical" if is_p1 else "high",
                    title=notif_title,
                    message=notif_msg,
                    details=custom_details,
                )
                logger.info(f"[AUTO-ALERT] Multi-channel notification pipeline completed for {src_ip}")
    except Exception as e:
        logger.warning(f"[AUTO-ALERT] Notification routing failed: {e}")


def dispatch_attack_alert_background(
    src_ip: str,
    target_function: str,
    target_endpoint: str = "",
    attack_type: str = "probe",
    severity: str = "critical",
    score: float = 0.0,
    evidence: str = "",
    is_simulated: bool = False,
    session_id: Optional[str] = None,
    is_critical: bool = False,
    category: Optional[str] = None,
) -> None:
    """Non-blocking fire-and-forget wrapper for background execution."""
    try:
        asyncio.create_task(
            trigger_autonomous_attack_alert(
                src_ip=src_ip,
                target_function=target_function,
                target_endpoint=target_endpoint,
                attack_type=attack_type,
                severity=severity,
                score=score,
                evidence=evidence,
                is_simulated=is_simulated,
                session_id=session_id,
                is_critical=is_critical,
                category=category,
            )
        )
    except Exception as e:
        logger.warning(f"[AUTO-ALERT] Failed to spawn background alert task: {e}")


async def dispatch_function_intel_live_alert(
    action: str,
    target_function: str,
    session_id: str = "demo_fn_session_interactive",
    src_ip: str = "198.51.100.99",
    attempts: int = 1,
    evidence: str = "",
) -> None:
    """
    Executes live alert dispatch when a user clicks any attack on Function Intelligence:
    1. Sends high-urgency Critical incident to PagerDuty Events API v2 (dials responder phone).
    2. Sends Twilio Voice Call to configured responder phone (+91 9372185727).
    3. Broadcasts pagerduty_incident over WebSockets so dashboard updates immediately.
    4. Creates/persists SOC Incident and broadcasts incident to update Incident Queue.
    5. Sends urgent Resend Email & Twilio SMS.
    """
    fn_name = target_function.replace("_", " ").title()
    pd_call_target = settings.pagerduty_phone or "9372185727"
    twilio_sms_target = settings.twilio_to_number or "8652477694"
    target_email = (settings.authority_email or "aryanreddy2006@gmail.com").strip('"')

    alert_tasks = []

    # 1. PagerDuty Incident Manager & WebSocket broadcast
    from app.services.pagerduty import dispatch_function_intel_pagerduty_alert
    alert_tasks.append(
        dispatch_function_intel_pagerduty_alert(
            action=action,
            target_function=target_function,
            session_id=session_id,
            src_ip=src_ip,
            attempts=attempts,
            evidence=evidence,
            is_simulated=True,
        )
    )

    # 2. Voice Call via Twilio
    from app.services.notifications import send_twilio_voice_call, send_resend_email, send_twilio_sms
    if settings.pagerduty_routing_key or settings.twilio_account_sid:
        alert_tasks.append(
            send_twilio_voice_call(
                to_number=pd_call_target,
                message=f"Sentinel SOC emergency alert. Function attack detected. Targeted function: {fn_name}. Immediate responder attention required.",
            )
        )

    # 3. Direct Email via Resend
    if settings.resend_api_key:
        html = f"""
        <div style="font-family: monospace; padding: 20px; background-color: #0b0f17; color: #f8fafc; border-radius: 8px;">
            <h2 style="color: #ef4444; margin-top: 0;">🚨 [SENTINEL SOC] Function Attack Triggered</h2>
            <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin: 15px 0;">
                <tr style="border-bottom: 1px solid #1e293b;"><td style="padding: 6px 0; color: #94a3b8;">Target Function:</td><td style="padding: 6px 0; font-weight: bold; color: #38bdf8;">{fn_name}</td></tr>
                <tr style="border-bottom: 1px solid #1e293b;"><td style="padding: 6px 0; color: #94a3b8;">Attack Action:</td><td style="padding: 6px 0; font-weight: bold; color: #f87171;">{action.upper()}</td></tr>
                <tr style="border-bottom: 1px solid #1e293b;"><td style="padding: 6px 0; color: #94a3b8;">Attacker IP:</td><td style="padding: 6px 0;">{src_ip}</td></tr>
                <tr style="border-bottom: 1px solid #1e293b;"><td style="padding: 6px 0; color: #94a3b8;">Attempts:</td><td style="padding: 6px 0; color: #fbbf24;">{attempts}</td></tr>
                <tr style="border-bottom: 1px solid #1e293b;"><td style="padding: 6px 0; color: #94a3b8;">Voice Call Dispatched:</td><td style="padding: 6px 0; color: #34d399;">+91 {pd_call_target}</td></tr>
            </table>
            <div style="background-color: #1e1b4b; border-left: 4px solid #818cf8; padding: 10px; border-radius: 4px;">
                <p style="margin: 0; font-size: 11px; color: #c7d2fe;">Evidence: {evidence or 'Live interactive attack from Function Intelligence console'}</p>
            </div>
            <p style="font-size: 10px; color: #64748b; margin-top: 15px;">Sentinel SOC Autonomous Deception Platform</p>
        </div>
        """
        alert_tasks.append(
            send_resend_email(
                api_key=settings.resend_api_key,
                to_email=target_email,
                subject=f"🚨 [SENTINEL SOC] Function Attack: {fn_name} ({action.upper()})",
                html=html,
            )
        )

    # 4. Twilio SMS
    if settings.twilio_account_sid and settings.twilio_auth_token:
        alert_tasks.append(
            send_twilio_sms(
                to_number=twilio_sms_target,
                body=f"🚨 [SENTINEL SOC] Function Attack: {fn_name} ({action}). Voice call dispatched to {pd_call_target}.",
            )
        )

    # 5. Persist SOC Incident & Broadcast to Dashboard
    try:
        from app.services.broadcast import broadcast
        from app.models import Incident, Attacker
        async with AsyncSessionLocal() as db:
            async with db.begin():
                atk_res = await db.execute(select(Attacker).where(Attacker.ip == src_ip))
                atk_obj = atk_res.scalar_one_or_none()
                atk_id = atk_obj.id if atk_obj else None

                inc = Incident(
                    title=f"CRITICAL: Function Attack - {fn_name}",
                    attacker_id=atk_id,
                    status="new",
                    risk_score_at_creation=85.0,
                    root_cause={"target_function": target_function, "action": action, "evidence": evidence},
                    blast_radius={"affected_service": fn_name, "severity": "critical", "attempts": attempts},
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                db.add(inc)
                await db.flush()
                await broadcast("incident", {
                    "id": inc.id,
                    "title": inc.title,
                    "status": inc.status,
                    "severity": "critical",
                    "attacker_id": inc.attacker_id,
                    "created_at": inc.created_at.isoformat(),
                })
    except Exception as e:
        logger.warning(f"[AUTO-ALERT] Failed to persist/broadcast SOC incident: {e}")

    if alert_tasks:
        try:
            await asyncio.gather(*alert_tasks, return_exceptions=True)
            logger.info(f"[AUTO-ALERT] Live function intel alerts dispatched for {target_function} ({action})")
        except Exception as e:
            logger.warning(f"[AUTO-ALERT] Live function intel alert dispatch error: {e}")
