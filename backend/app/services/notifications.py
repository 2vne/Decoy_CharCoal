from __future__ import annotations
from datetime import datetime, timezone, timedelta
import logging
import re
from typing import Any, Dict, Optional
import httpx
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.models import Attacker, NotificationLog
from app.services.audit import record_audit

logger = logging.getLogger(__name__)

SUPPRESSION_WINDOW_SECONDS = 300  # 5 minutes


def normalize_phone_e164(phone: str) -> str:
    """Normalize 10-digit or local phone number to E.164 (+91 standard default)."""
    if not phone:
        return ""
    clean = re.sub(r"[^\d+]", "", phone.strip())
    if clean.startswith("+"):
        return clean
    if len(clean) == 10:
        return f"+91{clean}"
    return f"+{clean}"


async def _is_suppressed(db: AsyncSession, attacker_id: int, channel: str) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=SUPPRESSION_WINDOW_SECONDS)
    stmt = (
        select(NotificationLog.id)
        .where(
            NotificationLog.attacker_id == attacker_id,
            NotificationLog.channel == channel,
            NotificationLog.created_at >= cutoff,
            NotificationLog.status.in_(["sent", "simulated"]),
        )
        .limit(1)
    )
    res = await db.execute(stmt)
    return res.scalar_one_or_none() is not None


async def send_telegram_alert(
    token: str,
    chat_id: str,
    text: str,
) -> bool:
    if not token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload)
            return resp.status_code == 200
    except Exception as e:
        logger.warning(f"Telegram notification failed: {e}")
        return False


async def send_pagerduty_alert(
    routing_key: str,
    summary: str,
    source: str,
    severity: str = "critical",
    custom_details: Optional[Dict[str, Any]] = None,
) -> bool:
    if not routing_key:
        return False
    url = "https://events.pagerduty.com/v2/enqueue"
    details = {
        "call_target_phone": settings.pagerduty_phone or "9372185727",
        "action_required": "Voice call dispatched to on-call responder",
        **(custom_details or {}),
    }
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": summary,
            "source": source,
            "severity": "critical" if severity == "critical" else "error",
            "custom_details": details,
        },
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload)
            logger.info(f"PagerDuty event response status: {resp.status_code}")
            return resp.status_code in (200, 202)
    except Exception as e:
        logger.warning(f"PagerDuty alert failed: {e}")
        return False


async def send_twilio_sms(
    to_number: str,
    body: str,
) -> bool:
    sid = settings.twilio_account_sid
    token = settings.twilio_auth_token
    from_num = settings.twilio_phone_number
    if not sid or not token:
        logger.info(f"[Twilio Simulated] SMS to {to_number}: {body}")
        return True

    dest = normalize_phone_e164(to_number or settings.twilio_to_number or "8652477694")
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    
    # Twilio form data
    data = {
        "To": dest,
        "From": normalize_phone_e164(from_num) if from_num else "+15005550006",
        "Body": body,
    }
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(url, data=data, auth=(sid, token))
            logger.info(f"Twilio SMS response status {resp.status_code}: {resp.text[:120]}")
            return resp.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"Twilio SMS failed to {dest}: {e}")
        return False


async def send_twilio_voice_call(
    to_number: str,
    message: str,
) -> bool:
    sid = settings.twilio_account_sid
    token = settings.twilio_auth_token
    from_num = settings.twilio_phone_number
    if not sid or not token:
        logger.info(f"[Twilio Simulated] Voice call to {to_number}: {message}")
        return True

    dest = normalize_phone_e164(to_number or settings.pagerduty_phone or "9372185727")
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json"
    twiml = f"<Response><Say voice='alice'>{message}</Say></Response>"
    data = {
        "To": dest,
        "From": normalize_phone_e164(from_num) if from_num else "+15005550006",
        "Twiml": twiml,
    }
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(url, data=data, auth=(sid, token))
            logger.info(f"Twilio Voice Call response status {resp.status_code}: {resp.text[:120]}")
            return resp.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"Twilio Voice Call failed to {dest}: {e}")
        return False


async def send_resend_email(
    api_key: str,
    to_email: str,
    subject: str,
    html: str,
) -> bool:
    key = (api_key or settings.resend_api_key or "").strip('"')
    dest = (to_email or settings.authority_email or "danishsjain@gmail.com").strip('"')
    if not key or not dest:
        logger.info(f"[Resend Email Simulated] To: {dest}, Subject: {subject}")
        return True

    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    payload = {
        "from": "onboarding@resend.dev",
        "to": [dest],
        "subject": subject,
        "html": html,
    }
    try:
        async with httpx.AsyncClient(timeout=3.5) as client:
            resp = await client.post(url, headers=headers, json=payload)
            logger.info(f"Resend email status {resp.status_code}: {resp.text[:120]}")
            return resp.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"Resend email failed to {dest}: {e}")
        return False


async def route_and_dispatch_notification(
    db: AsyncSession,
    attacker: Attacker,
    severity: str,  # high or critical
    title: str,
    message: str,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    results = {}
    # Prioritize email first for ultra-fast dispatch, followed by pagerduty, twilio, telegram
    channels = ["email", "pagerduty", "twilio", "telegram"]

    target_call_phone = settings.pagerduty_phone or "9372185727"
    target_sms_phone = settings.twilio_to_number or "8652477694"
    target_email = settings.authority_email or "danishsjain@gmail.com"

    for channel in channels:
        # Check 5-minute suppression window
        if await _is_suppressed(db, attacker.id, channel):
            log_entry = NotificationLog(
                attacker_id=attacker.id,
                target_ip=attacker.ip,
                channel=channel,
                severity=severity,
                recipient=target_call_phone if channel == "pagerduty" else target_sms_phone,
                payload={"title": title, "message": message, "reason": "rate_limit_5min"},
                status="suppressed",
                created_at=datetime.now(timezone.utc),
            )
            db.add(log_entry)
            results[channel] = "suppressed"
            continue

        # Execute or simulate
        status = "simulated"
        recipient = "simulated_channel"

        if channel == "pagerduty":
            recipient = target_call_phone
            pd_summary = f"[CRITICAL ATTACK ALERT] Sentinel SOC call to {target_call_phone} - Attacker {attacker.ip} (Risk {attacker.risk_score:.0f})"
            if settings.pagerduty_routing_key:
                pd_success = await send_pagerduty_alert(
                    routing_key=settings.pagerduty_routing_key,
                    summary=pd_summary,
                    source=f"sentinel:{attacker.ip}",
                    severity=severity,
                    custom_details={
                        "call_recipient": target_call_phone,
                        "sms_recipient": target_sms_phone,
                        "intent": attacker.intent,
                        **(details or {}),
                    },
                )
                # Also trigger Twilio voice call to the call target
                await send_twilio_voice_call(
                    to_number=target_call_phone,
                    message=f"Sentinel SOC emergency alert. Attack launched by IP {attacker.ip}. Risk velocity {attacker.risk_score:.0f} out of 100.",
                )
                status = "sent" if pd_success else "simulated"
            else:
                status = "simulated"

        elif channel == "twilio":
            recipient = target_sms_phone
            sms_text = f"🚨 [SENTINEL SOC] Attack alert: IP {attacker.ip} launched an attack. Risk: {attacker.risk_score:.0f}/100. Intent: {attacker.intent}. Call dispatched to {target_call_phone}."
            if settings.twilio_account_sid and settings.twilio_auth_token:
                tw_success = await send_twilio_sms(
                    to_number=target_sms_phone,
                    body=sms_text,
                )
                status = "sent" if tw_success else "simulated"
            else:
                status = "simulated"

        elif channel == "email":
            recipient = target_email
            email_subj = f"🚨 [THREAT DETECTED] Security Intrusion from {attacker.ip} (Risk {attacker.risk_score:.0f})"
            email_body = f"""
            <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #1e293b; max-width: 600px; border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px;">
                <div style="display: flex; align-items: center; margin-bottom: 16px;">
                    <span style="font-size: 24px; margin-right: 8px;">🚨</span>
                    <h2 style="color: #dc2626; margin: 0; font-size: 20px;">Threat Detected by Sentinel SOC</h2>
                </div>
                <p style="font-size: 14px; margin: 0 0 16px 0; color: #475569;">
                    An active security threat was detected engaging monitored decoy honeypots.
                </p>
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px;">
                    <tr style="border-bottom: 1px solid #f1f5f9;">
                        <td style="padding: 10px 0; font-weight: bold; color: #64748b; width: 40%;">Attacker IP:</td>
                        <td style="padding: 10px 0; font-family: monospace; font-size: 14px; font-weight: bold;">{attacker.ip}</td>
                    </tr>
                    <tr style="border-bottom: 1px solid #f1f5f9;">
                        <td style="padding: 10px 0; font-weight: bold; color: #64748b;">Risk Score:</td>
                        <td style="padding: 10px 0; color: #dc2626; font-weight: bold;">{attacker.risk_score:.0f}/100 ({severity.upper()})</td>
                    </tr>
                    <tr style="border-bottom: 1px solid #f1f5f9;">
                        <td style="padding: 10px 0; font-weight: bold; color: #64748b;">Detected Intent:</td>
                        <td style="padding: 10px 0; text-transform: uppercase;">{attacker.intent}</td>
                    </tr>
                    <tr style="border-bottom: 1px solid #f1f5f9;">
                        <td style="padding: 10px 0; font-weight: bold; color: #64748b;">Honeypots Touched:</td>
                        <td style="padding: 10px 0;">{', '.join(attacker.honeypots_touched or [])}</td>
                    </tr>
                    <tr style="border-bottom: 1px solid #f1f5f9;">
                        <td style="padding: 10px 0; font-weight: bold; color: #64748b;">Emergency Voice Call:</td>
                        <td style="padding: 10px 0;">Dispatched to {target_call_phone}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px 0; font-weight: bold; color: #64748b;">Emergency SMS:</td>
                        <td style="padding: 10px 0;">Dispatched to {target_sms_phone}</td>
                    </tr>
                </table>
                <div style="background-color: #fef2f2; border-left: 4px solid #ef4444; padding: 12px; border-radius: 4px; margin-bottom: 20px;">
                    <p style="margin: 0; font-size: 12px; color: #991b1b;">
                        <strong>Action Taken:</strong> Decoy telemetry and forensics payload captured in Sentinel SOC evidence vault.
                    </p>
                </div>
                <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 20px 0;">
                <p style="font-size: 11px; color: #94a3b8; margin: 0;">
                    Sentinel SOC Deception Platform &bull; Automated Incident Response
                </p>
            </div>
            """
            em_success = await send_resend_email(settings.resend_api_key, target_email, email_subj, email_body)
            status = "sent" if em_success else "failed"

        elif channel == "telegram":
            recipient = settings.telegram_chat_id or "default_chat"
            if settings.telegram_bot_token and settings.telegram_chat_id:
                text = f"🚨 *SENTINEL SOC ALERT [{severity.upper()}]*\n*Target IP:* `{attacker.ip}`\n*Risk Score:* `{attacker.risk_score:.0f}`\n\n{message}"
                success = await send_telegram_alert(settings.telegram_bot_token, settings.telegram_chat_id, text)
                status = "sent" if success else "simulated"
            else:
                status = "simulated"

        log_entry = NotificationLog(
            attacker_id=attacker.id,
            target_ip=attacker.ip,
            channel=channel,
            severity=severity,
            recipient=recipient,
            payload={"title": title, "message": message, "details": details or {}, "phone_call": target_call_phone, "sms": target_sms_phone},
            status=status,
            created_at=datetime.now(timezone.utc),
        )
        db.add(log_entry)
        results[channel] = status

        # Record in audit log
        await record_audit(
            db=db,
            entity_type="notification",
            entity_id=f"{attacker.id}:{channel}",
            action="dispatch_notification",
            actor="system",
            details={"channel": channel, "severity": severity, "status": status, "target_ip": attacker.ip, "recipient": recipient},
        )

    await db.flush()
    return results

