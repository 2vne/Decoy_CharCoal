from __future__ import annotations
import asyncio
import logging
from pathlib import Path
import sys
from fastapi import APIRouter, BackgroundTasks, Request
from app.config import settings

# Ensure repository root and backend directory are on sys.path so 'simulator' can be resolved
for _p in (Path(__file__).resolve().parents[3], Path(__file__).resolve().parents[2]):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

router = APIRouter()
logger = logging.getLogger(__name__)


async def run_scenario_background(scenario: str, speed: float) -> None:
    # Use httpx to POST to local server
    import httpx
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            from simulator.simulate_attack import SCENARIOS
            if scenario in SCENARIOS:
                fn = SCENARIOS[scenario]
                await fn(client, "http://127.0.0.1:8000", settings.api_key, speed)
            else:
                logger.warning(f"Unknown scenario: {scenario}")
    except Exception as e:
        logger.error(f"Error in simulated scenario background task: {e}")


@router.post("/simulate/start")
async def start_simulate(
    request: Request,
    background_tasks: BackgroundTasks,
):
    body = await request.json()
    scenario = body.get("scenario", "full_chain")
    operator = body.get("operator") or request.client.host if request.client else "soc_operator"
    launch_id = body.get("launch_id")
    raw_speed = body.get("speed", 1.0)
    speed_map = {"fast": 2.5, "faster": 4.0, "normal": 1.0, "slow": 0.5}
    if isinstance(raw_speed, str) and raw_speed in speed_map:
        speed = speed_map[raw_speed]
    else:
        try:
            speed = float(raw_speed)
        except (ValueError, TypeError):
            speed = 1.0

    # Immediate concurrent dispatch of attack alerts to Email, PagerDuty, and Twilio in parallel
    async def dispatch_attack_alerts():
        from app.services.notifications import send_pagerduty_alert, send_twilio_sms, send_twilio_voice_call, send_resend_email
        pd_call_target = settings.pagerduty_phone or "9372185727"
        twilio_sms_target = settings.twilio_to_number or "8652477694"
        target_email = settings.authority_email or "danishsjain@gmail.com"

        email_html = f"""
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #1e293b; max-width: 600px; border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px;">
            <div style="display: flex; align-items: center; margin-bottom: 16px;">
                <span style="font-size: 24px; margin-right: 8px;">🚨</span>
                <h2 style="color: #dc2626; margin: 0; font-size: 20px;">Threat Detected by Sentinel SOC</h2>
            </div>
            <p style="font-size: 14px; margin: 0 0 16px 0; color: #475569;">
                A live security incident has been detected across monitored honeypot decoys.
            </p>
            <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px;">
                <tr style="border-bottom: 1px solid #f1f5f9;">
                    <td style="padding: 10px 0; font-weight: bold; color: #64748b; width: 40%;">Incident Status:</td>
                    <td style="padding: 10px 0; color: #dc2626; font-weight: bold;">ACTIVE THREAT DETECTED</td>
                </tr>
                <tr style="border-bottom: 1px solid #f1f5f9;">
                    <td style="padding: 10px 0; font-weight: bold; color: #64748b;">Detected Pattern:</td>
                    <td style="padding: 10px 0; font-weight: bold; color: #0f172a;">{scenario.replace('_', ' ').title()}</td>
                </tr>
                <tr style="border-bottom: 1px solid #f1f5f9;">
                    <td style="padding: 10px 0; font-weight: bold; color: #64748b;">Emergency Voice Call:</td>
                    <td style="padding: 10px 0; color: #0f172a;">Dispatched to {pd_call_target}</td>
                </tr>
                <tr>
                    <td style="padding: 10px 0; font-weight: bold; color: #64748b;">Emergency SMS:</td>
                    <td style="padding: 10px 0; color: #0f172a;">Dispatched to {twilio_sms_target}</td>
                </tr>
            </table>
            <div style="background-color: #fef2f2; border-left: 4px solid #ef4444; padding: 12px; border-radius: 4px; margin-bottom: 20px;">
                <p style="margin: 0; font-size: 12px; color: #991b1b;">
                    <strong>Security Notice:</strong> Automated countermeasures and honeypot telemetry recording are in progress.
                </p>
            </div>
            <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 20px 0;">
            <p style="font-size: 11px; color: #94a3b8; margin: 0;">
                Sentinel SOC Deception Platform &bull; Automated Security Operations Center Alert
            </p>
        </div>
        """

        alert_tasks = []

        # 1. Email trigger (fired immediately in parallel)
        if settings.resend_api_key:
            alert_tasks.append(
                send_resend_email(
                    api_key=settings.resend_api_key,
                    to_email=target_email,
                    subject=f"🚨 [SENTINEL SOC] Threat Detected: {scenario.replace('_', ' ').title()}",
                    html=email_html,
                )
            )

        # 2. PagerDuty Incident Manager (handles correlation, [SIMULATED] tags, idempotency)
        try:
            from app.services.pagerduty import dispatch_launch_control_pagerduty_alert
            alert_tasks.append(
                dispatch_launch_control_pagerduty_alert(
                    scenario=scenario,
                    operator=operator,
                    launch_id=launch_id,
                    speed=speed,
                    is_simulated=True,
                )
            )
        except Exception as e:
            logger.warning(f"PagerDuty launch dispatch error: {e}")

        if settings.pagerduty_routing_key:
            alert_tasks.append(
                send_twilio_voice_call(
                    to_number=pd_call_target,
                    message=f"Sentinel SOC emergency alert. Attack scenario {scenario} has been launched. Responder attention required.",
                )
            )

        # 3. Twilio SMS trigger
        if settings.twilio_account_sid and settings.twilio_auth_token:
            alert_tasks.append(
                send_twilio_sms(
                    to_number=twilio_sms_target,
                    body=f"🚨 [SENTINEL SOC] Attack launched! Scenario: {scenario}. Emergency call dispatched to {pd_call_target}.",
                )
            )

        if alert_tasks:
            await asyncio.gather(*alert_tasks, return_exceptions=True)

    # Fire alert dispatch instantly without waiting for response transmission
    asyncio.create_task(dispatch_attack_alerts())
    background_tasks.add_task(run_scenario_background, scenario, speed)
    return {
        "status": "started",
        "scenario": scenario,
        "speed": speed,
        "alerts": {
            "pagerduty_call": settings.pagerduty_phone or "9372185727",
            "twilio_sms": settings.twilio_to_number or "8652477694",
            "email": settings.authority_email or "danishsjain@gmail.com",
        },
    }

