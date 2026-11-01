from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.services.function_intelligence import record_function_targeting
from app.services.ingest import get_or_create_attacker
from app.services.gateway import extract_client_ip
from app.services.decoy_observation import (
    observe_and_delay_decoy,
    get_decoy_observation_stats,
    set_decoy_latency_mode,
    get_decoy_latency_mode,
    run_latency_comparison_demo,
    sanitize_evidence_text,
)

router = APIRouter(prefix="/demo/decoy", tags=["Decoy Honeypot Application"])

# Isolated synthetic canary data (Breadcrumbs that trigger alarms if used)
CANARY_CUSTOMERS = [
    {"id": "canary_901", "name": "Shadow Corp Decoy", "plan": "Canary_Tier", "balance": "$99,999.00", "trap_tag": "flag_decoy_customer_query"},
    {"id": "canary_902", "name": "Ghost Holdings Ltd", "plan": "Honeypot_Core", "balance": "$88,888.00", "trap_tag": "flag_decoy_customer_query"},
]


class DecoyLoginRequest(BaseModel):
    email: str
    password: str


class DecoyOTPRequest(BaseModel):
    email: str
    otp_code: str


class DecoyPasswordResetRequest(BaseModel):
    email: str


class DecoyChargeRequest(BaseModel):
    customer_id: str
    amount: float
    currency: str = "USD"
    token: str


class DecoyModeRequest(BaseModel):
    mode: str  # "controlled" or "normal"


class DecoyCompareRequest(BaseModel):
    category: str = "auth_login"
    session_id: Optional[str] = None


def _get_client_ip(request: Request) -> str:
    remote_addr = request.client.host if request.client else "127.0.0.1"
    return extract_client_ip(dict(request.headers), remote_addr)


def _get_session_id(request: Request, ip: str) -> str:
    headers = dict(request.headers)
    return (
        headers.get("x-session-id")
        or headers.get("X-Session-ID")
        or request.cookies.get("sentinel_session")
        or f"sess_{ip.replace(':', '_')}"
    )


def _apply_decoy_headers(response: Response, obs: Dict[str, Any], session_id: str, category: str) -> None:
    response.headers["X-Sentinel-Decoy-Latency"] = str(obs.get("delay_applied_seconds", 0.0))
    response.headers["X-Sentinel-Decoy-Profile"] = category
    response.headers["X-Sentinel-Decoy-Session"] = session_id
    response.headers["X-Sentinel-Decoy-Sequence"] = str(obs.get("sequence", 1))


@router.post("/auth/login")
async def decoy_login(
    req: DecoyLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    session_id = _get_session_id(request, ip)
    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)

    # Telemetry: Record attacker targeting login on the decoy portal
    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="auth_login",
        target_endpoint="/demo/decoy/auth/login",
        attack_type="credential_probe",
        severity="medium",
        result="trapped_in_decoy",
        attempts=1,
        honeypot_source="decoy_app",
        evidence=f"[Observed] Decoy login probe with username: {req.email[:4]}*** (password redacted safely)",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    # Controlled Response Latency & Observation (Profile: 1–2 seconds)
    obs = await observe_and_delay_decoy(
        session_id=session_id,
        src_ip=ip,
        endpoint="/demo/decoy/auth/login",
        method="POST",
        category="auth_login",
        db=db,
        evidence=f"Decoy authentication attempt for {req.email[:4]}***",
        is_honeytoken=False,
        user_agent=request.headers.get("user-agent"),
        override_mode=request.headers.get("x-sentinel-decoy-mode"),
    )
    _apply_decoy_headers(response, obs, session_id, "auth_login")

    # Deceive attacker: return believable fake success requiring OTP
    return {
        "status": "authenticated",
        "session_token": f"decoy_sess_{hash(req.email) % 100000}_trap",
        "requires_otp": True,
        "message": "Security Verification: A 6-digit challenge has been sent to your device.",
        "observation": obs,
    }


@router.post("/auth/otp/verify")
async def decoy_otp_verify(
    req: DecoyOTPRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    session_id = _get_session_id(request, ip)
    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="auth_otp",
        target_endpoint="/demo/decoy/auth/otp/verify",
        attack_type="otp_bypass_attempt",
        severity="high",
        result="trapped_in_decoy",
        attempts=1,
        honeypot_source="decoy_app",
        evidence=f"[Observed] Attacker attempted 2FA bypass on decoy portal (token redacted)",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    # Controlled Response Latency & Observation (Profile: 2–3 seconds)
    obs = await observe_and_delay_decoy(
        session_id=session_id,
        src_ip=ip,
        endpoint="/demo/decoy/auth/otp/verify",
        method="POST",
        category="auth_otp",
        db=db,
        evidence="Decoy MFA verification challenge probe",
        is_honeytoken=False,
        user_agent=request.headers.get("user-agent"),
        override_mode=request.headers.get("x-sentinel-decoy-mode"),
    )
    _apply_decoy_headers(response, obs, session_id, "auth_otp")

    # Fake role elevation inside the decoy sandbox
    return {
        "status": "authorized",
        "role": "decoy_admin",
        "user": req.email.split("@")[0] if "@" in req.email else "decoy_user",
        "app_scope": "sandbox_isolated_container",
        "observation": obs,
    }


@router.post("/auth/password/reset")
async def decoy_password_reset(
    req: DecoyPasswordResetRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    session_id = _get_session_id(request, ip)
    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="auth_reset",
        target_endpoint="/demo/decoy/auth/password/reset",
        attack_type="account_recovery_probe",
        severity="medium",
        result="trapped_in_decoy",
        attempts=1,
        honeypot_source="decoy_app",
        evidence=f"[Observed] Account enumeration probe requesting password reset for: {req.email[:4]}***",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    # Controlled Response Latency & Observation (Profile: 1–2 seconds)
    obs = await observe_and_delay_decoy(
        session_id=session_id,
        src_ip=ip,
        endpoint="/demo/decoy/auth/password/reset",
        method="POST",
        category="auth_reset",
        db=db,
        evidence="Decoy account password recovery probe",
        is_honeytoken=False,
        user_agent=request.headers.get("user-agent"),
        override_mode=request.headers.get("x-sentinel-decoy-mode"),
    )
    _apply_decoy_headers(response, obs, session_id, "auth_reset")

    return {
        "status": "sent",
        "message": f"Password recovery token generated for {req.email[:4]}***.",
        "observation": obs,
    }


@router.get("/user/dashboard")
async def decoy_user_dashboard(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    session_id = _get_session_id(request, ip)

    # Controlled Response Latency & Observation (Profile: 0–300 ms)
    obs = await observe_and_delay_decoy(
        session_id=session_id,
        src_ip=ip,
        endpoint="/demo/decoy/user/dashboard",
        method="GET",
        category="landing",
        db=db,
        evidence="Decoy visitor viewing synthetic tenant dashboard",
        is_honeytoken=False,
        user_agent=request.headers.get("user-agent"),
        override_mode=request.headers.get("x-sentinel-decoy-mode"),
    )
    _apply_decoy_headers(response, obs, session_id, "landing")

    return {
        "app": "SENTINEL Production Portal",
        "environment": "cloud_infrastructure",
        "total_active_sessions": 14,
        "system_status": "operational",
        "active_tenants": len(CANARY_CUSTOMERS),
        "recent_activity": [
            {"id": "act_1", "action": "Cluster configuration updated", "time": "12 mins ago", "user": "devops-lead"},
            {"id": "act_2", "action": "Automatic SSL renewal completed", "time": "1 hour ago", "user": "system"},
            {"id": "act_3", "action": "Customer API token generated", "time": "3 hours ago", "user": "billing-admin"},
        ],
        "observation": obs,
    }


@router.get("/admin/system")
async def decoy_admin_system(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    session_id = _get_session_id(request, ip)
    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="admin_access",
        target_endpoint="/demo/decoy/admin/system",
        attack_type="privilege_escalation_probe",
        severity="high",
        result="trapped_in_decoy",
        attempts=1,
        honeypot_source="decoy_app",
        evidence="[Observed] Direct access to decoy administrative management portal",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    # Controlled Response Latency & Observation (Profile: 2–4 seconds)
    obs = await observe_and_delay_decoy(
        session_id=session_id,
        src_ip=ip,
        endpoint="/demo/decoy/admin/system",
        method="GET",
        category="admin_console",
        db=db,
        evidence="Decoy admin management portal console probe",
        is_honeytoken=False,
        user_agent=request.headers.get("user-agent"),
        override_mode=request.headers.get("x-sentinel-decoy-mode"),
    )
    _apply_decoy_headers(response, obs, session_id, "admin_console")

    return {
        "admin_portal": "Internal Administration Console [STAGING-SANDBOX]",
        "cluster_nodes": 2,
        "backup_server": "10.240.11.90 (Honeynet Decoy Subnet)",
        "service_health": "Degraded - Memory pressure detected",
        "notice": "All changes are recorded in security audit journal.",
        "observation": obs,
    }


@router.post("/checkout/charge")
async def decoy_charge(
    req: DecoyChargeRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    session_id = _get_session_id(request, ip)
    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="payment_gateway",
        target_endpoint="/demo/decoy/checkout/charge",
        attack_type="financial_transaction_probe",
        severity="critical",
        result="trapped_in_decoy",
        attempts=1,
        honeypot_source="decoy_app",
        evidence=f"[Observed] Payment processing probe amount: ${req.amount:.2f} (token redacted)",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    # Controlled Response Latency & Observation (Profile: 3–5 seconds)
    obs = await observe_and_delay_decoy(
        session_id=session_id,
        src_ip=ip,
        endpoint="/demo/decoy/checkout/charge",
        method="POST",
        category="payment_gateway",
        db=db,
        evidence=f"Decoy payment charge execution: ${req.amount:.2f}",
        is_honeytoken=False,
        user_agent=request.headers.get("user-agent"),
        override_mode=request.headers.get("x-sentinel-decoy-mode"),
    )
    _apply_decoy_headers(response, obs, session_id, "payment_gateway")

    return {
        "charge_id": f"ch_decoy_trap_{req.customer_id}",
        "amount": req.amount,
        "currency": req.currency,
        "status": "succeeded",
        "decoy_watermark": "SEC-HONEYNET-TRACE-491",
        "observation": obs,
    }


@router.get("/customers")
async def decoy_customers(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    session_id = _get_session_id(request, ip)
    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="database_api",
        target_endpoint="/demo/decoy/customers",
        attack_type="database_exfiltration_probe",
        severity="high",
        result="trapped_in_decoy",
        attempts=1,
        honeypot_source="decoy_app",
        evidence="[Observed] Direct query for customer database records on decoy application",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    # Controlled Response Latency & Observation (Profile: 2–5 seconds)
    obs = await observe_and_delay_decoy(
        session_id=session_id,
        src_ip=ip,
        endpoint="/demo/decoy/customers",
        method="GET",
        category="database_api",
        db=db,
        evidence="Decoy customer database query exfiltration probe",
        is_honeytoken=False,
        user_agent=request.headers.get("user-agent"),
        override_mode=request.headers.get("x-sentinel-decoy-mode"),
    )
    _apply_decoy_headers(response, obs, session_id, "database_api")

    return {
        "customers": CANARY_CUSTOMERS,
        "count": len(CANARY_CUSTOMERS),
        "observation": obs,
    }


@router.get("/.env")
async def decoy_env(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    session_id = _get_session_id(request, ip)
    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="secrets_env",
        target_endpoint="/demo/decoy/.env",
        attack_type="secrets_exfiltration",
        severity="critical",
        result="trapped_in_decoy",
        attempts=1,
        honeypot_source="decoy_app",
        evidence="[Observed] Direct request for production .env configuration file (Honeytoken served)",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    # Controlled Response Latency & Observation (Profile: 1–3 seconds, Honeytoken)
    obs = await observe_and_delay_decoy(
        session_id=session_id,
        src_ip=ip,
        endpoint="/demo/decoy/.env",
        method="GET",
        category="honeytoken",
        db=db,
        evidence="Exposed .env configuration file honeytoken access",
        is_honeytoken=True,
        user_agent=request.headers.get("user-agent"),
        override_mode=request.headers.get("x-sentinel-decoy-mode"),
    )
    _apply_decoy_headers(response, obs, session_id, "honeytoken")

    # Serve synthetic canary honeytoken environment variables
    return (
        "# SENTINEL DECOY CANARY ENVIRONMENT\n"
        "APP_ENV=production\n"
        "DATABASE_URL=postgres://sentinel_canary:HoneyPass991!@10.240.11.90:5432/core_db\n"
        "STRIPE_SECRET_KEY=sk_test_fake_honeytoken_stripe_key_9921\n"
        "AWS_ACCESS_KEY_ID=AKIA_CANARY_FAKE_TRAP_KEY_789\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )


@router.get("/.git")
@router.get("/.git/{subpath:path}")
async def decoy_git_probe(
    subpath: str = "",
    request: Request = None,
    response: Response = None,
    db: AsyncSession = Depends(get_db),
):
    """Serves believable synthetic git honeytokens and traps attacker in decoy telemetry."""
    ip = _get_client_ip(request)
    session_id = _get_session_id(request, ip)
    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)
    target_ep = f"/demo/decoy/.git/{subpath}" if subpath else "/demo/decoy/.git"

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="secrets_env",
        target_endpoint=target_ep,
        attack_type="git_repository_probe",
        severity="critical",
        result="trapped_in_decoy",
        attempts=1,
        honeypot_source="decoy_app",
        evidence=f"[Observed] Decoy git repository probe: {target_ep} (Synthetic canary repo served)",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    # Controlled Response Latency & Observation (Profile: 1–3 seconds, Honeytoken)
    obs = await observe_and_delay_decoy(
        session_id=session_id,
        src_ip=ip,
        endpoint=target_ep,
        method="GET",
        category="honeytoken",
        db=db,
        evidence=f"Git repository crawler probe on {target_ep}",
        is_honeytoken=True,
        user_agent=request.headers.get("user-agent") if request else None,
        override_mode=request.headers.get("x-sentinel-decoy-mode") if request else None,
    )
    if response:
        _apply_decoy_headers(response, obs, session_id, "honeytoken")

    return (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = false\n"
        "\tbare = false\n"
        "[remote \"origin\"]\n"
        "\turl = https://github-canary.sentinel.internal/deception-honeynet/core-api.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
    )


@router.post("/checkout/modify")
@router.post("/checkout/confirm")
async def decoy_payment_modify(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Synthetic fake payment modification handler in decoy sandbox."""
    ip = _get_client_ip(request)
    session_id = _get_session_id(request, ip)
    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="payment_gateway",
        target_endpoint=request.url.path,
        attack_type="financial_transaction_probe",
        severity="critical",
        result="trapped_in_decoy",
        attempts=1,
        honeypot_source="decoy_app",
        evidence="[Observed] Decoy transaction modification probe recorded",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    # Controlled Response Latency & Observation (Profile: 3–5 seconds)
    obs = await observe_and_delay_decoy(
        session_id=session_id,
        src_ip=ip,
        endpoint=request.url.path,
        method="POST",
        category="payment_gateway",
        db=db,
        evidence=f"Decoy transaction modification attempt on {request.url.path}",
        is_honeytoken=False,
        user_agent=request.headers.get("user-agent"),
        override_mode=request.headers.get("x-sentinel-decoy-mode"),
    )
    _apply_decoy_headers(response, obs, session_id, "payment_gateway")

    return {
        "status": "acknowledged",
        "notice": "Transaction updated in sandbox buffer",
        "decoy_watermark": "SEC-HONEYNET-TRACE-491",
        "observation": obs,
    }


@router.get("/db/dump")
async def decoy_db_dump(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Serves synthetic database dump honeytokens."""
    ip = _get_client_ip(request)
    session_id = _get_session_id(request, ip)
    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="database_api",
        target_endpoint="/demo/decoy/db/dump",
        attack_type="database_exfiltration_probe",
        severity="critical",
        result="trapped_in_decoy",
        attempts=1,
        honeypot_source="decoy_app",
        evidence="[Observed] Attacker downloaded synthetic canary SQL dump from decoy",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    # Controlled Response Latency & Observation (Profile: 2–5 seconds, Database Honeytoken)
    obs = await observe_and_delay_decoy(
        session_id=session_id,
        src_ip=ip,
        endpoint="/demo/decoy/db/dump",
        method="GET",
        category="database_api",
        db=db,
        evidence="Canary database SQL dump extract probe",
        is_honeytoken=True,
        user_agent=request.headers.get("user-agent"),
        override_mode=request.headers.get("x-sentinel-decoy-mode"),
    )
    _apply_decoy_headers(response, obs, session_id, "database_api")

    return (
        "-- SENTINEL CANARY HONEYTOKEN DB DUMP\n"
        "CREATE TABLE canary_users (id INT, email VARCHAR(64), password_hash VARCHAR(128));\n"
        "INSERT INTO canary_users VALUES (1, 'canary_admin@sentinel.fake', 'sha256$canary_fake_hash_99182');\n"
    )


# ==============================================================
# SOC OBSERVATION TELEMETRY & CONTROLLED DEMONSTRATION ENDPOINTS
# ==============================================================

@router.get("/observation/stats")
async def get_decoy_stats_endpoint(db: AsyncSession = Depends(get_db)):
    """
    Returns aggregated attacker observation telemetry, latency profiles,
    and honeytoken metrics for the SOC dashboard.
    """
    return await get_decoy_observation_stats(db)


@router.post("/observation/mode")
async def set_decoy_mode_endpoint(req: DecoyModeRequest):
    """
    Configures the decoy latency mode:
    - 'controlled': applies configured latency profiles (delays attacker)
    - 'normal': baseline instant response mode
    """
    mode = set_decoy_latency_mode(req.mode)
    return {"status": "success", "mode": mode}


@router.post("/observation/compare")
async def run_decoy_comparison_endpoint(req: Optional[DecoyCompareRequest] = None):
    """
    Demonstration comparison endpoint:
    Runs side-by-side comparison between Normal Mode and Controlled Latency Mode.
    """
    cat = req.category if req else "auth_login"
    sid = req.session_id if req else None
    return await run_latency_comparison_demo(category=cat, custom_session_id=sid)


# Standalone App instance for isolated honeypot deployment (Port :8002)
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Isolated Decoy Honeypot Application", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://.*$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.demo_apps.decoy_app:app", host="0.0.0.0", port=8002, reload=True)
