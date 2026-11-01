from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.services.function_intelligence import record_function_targeting
from app.services.ingest import get_or_create_attacker
from app.services.gateway import extract_client_ip

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


def _get_client_ip(request: Request) -> str:
    remote_addr = request.client.host if request.client else "127.0.0.1"
    return extract_client_ip(dict(request.headers), remote_addr)


@router.post("/auth/login")
async def decoy_login(req: DecoyLoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_client_ip(request)
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
        evidence=f"[Observed] Decoy login probe with username: {req.email[:4]}*** (password captured safely)",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    # Deceive attacker: return believable fake success requiring OTP
    return {
        "status": "authenticated",
        "session_token": f"decoy_sess_{hash(req.email) % 100000}_trap",
        "requires_otp": True,
        "message": "Security Verification: A 6-digit challenge has been sent to your device.",
    }


@router.post("/auth/otp/verify")
async def decoy_otp_verify(req: DecoyOTPRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_client_ip(request)
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
        evidence=f"[Observed] Attacker attempted 2FA bypass on decoy portal with token: {req.otp_code}",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    # Fake role elevation inside the decoy sandbox
    return {
        "status": "authorized",
        "role": "decoy_admin",
        "user": req.email.split("@")[0],
        "app_scope": "sandbox_isolated_container",
    }


@router.post("/auth/password/reset")
async def decoy_password_reset(req: DecoyPasswordResetRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_client_ip(request)
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
        evidence=f"[Observed] Account enumeration probe requesting password reset for: {req.email}",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    return {"status": "sent", "message": f"Password recovery token generated for {req.email}."}


@router.get("/user/dashboard")
async def decoy_user_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
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
    }


@router.get("/admin/system")
async def decoy_admin_system(request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_client_ip(request)
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

    # Expose realistic decoy admin dashboard with fake breadcrumb configurations
    return {
        "admin_portal": "Internal Administration Console [STAGING-SANDBOX]",
        "cluster_nodes": 2,
        "backup_server": "10.240.11.90 (Honeynet Decoy Subnet)",
        "service_health": "Degraded - Memory pressure detected",
        "notice": "All changes are recorded in security audit journal.",
    }


@router.post("/checkout/charge")
async def decoy_charge(req: DecoyChargeRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_client_ip(request)
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
        evidence=f"[Observed] Payment processing probe amount: ${req.amount:.2f} using token: {req.token[:8]}***",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await db.commit()

    return {
        "charge_id": f"ch_decoy_trap_{req.customer_id}",
        "amount": req.amount,
        "currency": req.currency,
        "status": "succeeded",
        "decoy_watermark": "SEC-HONEYNET-TRACE-491",
    }


@router.get("/customers")
async def decoy_customers(request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_client_ip(request)
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

    return {"customers": CANARY_CUSTOMERS, "count": len(CANARY_CUSTOMERS)}


@router.get("/.env")
async def decoy_env(request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_client_ip(request)
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
async def decoy_git_probe(subpath: str = "", request: Request = None, db: AsyncSession = Depends(get_db)):
    """Serves believable synthetic git honeytokens and traps attacker in decoy telemetry."""
    ip = _get_client_ip(request)
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
async def decoy_payment_modify(request: Request, db: AsyncSession = Depends(get_db)):
    """Synthetic fake payment modification handler in decoy sandbox."""
    ip = _get_client_ip(request)
    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="payment_gateway",
        target_endpoint="/demo/decoy/checkout/modify",
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

    return {
        "status": "acknowledged",
        "notice": "Transaction updated in sandbox buffer",
        "decoy_watermark": "SEC-HONEYNET-TRACE-491",
    }


@router.get("/db/dump")
async def decoy_db_dump(request: Request, db: AsyncSession = Depends(get_db)):
    """Serves synthetic database dump honeytokens."""
    ip = _get_client_ip(request)
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

    return (
        "-- SENTINEL CANARY HONEYTOKEN DB DUMP\n"
        "CREATE TABLE canary_users (id INT, email VARCHAR(64), password_hash VARCHAR(128));\n"
        "INSERT INTO canary_users VALUES (1, 'canary_admin@sentinel.fake', 'sha256$canary_fake_hash_99182');\n"
    )


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


