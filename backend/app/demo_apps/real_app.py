from __future__ import annotations
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.models import VisitorSessionRisk
from app.services.function_intelligence import record_function_targeting
from app.services.ingest import get_or_create_attacker
from app.services.gateway import extract_client_ip
from app.services.behaviour_risk import record_behaviour_event

router = APIRouter(prefix="/demo/real", tags=["Real Demo Application"])

# In-memory realistic demo database (Isolated dummy data only)
DEMO_USERS = {
    "analyst@sentinel.local": {
        "password": "Password123!",
        "name": "Sarah Connor",
        "role": "analyst",
        "otp_secret": "789123",
    },
    "admin@sentinel.local": {
        "password": "AdminSecure2026!",
        "name": "John Doe",
        "role": "admin",
        "otp_secret": "456789",
    },
}

DUMMY_CUSTOMERS = [
    {"id": "cust_101", "name": "Acme Cyber Dynamics", "plan": "Enterprise", "balance": "$4,200.00"},
    {"id": "cust_102", "name": "Global Shield Technologies", "plan": "Pro", "balance": "$1,450.00"},
    {"id": "cust_103", "name": "Apex Cloud Systems", "plan": "Enterprise Plus", "balance": "$12,800.00"},
]


class LoginRequest(BaseModel):
    email: str
    password: str


class OTPRequest(BaseModel):
    email: str
    otp_code: str


class PasswordResetRequest(BaseModel):
    email: str


class ChargeRequest(BaseModel):
    customer_id: str
    amount: float
    currency: str = "USD"
    token: str


def _get_caller_ip(request: Request) -> str:
    remote_addr = request.client.host if request.client else "127.0.0.1"
    return extract_client_ip(dict(request.headers), remote_addr)


def _get_caller_session(request: Request, client_ip: str) -> str:
    sess = request.headers.get("x-session-id") or request.headers.get("x-sentinel-session")
    if sess:
        return sess.strip()
    cookie_sess = request.cookies.get("sentinel_session") or request.cookies.get("session_id")
    if cookie_sess:
        return cookie_sess.strip()
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth.replace("Bearer ", "").strip()
        if token:
            return f"sess_{hashlib.md5(token.encode()).hexdigest()[:16]}"
    return f"sess_{client_ip.replace(':', '_')}"


async def _check_diversion_guard(db: AsyncSession, session_id: str, client_ip: str):
    """
    Prevents a session or client that has been moved to the decoy from accessing
    the real application using old cookies, tokens, or direct requests.
    """
    stmt = select(VisitorSessionRisk).where(
        (VisitorSessionRisk.session_id == session_id) |
        ((VisitorSessionRisk.src_ip == client_ip) & (VisitorSessionRisk.is_diverted == True))
    )
    res = await db.execute(stmt)
    records = res.scalars().all()
    for r in records:
        if r.is_diverted:
            raise HTTPException(
                status_code=403,
                detail="Forbidden: Session diverted to isolated honeypot environment. Access to production application prohibited."
            )


@router.post("/auth/login")
async def real_login(req: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_caller_ip(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip)

    user = DEMO_USERS.get(req.email)
    if not user or user["password"] != req.password:
        now = datetime.now(timezone.utc)
        attacker = await get_or_create_attacker(db, ip, now)
        await record_function_targeting(
            db=db,
            attacker=attacker,
            target_function="auth_login",
            target_endpoint="/auth/login",
            attack_type="credential_probe",
            severity="medium",
            result="auth_failed",
            attempts=1,
            honeypot_source="real_app_telemetry",
            evidence=f"[Observed] Failed login attempt with email: {req.email[:4]}***",
            confidence=1.0,
            is_simulated=False,
            event_timestamp=now,
        )
        await record_behaviour_event(
            db=db,
            session_id=session_id,
            src_ip=ip,
            category="login_failures",
            endpoint="/demo/real/auth/login",
            event_type="credential_failure",
            evidence=f"[Observed] Failed login attempt with email: {req.email[:4]}***",
            account_email=req.email,
            now=now,
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    return {
        "status": "authenticated",
        "session_token": f"real_sess_{req.email.split('@')[0]}_9921",
        "requires_otp": True,
        "message": "Primary credentials valid. Please enter your 6-digit OTP token.",
    }


@router.post("/auth/otp/verify")
async def real_otp_verify(req: OTPRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_caller_ip(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip)

    user = DEMO_USERS.get(req.email)
    if not user or user["otp_secret"] != req.otp_code:
        now = datetime.now(timezone.utc)
        attacker = await get_or_create_attacker(db, ip, now)
        await record_function_targeting(
            db=db,
            attacker=attacker,
            target_function="auth_otp",
            target_endpoint="/auth/otp/verify",
            attack_type="otp_bruteforce",
            severity="high",
            result="otp_failed",
            attempts=1,
            honeypot_source="real_app_telemetry",
            evidence=f"[Observed] Failed OTP verification attempt with token: {req.otp_code}",
            confidence=1.0,
            is_simulated=False,
            event_timestamp=now,
        )
        await record_behaviour_event(
            db=db,
            session_id=session_id,
            src_ip=ip,
            category="otp_failures",
            endpoint="/demo/real/auth/otp/verify",
            event_type="otp_failure",
            evidence=f"[Observed] Failed OTP challenge verification: {req.otp_code}",
            account_email=req.email,
            now=now,
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid OTP authentication code.")

    return {
        "status": "authorized",
        "role": user["role"],
        "user": user["name"],
        "app_scope": "production_demo_gateway",
    }


@router.post("/auth/password/reset")
async def real_password_reset(req: PasswordResetRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_caller_ip(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip)

    if req.email not in DEMO_USERS:
        now = datetime.now(timezone.utc)
        attacker = await get_or_create_attacker(db, ip, now)
        await record_function_targeting(
            db=db,
            attacker=attacker,
            target_function="auth_reset",
            target_endpoint="/auth/password/reset",
            attack_type="account_enumeration",
            severity="medium",
            result="reset_probed",
            attempts=1,
            honeypot_source="real_app_telemetry",
            evidence=f"[Observed] Account enumeration probe via password reset for {req.email}",
            confidence=0.90,
            is_simulated=False,
            event_timestamp=now,
        )
        await record_behaviour_event(
            db=db,
            session_id=session_id,
            src_ip=ip,
            category="password_reset",
            endpoint="/demo/real/auth/password/reset",
            event_type="account_enumeration",
            evidence=f"[Observed] Password recovery probe for unverified account: {req.email}",
            account_email=req.email,
            now=now,
        )
        await db.commit()
        return {"status": "queued", "message": "If the account exists, a recovery token has been dispatched."}

    return {"status": "sent", "message": f"Password reset instructions dispatched to {req.email}."}


@router.get("/user/dashboard")
async def real_user_dashboard(request: Request = None, db: AsyncSession = Depends(get_db)):
    if request:
        ip = _get_caller_ip(request)
        session_id = _get_caller_session(request, ip)
        await _check_diversion_guard(db, session_id, ip)

    return {
        "app": "SENTINEL Production Portal",
        "environment": "real_workload",
        "total_active_sessions": 42,
        "system_status": "operational",
        "active_tenants": len(DUMMY_CUSTOMERS),
        "recent_activity": [
            {"id": "act_101", "action": "Cluster health check passed", "time": "5 mins ago", "user": "monitoring"},
            {"id": "act_102", "action": "Enterprise customer onboarded", "time": "45 mins ago", "user": "sales-ops"},
            {"id": "act_103", "action": "Backup snapshot verified", "time": "2 hours ago", "user": "backup-daemon"},
        ],
    }


@router.get("/admin/system")
async def real_admin_system(request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_caller_ip(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip)

    auth_header = request.headers.get("Authorization", "")
    if "admin" not in auth_header:
        now = datetime.now(timezone.utc)
        attacker = await get_or_create_attacker(db, ip, now)
        await record_function_targeting(
            db=db,
            attacker=attacker,
            target_function="admin_access",
            target_endpoint="/admin/system",
            attack_type="privilege_escalation",
            severity="critical",
            result="forbidden_probe",
            attempts=1,
            honeypot_source="real_app_telemetry",
            evidence="[Observed] Unauthorized access probe on administrative system console",
            confidence=1.0,
            is_simulated=False,
            event_timestamp=now,
        )
        await record_behaviour_event(
            db=db,
            session_id=session_id,
            src_ip=ip,
            category="admin_access",
            endpoint="/demo/real/admin/system",
            event_type="unauthorized_admin",
            evidence="[Observed] Unauthorized access probe on administrative system console",
            now=now,
        )
        await db.commit()
        raise HTTPException(status_code=403, detail="Forbidden: Admin role authorization token required.")

    return {
        "admin_portal": "Production Infrastructure Console",
        "cluster_nodes": 4,
        "service_health": "100%",
        "maintenance_mode": False,
    }


@router.get("/.env")
async def real_env_probe(request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_caller_ip(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip)

    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)
    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="secrets_env",
        target_endpoint="/demo/real/.env",
        attack_type="secrets_exfiltration",
        severity="critical",
        result="blocked",
        attempts=1,
        honeypot_source="real_app_telemetry",
        evidence="[Observed] Direct request for production .env configuration file",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await record_behaviour_event(
        db=db,
        session_id=session_id,
        src_ip=ip,
        category="secrets_probing",
        endpoint="/demo/real/.env",
        event_type="secrets_probe",
        evidence="[Observed] Direct request for production .env configuration file",
        now=now,
    )
    await db.commit()
    raise HTTPException(status_code=404, detail="Not Found")


@router.post("/checkout/charge")
async def real_charge(req: ChargeRequest, request: Request = None, db: AsyncSession = Depends(get_db)):
    if request:
        ip = _get_caller_ip(request)
        session_id = _get_caller_session(request, ip)
        await _check_diversion_guard(db, session_id, ip)

    if req.amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid charge amount.")
    return {
        "charge_id": f"ch_real_{req.customer_id}_8819",
        "amount": req.amount,
        "currency": req.currency,
        "status": "succeeded",
        "receipt_url": f"https://real.sentinel.internal/receipts/ch_real_{req.customer_id}",
    }


@router.get("/customers")
async def real_customers(request: Request = None, db: AsyncSession = Depends(get_db)):
    if request:
        ip = _get_caller_ip(request)
        session_id = _get_caller_session(request, ip)
        await _check_diversion_guard(db, session_id, ip)

    return {"customers": DUMMY_CUSTOMERS, "count": len(DUMMY_CUSTOMERS)}


# Standalone App instance for multi-process deployment (Port :8001)
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Production Real Application", version="1.0.0")
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
    uvicorn.run("app.demo_apps.real_app:app", host="0.0.0.0", port=8001, reload=True)



