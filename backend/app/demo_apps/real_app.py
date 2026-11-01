from __future__ import annotations
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Set
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
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

# In-memory tracking of revoked tokens and diverted sessions
REVOKED_TOKENS: Set[str] = set()
REVOKED_SESSIONS: Set[str] = set()
ACTIVE_REAL_SESSIONS: Dict[str, Dict[str, Any]] = {}

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


class PaymentModifyRequest(BaseModel):
    charge_id: str
    new_amount: float
    reason: Optional[str] = "modification"


def _get_caller_ip(request: Request) -> str:
    remote_addr = request.client.host if request.client else "127.0.0.1"
    return extract_client_ip(dict(request.headers), remote_addr)


def _extract_caller_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if auth.startswith("Bearer "):
        return auth.replace("Bearer ", "").strip()
    return request.headers.get("x-session-token") or request.cookies.get("sentinel_auth_key") or request.cookies.get("session_token")


def _get_caller_session(request: Request, client_ip: str) -> str:
    sess = request.headers.get("x-session-id") or request.headers.get("x-sentinel-session")
    if sess:
        return sess.strip()
    cookie_sess = request.cookies.get("sentinel_session") or request.cookies.get("session_id")
    if cookie_sess:
        return cookie_sess.strip()
    token = _extract_caller_token(request)
    if token:
        return f"sess_{hashlib.md5(token.encode()).hexdigest()[:16]}"
    return f"sess_{client_ip.replace(':', '_')}"


def revoke_real_session(session_id: str, client_ip: Optional[str] = None, token: Optional[str] = None):
    """Authoritatively invalidates real application session and revoked tokens."""
    if session_id:
        REVOKED_SESSIONS.add(session_id)
        ACTIVE_REAL_SESSIONS.pop(session_id, None)
    if token:
        REVOKED_TOKENS.add(token.strip())


async def _check_diversion_guard(db: AsyncSession, session_id: str, client_ip: str, token: Optional[str] = None):
    """
    Strict Server-Side Session Guard:
    Prevents a session, token, or client that has been moved to the decoy from accessing
    the real application using old cookies, tokens, or direct requests.
    """
    # 1. Fast path: in-memory revocation check
    if token and token in REVOKED_TOKENS:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Session token has been revoked due to security violation. Production access prohibited.",
            headers={"X-Sentinel-Route": "decoy", "X-Sentinel-Diverted": "true"},
        )
    if session_id in REVOKED_SESSIONS:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Session diverted to isolated honeypot environment. Production application access prohibited.",
            headers={"X-Sentinel-Route": "decoy", "X-Sentinel-Diverted": "true"},
        )

    # 2. Database persistent verification
    stmt = select(VisitorSessionRisk).where(
        (VisitorSessionRisk.session_id == session_id) |
        ((VisitorSessionRisk.src_ip == client_ip) & (VisitorSessionRisk.is_diverted == True))
    )
    res = await db.execute(stmt)
    records = res.scalars().all()
    for r in records:
        if r.is_diverted:
            if token:
                REVOKED_TOKENS.add(token)
            REVOKED_SESSIONS.add(session_id)
            raise HTTPException(
                status_code=403,
                detail="Forbidden: Session diverted to isolated honeypot environment. Access to production application prohibited.",
                headers={"X-Sentinel-Route": "decoy", "X-Sentinel-Diverted": "true"},
            )


@router.post("/auth/login")
async def real_login(req: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

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

    generated_token = f"real_sess_{req.email.split('@')[0]}_9921"
    ACTIVE_REAL_SESSIONS[session_id] = {
        "token": generated_token,
        "email": req.email,
        "role": user["role"],
        "authenticated_at": datetime.now(timezone.utc).isoformat(),
    }

    return {
        "status": "authenticated",
        "session_token": generated_token,
        "requires_otp": True,
        "message": "Primary credentials valid. Please enter your 6-digit OTP token.",
    }


@router.post("/auth/otp/verify")
async def real_otp_verify(req: OTPRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

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
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

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
async def real_user_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

    return {
        "app": "MIRAGE Production Portal",
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


# =========================================================================
# 1. PROTECT SENSITIVE SECRETS, .ENV, .GIT, AND SYSTEM CONFIGURATION
# =========================================================================

@router.get("/.env")
async def real_env_probe(request: Request, db: AsyncSession = Depends(get_db)):
    """Server-side check: Blocks .env download, records event, and immediately triggers diversion policy."""
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)
    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="secrets_env",
        target_endpoint="/demo/real/.env",
        attack_type="secrets_exfiltration",
        severity="critical",
        result="blocked_and_diverted",
        attempts=1,
        honeypot_source="real_app_telemetry",
        evidence="[Blocked] Unauthorized direct download request for production .env configuration file",
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
        evidence="[Blocked] Unauthorized direct download request for production .env configuration file",
        is_critical=True,
        critical_reason="Direct request for production .env configuration file",
        now=now,
    )
    revoke_real_session(session_id, ip, token)
    await db.commit()

    raise HTTPException(
        status_code=403,
        detail="Forbidden: Access to system configuration files prohibited.",
        headers={"X-Sentinel-Route": "decoy", "X-Sentinel-Diverted": "true"},
    )


@router.get("/.git")
@router.get("/.git/{subpath:path}")
async def real_git_probe(subpath: str = "", request: Request = None, db: AsyncSession = Depends(get_db)):
    """Server-side check: Blocks repository .git probing, records event, and immediately triggers diversion policy."""
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)
    target_ep = f"/demo/real/.git/{subpath}" if subpath else "/demo/real/.git"
    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="secrets_env",
        target_endpoint=target_ep,
        attack_type="git_repository_probe",
        severity="critical",
        result="blocked_and_diverted",
        attempts=1,
        honeypot_source="real_app_telemetry",
        evidence=f"[Blocked] Unauthorized probe targeting repository metadata: {target_ep}",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await record_behaviour_event(
        db=db,
        session_id=session_id,
        src_ip=ip,
        category="secrets_probing",
        endpoint=target_ep,
        event_type="git_probe",
        evidence=f"[Blocked] Unauthorized probe targeting repository metadata: {target_ep}",
        is_critical=True,
        critical_reason="Direct probe targeting repository .git metadata",
        now=now,
    )
    revoke_real_session(session_id, ip, token)
    await db.commit()

    raise HTTPException(
        status_code=403,
        detail="Forbidden: Access to version control metadata prohibited.",
        headers={"X-Sentinel-Route": "decoy", "X-Sentinel-Diverted": "true"},
    )


@router.get("/config.json")
@router.get("/secrets.json")
@router.get("/aws/credentials")
@router.get("/backup.sql")
async def real_secrets_probe(request: Request, db: AsyncSession = Depends(get_db)):
    """Server-side check: Blocks application secrets/configuration files and immediately diverts."""
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

    now = datetime.now(timezone.utc)
    endpoint = request.url.path
    attacker = await get_or_create_attacker(db, ip, now)
    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="secrets_env",
        target_endpoint=endpoint,
        attack_type="secrets_exfiltration",
        severity="critical",
        result="blocked_and_diverted",
        attempts=1,
        honeypot_source="real_app_telemetry",
        evidence=f"[Blocked] Direct request targeting application secret configuration: {endpoint}",
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await record_behaviour_event(
        db=db,
        session_id=session_id,
        src_ip=ip,
        category="secrets_probing",
        endpoint=endpoint,
        event_type="config_probe",
        evidence=f"[Blocked] Direct request targeting application secret configuration: {endpoint}",
        is_critical=True,
        critical_reason=f"Direct request for sensitive file {endpoint}",
        now=now,
    )
    revoke_real_session(session_id, ip, token)
    await db.commit()

    raise HTTPException(
        status_code=403,
        detail="Forbidden: Sensitive configuration access denied.",
        headers={"X-Sentinel-Route": "decoy", "X-Sentinel-Diverted": "true"},
    )


# =========================================================================
# 2. PROTECT ADMIN OPERATIONS & PRIVILEGE ESCALATION
# =========================================================================

@router.get("/admin/system")
@router.get("/admin/users")
@router.get("/admin/config")
async def real_admin_operations(request: Request, db: AsyncSession = Depends(get_db)):
    """Server-side check: Protects admin operations; blocks unauthorized privilege escalation and immediately diverts."""
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

    auth_header = request.headers.get("Authorization", "")
    # Legitimate admin check: must have admin role in authorization header or active session
    is_admin = "admin" in auth_header.lower() or (
        session_id in ACTIVE_REAL_SESSIONS and ACTIVE_REAL_SESSIONS[session_id].get("role") == "admin"
    )

    if not is_admin:
        now = datetime.now(timezone.utc)
        endpoint = request.url.path
        attacker = await get_or_create_attacker(db, ip, now)
        await record_function_targeting(
            db=db,
            attacker=attacker,
            target_function="admin_access",
            target_endpoint=endpoint,
            attack_type="privilege_escalation",
            severity="critical",
            result="blocked_and_diverted",
            attempts=1,
            honeypot_source="real_app_telemetry",
            evidence=f"[Blocked] Unauthorized administrative escalation attempt on: {endpoint}",
            confidence=1.0,
            is_simulated=False,
            event_timestamp=now,
        )
        await record_behaviour_event(
            db=db,
            session_id=session_id,
            src_ip=ip,
            category="admin_access",
            endpoint=endpoint,
            event_type="admin_escalation",
            evidence=f"[Blocked] Unauthorized administrative escalation attempt on: {endpoint}",
            is_critical=True,
            critical_reason="Unauthorized administrative console access attempt",
            now=now,
        )
        revoke_real_session(session_id, ip, token)
        await db.commit()

        raise HTTPException(
            status_code=403,
            detail="Forbidden: Administrative privileges required.",
            headers={"X-Sentinel-Route": "decoy", "X-Sentinel-Diverted": "true"},
        )

    return {
        "admin_portal": "Production Infrastructure Console",
        "cluster_nodes": 4,
        "service_health": "100%",
        "maintenance_mode": False,
        "active_tenants": len(DUMMY_CUSTOMERS),
    }


# =========================================================================
# 3. PAYMENT SECURITY & AUTHORIZATION MANIPULATION PROTECTION
# =========================================================================

@router.post("/checkout/charge")
async def real_charge(req: ChargeRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """
    Server-side Payment Security:
    - If a visitor attempts unauthorized payment authorization or transaction manipulation:
      1. Reject the real transaction first.
      2. Do not charge or authorize any real payment.
      3. Record the suspicious event.
      4. Trigger the configured diversion policy.
    """
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

    # Detect payment manipulation patterns:
    # 1. Negative or zero amount
    # 2. Manipulated / tampered / forged token keywords
    # 3. Unusually excessive transaction manipulation (> 50,000)
    # 4. Token format tampering
    is_tampered = (
        req.amount <= 0
        or req.amount > 50000.0
        or "tampered" in req.token.lower()
        or "manipulated" in req.token.lower()
        or "inject" in req.token.lower()
        or not req.token.startswith("tok_")
    )

    if is_tampered:
        # REJECT THE REAL TRANSACTION FIRST — NEVER AUTHORIZE OR CHARGE REAL PAYMENT
        now = datetime.now(timezone.utc)
        attacker = await get_or_create_attacker(db, ip, now)
        evidence = f"[Blocked] Payment authorization manipulation detected: token '{req.token[:16]}', amount ${req.amount}"

        await record_function_targeting(
            db=db,
            attacker=attacker,
            target_function="payment_gateway",
            target_endpoint="/demo/real/checkout/charge",
            attack_type="payment_manipulation",
            severity="critical",
            result="transaction_rejected_and_diverted",
            attempts=1,
            honeypot_source="real_app_telemetry",
            evidence=evidence,
            confidence=1.0,
            is_simulated=False,
            event_timestamp=now,
        )
        await record_behaviour_event(
            db=db,
            session_id=session_id,
            src_ip=ip,
            category="combined_patterns",
            endpoint="/demo/real/checkout/charge",
            event_type="payment_manipulation",
            evidence=evidence,
            is_critical=True,
            critical_reason=f"Payment authorization manipulation (Amount: ${req.amount}, Token: {req.token[:8]}...)",
            now=now,
        )
        revoke_real_session(session_id, ip, token)
        await db.commit()

        raise HTTPException(
            status_code=400,
            detail="Transaction rejected: Payment authorization check failed due to invalid or manipulated parameters.",
            headers={"X-Sentinel-Route": "decoy", "X-Sentinel-Diverted": "true"},
        )

    # Legitimate mock payment execution
    return {
        "charge_id": f"ch_real_{req.customer_id}_8819",
        "amount": req.amount,
        "currency": req.currency,
        "status": "succeeded",
        "receipt_url": f"https://real.sentinel.internal/receipts/ch_real_{req.customer_id}",
    }


@router.post("/checkout/modify")
@router.post("/checkout/confirm")
async def real_transaction_modification(req: PaymentModifyRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Server-side check: Rejects transaction manipulation / parameter tampering and triggers diversion."""
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

    # Any unauthorized modification attempt on an in-flight transaction is rejected immediately
    now = datetime.now(timezone.utc)
    attacker = await get_or_create_attacker(db, ip, now)
    evidence = f"[Blocked] Unauthorized transaction modification probe on charge {req.charge_id} (altered amount: ${req.new_amount})"

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="payment_gateway",
        target_endpoint="/demo/real/checkout/modify",
        attack_type="transaction_tampering",
        severity="critical",
        result="transaction_rejected_and_diverted",
        attempts=1,
        honeypot_source="real_app_telemetry",
        evidence=evidence,
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await record_behaviour_event(
        db=db,
        session_id=session_id,
        src_ip=ip,
        category="combined_patterns",
        endpoint="/demo/real/checkout/modify",
        event_type="payment_manipulation",
        evidence=evidence,
        is_critical=True,
        critical_reason=f"Unauthorized transaction alteration attempt for {req.charge_id}",
        now=now,
    )
    revoke_real_session(session_id, ip, token)
    await db.commit()

    raise HTTPException(
        status_code=403,
        detail="Transaction modification rejected: In-flight payment modification prohibited.",
        headers={"X-Sentinel-Route": "decoy", "X-Sentinel-Diverted": "true"},
    )


# =========================================================================
# 4. CUSTOMER DATA & DATABASE PROTECTION
# =========================================================================

@router.get("/customers")
async def real_customers(
    request: Request,
    q: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Server-side Customer Data Protection:
    - Verifies valid session authorization.
    - Inspects query parameters for database extraction / SQL injection probes.
    - Unauthorized access is blocked and triggers immediate diversion.
    """
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

    # Detect unauthorized database extraction payloads
    sql_probe = False
    if q:
        q_upper = q.upper()
        if any(keyword in q_upper for keyword in ["UNION", "SELECT", "DUMP", "DROP", "1=1", "OR '1'='1", "SLEEP(", "--"]):
            sql_probe = True

    # Check for authentication: real customer list requires a valid session token
    has_auth = bool(token and not token.startswith("decoy_")) or (session_id in ACTIVE_REAL_SESSIONS)

    if not has_auth or sql_probe:
        now = datetime.now(timezone.utc)
        attacker = await get_or_create_attacker(db, ip, now)
        evidence = (
            f"[Blocked] SQL injection probe on customer API: q='{q}'"
            if sql_probe
            else "[Blocked] Unauthorized direct query for production customer records without session authentication"
        )

        await record_function_targeting(
            db=db,
            attacker=attacker,
            target_function="database_api",
            target_endpoint="/demo/real/customers",
            attack_type="unauthorized_database_query" if not sql_probe else "sql_injection_probe",
            severity="critical",
            result="blocked_and_diverted",
            attempts=1,
            honeypot_source="real_app_telemetry",
            evidence=evidence,
            confidence=1.0,
            is_simulated=False,
            event_timestamp=now,
        )
        await record_behaviour_event(
            db=db,
            session_id=session_id,
            src_ip=ip,
            category="database_access",
            endpoint="/demo/real/customers",
            event_type="unauthorized_db_probe",
            evidence=evidence,
            is_critical=True,
            critical_reason="Unauthorized customer database access attempt",
            now=now,
        )
        revoke_real_session(session_id, ip, token)
        await db.commit()

        status_code = 403 if sql_probe else 401
        raise HTTPException(
            status_code=status_code,
            detail="Unauthorized: Authentication token required to query customer records." if not sql_probe else "Forbidden: Malformed database query syntax.",
            headers={"X-Sentinel-Route": "decoy", "X-Sentinel-Diverted": "true"},
        )

    return {"customers": DUMMY_CUSTOMERS, "count": len(DUMMY_CUSTOMERS)}


@router.get("/customers/{customer_id}")
async def real_customer_by_id(customer_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Server-side check: Protects individual customer record queries."""
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

    has_auth = bool(token and not token.startswith("decoy_")) or (session_id in ACTIVE_REAL_SESSIONS)
    if not has_auth or "union" in customer_id.lower() or "'" in customer_id:
        now = datetime.now(timezone.utc)
        attacker = await get_or_create_attacker(db, ip, now)
        await record_function_targeting(
            db=db,
            attacker=attacker,
            target_function="database_api",
            target_endpoint=f"/demo/real/customers/{customer_id}",
            attack_type="unauthorized_database_query",
            severity="critical",
            result="blocked_and_diverted",
            attempts=1,
            honeypot_source="real_app_telemetry",
            evidence=f"[Blocked] Unauthorized customer lookup for ID: {customer_id}",
            confidence=1.0,
            is_simulated=False,
            event_timestamp=now,
        )
        await record_behaviour_event(
            db=db,
            session_id=session_id,
            src_ip=ip,
            category="database_access",
            endpoint=f"/demo/real/customers/{customer_id}",
            event_type="unauthorized_db_probe",
            evidence=f"[Blocked] Unauthorized customer lookup for ID: {customer_id}",
            is_critical=True,
            critical_reason="Unauthorized customer database record query",
            now=now,
        )
        revoke_real_session(session_id, ip, token)
        await db.commit()

        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Authentication required to query customer records.",
            headers={"X-Sentinel-Route": "decoy", "X-Sentinel-Diverted": "true"},
        )

    matched = next((c for c in DUMMY_CUSTOMERS if c["id"] == customer_id), None)
    if not matched:
        raise HTTPException(status_code=404, detail="Customer not found.")
    return matched


@router.get("/db/dump")
@router.get("/api/v1/internal/{subpath:path}")
async def real_db_dump_probe(subpath: str = "", request: Request = None, db: AsyncSession = Depends(get_db)):
    """Server-side check: Blocks direct database dump and internal API access."""
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

    now = datetime.now(timezone.utc)
    endpoint = request.url.path
    attacker = await get_or_create_attacker(db, ip, now)
    evidence = f"[Blocked] Direct database extraction probe targeting: {endpoint}"

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="database_api",
        target_endpoint=endpoint,
        attack_type="database_extraction_attempt",
        severity="critical",
        result="blocked_and_diverted",
        attempts=1,
        honeypot_source="real_app_telemetry",
        evidence=evidence,
        confidence=1.0,
        is_simulated=False,
        event_timestamp=now,
    )
    await record_behaviour_event(
        db=db,
        session_id=session_id,
        src_ip=ip,
        category="database_access",
        endpoint=endpoint,
        event_type="unauthorized_db_probe",
        evidence=evidence,
        is_critical=True,
        critical_reason="Direct database dump / internal endpoint probe",
        now=now,
    )
    revoke_real_session(session_id, ip, token)
    await db.commit()

    raise HTTPException(
        status_code=403,
        detail="Forbidden: Direct database extraction prohibited.",
        headers={"X-Sentinel-Route": "decoy", "X-Sentinel-Diverted": "true"},
    )


# =========================================================================
# 5. SENSITIVE ENDPOINT ENUMERATION PROTECTION
# =========================================================================

@router.get("/actuator/{path:path}")
@router.get("/phpmyadmin")
@router.get("/wp-admin")
async def real_endpoint_enumeration(path: str = "", request: Request = None, db: AsyncSession = Depends(get_db)):
    """Server-side check: Records sensitive endpoint enumeration."""
    ip = _get_caller_ip(request)
    token = _extract_caller_token(request)
    session_id = _get_caller_session(request, ip)
    await _check_diversion_guard(db, session_id, ip, token)

    now = datetime.now(timezone.utc)
    endpoint = request.url.path
    attacker = await get_or_create_attacker(db, ip, now)
    evidence = f"[Observed] Systematic enumeration targeting sensitive management route: {endpoint}"

    await record_function_targeting(
        db=db,
        attacker=attacker,
        target_function="secrets_env",
        target_endpoint=endpoint,
        attack_type="endpoint_enumeration",
        severity="medium",
        result="enumerated_404",
        attempts=1,
        honeypot_source="real_app_telemetry",
        evidence=evidence,
        confidence=0.90,
        is_simulated=False,
        event_timestamp=now,
    )
    await record_behaviour_event(
        db=db,
        session_id=session_id,
        src_ip=ip,
        category="endpoint_enumeration",
        endpoint=endpoint,
        event_type="endpoint_enumeration",
        evidence=evidence,
        now=now,
    )
    await db.commit()

    raise HTTPException(status_code=404, detail="Not Found")


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
