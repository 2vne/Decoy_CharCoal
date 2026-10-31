from __future__ import annotations
from datetime import datetime, timezone, timedelta
import ipaddress
import time
from typing import Any, Dict, Optional, Tuple
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.models import Attacker, GatewayRequestLog
from app.services.broadcast import broadcast

# Trusted proxy networks (e.g. localhost, private GCP VPC)
TRUSTED_PROXIES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def extract_client_ip(headers: Dict[str, str], remote_addr: str) -> str:
    """
    Safely resolves the true client IP from forwarded headers.
    Only trusts X-Forwarded-For / X-Real-IP if received from trusted proxy infrastructure.
    """
    is_trusted = False
    try:
        remote_ip_obj = ipaddress.ip_address(remote_addr)
        is_trusted = any(remote_ip_obj in net for net in TRUSTED_PROXIES)
    except ValueError:
        is_trusted = False

    if is_trusted:
        x_forwarded = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For")
        if x_forwarded:
            first_ip = x_forwarded.split(",")[0].strip()
            try:
                ipaddress.ip_address(first_ip)
                return first_ip
            except ValueError:
                pass

        x_real = headers.get("x-real-ip") or headers.get("X-Real-IP")
        if x_real:
            try:
                ipaddress.ip_address(x_real.strip())
                return x_real.strip()
            except ValueError:
                pass

    return remote_addr


async def evaluate_gateway_routing(
    db: AsyncSession,
    client_ip: str,
    path: str = "/",
    method: str = "GET",
) -> Tuple[str, float, str, Dict[str, Any]]:
    """
    Evaluates dynamic risk-based routing for an incoming request:
    Returns (decision, risk_score, reason, telemetry_metadata)
    - 0-30: 'real' (Low risk - Real Application)
    - 31-70: 'challenge' (Medium risk - Rate limiting or verification)
    - 71-100: 'decoy' (High risk - Divert to isolated decoy honeypot application)
    """
    start_time = time.time()
    now = datetime.now(timezone.utc)

    # 1. Lookup attacker profile in database
    stmt = select(Attacker).where(Attacker.ip == client_ip)
    res = await db.execute(stmt)
    attacker = res.scalar_one_or_none()

    if not attacker:
        # Unknown client: Default safe low-risk real route
        score = 0.0
        decision = "real"
        reason = f"Normal visitor {client_ip}: No prior suspicious indicators recorded."
        targeted_funcs = []
    else:
        # Use existing attacker risk score and Level-2 function risk score
        fn_score = attacker.function_risk_score or 0.0
        primary_score = attacker.risk_score or 0.0
        # Gateway considers maximum of primary risk and Level-2 function intelligence
        score = min(100.0, max(primary_score, fn_score))
        targeted_funcs = attacker.targeted_functions or []

        # Decision threshold policy
        if score >= 71.0 or "secrets_env" in targeted_funcs or ("admin_access" in targeted_funcs and len(targeted_funcs) >= 2):
            decision = "decoy"
            funcs_str = ", ".join(targeted_funcs) if targeted_funcs else "multi-vector attack pattern"
            reason = (
                f"Diverted to DECOY: Threat score {score:.1f}/100. "
                f"Source targeted {len(targeted_funcs)} sensitive function(s) ({funcs_str}) with rapid correlation."
            )
        elif score >= 31.0:
            decision = "challenge"
            reason = f"Challenge / Rate-Limit applied: Elevated risk score {score:.1f}/100 detected from previous activity."
        else:
            decision = "real"
            reason = f"Allowed to REAL application: Low risk score {score:.1f}/100 within legitimate tolerance."

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    # 2. Persist gateway telemetry log
    gateway_log = GatewayRequestLog(
        src_ip=client_ip,
        method=method,
        path=path,
        routed_to=decision,
        risk_score=score,
        decision_reason=reason,
        status_code=200 if decision != "blocked" else 403,
        response_time_ms=elapsed_ms,
        timestamp=now,
    )
    db.add(gateway_log)
    await db.flush()

    # 3. Broadcast live gateway telemetry over WebSocket
    try:
        await broadcast("gateway_routing", {
            "id": gateway_log.id,
            "src_ip": client_ip,
            "method": method,
            "path": path,
            "routed_to": decision,
            "risk_score": score,
            "decision_reason": reason,
            "response_time_ms": elapsed_ms,
            "timestamp": now.isoformat(),
        })
    except Exception:
        pass

    metadata = {
        "client_ip": client_ip,
        "risk_score": score,
        "decision": decision,
        "reason": reason,
        "targeted_functions": targeted_funcs,
        "elapsed_ms": elapsed_ms,
    }

    return decision, score, reason, metadata

