from __future__ import annotations
from datetime import datetime, timezone, timedelta
import math
import re
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.models import Attacker, FunctionTargetEvent
from app.services.broadcast import broadcast

# Canonical Functions and Metadata
FUNCTION_METADATA: Dict[str, Dict[str, Any]] = {
    "auth_login": {
        "name": "Login / Authentication",
        "description": "Primary authentication gateways and session credential validation",
        "category": "Authentication",
        "default_weight": 10,
    },
    "auth_otp": {
        "name": "Two-Factor Authentication / OTP",
        "description": "Out-of-band one-time password and multi-factor challenge endpoints",
        "category": "Authentication",
        "default_weight": 15,
    },
    "auth_reset": {
        "name": "Password Reset / Account Recovery",
        "description": "Credential reset tokens, recovery questions, and password recovery workflows",
        "category": "Authentication",
        "default_weight": 12,
    },
    "admin_access": {
        "name": "Admin / Privilege Access",
        "description": "Administrative portals, permission escalation, and elevated system controls",
        "category": "Authorization",
        "default_weight": 20,
    },
    "payment_gateway": {
        "name": "Payment Gateway / Transactions",
        "description": "Payment checkout endpoints, card processing, and transaction APIs",
        "category": "Financial",
        "default_weight": 25,
    },
    "database_api": {
        "name": "Database & Query Endpoints",
        "description": "Database management interfaces, GraphQL/SQL APIs, and customer data queries",
        "category": "Data Access",
        "default_weight": 25,
    },
    "secrets_env": {
        "name": "Configuration & Secrets Exposure",
        "description": "Environment variables, .env, cloud keys, and configuration leaks",
        "category": "Configuration",
        "default_weight": 30,
    },
}

# Detection Signatures for Event-to-Function Mapping
URL_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"(\.env|config\.json|wp-config|\.git|actuator|aws/credentials|id_rsa)", re.I), "secrets_env", "Sensitive configuration / secrets file probe"),
    (re.compile(r"/(payment|checkout|pay|transactions?|stripe|paypal|card|billing)", re.I), "payment_gateway", "Payment gateway or financial transaction endpoint probe"),
    (re.compile(r"/(admin|wp-admin|manage|administrator|sudo|privilege)", re.I), "admin_access", "Administrative panel or privilege escalation probe"),
    (re.compile(r"/(otp|2fa|mfa|verify-token|two-factor)", re.I), "auth_otp", "Multi-factor authentication or OTP challenge bypass attempt"),
    (re.compile(r"/(reset-password|forgot-password|recover|account-recovery|password/reset|password)", re.I), "auth_reset", "Password reset or account recovery token attempt"),
    (re.compile(r"/(login|signin|session|authenticate|oauth|auth)", re.I), "auth_login", "Authentication or credential validation endpoint probe"),
    (re.compile(r"/(phpmyadmin|graphql|api/v1/customers|api/v1/users|sql|dbadmin)", re.I), "database_api", "Database query or sensitive customer data endpoint probe"),
]

COMMAND_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"(cat\s+\.env|cat\s+/etc/shadow|grep.*pass|aws\s+configure|\.aws/credentials)", re.I), "secrets_env", "Command inspecting environment or credentials files"),
    (re.compile(r"(mysql|psql|sqlite3|mongo|redis-cli|select\s+.*from)", re.I), "database_api", "Interactive database client or SQL query execution"),
    (re.compile(r"(sudo|useradd|usermod|chmod\s+777|visudo|su\s+root)", re.I), "admin_access", "Administrative command or privilege escalation attempt"),
    (re.compile(r"(curl|wget).*(checkout|payment|billing|api/transaction)", re.I), "payment_gateway", "Outbound probe targeting transaction or payment endpoints"),
]

PORT_FUNCTION_MAP: Dict[int, Tuple[str, str]] = {
    3306: ("database_api", "MySQL database decoy ingress"),
    1433: ("database_api", "MSSQL database decoy ingress"),
    5432: ("database_api", "PostgreSQL database decoy ingress"),
    27017: ("database_api", "MongoDB database decoy ingress"),
    6379: ("database_api", "Redis cache decoy ingress"),
}


def sanitize_text(text: str) -> str:
    """Redacts credentials, tokens, and secret parameters from endpoints/evidence."""
    if not text:
        return ""
    cleaned = re.sub(r"([?&](?:token|key|api_key|password|pass|secret)=)[^&\s]+", r"\1[REDACTED]", text, flags=re.I)
    cleaned = re.sub(r"://([^:@]+):([^@]+)@", r"://\1:[REDACTED]@", cleaned)
    cleaned = re.sub(r"(-p\s*)([^\s]+)", r"\1[REDACTED]", cleaned)
    return cleaned


def map_event_to_function(
    event_type: str,
    command: Optional[str] = None,
    url: Optional[str] = None,
    dst_port: Optional[int] = None,
    honeypot: Optional[str] = None,
    raw: Optional[Dict[str, Any]] = None,
) -> Optional[Tuple[str, str, str, float, bool]]:
    """
    Maps an incoming security event to one of the 7 sensitive functions.
    Clearly distinguishes observed application endpoints from inferred honeypot signals.
    Returns (target_function, target_endpoint, evidence, confidence, is_inferred) or None.
    """
    raw_dict = raw or {}

    # 1. Check for explicit target tag (e.g. from gateway or simulation)
    if "target_function" in raw_dict and raw_dict["target_function"] in FUNCTION_METADATA:
        fn = raw_dict["target_function"]
        ep = sanitize_text(raw_dict.get("target_endpoint", url or f"/{fn}"))
        return fn, ep, f"[Observed] Direct API targeting: {FUNCTION_METADATA[fn]['name']}", 1.0, False

    # 2. Match URL / Endpoint paths (Observed web application targeting)
    if url:
        for pattern, fn_key, desc in URL_PATTERNS:
            if pattern.search(url):
                return fn_key, sanitize_text(url), f"[Observed] {desc} ({sanitize_text(url)})", 0.90, False

    # 3. Match Honeypot shell commands (Inferred from Cowrie interactive session)
    if command:
        for pattern, fn_key, desc in COMMAND_PATTERNS:
            if pattern.search(command):
                return fn_key, sanitize_text(command), f"[Inferred] Shell command targeting {FUNCTION_METADATA[fn_key]['name']}: {sanitize_text(command)}", 0.75, True

    # 4. Match Database Ports (Inferred from direct decoy port probe)
    if dst_port and dst_port in PORT_FUNCTION_MAP:
        fn_key, desc = PORT_FUNCTION_MAP[dst_port]
        return fn_key, f"port:{dst_port}", f"[Inferred] {desc}", 0.65, True

    # Note: Unmatched events (including Cowrie SSH port 22 connections/logins) remain unmatched!
    return None


def compute_bounded_function_risk(
    function_events: List[Any],
    now: Optional[datetime] = None,
) -> Tuple[float, str, Dict[str, Any]]:
    """
    Calculates bounded function-level risk score (0-100) using:
    - Base function weights (max weight + breadth scaling)
    - Sliding temporal window multiplier (30s, 1m, 5m, 15m)
    - Canonical attack sequence synergy (e.g., login -> otp -> admin -> payment)
    - Frequency logarithm scaling
    """
    if not function_events:
        return 0.0, "low", {
            "distinct_functions": [],
            "score": 0.0,
            "bounded_score": 0.0,
            "function_risk_score": 0.0,
            "risk_band": "low",
            "function_risk_band": "low",
            "temporal_multiplier": 1.0,
            "synergy_bonus": 0.0,
            "synergies": [],
            "synergies_detected": [],
            "explanation": "No sensitive functions targeted.",
            "confidence": 0.0,
        }

    now_utc = now or datetime.now(timezone.utc)
    weights_cfg = settings.function_weights

    def _get_ts(e: Any) -> datetime:
        ts = e.get("timestamp") if isinstance(e, dict) else getattr(e, "timestamp", None)
        if ts is None:
            return now_utc
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts

    def _get_fn(e: Any) -> str:
        return e.get("target_function") if isinstance(e, dict) else getattr(e, "target_function", "")

    def _get_attempts(e: Any) -> int:
        return e.get("attempts", 1) if isinstance(e, dict) else getattr(e, "attempts", 1)

    # Sort events chronologically
    sorted_evs = sorted(function_events, key=_get_ts)

    distinct_funcs: List[str] = []
    function_counts: Dict[str, int] = {}
    for ev in sorted_evs:
        fn = _get_fn(ev)
        if not fn:
            continue
        attempts = _get_attempts(ev)
        function_counts[fn] = function_counts.get(fn, 0) + attempts
        if fn not in distinct_funcs:
            distinct_funcs.append(fn)

    # 1. Base Function Impact (Max weight + bounded breadth)
    weights = [weights_cfg.get(fn, FUNCTION_METADATA.get(fn, {}).get("default_weight", 10)) for fn in distinct_funcs]
    max_w = max(weights) if weights else 0
    sum_w = sum(weights)
    # Bounded base score up to 60 points
    base_score = min(60.0, max_w + 0.35 * (sum_w - max_w))

    # 2. Time Window Calculation across sequence
    t_start = _get_ts(sorted_evs[0])
    t_end = _get_ts(sorted_evs[-1])
    delta_seconds = abs((t_end - t_start).total_seconds())

    # Temporal multiplier
    if len(distinct_funcs) >= 2:
        if delta_seconds <= 30.0:
            time_mult = 1.45
            time_label = f"rapid burst across {len(distinct_funcs)} critical functions within {delta_seconds:.0f}s"
        elif delta_seconds <= 60.0:
            time_mult = 1.35
            time_label = f"coordinated multi-function sequence within {delta_seconds:.0f}s"
        elif delta_seconds <= 300.0:
            time_mult = 1.20
            time_label = f"sustained multi-function targeting within {delta_seconds / 60:.1f}m"
        elif delta_seconds <= 900.0:
            time_mult = 1.10
            time_label = f"distributed probe across {delta_seconds / 60:.1f}m"
        else:
            time_mult = 1.0
            time_label = f"sparse accesses across {delta_seconds / 60:.1f}m"
    else:
        time_mult = 1.0
        time_label = f"{distinct_funcs[0]} targeted" if distinct_funcs else "single target"

    # 3. Canonical Sequence Synergies
    synergies: List[str] = []
    synergy_bonus = 0.0

    fn_set = set(distinct_funcs)
    if "auth_login" in fn_set and "auth_otp" in fn_set:
        synergy_bonus += 8.0
        synergies.append("Credential Compromise + 2FA Bypass attempt")
    if "auth_login" in fn_set and "admin_access" in fn_set:
        synergy_bonus += 10.0
        synergies.append("Administrative Privilege Escalation pattern")
    if "admin_access" in fn_set and ("payment_gateway" in fn_set or "database_api" in fn_set):
        synergy_bonus += 15.0
        synergies.append("Privilege Escalation to Financial/Database Core")
    if "secrets_env" in fn_set and len(fn_set) > 1:
        synergy_bonus += 12.0
        synergies.append("Configuration Exfiltration accompanying service targeting")

    # 4. Attempt Frequency Log Factor
    total_attempts = sum(function_counts.values())
    freq_bonus = min(10.0, math.log1p(total_attempts) * 2.5)

    # 5. Mathematical Aggregation & Bounding
    raw_score = (base_score + synergy_bonus + freq_bonus) * time_mult
    final_score = min(100.0, max(0.0, round(raw_score, 1)))

    # Classification Band
    thresholds = settings.function_risk_thresholds
    if final_score <= thresholds.get("low", 30.0):
        band = "low"
    elif final_score <= thresholds.get("medium", 70.0):
        band = "medium"
    else:
        band = "high"

    # Human-readable explainable summary
    fn_display = [FUNCTION_METADATA.get(fn, {}).get("name", fn) for fn in distinct_funcs]
    explanation_parts = [
        f"{band.upper()} RISK ({final_score:.1f}/100): Attacker targeted {len(distinct_funcs)} sensitive function(s) ({', '.join(fn_display)}) with {time_label}."
    ]
    if synergies:
        explanation_parts.append(f"Attack patterns: {'; '.join(synergies)}.")
    if total_attempts > len(distinct_funcs):
        explanation_parts.append(f"Recorded {total_attempts} total attempts with payload variations.")

    confidence = min(0.98, round(0.60 + 0.12 * len(distinct_funcs) + (0.10 if synergies else 0.0), 2))

    breakdown = {
        "function_risk_score": final_score,
        "bounded_score": final_score,
        "function_risk_band": band,
        "risk_band": band,
        "distinct_functions": distinct_funcs,
        "function_counts": function_counts,
        "time_window_seconds": round(delta_seconds, 1),
        "temporal_multiplier": time_mult,
        "base_score": round(base_score, 1),
        "synergy_bonus": round(synergy_bonus, 1),
        "synergies": synergies,
        "synergies_detected": synergies,
        "freq_bonus": round(freq_bonus, 1),
        "total_attempts": total_attempts,
        "explanation": " ".join(explanation_parts),
        "confidence": confidence,
    }

    return final_score, band, breakdown


async def record_function_targeting(
    db: AsyncSession,
    attacker: Attacker,
    target_function: str,
    target_endpoint: str = "",
    attack_type: str = "probe",
    severity: str = "medium",
    result: str = "intercepted",
    attempts: int = 1,
    honeypot_source: str = "gateway",
    evidence: str = "",
    confidence: float = 1.0,
    is_simulated: bool = False,
    event_timestamp: Optional[datetime] = None,
    session_id: Optional[str] = None,
) -> FunctionTargetEvent:
    """
    Persists a function-targeting incident, recalculates the attacker's
    function risk score, and broadcasts live telemetry.
    """
    ts = event_timestamp or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    fn_ev = FunctionTargetEvent(
        attacker_id=attacker.id,
        src_ip=attacker.ip,
        target_function=target_function,
        target_endpoint=sanitize_text(target_endpoint),
        attack_type=attack_type,
        severity=severity,
        result=result,
        attempts=attempts,
        honeypot_source=honeypot_source,
        evidence=sanitize_text(evidence),
        confidence=confidence,
        is_simulated=is_simulated,
        session_id=session_id,
        timestamp=ts,
    )
    db.add(fn_ev)
    await db.flush()

    # Load recent function events for this attacker (last 24h)
    cutoff = ts - timedelta(hours=24)
    stmt = (
        select(FunctionTargetEvent)
        .where(FunctionTargetEvent.attacker_id == attacker.id, FunctionTargetEvent.timestamp >= cutoff)
        .order_by(FunctionTargetEvent.timestamp.asc())
    )
    res = await db.execute(stmt)
    all_fn_events = list(res.scalars().all())

    # If this is real traffic, calculate using observed events so simulated attacks don't inflate production stats
    eval_events = all_fn_events if is_simulated else [e for e in all_fn_events if not e.is_simulated]
    if not eval_events and all_fn_events:
        eval_events = all_fn_events

    # Compute Level-2 function risk score
    score, band, breakdown = compute_bounded_function_risk(eval_events, now=ts)
    breakdown["is_simulated"] = is_simulated

    attacker.targeted_functions = breakdown["distinct_functions"]
    attacker.function_risk_score = score
    attacker.function_risk_breakdown = breakdown

    # Add Level-2 risk factor to primary attacker profile ONLY IF NOT SIMULATED
    if score >= 30.0 and not is_simulated:
        existing_factors = list(attacker.risk_factors or [])
        factor_idx = next((i for i, f in enumerate(existing_factors) if f.get("factor") == "function_targeting"), -1)
        factor_obj = {
            "factor": "function_targeting",
            "points": round(score * 0.35, 1),
            "reason": breakdown["explanation"][:160],
        }
        if factor_idx >= 0:
            existing_factors[factor_idx] = factor_obj
        else:
            existing_factors.append(factor_obj)
        attacker.risk_factors = existing_factors

    await db.flush()

    # Broadcast function targeting event over live WebSocket
    try:
        await broadcast("function_targeting", {
            "id": fn_ev.id,
            "attacker_id": attacker.id,
            "src_ip": attacker.ip,
            "session_id": session_id,
            "target_function": target_function,
            "function_name": FUNCTION_METADATA.get(target_function, {}).get("name", target_function),
            "category": FUNCTION_METADATA.get(target_function, {}).get("category", "General"),
            "target_endpoint": fn_ev.target_endpoint,
            "attack_type": attack_type,
            "severity": severity,
            "result": result,
            "attempts": attempts,
            "confidence": confidence,
            "is_simulated": is_simulated,
            "evidence": fn_ev.evidence,
            "timestamp": ts.isoformat(),
            "function_risk_score": score,
            "function_risk_band": band,
            "explanation": breakdown["explanation"],
            "breakdown": breakdown,
        })
    except Exception:
        pass

    # Autonomous Alert Dispatch: Automatically notify PagerDuty, Resend Email, Twilio on attack
    if attack_type != "normal_access" and (severity in ("high", "critical") or score >= 35.0):
        try:
            from app.services.alert_dispatcher import dispatch_attack_alert_background
            dispatch_attack_alert_background(
                src_ip=attacker.ip,
                target_function=target_function,
                target_endpoint=fn_ev.target_endpoint,
                attack_type=attack_type,
                severity=severity,
                score=score,
                evidence=fn_ev.evidence,
                is_simulated=is_simulated,
                session_id=session_id,
                is_critical=(severity == "critical"),
                category=FUNCTION_METADATA.get(target_function, {}).get("category", "Function Targeting"),
            )
        except Exception:
            pass

    return fn_ev


# --------------------------------------------------------------------------
# Manual Function Intelligence Demonstration Controller
# --------------------------------------------------------------------------
import asyncio

DEMO_ATTACKER_IP = "198.51.100.99"
DEMO_DEFAULT_SESSION = "demo_fn_session_interactive"
ACTIVE_DEMO_TASKS: Dict[str, asyncio.Task] = {}
DEMO_ATTEMPT_COUNTERS: Dict[Tuple[str, str], int] = {}


async def _get_or_create_demo_attacker(db: AsyncSession, now: datetime) -> Attacker:
    stmt = select(Attacker).where(Attacker.ip == DEMO_ATTACKER_IP)
    res = await db.execute(stmt)
    atk = res.scalar_one_or_none()
    if not atk:
        atk = Attacker(
            ip=DEMO_ATTACKER_IP,
            status="active",
            risk_score=10.0,
            risk_band="low",
            function_risk_score=0.0,
            function_risk_breakdown={},
            targeted_functions=[],
            first_seen=now,
            last_seen=now,
        )
        db.add(atk)
        await db.flush()
    return atk


async def execute_demo_action(
    db: AsyncSession,
    action: str,
    session_id: Optional[str] = None,
    target_function: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes a controlled manual synthetic function targeting action:
    1. 'normal': Legitimate single session access (low risk)
    2. 'repeated': Sequential attempt bursts for same function (increasing attempts counter)
    3. 'sensitive_probe': Probing high-impact confidential configuration/payment/admin
    """
    sess_id = (session_id or DEMO_DEFAULT_SESSION).strip()
    now = datetime.now(timezone.utc)
    attacker = await _get_or_create_demo_attacker(db, now)

    if action == "normal":
        fn = target_function or "auth_login"
        if fn not in FUNCTION_METADATA:
            fn = "auth_login"
        fn_name = FUNCTION_METADATA[fn]["name"]
        attempts = 1
        severity = "low"
        attack_type = "standard_access"
        result = "authorized"
        endpoint = f"/api/v1/{fn.replace('_', '/')}"
        evidence = f"[Simulated Demo] Legitimate single session access to {fn_name}"

        fn_ev = await record_function_targeting(
            db=db,
            attacker=attacker,
            target_function=fn,
            target_endpoint=endpoint,
            attack_type=attack_type,
            severity=severity,
            result=result,
            attempts=attempts,
            honeypot_source="demo_console",
            evidence=evidence,
            confidence=1.0,
            is_simulated=True,
            session_id=sess_id,
            event_timestamp=now,
        )
        await db.commit()

        return {
            "status": "success",
            "action": "normal",
            "session_id": sess_id,
            "event_id": fn_ev.id,
            "target_function": fn,
            "function_name": fn_name,
            "category": FUNCTION_METADATA[fn]["category"],
            "attempts": attempts,
            "severity": severity,
            "result": result,
            "function_risk_score": attacker.function_risk_score,
            "function_risk_band": attacker.risk_band,
            "is_simulated": True,
            "explanation": attacker.function_risk_breakdown.get("explanation", ""),
            "timestamp": now.isoformat(),
        }

    elif action == "repeated":
        fn = target_function or "auth_login"
        if fn not in FUNCTION_METADATA:
            fn = "auth_login"
        fn_name = FUNCTION_METADATA[fn]["name"]

        # Increment consecutive attempt counter for this session & function
        counter_key = (sess_id, fn)
        current_attempts = DEMO_ATTEMPT_COUNTERS.get(counter_key, 1) + 2
        DEMO_ATTEMPT_COUNTERS[counter_key] = current_attempts

        severity = "high" if current_attempts >= 5 else "medium"
        attack_type = "credential_stuffing_burst"
        result = "rate_limited"
        endpoint = f"/api/v1/{fn.replace('_', '/')}"
        evidence = f"[Simulated Demo] Repeated automated burst ({current_attempts} attempts) targeting {fn_name}"

        fn_ev = await record_function_targeting(
            db=db,
            attacker=attacker,
            target_function=fn,
            target_endpoint=endpoint,
            attack_type=attack_type,
            severity=severity,
            result=result,
            attempts=current_attempts,
            honeypot_source="demo_console",
            evidence=evidence,
            confidence=1.0,
            is_simulated=True,
            session_id=sess_id,
            event_timestamp=now,
        )
        await db.commit()

        return {
            "status": "success",
            "action": "repeated",
            "session_id": sess_id,
            "event_id": fn_ev.id,
            "target_function": fn,
            "function_name": fn_name,
            "category": FUNCTION_METADATA[fn]["category"],
            "attempts": current_attempts,
            "severity": severity,
            "result": result,
            "function_risk_score": attacker.function_risk_score,
            "function_risk_band": attacker.risk_band,
            "is_simulated": True,
            "explanation": attacker.function_risk_breakdown.get("explanation", ""),
            "timestamp": now.isoformat(),
        }

    elif action in ("sensitive", "sensitive_probe"):
        fn = target_function or "secrets_env"
        if fn not in FUNCTION_METADATA:
            fn = "secrets_env"
        fn_name = FUNCTION_METADATA[fn]["name"]

        endpoint_map = {
            "secrets_env": "/.env",
            "admin_access": "/admin/privilege/escalate",
            "payment_gateway": "/checkout/stripe/charge",
            "database_api": "/api/v1/customers/export",
            "auth_otp": "/api/v1/auth/otp/bypass",
            "auth_reset": "/api/v1/auth/password/override",
            "auth_login": "/api/v1/auth/token/steal",
        }
        endpoint = endpoint_map.get(fn, f"/api/v1/{fn}")
        severity = "critical" if fn in ("secrets_env", "payment_gateway", "database_api") else "high"
        attack_type = "sensitive_function_probe"
        result = "blocked"
        evidence = f"[Simulated Demo] Direct unauthorized probe targeting sensitive function {fn_name} ({endpoint})"

        fn_ev = await record_function_targeting(
            db=db,
            attacker=attacker,
            target_function=fn,
            target_endpoint=endpoint,
            attack_type=attack_type,
            severity=severity,
            result=result,
            attempts=1,
            honeypot_source="demo_console",
            evidence=evidence,
            confidence=1.0,
            is_simulated=True,
            session_id=sess_id,
            event_timestamp=now,
        )
        await db.commit()

        return {
            "status": "success",
            "action": "sensitive_probe",
            "session_id": sess_id,
            "event_id": fn_ev.id,
            "target_function": fn,
            "function_name": fn_name,
            "category": FUNCTION_METADATA[fn]["category"],
            "attempts": 1,
            "severity": severity,
            "result": result,
            "function_risk_score": attacker.function_risk_score,
            "function_risk_band": attacker.risk_band,
            "is_simulated": True,
            "explanation": attacker.function_risk_breakdown.get("explanation", ""),
            "timestamp": now.isoformat(),
        }

    else:
        raise ValueError(f"Unknown demonstration action: {action}")


async def _run_recon_coroutine(session_id: str) -> None:
    """Asynchronous multi-step generator that dispatches sequential function targeting events."""
    from app.db import AsyncSessionLocal
    steps = [
        {
            "fn": "auth_login",
            "attempts": 2,
            "endpoint": "/api/v1/auth/login",
            "severity": "medium",
            "evidence": "[Multi-Recon 1/4] Initial credential probe targeting primary authentication",
        },
        {
            "fn": "auth_otp",
            "attempts": 2,
            "endpoint": "/api/v1/auth/otp/verify",
            "severity": "high",
            "evidence": "[Multi-Recon 2/4] Rapid 2FA verification bypass attempt (Synergy: Credential + 2FA triggered)",
        },
        {
            "fn": "admin_access",
            "attempts": 1,
            "endpoint": "/admin/system/privilege",
            "severity": "high",
            "evidence": "[Multi-Recon 3/4] Privilege escalation probe targeting administrative endpoints (Synergy: Admin Escalation)",
        },
        {
            "fn": "database_api",
            "attempts": 1,
            "endpoint": "/api/v1/customers/export",
            "severity": "critical",
            "evidence": "[Multi-Recon 4/4] Data exfiltration probe targeting customer records (Synergy: Core Data Access)",
        },
    ]

    try:
        for idx, step in enumerate(steps):
            await asyncio.sleep(0.4 if idx > 0 else 0.05)
            async with AsyncSessionLocal() as session:
                async with session.begin():
                    attacker = await _get_or_create_demo_attacker(session, datetime.now(timezone.utc))
                    await record_function_targeting(
                        db=session,
                        attacker=attacker,
                        target_function=step["fn"],
                        target_endpoint=step["endpoint"],
                        attack_type="multi_function_recon",
                        severity=step["severity"],
                        result="intercepted",
                        attempts=step["attempts"],
                        honeypot_source="demo_console",
                        evidence=step["evidence"],
                        confidence=1.0,
                        is_simulated=True,
                        session_id=session_id,
                        event_timestamp=datetime.now(timezone.utc),
                    )
    except asyncio.CancelledError:
        pass
    finally:
        ACTIVE_DEMO_TASKS.pop(session_id, None)


async def execute_demo_recon_sequence(session_id: Optional[str] = None) -> Dict[str, Any]:
    """Launches the 4-step multi-function reconnaissance sequence asynchronously."""
    sess_id = (session_id or DEMO_DEFAULT_SESSION).strip()
    # Cancel any currently active task for this session
    if sess_id in ACTIVE_DEMO_TASKS and not ACTIVE_DEMO_TASKS[sess_id].done():
        ACTIVE_DEMO_TASKS[sess_id].cancel()

    task = asyncio.create_task(_run_recon_coroutine(sess_id))
    ACTIVE_DEMO_TASKS[sess_id] = task

    return {
        "status": "started",
        "action": "multi_recon",
        "session_id": sess_id,
        "steps_count": 4,
        "sequence": ["auth_login", "auth_otp", "admin_access", "database_api"],
        "message": "Multi-Function Reconnaissance sequence initiated. Telemetry events will stream live via WebSocket.",
    }


def stop_demo_simulation(session_id: Optional[str] = None) -> Dict[str, Any]:
    """Immediately stops any ongoing multi-step reconnaissance simulation."""
    sess_id = (session_id or DEMO_DEFAULT_SESSION).strip()
    stopped = False
    if sess_id in ACTIVE_DEMO_TASKS:
        task = ACTIVE_DEMO_TASKS[sess_id]
        if not task.done():
            task.cancel()
            stopped = True
        ACTIVE_DEMO_TASKS.pop(sess_id, None)

    return {
        "status": "stopped",
        "session_id": sess_id,
        "was_running": stopped,
        "message": f"Simulation stopped for session {sess_id}.",
    }


async def reset_demo_session(db: AsyncSession, session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Resets the isolated synthetic demonstration session back to 0.
    ONLY deletes simulated events (is_simulated = True).
    Real observed telemetry and genuine attacker profiles are strictly preserved.
    """
    from sqlalchemy import delete
    sess_id = (session_id or DEMO_DEFAULT_SESSION).strip()

    # 1. Stop any active task
    stop_demo_simulation(sess_id)

    # 2. Clear attempt counter dictionary for this session
    keys_to_remove = [k for k in DEMO_ATTEMPT_COUNTERS.keys() if k[0] == sess_id]
    for k in keys_to_remove:
        DEMO_ATTEMPT_COUNTERS.pop(k, None)

    # 3. Delete simulated events for this demo session / synthetic IP ONLY
    del_stmt = delete(FunctionTargetEvent).where(
        FunctionTargetEvent.is_simulated.is_(True),
        (FunctionTargetEvent.session_id == sess_id) | (FunctionTargetEvent.src_ip == DEMO_ATTACKER_IP),
    )
    res_del = await db.execute(del_stmt)
    deleted_count = res_del.rowcount or 0

    # 4. Reset synthetic attacker profile
    stmt = select(Attacker).where(Attacker.ip == DEMO_ATTACKER_IP)
    atk_res = await db.execute(stmt)
    atk = atk_res.scalar_one_or_none()
    if atk:
        atk.function_risk_score = 0.0
        atk.function_risk_breakdown = {}
        atk.targeted_functions = []
        atk.risk_band = "low"
        atk.risk_score = 0.0

    await db.commit()

    # 5. Broadcast reset event to live SOC clients
    try:
        await broadcast("function_targeting_reset", {
            "session_id": sess_id,
            "src_ip": DEMO_ATTACKER_IP,
            "deleted_events": deleted_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception:
        pass

    return {
        "status": "reset_complete",
        "session_id": sess_id,
        "cleared_events": deleted_count,
        "ip": DEMO_ATTACKER_IP,
        "function_risk_score": 0.0,
        "message": f"Isolated demo session {sess_id} reset to baseline 0. Genuine observed telemetry preserved.",
    }


async def get_demo_status(db: AsyncSession, session_id: Optional[str] = None) -> Dict[str, Any]:
    """Returns the current state of the isolated demo session."""
    sess_id = (session_id or DEMO_DEFAULT_SESSION).strip()
    is_running = sess_id in ACTIVE_DEMO_TASKS and not ACTIVE_DEMO_TASKS[sess_id].done()

    stmt = select(func.count(FunctionTargetEvent.id)).where(
        FunctionTargetEvent.is_simulated.is_(True),
        (FunctionTargetEvent.session_id == sess_id) | (FunctionTargetEvent.src_ip == DEMO_ATTACKER_IP),
    )
    count_res = await db.execute(stmt)
    events_count = int(count_res.scalar() or 0)

    stmt_atk = select(Attacker).where(Attacker.ip == DEMO_ATTACKER_IP)
    atk_res = await db.execute(stmt_atk)
    atk = atk_res.scalar_one_or_none()

    active_counters = {
        fn: count for (s, fn), count in DEMO_ATTEMPT_COUNTERS.items() if s == sess_id
    }

    return {
        "session_id": sess_id,
        "is_running": is_running,
        "simulated_events_count": events_count,
        "attacker_ip": DEMO_ATTACKER_IP,
        "function_risk_score": atk.function_risk_score if atk else 0.0,
        "function_risk_band": atk.risk_band if atk else "low",
        "targeted_functions": atk.targeted_functions if atk else [],
        "attempt_counters": active_counters,
    }


