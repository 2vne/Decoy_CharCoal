from __future__ import annotations
import asyncio
from datetime import datetime, timezone, timedelta
import random
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import DecoyInteractionLog, VisitorSessionRisk
from app.services.broadcast import broadcast

# Concurrency guard: Bounds the number of concurrent delayed requests to prevent resource exhaustion
_decoy_semaphore = asyncio.Semaphore(settings.decoy_max_concurrent_delayed_requests)

# In-memory tracking of active decoy session start times and sequence counters
_session_sequences: Dict[str, int] = {}
_session_first_seen: Dict[str, datetime] = {}
_recent_decoy_interactions: List[Dict[str, Any]] = []

# Runtime latency mode: "controlled" (applies delay profiles) or "normal" (instant baseline)
_runtime_latency_mode: str = "controlled"


def set_decoy_latency_mode(mode: str) -> str:
    global _runtime_latency_mode
    if mode in ("controlled", "normal"):
        _runtime_latency_mode = mode
    return _runtime_latency_mode


def get_decoy_latency_mode() -> str:
    return _runtime_latency_mode


def sanitize_evidence_text(raw_text: str) -> str:
    """
    Sanitizes sensitive request data, passwords, OTPs, credit card tokens, and secrets.
    Ensures no plaintext credentials or sensitive tokens are stored or broadcast.
    """
    if not raw_text:
        return ""

    sanitized = raw_text
    # Redact passwords (e.g. password=..., pwd=..., "password": "...")
    sanitized = re.sub(r'(?i)(password|passwd|pwd|pass)\s*[:=]\s*["\']?[^\s,"\'&]+["\']?', r'\1=[REDACTED_PASSWORD]', sanitized)
    # Redact OTP / MFA codes (e.g. otp=123456, code=999999)
    sanitized = re.sub(r'(?i)(otp|otp_code|mfa_code|challenge_token)\s*[:=]\s*["\']?[^\s,"\'&]+["\']?', r'\1=[REDACTED_MFA_TOKEN]', sanitized)
    # Redact payment tokens and card numbers
    sanitized = re.sub(r'(?i)(token|card_number|card|cvv|cvc)\s*[:=]\s*["\']?[^\s,"\'&]+["\']?', r'\1=[REDACTED_PAYMENT_SECRET]', sanitized)
    # Redact authorization bearer tokens
    sanitized = re.sub(r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+', 'Bearer [REDACTED_TOKEN]', sanitized)
    return sanitized


def get_latency_bounds(category: str) -> Tuple[float, float]:
    """Retrieves the configured minimum and maximum delay in seconds for a category."""
    profiles = settings.decoy_latency_profiles
    prof = profiles.get(category) or profiles.get("default") or {"min": 0.2, "max": 0.8}
    return float(prof.get("min", 0.0)), float(prof.get("max", 0.5))


def compute_decoy_delay(category: str, override_mode: Optional[str] = None) -> float:
    """
    Computes an asynchronous delay within the configured min-max profile.
    Introduces uniform random variation within the range to model realistic server processing.
    Returns 0.0 if latency is disabled or in 'normal' mode.
    """
    mode = override_mode or _runtime_latency_mode
    if not settings.decoy_latency_enabled or mode == "normal":
        return 0.0

    min_s, max_s = get_latency_bounds(category)
    if max_s <= 0.0:
        return 0.0
    if min_s >= max_s:
        return round(min_s, 3)

    return round(random.uniform(min_s, max_s), 3)


async def observe_and_delay_decoy(
    session_id: str,
    src_ip: str,
    endpoint: str,
    method: str,
    category: str,
    db: AsyncSession,
    evidence: str = "",
    is_honeytoken: bool = False,
    user_agent: Optional[str] = None,
    override_mode: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Attacker Behaviour Observation & Controlled Delay Engine:
    1. Tracks sequence number and session duration for the isolated decoy visitor.
    2. Computes category-specific response latency.
    3. Asynchronously broadcasts live telemetry to SOC dashboard BEFORE delaying response.
    4. Applies non-blocking asynchronous sleep (bounded by concurrency semaphore).
    5. Records sanitized interaction telemetry into DecoyInteractionLog.
    """
    start_time = time.time()
    now_utc = datetime.now(timezone.utc)

    # 1. Update session sequence and first-seen duration tracking
    if session_id not in _session_first_seen:
        _session_first_seen[session_id] = now_utc
        _session_sequences[session_id] = 1
    else:
        _session_sequences[session_id] = _session_sequences.get(session_id, 0) + 1

    sequence_num = _session_sequences[session_id]
    first_seen_ts = _session_first_seen[session_id]
    session_duration_s = max(0.0, round((now_utc - first_seen_ts).total_seconds(), 2))

    # 2. Determine non-blocking delay
    delay_s = compute_decoy_delay(category, override_mode=override_mode)
    sanitized_ev = sanitize_evidence_text(evidence)

    # 3. Asynchronously broadcast live telemetry IMMEDIATELY (SOC dashboard is never delayed by decoy latency)
    telemetry_item = {
        "session_id": session_id,
        "src_ip": src_ip,
        "endpoint": endpoint,
        "method": method,
        "interaction_category": category,
        "request_sequence": sequence_num,
        "configured_delay_seconds": delay_s,
        "is_honeytoken": is_honeytoken,
        "sanitized_evidence": sanitized_ev,
        "session_duration_seconds": session_duration_s,
        "user_agent": user_agent or "Unknown",
        "timestamp": now_utc.isoformat(),
        "latency_mode": override_mode or _runtime_latency_mode,
    }

    try:
        await broadcast("decoy_interaction", telemetry_item)
    except Exception:
        pass

    # Asynchronously dispatch PagerDuty alert without delaying decoy response
    try:
        from app.services.pagerduty import dispatch_decoy_pagerduty_alert
        asyncio.create_task(
            dispatch_decoy_pagerduty_alert(
                session_id=session_id,
                src_ip=src_ip,
                endpoint=endpoint,
                method=method,
                category=category,
                is_honeytoken=is_honeytoken,
                sanitized_evidence=sanitized_ev,
                user_agent=user_agent,
                is_simulated=False,
            )
        )
    except Exception:
        pass

    # 4. Apply non-blocking asynchronous delay under concurrency semaphore
    if delay_s > 0.0:
        try:
            async with _decoy_semaphore:
                await asyncio.sleep(delay_s)
        except Exception:
            # Prevent hangs if task is interrupted or cancelled
            pass

    measured_latency_ms = round((time.time() - start_time) * 1000, 2)
    telemetry_item["response_latency_ms"] = measured_latency_ms

    # 5. Persist interaction log to database
    try:
        log_entry = DecoyInteractionLog(
            session_id=session_id,
            src_ip=src_ip,
            endpoint=endpoint,
            method=method,
            interaction_category=category,
            request_sequence=sequence_num,
            response_latency_ms=measured_latency_ms,
            delay_applied_seconds=delay_s,
            is_honeytoken=is_honeytoken,
            sanitized_evidence=sanitized_ev,
            user_agent=user_agent,
            session_duration_seconds=session_duration_s,
            timestamp=now_utc,
        )
        db.add(log_entry)
        await db.commit()
    except Exception:
        await db.rollback()

    # Update in-memory buffer
    _recent_decoy_interactions.insert(0, telemetry_item)
    if len(_recent_decoy_interactions) > 200:
        _recent_decoy_interactions.pop()

    return {
        "session_id": session_id,
        "sequence": sequence_num,
        "category": category,
        "delay_applied_seconds": delay_s,
        "response_latency_ms": measured_latency_ms,
        "session_duration_seconds": session_duration_s,
        "is_honeytoken": is_honeytoken,
    }


async def get_decoy_observation_stats(db: AsyncSession) -> Dict[str, Any]:
    """
    Aggregates decoy interaction metrics for the Deception Gateway & Honeypots SOC dashboard:
    - Session duration
    - Total requests
    - Average response latency
    - Interaction history
    - Category distribution
    - Most frequently accessed endpoints
    - Honeytoken interactions
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)

    # 1. Total requests & average latency
    stmt_totals = select(
        func.count(DecoyInteractionLog.id),
        func.avg(DecoyInteractionLog.response_latency_ms),
        func.count(func.distinct(DecoyInteractionLog.session_id)),
    ).where(DecoyInteractionLog.timestamp >= cutoff)
    totals_res = await db.execute(stmt_totals)
    tot_row = totals_res.fetchone()

    total_requests = int(tot_row[0] or 0) if tot_row else 0
    avg_latency_ms = round(float(tot_row[1] or 0.0), 2) if tot_row else 0.0
    active_sessions_count = int(tot_row[2] or 0) if tot_row else 0

    # 2. Category distribution
    stmt_cats = (
        select(DecoyInteractionLog.interaction_category, func.count(DecoyInteractionLog.id))
        .where(DecoyInteractionLog.timestamp >= cutoff)
        .group_by(DecoyInteractionLog.interaction_category)
    )
    cats_res = await db.execute(stmt_cats)
    category_distribution = {row[0]: int(row[1]) for row in cats_res.all()}

    # 3. Most frequently accessed decoy endpoints
    stmt_eps = (
        select(
            DecoyInteractionLog.endpoint,
            func.count(DecoyInteractionLog.id),
            func.avg(DecoyInteractionLog.response_latency_ms),
        )
        .where(DecoyInteractionLog.timestamp >= cutoff)
        .group_by(DecoyInteractionLog.endpoint)
        .order_by(desc(func.count(DecoyInteractionLog.id)))
        .limit(6)
    )
    eps_res = await db.execute(stmt_eps)
    frequent_endpoints = [
        {"endpoint": row[0], "hits": int(row[1]), "avg_latency_ms": round(float(row[2] or 0.0), 1)}
        for row in eps_res.all()
    ]

    # 4. Honeytoken interactions count
    stmt_ht = select(func.count(DecoyInteractionLog.id)).where(
        DecoyInteractionLog.is_honeytoken.is_(True),
        DecoyInteractionLog.timestamp >= cutoff,
    )
    ht_res = await db.execute(stmt_ht)
    honeytoken_hits = int(ht_res.scalar() or 0)

    # 5. Recent interaction logs
    stmt_recent = (
        select(DecoyInteractionLog)
        .order_by(desc(DecoyInteractionLog.timestamp))
        .limit(20)
    )
    recent_res = await db.execute(stmt_recent)
    recent_logs = [
        {
            "id": r.id,
            "session_id": r.session_id,
            "src_ip": r.src_ip,
            "endpoint": r.endpoint,
            "method": r.method,
            "category": r.interaction_category,
            "sequence": r.request_sequence,
            "latency_ms": r.response_latency_ms,
            "delay_applied_seconds": r.delay_applied_seconds,
            "is_honeytoken": r.is_honeytoken,
            "evidence": r.sanitized_evidence,
            "session_duration_seconds": r.session_duration_seconds,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in recent_res.scalars().all()
    ]

    # Merge with in-memory buffer if DB is fresh
    if not recent_logs and _recent_decoy_interactions:
        recent_logs = _recent_decoy_interactions[:20]

    # Calculate average session duration across active sessions
    avg_session_duration = 0.0
    if _session_first_seen:
        durations = [(now - fs).total_seconds() for fs in _session_first_seen.values()]
        avg_session_duration = round(sum(durations) / max(1, len(durations)), 1)

    return {
        "status": "operational",
        "latency_mode": _runtime_latency_mode,
        "latency_enabled": settings.decoy_latency_enabled,
        "total_attacker_requests": total_requests or len(_recent_decoy_interactions),
        "active_decoy_sessions": active_sessions_count or len(_session_first_seen),
        "average_response_latency_ms": avg_latency_ms,
        "average_session_duration_seconds": avg_session_duration,
        "honeytoken_hits": honeytoken_hits,
        "category_distribution": category_distribution,
        "frequently_accessed_endpoints": frequent_endpoints,
        "latency_profiles": settings.decoy_latency_profiles,
        "recent_interactions": recent_logs,
        "latest_activity": recent_logs[0]["timestamp"] if recent_logs else now.isoformat(),
    }


async def run_latency_comparison_demo(
    category: str = "auth_login",
    custom_session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Controlled demonstration comparing:
    1. Normal decoy response mode (fast baseline ~5-25ms)
    2. Controlled latency mode (delayed with realistic variation within bounds)
    Returns side-by-side comparison with configured bounds and measured latency.
    """
    test_session = custom_session_id or f"demo_compare_{int(time.time())}"
    min_s, max_s = get_latency_bounds(category)

    # 1. Measure Normal Mode (instant baseline)
    t0_normal = time.time()
    delay_normal = compute_decoy_delay(category, override_mode="normal")
    await asyncio.sleep(delay_normal)
    normal_measured_ms = round((time.time() - t0_normal) * 1000, 2)

    # 2. Measure Controlled Latency Mode
    t0_controlled = time.time()
    delay_controlled = compute_decoy_delay(category, override_mode="controlled")
    await asyncio.sleep(delay_controlled)
    controlled_measured_ms = round((time.time() - t0_controlled) * 1000, 2)

    return {
        "scenario": "Decoy Latency & Interaction Observation Comparison",
        "category": category,
        "test_session_id": test_session,
        "profile_bounds": {
            "min_seconds": min_s,
            "max_seconds": max_s,
            "min_ms": int(min_s * 1000),
            "max_ms": int(max_s * 1000),
        },
        "normal_mode": {
            "mode": "normal",
            "delay_applied_seconds": delay_normal,
            "measured_response_ms": normal_measured_ms,
            "attacker_experience": "Immediate response; attacker proceeds quickly without observation opportunity",
        },
        "controlled_mode": {
            "mode": "controlled",
            "delay_applied_seconds": delay_controlled,
            "measured_response_ms": controlled_measured_ms,
            "within_bounds": (min_s * 1000 <= controlled_measured_ms + 100) and (controlled_measured_ms - 100 <= max_s * 1000),
            "attacker_experience": f"Controlled delay applied ({delay_controlled:.2f}s). SENTINEL holds session active to observe and fingerprint behaviour.",
        },
        "observation_benefit": {
            "time_dilation_factor": round(max(1.0, controlled_measured_ms / max(1.0, normal_measured_ms)), 1),
            "additional_observation_window_ms": max(0, round(controlled_measured_ms - normal_measured_ms, 2)),
        },
    }

