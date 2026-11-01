from __future__ import annotations
from datetime import datetime, timezone, timedelta
import hashlib
import math
from typing import Any, Dict, List, Optional, Tuple, Set

from sqlalchemy import desc, func, select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import (
    Attacker,
    VisitorSessionRisk,
    AccountRiskHistory,
    ObservedBehaviourEvent,
)
from app.services.broadcast import broadcast

# Canonical Categories & Descriptions
BEHAVIOUR_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "login_failures": {
        "name": "Repeated Login Failures",
        "description": "Sequential or credential-stuffing authentication failures",
        "window_type": "auth",
        "default_max": 12,
    },
    "otp_failures": {
        "name": "Repeated OTP Failures",
        "description": "Multi-factor authentication brute-force and bypass attempts",
        "window_type": "auth",
        "default_max": 8,
    },
    "password_reset": {
        "name": "Password-Reset Abuse",
        "description": "Account enumeration and token flooding via password recovery",
        "window_type": "auth",
        "default_max": 5,
    },
    "admin_access": {
        "name": "Unauthorized Admin Access Attempts",
        "description": "Privilege escalation and unauthorized admin portal probing",
        "window_type": "probe",
        "default_max": 15,
    },
    "secrets_probing": {
        "name": "Source Code & Secrets Probing",
        "description": "Probing for .env, .git, cloud credentials, or secrets configuration",
        "window_type": "probe",
        "default_max": 20,
    },
    "endpoint_enumeration": {
        "name": "Sensitive Endpoint Enumeration",
        "description": "Systematic scanning and crawling of unpublished API endpoints",
        "window_type": "probe",
        "default_max": 15,
    },
    "abnormal_rate": {
        "name": "Abnormal Request Frequency / Scanning",
        "description": "High-velocity automated tool signatures and traffic bursts",
        "window_type": "rate",
        "default_max": 10,
    },
    "database_access": {
        "name": "Unauthorized Customer / Database Access",
        "description": "Direct attempts to query, extract or tamper with database records",
        "window_type": "probe",
        "default_max": 10,
    },
    "combined_patterns": {
        "name": "Combined Suspicious Behaviour Patterns",
        "description": "Cross-vector attack sequence synergy across independent techniques",
        "window_type": "session",
        "default_max": 5,
    },
}


def get_configured_allocations() -> Dict[str, float]:
    """Returns the configured max point allocations, ensuring sum == 100."""
    allocations = dict(settings.behaviour_point_allocation)
    total = sum(allocations.values())
    if abs(total - 100.0) > 0.01:
        # Scale proportionally to guarantee exactly 100
        factor = 100.0 / total
        allocations = {k: round(v * factor, 2) for k, v in allocations.items()}
    return allocations


def get_observation_window_seconds(window_type: str) -> int:
    """Returns configured observation window in seconds for the behaviour type."""
    cfg = settings.observation_windows
    return int(cfg.get(window_type, 600))


def calculate_event_decay(
    event_timestamp: datetime,
    now: datetime,
    window_seconds: int,
) -> float:
    """
    Computes time-decay factor for an event:
    - 0 <= delta_t <= window: full weight (1.0)
    - window < delta_t <= 2 * window: linear decay from 1.0 down to 0.25
    - delta_t > 2 * window: exponential decay approaching 0.05
    Original events in the database are never deleted.
    """
    if event_timestamp.tzinfo is None:
        event_timestamp = event_timestamp.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    delta_seconds = max(0.0, (now - event_timestamp).total_seconds())

    if delta_seconds <= window_seconds:
        return 1.0
    elif delta_seconds <= 2 * window_seconds:
        fraction = (delta_seconds - window_seconds) / float(window_seconds)
        return max(0.25, 1.0 - (0.75 * fraction))
    elif delta_seconds <= 4 * window_seconds:
        fraction = (delta_seconds - (2 * window_seconds)) / float(2 * window_seconds)
        return max(0.05, 0.25 * math.exp(-fraction))
    return 0.0


def calculate_category_severity(
    category: str,
    effective_count: float,
    extra: Optional[Dict[str, Any]] = None,
) -> Tuple[float, str]:
    """
    Maps effective behaviour count / metrics to a severity score from 0 to 100.
    Returns (severity_0_to_100, reason_description).
    """
    extra = extra or {}
    c = effective_count

    if category == "combined_patterns":
        # Evaluates synergy across other independent categories
        active_independent = extra.get("active_independent_categories", [])
        synergies = extra.get("synergies", [])
        k = len(active_independent)

        if k < 2 and not synergies:
            return 0.0, "No combined behaviour synergies detected."

        if (synergies and len(synergies) >= 2) or k >= 4:
            return 100.0, f"Critical multi-stage synergy ({', '.join(synergies or active_independent)})"
        elif synergies or k >= 3:
            return 70.0, f"Correlated multi-vector attack synergy ({', '.join(synergies or active_independent)})"
        elif k >= 2:
            return 40.0, f"Cross-category activity observed across {k} independent vectors ({', '.join(active_independent)})"
        return 0.0, "No combined behaviour synergies detected."

    if c <= 0.01:
        return 0.0, f"No suspicious activity detected in {category}."

    if category == "login_failures":
        if c < 1.0:
            return round(5.0 * c, 2), f"{c:.2f} decaying login failure"
        elif c < 2.0:
            return 5.0, "1 login failure (isolated attempt)"
        elif c < 3.0:
            return 15.0, "2 login failures (suspicious repetition)"
        elif c < 5.0:
            return 35.0, f"{int(c)} login failures (brute-force threshold)"
        elif c < 8.0:
            return 65.0, f"{int(c)} login failures (active brute-force assault)"
        else:
            return 100.0, f"{int(c)} login failures (critical credential stuffing attack)"

    elif category == "otp_failures":
        if c < 1.0:
            return round(10.0 * c, 2), f"{c:.2f} decaying OTP challenge failure"
        elif c < 2.0:
            return 10.0, "1 failed OTP challenge (possible typo)"
        elif c < 3.0:
            return 30.0, "2 failed OTP challenges (suspicious 2FA probing)"
        elif c < 5.0:
            return 60.0, f"{int(c)} failed OTP challenges (2FA brute-force attempt)"
        else:
            return 100.0, f"{int(c)} failed OTP challenges (critical 2FA bypass campaign)"

    elif category == "password_reset":
        if c < 1.0:
            return round(15.0 * c, 2), f"{c:.2f} decaying reset probe"
        elif c < 2.0:
            return 15.0, "1 password reset probe (unverified identity)"
        elif c < 3.0:
            return 35.0, "2 password reset probes (account enumeration pattern)"
        elif c < 5.0:
            return 70.0, f"{int(c)} password reset probes (rapid user harvest)"
        else:
            return 100.0, f"{int(c)} password reset probes (critical recovery mechanism abuse)"

    elif category == "admin_access":
        if c < 1.0:
            return round(20.0 * c, 2), f"{c:.2f} decaying admin probe"
        elif c < 2.0:
            return 20.0, "1 unauthorized admin endpoint access attempt"
        elif c < 3.0:
            return 45.0, "2 unauthorized admin access attempts (privilege probing)"
        elif c < 5.0:
            return 75.0, f"{int(c)} unauthorized admin access attempts (privilege escalation search)"
        else:
            return 100.0, f"{int(c)} unauthorized admin access attempts (critical infrastructure attack)"

    elif category == "secrets_probing":
        if c < 1.0:
            return round(25.0 * c, 2), f"{c:.2f} decaying secrets probe"
        elif c < 2.0:
            return 25.0, "1 sensitive configuration probe (.env / .git / keys)"
        elif c < 3.0:
            return 50.0, "2 sensitive configuration probes (targeted secrets exfiltration)"
        elif c < 5.0:
            return 80.0, f"{int(c)} sensitive configuration probes (aggressive credential harvesting)"
        else:
            return 100.0, f"{int(c)} sensitive configuration probes (critical configuration exposure raid)"

    elif category == "endpoint_enumeration":
        # Distinct endpoints probed
        distinct_eps = extra.get("distinct_endpoints", int(c))
        if distinct_eps <= 0:
            return 0.0, "No endpoint enumeration detected."
        elif distinct_eps <= 2:
            return 15.0, f"{distinct_eps} unpublished or non-existent endpoint(s) probed"
        elif distinct_eps <= 4:
            return 40.0, f"{distinct_eps} endpoints enumerated (directory/API traversal)"
        elif distinct_eps <= 7:
            return 70.0, f"{distinct_eps} endpoints enumerated (broad automated scan)"
        else:
            return 100.0, f"{distinct_eps} endpoints enumerated (exhaustive attack surface mapping)"

    elif category == "abnormal_rate":
        # Rate per minute
        rate = extra.get("requests_per_minute", c)
        if rate < 20:
            return 0.0, f"Request rate normal ({rate:.0f} req/min)"
        elif rate < 40:
            return 20.0, f"Elevated request rate ({rate:.0f} req/min)"
        elif rate < 80:
            return 50.0, f"High request frequency ({rate:.0f} req/min - automated tool signature)"
        elif rate < 150:
            return 80.0, f"Very high request frequency ({rate:.0f} req/min - aggressive scanning)"
        else:
            return 100.0, f"Critical request burst ({rate:.0f} req/min - DoS or fuzzing flood)"

    elif category == "database_access":
        if c < 1.0:
            return round(20.0 * c, 2), f"{c:.2f} decaying database probe"
        elif c < 2.0:
            return 20.0, "1 unauthorized customer or database query attempt"
        elif c < 3.0:
            return 45.0, "2 unauthorized database query attempts (tenant data probe)"
        elif c < 5.0:
            return 75.0, f"{int(c)} unauthorized database query attempts (data exfiltration)"
        else:
            return 100.0, f"{int(c)} unauthorized database queries (critical database breach attempt)"

    return 0.0, f"Unknown category: {category}"


def detect_combined_synergies(
    active_categories: Set[str],
    category_counts: Dict[str, float],
    recent_endpoints: List[str],
) -> List[str]:
    """
    Detects specific cross-category attack patterns to establish combined behaviour severity.
    Avoids double-counting the underlying events.
    """
    synergies: List[str] = []

    # 1. Login failures + OTP failures (Account Takeover Chain)
    if "login_failures" in active_categories and "otp_failures" in active_categories:
        synergies.append("auth_takeover_chain (login + OTP bypass)")

    # 2. Admin probing + Secrets/Env probing (Infrastructure Escalation)
    if "admin_access" in active_categories and "secrets_probing" in active_categories:
        synergies.append("privilege_secrets_escalation (admin + .env probe)")

    # 3. High-frequency scanning + Endpoint enumeration (Automated Surface Fuzzing)
    if "abnormal_rate" in active_categories and "endpoint_enumeration" in active_categories:
        synergies.append("automated_recon_fuzzing (high-rate + endpoint enumeration)")

    # 4. Password reset probing + Unknown user enumeration
    if "password_reset" in active_categories and ("login_failures" in active_categories or "database_access" in active_categories):
        synergies.append("identity_harvesting (recovery abuse + credential probing)")

    # 5. Multiple sensitive endpoints accessed within a short observation window
    distinct_sensitive = set(recent_endpoints)
    if len(distinct_sensitive) >= 3:
        synergies.append(f"multi_sensitive_target_burst ({len(distinct_sensitive)} sensitive endpoints)")

    return synergies


def classify_risk_score(score: float) -> str:
    """
    Classifies a 0-100 risk score:
    - 0-29: NORMAL
    - 30-49: SUSPICIOUS
    - 50-69: HIGH_RISK
    - 70-100: LIKELY_MALICIOUS
    """
    cfg = settings.classification_thresholds
    normal_max = cfg.get("NORMAL", 29.99)
    suspicious_max = cfg.get("SUSPICIOUS", 49.99)
    high_max = cfg.get("HIGH_RISK", 69.99)

    if score <= normal_max:
        return "NORMAL"
    elif score <= suspicious_max:
        return "SUSPICIOUS"
    elif score <= high_max:
        return "HIGH_RISK"
    else:
        return "LIKELY_MALICIOUS"


def compute_behaviour_risk_score(
    events: List[ObservedBehaviourEvent],
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Deterministic calculation of 0-100 behaviour-based risk score:
    For each category:
      category_contribution = category_max_points * category_severity / 100
    Final risk score:
      risk_score = min(100.0, sum(all_category_contributions))
    Rounded to 2 decimal places.
    """
    now_utc = now or datetime.now(timezone.utc)
    point_allocations = get_configured_allocations()

    # 1. Group events by category with time-decay applied
    category_effective_counts: Dict[str, float] = {k: 0.0 for k in BEHAVIOUR_CATEGORIES}
    category_raw_counts: Dict[str, int] = {k: 0 for k in BEHAVIOUR_CATEGORIES}
    category_endpoints: Dict[str, Set[str]] = {k: set() for k in BEHAVIOUR_CATEGORIES}
    recent_requests_last_minute: int = 0
    all_recent_sensitive_endpoints: Set[str] = set()

    one_minute_ago = now_utc - timedelta(seconds=60)

    for ev in events:
        cat = ev.category
        if cat not in BEHAVIOUR_CATEGORIES:
            continue

        category_raw_counts[cat] += 1
        if ev.endpoint:
            category_endpoints[cat].add(ev.endpoint)
            all_recent_sensitive_endpoints.add(ev.endpoint)

        window_type = BEHAVIOUR_CATEGORIES[cat]["window_type"]
        window_sec = get_observation_window_seconds(window_type)
        decay = calculate_event_decay(ev.timestamp, now_utc, window_sec)
        category_effective_counts[cat] += decay

        # Check rate within 1 minute
        ev_ts = ev.timestamp if ev.timestamp.tzinfo else ev.timestamp.replace(tzinfo=timezone.utc)
        if ev_ts >= one_minute_ago:
            recent_requests_last_minute += 1

    # Populate rate metrics
    category_effective_counts["abnormal_rate"] = float(recent_requests_last_minute)

    # 2. Identify active independent categories (excluding combined_patterns)
    # A category is only active if its activity exceeds minimum threshold (e.g. >= 20 req/min for rate)
    active_independent_categories: Set[str] = set()
    for cat in BEHAVIOUR_CATEGORIES:
        if cat == "combined_patterns":
            continue
        if cat == "abnormal_rate":
            if recent_requests_last_minute >= 20:
                active_independent_categories.add(cat)
        elif category_effective_counts[cat] >= 0.5:
            active_independent_categories.add(cat)

    # 3. Detect synergies for the combined_patterns category
    synergies = detect_combined_synergies(
        active_categories=active_independent_categories,
        category_counts=category_effective_counts,
        recent_endpoints=list(all_recent_sensitive_endpoints),
    )

    # 4. Compute severity and contribution for each category
    category_breakdown: Dict[str, Any] = {}
    total_contribution = 0.0
    reason_codes: List[str] = []
    active_categories_list: List[str] = []

    for cat, meta in BEHAVIOUR_CATEGORIES.items():
        max_points = point_allocations.get(cat, meta["default_max"])
        effective_count = category_effective_counts[cat]

        extra_info: Dict[str, Any] = {}
        if cat == "endpoint_enumeration":
            extra_info["distinct_endpoints"] = len(category_endpoints[cat])
        elif cat == "abnormal_rate":
            extra_info["requests_per_minute"] = recent_requests_last_minute
        elif cat == "combined_patterns":
            extra_info["active_independent_categories"] = list(active_independent_categories)
            extra_info["synergies"] = synergies

        severity, reason = calculate_category_severity(
            category=cat,
            effective_count=effective_count,
            extra=extra_info,
        )

        contribution = round((max_points * severity) / 100.0, 2)
        total_contribution += contribution

        if contribution > 0:
            active_categories_list.append(cat)
            reason_codes.append(f"{cat.upper()}: {reason} (+{contribution:.2f} pts)")

        category_breakdown[cat] = {
            "name": meta["name"],
            "max_points": max_points,
            "severity": round(severity, 2),
            "contribution": contribution,
            "raw_count": category_raw_counts[cat],
            "effective_count": round(effective_count, 2),
            "reason": reason,
        }

    final_score = round(min(100.0, total_contribution), 2)
    classification = classify_risk_score(final_score)

    return {
        "risk_score": final_score,
        "classification": classification,
        "category_breakdown": category_breakdown,
        "active_categories": active_categories_list,
        "independent_categories_count": len(active_independent_categories),
        "reason_codes": reason_codes,
        "synergies": synergies,
        "recent_requests_last_minute": recent_requests_last_minute,
        "total_observed_events": len(events),
    }


def evaluate_routing_decision(
    risk_score: float,
    independent_categories_count: int,
    active_categories: List[str],
    is_already_diverted: bool = False,
) -> Tuple[str, str]:
    """
    Evaluates dynamic route with independent-category safeguard:
    - 0-29: real (Normal legitimate traffic)
    - 30-49: real (Enhanced monitoring)
    - 50-69: real (Additional scrutiny)
    - 70-100: decoy (High risk / Likely malicious)
      SAFEGUARD: Requires evidence from at least TWO independent behaviour categories,
      unless emergency policy is explicitly enabled.
    - If already diverted: remains isolated on decoy.
    """
    if is_already_diverted:
        return (
            "decoy",
            "Session previously diverted to isolated honeypot; real application access prohibited.",
        )

    threshold = settings.decoy_routing_threshold
    min_independent = settings.decoy_min_independent_categories
    emergency_policy = settings.emergency_single_vector_divert

    if risk_score < 30.0:
        return (
            "real",
            f"Allowed to REAL application: Low risk score {risk_score:.2f}/100 within legitimate tolerance.",
        )
    elif risk_score < 50.0:
        return (
            "real",
            f"Allowed to REAL application with enhanced monitoring: Elevated risk score {risk_score:.2f}/100.",
        )
    elif risk_score < threshold:
        return (
            "real",
            f"Allowed to REAL application with additional scrutiny: High risk score {risk_score:.2f}/100.",
        )
    else:
        # Score >= 70.0: Check independent-category safeguard!
        if independent_categories_count >= min_independent or emergency_policy:
            cats_str = ", ".join([c for c in active_categories if c != "combined_patterns"])
            return (
                "decoy",
                f"Diverted to DECOY: Threat score {risk_score:.2f}/100 confirmed by {independent_categories_count} independent categories ({cats_str}).",
            )
        else:
            cats_str = ", ".join(active_categories)
            return (
                "real",
                f"Elevated Scrutiny on REAL application: Threat score {risk_score:.2f}/100 exceeds threshold but lacks confirmation from at least {min_independent} independent categories (active: {cats_str}). Safeguard prevented false-positive decoy routing.",
            )


async def get_or_create_session_risk(
    db: AsyncSession,
    session_id: str,
    src_ip: str,
    account_email: Optional[str] = None,
    now: Optional[datetime] = None,
) -> VisitorSessionRisk:
    """Retrieves or initializes a VisitorSessionRisk record."""
    now_utc = now or datetime.now(timezone.utc)
    stmt = select(VisitorSessionRisk).where(VisitorSessionRisk.session_id == session_id)
    res = await db.execute(stmt)
    sess = res.scalar_one_or_none()

    if not sess:
        sess = VisitorSessionRisk(
            session_id=session_id,
            src_ip=src_ip,
            account_email=account_email,
            risk_score=0.0,
            previous_risk_score=0.0,
            risk_classification="NORMAL",
            category_scores={},
            active_categories=[],
            independent_categories_count=0,
            reason_codes=[],
            current_route="real",
            is_diverted=False,
            routing_transitions=[],
            request_count=1,
            first_seen=now_utc,
            last_seen=now_utc,
        )
        db.add(sess)
        await db.flush()
    else:
        sess.last_seen = now_utc
        sess.request_count += 1
        if account_email and not sess.account_email:
            sess.account_email = account_email

    return sess


async def record_behaviour_event(
    db: AsyncSession,
    session_id: str,
    src_ip: str,
    category: str,
    endpoint: str = "",
    event_type: str = "probe",
    evidence: str = "",
    account_email: Optional[str] = None,
    is_simulated: bool = False,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Ingests an observed behaviour event:
    1. Deduplicates rapid consecutive duplicate events using a temporal fingerprint.
    2. Persists the ObservedBehaviourEvent.
    3. Recomputes rolling 0-100 behaviour score with time decay.
    4. Evaluates gateway routing decision with independent-category safeguard.
    5. Records REAL -> DECOY transition if threshold is crossed.
    6. Updates Session, Account, and IP records.
    7. Broadcasts live updates over WebSockets.
    """
    now_utc = now or datetime.now(timezone.utc)

    # 1. Temporal fingerprint for deduplication
    if is_simulated:
        # Simulated events preserve unique evidence and precise timestamp for accelerated demos
        fingerprint_raw = f"{session_id}:{category}:{endpoint}:{event_type}:{evidence}:{now_utc.timestamp()}"
    else:
        # Real events use 2-second quantization for debouncing rapid duplicate requests
        time_bucket = int(now_utc.timestamp() // 2)
        fingerprint_raw = f"{session_id}:{category}:{endpoint}:{event_type}:{time_bucket}"
    fingerprint = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()

    # Check for duplicate event within debounce window
    dedup_stmt = select(ObservedBehaviourEvent).where(
        ObservedBehaviourEvent.event_fingerprint == fingerprint
    )
    dup_res = await db.execute(dedup_stmt)
    existing_event = dup_res.scalar_one_or_none()

    if not existing_event:
        # Create event
        new_event = ObservedBehaviourEvent(
            session_id=session_id,
            src_ip=src_ip,
            account_email=account_email,
            category=category,
            endpoint=endpoint,
            event_type=event_type,
            event_fingerprint=fingerprint,
            evidence=evidence,
            timestamp=now_utc,
            is_simulated=is_simulated,
        )
        db.add(new_event)
        await db.flush()

    # 2. Fetch recent events for this session across observation window (30 mins)
    cutoff = now_utc - timedelta(seconds=1800)
    events_stmt = (
        select(ObservedBehaviourEvent)
        .where(
            ObservedBehaviourEvent.session_id == session_id,
            ObservedBehaviourEvent.timestamp >= cutoff,
        )
        .order_by(ObservedBehaviourEvent.timestamp.asc())
    )
    events_res = await db.execute(events_stmt)
    session_events = list(events_res.scalars().all())

    # 3. Compute score
    calc = compute_behaviour_risk_score(session_events, now=now_utc)
    new_score = calc["risk_score"]
    new_classification = calc["classification"]

    # 4. Update session record
    sess = await get_or_create_session_risk(
        db=db,
        session_id=session_id,
        src_ip=src_ip,
        account_email=account_email,
        now=now_utc,
    )
    old_score = sess.risk_score
    old_route = sess.current_route

    sess.previous_risk_score = old_score
    sess.risk_score = new_score
    sess.risk_classification = new_classification
    sess.category_scores = calc["category_breakdown"]
    sess.active_categories = calc["active_categories"]
    sess.independent_categories_count = calc["independent_categories_count"]
    sess.reason_codes = calc["reason_codes"]
    sess.last_seen = now_utc

    # 5. Evaluate routing decision with safeguard
    new_route, route_reason = evaluate_routing_decision(
        risk_score=new_score,
        independent_categories_count=calc["independent_categories_count"],
        active_categories=calc["active_categories"],
        is_already_diverted=sess.is_diverted,
    )

    # 6. Check for REAL -> DECOY transition
    transition_record = None
    if old_route == "real" and new_route == "decoy":
        sess.is_diverted = True
        sess.diverted_at = now_utc
        sess.diversion_reason = route_reason
        sess.current_route = "decoy"

        transition_record = {
            "transition": "REAL → DECOY",
            "session_id": session_id,
            "src_ip": src_ip,
            "account_email": account_email,
            "previous_score": old_score,
            "new_score": new_score,
            "classification": new_classification,
            "independent_categories": [c for c in calc["active_categories"] if c != "combined_patterns"],
            "reason": route_reason,
            "timestamp": now_utc.isoformat(),
        }

        transitions = list(sess.routing_transitions or [])
        transitions.append(transition_record)
        sess.routing_transitions = transitions

        # Broadcast explicit transition event
        try:
            await broadcast("session_transition", transition_record)
        except Exception:
            pass

    else:
        sess.current_route = new_route

    # 7. Synchronize Account Risk History if account is known
    if account_email:
        acc_stmt = select(AccountRiskHistory).where(AccountRiskHistory.account_email == account_email)
        acc_res = await db.execute(acc_stmt)
        acc = acc_res.scalar_one_or_none()
        if not acc:
            acc = AccountRiskHistory(
                account_email=account_email,
                risk_score=new_score,
                risk_classification=new_classification,
                last_session_id=session_id,
                history_events=[{"timestamp": now_utc.isoformat(), "score": new_score, "category": category}],
                updated_at=now_utc,
            )
            db.add(acc)
        else:
            acc.risk_score = max(acc.risk_score, new_score)
            acc.risk_classification = classify_risk_score(acc.risk_score)
            acc.last_session_id = session_id
            hist = list(acc.history_events or [])
            hist.append({"timestamp": now_utc.isoformat(), "score": new_score, "category": category})
            acc.history_events = hist[-50:]
            acc.updated_at = now_utc

    # 8. Synchronize Attacker IP record
    atk_stmt = select(Attacker).where(Attacker.ip == src_ip)
    atk_res = await db.execute(atk_stmt)
    atk = atk_res.scalar_one_or_none()
    if atk:
        atk.risk_score = max(atk.risk_score or 0.0, new_score)
        atk.risk_band = new_classification.lower()
        if sess.is_diverted and atk.status != "blocked":
            atk.status = "watchlist"

    await db.flush()

    # 9. Broadcast live risk score update
    telemetry_payload = {
        "session_id": session_id,
        "src_ip": src_ip,
        "account_email": account_email,
        "current_risk_score": new_score,
        "previous_risk_score": old_score,
        "risk_classification": new_classification,
        "current_route": sess.current_route,
        "is_diverted": sess.is_diverted,
        "behaviour_category": category,
        "severity": calc["category_breakdown"][category]["severity"],
        "point_contribution": calc["category_breakdown"][category]["contribution"],
        "reason_codes": calc["reason_codes"],
        "category_breakdown": calc["category_breakdown"],
        "routing_transition": transition_record,
        "timestamp": now_utc.isoformat(),
    }

    try:
        await broadcast("risk_score_update", telemetry_payload)
    except Exception:
        pass

    return telemetry_payload
