from __future__ import annotations
from datetime import datetime, timezone, timedelta
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.db import get_db
from app.models import (
    Attacker,
    VisitorSessionRisk,
    ObservedBehaviourEvent,
    AccountRiskHistory,
)
from app.services.behaviour_risk import (
    compute_behaviour_risk_score,
    calculate_category_severity,
    calculate_event_decay,
    evaluate_routing_decision,
    classify_risk_score,
    record_behaviour_event,
    get_configured_allocations,
    BEHAVIOUR_CATEGORIES,
)
from app.services.gateway import evaluate_gateway_routing


# ---------------------------------------------------------------------------
# Test 1: No suspicious activity produces a score of zero
# ---------------------------------------------------------------------------
def test_no_suspicious_activity_produces_zero():
    calc = compute_behaviour_risk_score([])
    assert calc["risk_score"] == 0.0
    assert calc["classification"] == "NORMAL"
    assert calc["active_categories"] == []
    assert calc["independent_categories_count"] == 0


# ---------------------------------------------------------------------------
# Test 2: One failed login produces only a small contribution
# ---------------------------------------------------------------------------
def test_one_failed_login_small_contribution():
    now = datetime.now(timezone.utc)
    ev = ObservedBehaviourEvent(
        session_id="test_sess_1",
        src_ip="192.0.2.1",
        category="login_failures",
        endpoint="/auth/login",
        event_type="credential_failure",
        timestamp=now,
    )
    calc = compute_behaviour_risk_score([ev], now=now)
    # Max points = 12. 1 failure = severity 5. Contribution = 12 * 5 / 100 = 0.60
    assert calc["risk_score"] == 0.60
    assert calc["classification"] == "NORMAL"
    assert "login_failures" in calc["active_categories"]
    assert calc["category_breakdown"]["login_failures"]["contribution"] == 0.60


# ---------------------------------------------------------------------------
# Test 3: Repeated login failures increase severity according to configuration
# ---------------------------------------------------------------------------
def test_repeated_login_failures_severity_mapping():
    now = datetime.now(timezone.utc)
    # 0 failures = 0
    sev0, _ = calculate_category_severity("login_failures", 0.0)
    assert sev0 == 0.0

    # 1 failure = 5 (points: 0.60)
    sev1, _ = calculate_category_severity("login_failures", 1.0)
    assert sev1 == 5.0

    # 2 failures = 15 (points: 1.80)
    sev2, _ = calculate_category_severity("login_failures", 2.0)
    assert sev2 == 15.0

    # 3-4 failures = 35 (points: 4.20)
    sev3, _ = calculate_category_severity("login_failures", 3.0)
    assert sev3 == 35.0
    sev4, _ = calculate_category_severity("login_failures", 4.0)
    assert sev4 == 35.0

    # 5-7 failures = 65 (points: 7.80)
    sev5, _ = calculate_category_severity("login_failures", 5.0)
    assert sev5 == 65.0

    # 8+ failures = 100 (points: 12.00, maximum allocated)
    sev8, _ = calculate_category_severity("login_failures", 8.0)
    assert sev8 == 100.0


# ---------------------------------------------------------------------------
# Test 4: OTP failures increase the correct category
# ---------------------------------------------------------------------------
def test_otp_failures_increase_correct_category():
    now = datetime.now(timezone.utc)
    evs = [
        ObservedBehaviourEvent(
            session_id="test_sess_otp",
            src_ip="192.0.2.2",
            category="otp_failures",
            endpoint="/auth/otp/verify",
            timestamp=now,
        )
        for _ in range(3)
    ]
    calc = compute_behaviour_risk_score(evs, now=now)
    # 3 OTP failures: max points = 8, severity = 60, contribution = 8 * 60 / 100 = 4.80
    assert calc["category_breakdown"]["otp_failures"]["contribution"] == 4.80
    assert calc["category_breakdown"]["login_failures"]["contribution"] == 0.0
    assert "otp_failures" in calc["active_categories"]


# ---------------------------------------------------------------------------
# Test 5: Source/configuration probing increases the correct category
# ---------------------------------------------------------------------------
def test_source_config_probing_increases_correct_category():
    now = datetime.now(timezone.utc)
    ev1 = ObservedBehaviourEvent(
        session_id="test_sess_env",
        src_ip="192.0.2.3",
        category="secrets_probing",
        endpoint="/.env",
        timestamp=now,
    )
    calc1 = compute_behaviour_risk_score([ev1], now=now)
    # 1 probe: max points = 20, severity = 25, contribution = 20 * 25 / 100 = 5.00
    assert calc1["category_breakdown"]["secrets_probing"]["contribution"] == 5.00

    ev2 = ObservedBehaviourEvent(
        session_id="test_sess_env",
        src_ip="192.0.2.3",
        category="secrets_probing",
        endpoint="/.git/config",
        timestamp=now,
    )
    calc2 = compute_behaviour_risk_score([ev1, ev2], now=now)
    # 2 probes: severity = 50, contribution = 20 * 50 / 100 = 10.00
    assert calc2["category_breakdown"]["secrets_probing"]["contribution"] == 10.00


# ---------------------------------------------------------------------------
# Test 6: Multiple categories combine correctly
# ---------------------------------------------------------------------------
def test_multiple_categories_combine_correctly():
    now = datetime.now(timezone.utc)
    evs = []
    # 2 login failures -> contribution = 12 * 15 / 100 = 1.80
    for _ in range(2):
        evs.append(ObservedBehaviourEvent(session_id="comb", src_ip="1.1.1.1", category="login_failures", timestamp=now))
    # 1 OTP failure -> contribution = 8 * 10 / 100 = 0.80
    evs.append(ObservedBehaviourEvent(session_id="comb", src_ip="1.1.1.1", category="otp_failures", timestamp=now))
    # 1 admin access probe -> contribution = 15 * 20 / 100 = 3.00
    evs.append(ObservedBehaviourEvent(session_id="comb", src_ip="1.1.1.1", category="admin_access", timestamp=now))
    # Combined synergy between login + OTP (auth takeover) -> severity 70, contribution = 5 * 70 / 100 = 3.50
    calc = compute_behaviour_risk_score(evs, now=now)

    expected = round(1.80 + 0.80 + 3.00 + 3.50, 2)
    assert calc["risk_score"] == expected
    assert calc["independent_categories_count"] == 3
    assert len(calc["synergies"]) >= 1


# ---------------------------------------------------------------------------
# Test 7: The total score never exceeds 100
# ---------------------------------------------------------------------------
def test_total_score_never_exceeds_100():
    now = datetime.now(timezone.utc)
    evs = []
    # Flood each of the 8 behaviour categories with 25 events each (total 175 events > 150 req/min)
    for cat in [
        "login_failures",
        "otp_failures",
        "password_reset",
        "admin_access",
        "secrets_probing",
        "endpoint_enumeration",
        "database_access",
    ]:
        for i in range(25):
            evs.append(ObservedBehaviourEvent(
                session_id="flood",
                src_ip="2.2.2.2",
                category=cat,
                endpoint=f"/endpoint_{cat}_{i}",
                timestamp=now,
            ))

    calc = compute_behaviour_risk_score(evs, now=now)
    assert calc["risk_score"] == 100.00
    assert calc["risk_score"] <= 100.00
    assert calc["classification"] == "LIKELY_MALICIOUS"


# ---------------------------------------------------------------------------
# Test 8: Score decay operates correctly
# ---------------------------------------------------------------------------
def test_score_decay_operates_correctly():
    now = datetime.now(timezone.utc)
    window_sec = 600  # 10 minutes

    # Recent event (0 minutes ago) -> decay factor = 1.0
    decay_recent = calculate_event_decay(now, now, window_sec)
    assert decay_recent == 1.0

    # Event 15 minutes ago (1.5x window) -> decayed between 0.25 and 1.0
    t_15m = now - timedelta(minutes=15)
    decay_15m = calculate_event_decay(t_15m, now, window_sec)
    assert 0.25 <= decay_15m < 1.0

    # Event 35 minutes ago -> decayed to <= 0.25
    t_35m = now - timedelta(minutes=35)
    decay_35m = calculate_event_decay(t_35m, now, window_sec)
    assert decay_35m <= 0.25

    # Verify score with decayed events is lower than with recent events
    ev_old = ObservedBehaviourEvent(
        session_id="decay_test",
        src_ip="3.3.3.3",
        category="secrets_probing",
        timestamp=now - timedelta(minutes=25),
    )
    ev_fresh = ObservedBehaviourEvent(
        session_id="decay_test",
        src_ip="3.3.3.3",
        category="secrets_probing",
        timestamp=now,
    )
    score_old = compute_behaviour_risk_score([ev_old], now=now)["risk_score"]
    score_fresh = compute_behaviour_risk_score([ev_fresh], now=now)["risk_score"]
    assert score_old < score_fresh


# ---------------------------------------------------------------------------
# Test 9: Duplicate events do not inflate scores
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_duplicate_events_do_not_inflate_scores(db: AsyncSession):
    now = datetime.now(timezone.utc)
    sess_id = "dedup_session_test"
    ip = "198.51.100.44"

    # Ingest event 1
    res1 = await record_behaviour_event(
        db=db,
        session_id=sess_id,
        src_ip=ip,
        category="login_failures",
        endpoint="/auth/login",
        event_type="fail",
        now=now,
    )
    score1 = res1["current_risk_score"]

    # Ingest identical event within same 2-second temporal fingerprint bucket
    res2 = await record_behaviour_event(
        db=db,
        session_id=sess_id,
        src_ip=ip,
        category="login_failures",
        endpoint="/auth/login",
        event_type="fail",
        now=now,
    )
    score2 = res2["current_risk_score"]

    assert score1 == score2
    # Verify only 1 event recorded in DB
    ev_stmt = select(ObservedBehaviourEvent).where(ObservedBehaviourEvent.session_id == sess_id)
    evs = (await db.execute(ev_stmt)).scalars().all()
    assert len(evs) == 1


# ---------------------------------------------------------------------------
# Test 10: A score below 70 does not trigger normal automatic decoy routing
# ---------------------------------------------------------------------------
def test_score_below_70_does_not_trigger_decoy_routing():
    # Score 25 (Normal) -> route 'real'
    route1, _ = evaluate_routing_decision(25.0, 2, ["login_failures", "otp_failures"])
    assert route1 == "real"

    # Score 45 (Suspicious) -> route 'real' with enhanced monitoring
    route2, _ = evaluate_routing_decision(45.0, 2, ["login_failures", "otp_failures"])
    assert route2 == "real"

    # Score 65 (High Risk) -> route 'real' with scrutiny, not decoy
    route3, _ = evaluate_routing_decision(65.0, 2, ["login_failures", "otp_failures"])
    assert route3 == "real"


# ---------------------------------------------------------------------------
# Test 11: A score of 70 or higher with at least two independent categories triggers decoy routing
# ---------------------------------------------------------------------------
def test_score_70_or_higher_with_two_categories_triggers_decoy():
    # Score 75 with 2 independent categories -> routes to 'decoy'
    route, reason = evaluate_routing_decision(
        risk_score=75.0,
        independent_categories_count=2,
        active_categories=["login_failures", "secrets_probing"],
    )
    assert route == "decoy"
    assert "Diverted to DECOY" in reason

    # Safeguard check: Score 75 with only 1 category -> routes to 'real'
    safeguard_route, safeguard_reason = evaluate_routing_decision(
        risk_score=75.0,
        independent_categories_count=1,
        active_categories=["secrets_probing"],
    )
    assert safeguard_route == "real"
    assert "Safeguard prevented false-positive" in safeguard_reason


# ---------------------------------------------------------------------------
# Test 12: One ordinary event cannot independently classify a session as malicious
# ---------------------------------------------------------------------------
def test_one_ordinary_event_cannot_independently_classify_malicious():
    now = datetime.now(timezone.utc)
    # 1 failed login
    ev1 = ObservedBehaviourEvent(session_id="ord", src_ip="4.4.4.4", category="login_failures", timestamp=now)
    c1 = compute_behaviour_risk_score([ev1], now=now)
    assert c1["classification"] != "LIKELY_MALICIOUS"
    assert c1["classification"] == "NORMAL"

    # 1 OTP challenge failure
    ev2 = ObservedBehaviourEvent(session_id="ord2", src_ip="4.4.4.4", category="otp_failures", timestamp=now)
    c2 = compute_behaviour_risk_score([ev2], now=now)
    assert c2["classification"] != "LIKELY_MALICIOUS"
    assert c2["classification"] == "NORMAL"

    # 1 unverified password reset
    ev3 = ObservedBehaviourEvent(session_id="ord3", src_ip="4.4.4.4", category="password_reset", timestamp=now)
    c3 = compute_behaviour_risk_score([ev3], now=now)
    assert c3["classification"] != "LIKELY_MALICIOUS"
    assert c3["classification"] == "NORMAL"


# ---------------------------------------------------------------------------
# Test 13: The old real session cannot access real endpoints after a transition
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_old_real_session_cannot_access_real_endpoints_after_transition(db: AsyncSession):
    test_ip = "198.51.100.89"
    sess_id = f"sess_{test_ip.replace(':', '_')}"

    # Create diverted session record
    sess = VisitorSessionRisk(
        session_id=sess_id,
        src_ip=test_ip,
        risk_score=85.0,
        risk_classification="LIKELY_MALICIOUS",
        current_route="decoy",
        is_diverted=True,
        diverted_at=datetime.now(timezone.utc),
        diversion_reason="Automated test diversion",
    )
    db.add(sess)
    await db.commit()

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            headers = {
                "x-forwarded-for": test_ip,
                "x-real-ip": test_ip,
                "x-session-id": sess_id,
            }
            # Attempt to access real protected dashboard with diverted session
            resp = await ac.get("/demo/real/user/dashboard", headers=headers)
            assert resp.status_code == 403
            assert "diverted to isolated honeypot environment" in resp.json()["detail"].lower()
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Test 14: The decoy session remains isolated
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_decoy_session_remains_isolated(db: AsyncSession):
    test_ip = "198.51.100.90"
    sess_id = f"sess_{test_ip.replace(':', '_')}"

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            headers = {
                "x-forwarded-for": test_ip,
                "x-real-ip": test_ip,
                "x-session-id": sess_id,
            }
            # Access decoy dashboard -> Returns fake synthetic data successfully
            resp = await ac.get("/demo/decoy/user/dashboard", headers=headers)
            assert resp.status_code == 200
            json_data = resp.json()
            assert json_data["environment"] == "cloud_infrastructure"
            assert "CANARY" in str(json_data) or "active_tenants" in json_data

            # Access decoy canary customers
            cust_resp = await ac.get("/demo/decoy/customers", headers=headers)
            assert cust_resp.status_code == 200
            assert "canary_901" in str(cust_resp.json())
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Test 15: Existing telemetry and SOC dashboard functionality continue working
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_telemetry_and_soc_dashboard_integration(db: AsyncSession):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # 1. Test Gateway stats endpoint
            stats_resp = await ac.get("/api/gateway/stats")
            assert stats_resp.status_code == 200
            stats = stats_resp.json()
            assert "point_allocations" in stats
            assert "routing_policy" in stats
            assert "gateway_status" in stats

            # 2. Ingest behaviour event via API
            event_payload = {
                "session_id": "soc_test_sess",
                "src_ip": "198.51.100.99",
                "category": "secrets_probing",
                "endpoint": "/.env",
                "event_type": "secrets_probe",
                "evidence": "Direct probe for .env file",
            }
            ev_resp = await ac.post("/api/gateway/behaviour_event", json=event_payload)
            assert ev_resp.status_code == 200
            ev_data = ev_resp.json()
            assert ev_data["current_risk_score"] == 5.00  # 1 probe: 20 * 25 / 100
            assert ev_data["risk_classification"] == "NORMAL"

            # 3. Retrieve session risk inspection
            sess_resp = await ac.get("/api/gateway/session/soc_test_sess")
            assert sess_resp.status_code == 200
            sess_data = sess_resp.json()
            assert sess_data["risk_score"] == 5.00
            assert sess_data["category_scores"]["secrets_probing"]["contribution"] == 5.00

            # 4. List all active visitor sessions
            list_resp = await ac.get("/api/gateway/sessions")
            assert list_resp.status_code == 200
            assert list_resp.json()["total"] >= 1
    finally:
        app.dependency_overrides.clear()
