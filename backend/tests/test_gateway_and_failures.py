from __future__ import annotations
import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.main import app
from app.db import get_db
from app.models import Attacker, Incident, GatewayRequestLog, GatewayIncident, CommitAttribution, FunctionTargetEvent
from app.services.gateway import extract_client_ip, evaluate_gateway_routing
from app.services.failure_intelligence import record_gateway_failure, generate_failure_investigation
from app.services.git_intelligence import get_local_git_commits, correlate_commits_for_incident, resolve_team_from_paths
from app.services.ai_investigation import run_ai_investigation


# ---------------------------------------------------------------------------
# 1. Gateway Client IP Extraction & Security
# ---------------------------------------------------------------------------

def test_extract_client_ip_direct():
    headers = {}
    ip = extract_client_ip(headers, remote_addr="198.51.100.42")
    assert ip == "198.51.100.42"


def test_extract_client_ip_untrusted_proxy():
    # Peer is a public IP (untrusted), trying to spoof X-Forwarded-For
    headers = {"x-forwarded-for": "203.0.113.19"}
    ip = extract_client_ip(headers, remote_addr="198.51.100.42")
    assert ip == "198.51.100.42", "Must not trust X-Forwarded-For from untrusted remote peer"


def test_extract_client_ip_trusted_proxy():
    # Peer is localhost / internal trusted reverse proxy
    headers = {"x-forwarded-for": "203.0.113.19, 127.0.0.1"}
    ip = extract_client_ip(headers, remote_addr="127.0.0.1")
    assert ip == "203.0.113.19", "Must trust client IP from trusted local reverse proxy"


# ---------------------------------------------------------------------------
# 2. Risk-Based Routing Evaluation Service
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_evaluate_gateway_routing_unknown_ip(db: AsyncSession):
    # Unknown IP has score 0 -> routes to real
    decision, score, reason, meta = await evaluate_gateway_routing(db, "198.51.100.99", "/api/v1/orders")
    assert decision == "real"
    assert score == 0.0


@pytest.mark.asyncio
async def test_evaluate_gateway_routing_high_risk_attacker(db: AsyncSession):
    # Create attacker with risk score 88.0
    atk = Attacker(
        ip="203.0.113.88",
        risk_score=88.0,
        risk_band="critical",
        status="active",
        total_events=12
    )
    db.add(atk)
    await db.commit()

    decision, score, reason, meta = await evaluate_gateway_routing(db, "203.0.113.88", "/api/v1/auth/login")
    assert decision == "decoy"
    assert score == 88.0
    assert "decoy" in reason.lower()


# ---------------------------------------------------------------------------
# 3. HTTP Gateway & Demo App Endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gateway_evaluate_endpoint_low_risk(db: AsyncSession):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get(
                "/api/gateway/evaluate",
                headers={"x-real-ip": "100.64.0.5", "x-original-uri": "/api/v1/dashboard"}
            )
            assert resp.status_code == 200
            assert resp.headers.get("x-sentinel-route") == "real"
            data = resp.json()
            assert data["route"] == "real"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_gateway_evaluate_endpoint_high_risk(db: AsyncSession):
    # Seed high risk attacker
    atk = Attacker(
        ip="198.51.100.77",
        risk_score=85.0,
        risk_band="critical",
        status="active",
        total_events=30
    )
    db.add(atk)
    await db.commit()

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get(
                "/api/gateway/evaluate",
                headers={"x-real-ip": "198.51.100.77", "x-original-uri": "/api/v1/admin/system"}
            )
            assert resp.status_code == 200
            assert resp.headers.get("x-sentinel-route") == "decoy"
            data = resp.json()
            assert data["route"] == "decoy"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_real_vs_decoy_demo_endpoints(db: AsyncSession):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # Real login endpoint
            real_resp = await ac.post("/demo/real/auth/login", json={"email": "analyst@sentinel.local", "password": "Password123!"})
            assert real_resp.status_code == 200
            assert "real_sess_" in real_resp.json()["session_token"]
            assert real_resp.json()["status"] == "authenticated"

            # Decoy login endpoint
            decoy_resp = await ac.post(
                "/demo/decoy/auth/login",
                json={"email": "attacker@evil.corp", "password": "wrong_password"},
                headers={"x-forwarded-for": "198.51.100.66"}
            )
            assert decoy_resp.status_code == 200
            assert "decoy_sess_" in decoy_resp.json()["session_token"]

            # Verify telemetry was recorded into FunctionTargetEvent with confidence 1.0 and is_simulated=False
            events_stmt = select(FunctionTargetEvent).where(FunctionTargetEvent.honeypot_source == "decoy_app")
            events = (await db.execute(events_stmt)).scalars().all()
            assert len(events) >= 1
            assert events[0].target_function == "auth_login"
            assert events[0].confidence == 1.0
            assert events[0].is_simulated is False
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_end_to_end_visitor_to_decoy_progression_and_reset(db: AsyncSession):
    """
    Mandatory Demonstration Verification:
    - Request 1: Normal login page -> real application.
    - Requests 2-5: Suspicious authentication attempts -> risk increases.
    - Request 6: Gateway evaluates updated risk -> decoy application.
    - Requests 7+: Decoy interactions recorded into telemetry.
    - Controlled Reset: Risk profile reset to 0 -> routes back to real application.
    """
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    test_ip = "198.51.100.222"
    proxy_headers = {"x-forwarded-for": test_ip, "x-real-ip": test_ip}

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # Request 1: Initial evaluation (unknown visitor) -> routes to Real
            eval1 = await ac.get(
                "/api/gateway/evaluate",
                headers={**proxy_headers, "x-original-uri": "/auth/login", "x-original-method": "GET"}
            )
            assert eval1.status_code == 200
            assert eval1.headers.get("x-sentinel-route") == "real"
            assert eval1.json()["route"] == "real"
            assert eval1.json()["risk_score"] == 0.0

            # Normal browsing: Valid login to real app
            real_ok = await ac.post(
                "/demo/real/auth/login",
                json={"email": "analyst@sentinel.local", "password": "Password123!"},
                headers=proxy_headers
            )
            assert real_ok.status_code == 200
            assert "real_sess_" in real_ok.json()["session_token"]

            # Requests 2-5: Suspicious authentication & admin probing
            # Request 2: Failed login attempt
            f1 = await ac.post(
                "/demo/real/auth/login",
                json={"email": "victim@sentinel.local", "password": "wrong_password_1"},
                headers=proxy_headers
            )
            assert f1.status_code == 401

            # Request 3: Second failed login attempt (temporal acceleration)
            f2 = await ac.post(
                "/demo/real/auth/login",
                json={"email": "victim@sentinel.local", "password": "wrong_password_2"},
                headers=proxy_headers
            )
            assert f2.status_code == 401

            # Request 4: Failed OTP probe (multi-vector auth synergy)
            f3 = await ac.post(
                "/demo/real/auth/otp/verify",
                json={"email": "victim@sentinel.local", "otp_code": "000000"},
                headers=proxy_headers
            )
            assert f3.status_code == 401

            # Request 5: Probing sensitive admin system endpoint
            f4 = await ac.get("/demo/real/admin/system", headers=proxy_headers)
            assert f4.status_code == 403

            # Request 6: Next request evaluated by Gateway -> Threshold breached (Score >= 71) -> DIVERT TO DECOY
            eval2 = await ac.get(
                "/api/gateway/evaluate",
                headers={**proxy_headers, "x-original-uri": "/auth/login", "x-original-method": "POST"}
            )
            assert eval2.status_code == 200
            assert eval2.headers.get("x-sentinel-route") == "decoy"
            assert eval2.json()["route"] == "decoy"
            assert eval2.json()["risk_score"] >= 71.0
            assert "decoy" in eval2.json()["reason"].lower()

            # Requests 7+: Attacker reaches Decoy application
            decoy_hit = await ac.post(
                "/demo/decoy/auth/login",
                json={"email": "target@corp.com", "password": "stolen_password"},
                headers=proxy_headers
            )
            assert decoy_hit.status_code == 200
            assert "decoy_sess_" in decoy_hit.json()["session_token"]

            # Verify decoy telemetry was captured with confidence 1.0
            decoy_ev_stmt = select(FunctionTargetEvent).where(
                FunctionTargetEvent.src_ip == test_ip,
                FunctionTargetEvent.honeypot_source == "decoy_app"
            )
            decoy_events = (await db.execute(decoy_ev_stmt)).scalars().all()
            assert len(decoy_events) >= 1
            assert decoy_events[0].target_function == "auth_login"
            assert decoy_events[0].confidence == 1.0

            # Controlled Reset: Reset visitor profile back to 0
            reset_resp = await ac.post("/api/gateway/reset_visitor", json={"src_ip": test_ip})
            assert reset_resp.status_code == 200
            assert reset_resp.json()["status"] == "reset_complete"
            assert reset_resp.json()["new_risk_score"] == 0.0

            # Post-reset verification: Next request routes back to Real
            eval_reset = await ac.get(
                "/api/gateway/evaluate",
                headers={**proxy_headers, "x-original-uri": "/auth/login", "x-original-method": "GET"}
            )
            assert eval_reset.status_code == 200
            assert eval_reset.headers.get("x-sentinel-route") == "real"
            assert eval_reset.json()["route"] == "real"
            assert eval_reset.json()["risk_score"] == 0.0
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 4. Failure Intelligence & 72-Hour Recurrence Detection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gateway_failure_recording_and_recurrence(db: AsyncSession):
    now = datetime.now(timezone.utc)
    
    # Record first failure
    inc1 = await record_gateway_failure(
        db=db,
        endpoint="/api/v1/checkout/charge",
        error_code=502,
        error_details="Bad Gateway upstream timeout",
        related_function="payment_gateway"
    )
    assert inc1.id is not None
    assert inc1.recurrence_count == 1
    assert inc1.status == "active"

    # Simulate earlier incident timestamp 24h ago with same endpoint
    inc1.first_failure_ts = now - timedelta(hours=24)
    inc1.last_failure_ts = now - timedelta(hours=24)
    await db.commit()

    # Record second failure on same endpoint within 72h window
    inc2 = await record_gateway_failure(
        db=db,
        endpoint="/api/v1/checkout/charge",
        error_code=502,
        error_details="Bad Gateway upstream reset",
        related_function="payment_gateway"
    )
    assert inc2.status == "recurring"
    assert inc2.recurrence_count == 2

    # AI Root cause investigation generator
    investigation = generate_failure_investigation(
        endpoint="/api/v1/checkout/charge",
        error_code=502,
        error_details="Bad Gateway upstream reset",
        recurrence_count=2,
        related_function="payment_gateway"
    )
    assert "observed_facts" in investigation
    assert "hypotheses" in investigation
    assert "recommended_actions" in investigation
    assert len(investigation["observed_facts"]) >= 2
    assert investigation["recommended_team"] == "payments"


# ---------------------------------------------------------------------------
# 5. Git Commit Intelligence & Team Attribution
# ---------------------------------------------------------------------------

def test_team_path_resolution():
    team_devops = resolve_team_from_paths(["backend/nginx/sentinel_gateway.conf"])
    assert team_devops == "DevOps / Infrastructure"

    team_pay = resolve_team_from_paths(["backend/app/demo_apps/checkout.py"])
    assert team_pay == "Payments"


@pytest.mark.asyncio
async def test_correlate_commits_for_incident(db: AsyncSession):
    # Test reading actual commits from local repository
    commits = get_local_git_commits(max_count=5)
    assert len(commits) > 0
    assert "commit_hash" in commits[0]
    assert "author_name" in commits[0]

    # Create dummy incident
    inc = GatewayIncident(
        incident_uuid="gw-inc-test",
        endpoint="/api/v1/auth/login",
        status="active",
        severity="high",
        error_code=503,
        first_failure_ts=datetime.now(timezone.utc),
        detection_ts=datetime.now(timezone.utc),
        last_failure_ts=datetime.now(timezone.utc),
        recurrence_count=1,
        related_function="auth_login",
    )
    db.add(inc)
    await db.commit()
    await db.refresh(inc)

    correlations = await correlate_commits_for_incident(
        db=db,
        incident_id=inc.id,
        affected_function="auth_login",
        affected_endpoint="/api/v1/auth/login"
    )
    assert isinstance(correlations, list)
    # Check that any generated lead uses objective, non-accusatory language
    for c in correlations:
        assert "lead" in c.correlation_explanation.lower() or "investigation" in c.correlation_explanation.lower()


# ---------------------------------------------------------------------------
# 6. Unified AI Investigation Integration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unified_ai_investigation(db: AsyncSession):
    # Create attacker
    atk = Attacker(
        ip="198.51.100.90",
        risk_score=92.0,
        risk_band="critical",
        status="active",
        total_events=45
    )
    db.add(atk)
    await db.commit()
    await db.refresh(atk)

    # Create incident for this attacker
    inc = Incident(
        title="Critical Automated Brute-Force",
        status="new",
        attacker_id=atk.id,
        risk_score_at_creation=92.0,
        root_cause={"factors": ["Brute force", "Command execution"]},
        blast_radius={"honeypots": ["cowrie", "opencanary"]},
    )
    db.add(inc)
    await db.commit()
    await db.refresh(inc)

    report = await run_ai_investigation(db=db, incident_id=inc.id, force_refresh=True)
    assert "executive_summary" in report
    assert "observed_facts" in report
    assert "ai_hypotheses" in report
    assert "recommended_actions" in report
    assert len(report["observed_facts"]) >= 1
    assert "what_happened" in report
    assert "why_dangerous" in report
