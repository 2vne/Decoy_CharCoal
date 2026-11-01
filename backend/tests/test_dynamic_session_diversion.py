from __future__ import annotations
import pytest
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.main import app
from app.db import get_db
from app.models import VisitorSessionRisk, FunctionTargetEvent, ObservedBehaviourEvent
from app.config import settings
from app.demo_apps.real_app import REVOKED_TOKENS, REVOKED_SESSIONS, ACTIVE_REAL_SESSIONS


@pytest.fixture(autouse=True)
def clean_in_memory_state():
    REVOKED_TOKENS.clear()
    REVOKED_SESSIONS.clear()
    ACTIVE_REAL_SESSIONS.clear()
    yield
    REVOKED_TOKENS.clear()
    REVOKED_SESSIONS.clear()
    ACTIVE_REAL_SESSIONS.clear()


@pytest.mark.asyncio
async def test_1_normal_browsing_remains_real(db: AsyncSession):
    """1. Normal browsing remains on REAL application."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Legitimate visitor browses dashboard
        headers = {"X-Real-IP": "198.51.100.11", "X-Session-ID": "sess_alice_norm_01"}
        res = await client.get("/demo/real/user/dashboard", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["environment"] == "real_workload"

        # Gateway evaluate also confirms route is REAL with 0 risk
        eval_res = await client.get("/api/gateway/evaluate", headers={"X-Real-IP": "198.51.100.11", "X-Session-ID": "sess_alice_norm_01"})
        assert eval_res.status_code == 200
        assert eval_res.headers.get("X-Sentinel-Route") == "real"
        assert float(eval_res.headers.get("X-Sentinel-Risk", "0")) == 0.0


@pytest.mark.asyncio
async def test_2_one_incorrect_password_does_not_divert(db: AsyncSession):
    """2. One incorrect password does not automatically divert."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Real-IP": "198.51.100.22", "X-Session-ID": "sess_bob_typo_02"}
        payload = {"email": "analyst@sentinel.local", "password": "TypoWrongPassword!"}
        res = await client.post("/demo/real/auth/login", json=payload, headers=headers)
        assert res.status_code == 401
        assert "Invalid email or password" in res.json()["detail"]

        # Gateway routing must remain REAL (risk is low, well below threshold 70)
        eval_res = await client.get("/api/gateway/evaluate", headers=headers)
        assert eval_res.status_code == 200
        assert eval_res.headers.get("X-Sentinel-Route") == "real"
        risk = float(eval_res.headers.get("X-Sentinel-Risk", "0"))
        assert 0.0 < risk < 30.0, f"Single typo should increase risk slightly but remain < 30 (got {risk})"


@pytest.mark.asyncio
async def test_3_repeated_login_attempts_increase_risk(db: AsyncSession):
    """3. Repeated login attempts increase risk score."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Real-IP": "198.51.100.33", "X-Session-ID": "sess_charlie_brute_03"}
        for i in range(4):
            await client.post(
                "/demo/real/auth/login",
                json={"email": "analyst@sentinel.local", "password": f"WrongAttempt{i}!"},
                headers=headers,
            )

        sess_stmt = select(VisitorSessionRisk).where(VisitorSessionRisk.session_id == "sess_charlie_brute_03")
        res = await db.execute(sess_stmt)
        sess = res.scalar_one_or_none()
        assert sess is not None
        assert sess.risk_score > 0.0
        assert "login_failures" in sess.active_categories
        assert sess.category_scores["login_failures"]["contribution"] > 0


@pytest.mark.asyncio
async def test_4_env_access_blocked_and_triggers_critical_diversion(db: AsyncSession):
    """4. .env access is blocked and triggers the configured critical-event policy."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Real-IP": "198.51.100.44", "X-Session-ID": "sess_attacker_env_04"}
        res = await client.get("/demo/real/.env", headers=headers)
        # Blocked server-side! Does NOT expose .env
        assert res.status_code == 403
        assert res.headers.get("X-Sentinel-Route") == "decoy"
        assert res.headers.get("X-Sentinel-Diverted") == "true"
        assert "DATABASE_URL" not in res.text

        # Verify session is marked diverted in database
        sess_stmt = select(VisitorSessionRisk).where(VisitorSessionRisk.session_id == "sess_attacker_env_04")
        sess_res = await db.execute(sess_stmt)
        sess = sess_res.scalar_one_or_none()
        assert sess is not None
        assert sess.is_diverted is True
        assert sess.current_route == "decoy"
        assert sess.diverted_at is not None
        assert "critical security violation" in sess.diversion_reason.lower() or "direct request for production .env" in sess.diversion_reason.lower()


@pytest.mark.asyncio
async def test_5_git_probing_blocked_and_triggers_critical_diversion(db: AsyncSession):
    """5. .git probing is blocked and triggers configured policy."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Real-IP": "198.51.100.55", "X-Session-ID": "sess_attacker_git_05"}
        res = await client.get("/demo/real/.git/config", headers=headers)
        assert res.status_code == 403
        assert res.headers.get("X-Sentinel-Route") == "decoy"
        assert res.headers.get("X-Sentinel-Diverted") == "true"

        # Gateway evaluate also immediately returns decoy
        eval_res = await client.get("/api/gateway/evaluate", headers=headers)
        assert eval_res.headers.get("X-Sentinel-Route") == "decoy"


@pytest.mark.asyncio
async def test_6_unauthorized_payment_manipulation_rejected_before_diversion(db: AsyncSession):
    """6. Unauthorized payment authorization manipulation is rejected before diversion."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Real-IP": "198.51.100.66", "X-Session-ID": "sess_payer_tamper_06"}
        tampered_charge = {
            "customer_id": "cust_101",
            "amount": -500.0,  # Negative manipulation
            "token": "tok_tampered_exploit_9918",
        }
        res = await client.post("/demo/real/checkout/charge", json=tampered_charge, headers=headers)
        # REJECTED FIRST: No real payment processed!
        assert res.status_code == 400
        assert "Transaction rejected" in res.json()["detail"]
        assert res.headers.get("X-Sentinel-Route") == "decoy"

        # Session is now diverted
        sess_stmt = select(VisitorSessionRisk).where(VisitorSessionRisk.session_id == "sess_payer_tamper_06")
        sess_res = await db.execute(sess_stmt)
        sess = sess_res.scalar_one_or_none()
        assert sess.is_diverted is True
        assert sess.current_route == "decoy"


@pytest.mark.asyncio
async def test_7_real_customer_database_access_protected(db: AsyncSession):
    """7. Real customer/database access remains protected."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Real-IP": "198.51.100.77", "X-Session-ID": "sess_unauth_db_07"}
        # Unauthenticated query for production customer records
        res = await client.get("/demo/real/customers", headers=headers)
        assert res.status_code == 401
        assert "Unauthorized" in res.json()["detail"]
        assert res.headers.get("X-Sentinel-Route") == "decoy"

        # Direct database dump probe is also blocked
        res2 = await client.get("/demo/real/db/dump", headers=headers)
        assert res2.status_code == 403


@pytest.mark.asyncio
async def test_8_diverted_session_cannot_access_real_apis_using_old_tokens(db: AsyncSession):
    """8. A diverted session cannot access real APIs using old tokens."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Real-IP": "198.51.100.88", "X-Session-ID": "sess_token_revoked_08"}

        # 1. First authenticate legitimately and obtain real session token
        login_res = await client.post(
            "/demo/real/auth/login",
            json={"email": "analyst@sentinel.local", "password": "Password123!"},
            headers=headers,
        )
        assert login_res.status_code == 200
        old_token = login_res.json()["session_token"]
        assert old_token.startswith("real_sess_")

        # 2. Attacker then performs a malicious operation (.env probe)
        probe_res = await client.get("/demo/real/.env", headers=headers)
        assert probe_res.status_code == 403

        # 3. Attacker attempts to use old token on real customer endpoint
        auth_headers = {
            "X-Real-IP": "198.51.100.88",
            "X-Session-ID": "sess_token_revoked_08",
            "Authorization": f"Bearer {old_token}",
        }
        res = await client.get("/demo/real/customers", headers=auth_headers)
        # MUST BE PROHIBITED (403 Forbidden)
        assert res.status_code == 403
        assert "Forbidden" in res.json()["detail"]
        assert res.headers.get("X-Sentinel-Route") == "decoy"


@pytest.mark.asyncio
async def test_9_diverted_session_cannot_manually_return_to_real(db: AsyncSession):
    """9. A diverted session cannot manually return to REAL through frontend manipulation, headers, or URLs."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Real-IP": "198.51.100.99", "X-Session-ID": "sess_locked_decoy_09"}

        # Trigger diversion via .git probing
        await client.get("/demo/real/.git", headers=headers)

        # Attacker tries to bypass by sending fake headers claiming they are real
        spoofed_headers = {
            "X-Real-IP": "198.51.100.99",
            "X-Session-ID": "sess_locked_decoy_09",
            "X-Sentinel-Route": "real",
            "X-Override-Route": "real",
        }
        eval_res = await client.get("/api/gateway/evaluate", headers=spoofed_headers)
        assert eval_res.status_code == 200
        assert eval_res.headers.get("X-Sentinel-Route") == "decoy"
        assert eval_res.json()["route"] == "decoy"

        # Direct calls to /demo/real/* remain blocked
        real_res = await client.get("/demo/real/user/dashboard", headers=spoofed_headers)
        assert real_res.status_code == 403


@pytest.mark.asyncio
async def test_10_decoy_interactions_generate_telemetry(db: AsyncSession):
    """10. Decoy interactions generate telemetry."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Real-IP": "198.51.100.100", "X-Session-ID": "sess_decoy_telem_10"}

        # Attacker interacts with decoy app endpoints
        res_env = await client.get("/demo/decoy/.env", headers=headers)
        assert res_env.status_code == 200
        assert "SENTINEL DECOY CANARY ENVIRONMENT" in res_env.text

        res_charge = await client.post(
            "/demo/decoy/checkout/charge",
            json={"customer_id": "canary_901", "amount": 100.0, "token": "tok_decoy_trap_01"},
            headers=headers,
        )
        assert res_charge.status_code == 200
        assert res_charge.json()["decoy_watermark"] == "SEC-HONEYNET-TRACE-491"

        # Verify telemetry in FunctionTargetEvent table
        stmt = select(FunctionTargetEvent).where(
            FunctionTargetEvent.src_ip == "198.51.100.100",
            FunctionTargetEvent.honeypot_source == "decoy_app",
        )
        events_res = await db.execute(stmt)
        events = events_res.scalars().all()
        assert len(events) >= 2
        functions = [e.target_function for e in events]
        assert "secrets_env" in functions
        assert "payment_gateway" in functions


@pytest.mark.asyncio
async def test_11_soc_receives_session_transition_immediately(db: AsyncSession):
    """11. SOC receives session transition immediately with rich metadata."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Real-IP": "198.51.100.111", "X-Session-ID": "sess_soc_stream_11"}

        # Ingest behaviour event for payment manipulation
        ev_payload = {
            "session_id": "sess_soc_stream_11",
            "src_ip": "198.51.100.111",
            "category": "combined_patterns",
            "endpoint": "/demo/real/checkout/charge",
            "event_type": "payment_manipulation",
            "evidence": "[Blocked] Payment authorization manipulation detected",
        }
        res = await client.post("/api/gateway/behaviour_event", json=ev_payload)
        assert res.status_code == 200
        data = res.json()
        assert data["is_diverted"] is True
        assert data["current_route"] == "decoy"
        assert data["routing_transition"] is not None
        tr = data["routing_transition"]
        assert tr["transition"] == "REAL → DECOY"
        assert tr["triggering_event"] == "payment_manipulation"
        assert tr["severity"] == "critical"
        assert tr["is_critical_divert"] is True

        # Query session via SOC session API
        sess_res = await client.get("/api/gateway/session/sess_soc_stream_11")
        assert sess_res.status_code == 200
        sess_data = sess_res.json()
        assert sess_data["is_diverted"] is True
        assert len(sess_data["routing_transitions"]) >= 1


@pytest.mark.asyncio
async def test_12_authorized_soc_reset_clears_diversion_cleanly(db: AsyncSession):
    """Bonus: Authorized SOC reset allows controlled re-testing without polluting telemetry."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Real-IP": "198.51.100.122", "X-Session-ID": "sess_reset_test_12"}

        # Divert session
        await client.get("/demo/real/.env", headers=headers)
        eval_before = await client.get("/api/gateway/evaluate", headers=headers)
        assert eval_before.headers.get("X-Sentinel-Route") == "decoy"

        # Authorized reset
        reset_res = await client.post("/api/gateway/reset_session", json={"session_id": "sess_reset_test_12"})
        assert reset_res.status_code == 200

        # After reset: Next request routes to REAL
        eval_after = await client.get("/api/gateway/evaluate", headers=headers)
        assert eval_after.headers.get("X-Sentinel-Route") == "real"
        assert float(eval_after.headers.get("X-Sentinel-Risk", "0")) == 0.0

