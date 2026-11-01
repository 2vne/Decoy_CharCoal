from __future__ import annotations
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app


# The 5 Hackathon Live Scenarios exactly as defined in GatewayPage.jsx
SCENARIOS = {
    "normal_visitor": {
        "sessionId": "demo_sess_normal_alice",
        "ip": "198.51.100.12",
        "account": "alice@legitimate-corp.com",
        "steps": [
            {"category": "abnormal_rate", "endpoint": "/", "eventType": "page_view", "evidence": "Normal landing page request"},
            {"category": "endpoint_enumeration", "endpoint": "/api/products/catalog", "eventType": "api_read", "evidence": "Catalog pagination"},
            {"category": "login_failures", "endpoint": "/api/auth/login", "eventType": "auth_success", "evidence": "Alice logged in successfully"},
            {"category": "database_access", "endpoint": "/api/user/dashboard", "eventType": "normal_access", "evidence": "Authorized profile access"},
        ],
        "expected_route": "real",
        "expected_diverted": False,
    },
    "brute_force": {
        "sessionId": "demo_sess_bruteforce_bob",
        "ip": "198.51.100.45",
        "account": "target_admin@sentinel.io",
        "steps": [
            {"category": "login_failures", "endpoint": "/api/auth/login", "eventType": "auth_failure", "evidence": "Attempt 1"},
            {"category": "login_failures", "endpoint": "/api/auth/login", "eventType": "auth_failure", "evidence": "Attempt 2"},
            {"category": "login_failures", "endpoint": "/api/auth/login", "eventType": "auth_failure", "evidence": "Attempt 3"},
            {"category": "login_failures", "endpoint": "/api/auth/login", "eventType": "auth_failure", "evidence": "Attempt 4"},
            {"category": "login_failures", "endpoint": "/api/auth/login", "eventType": "auth_failure", "evidence": "Attempt 5"},
            {"category": "login_failures", "endpoint": "/api/auth/login", "eventType": "auth_failure", "evidence": "Attempt 10"},
        ],
        # Single vector only (login_failures max 12 pts) -> never diverted to decoy
        "expected_route": "real",
        "expected_diverted": False,
        "max_score": 12.0,
    },
    "otp_guessing": {
        "sessionId": "demo_sess_otp_guess",
        "ip": "198.51.100.78",
        "account": "vip_user@enterprise.org",
        "steps": [
            {"category": "otp_failures", "endpoint": "/api/auth/verify-otp", "eventType": "auth_failure", "evidence": "Invalid OTP 1"},
            {"category": "otp_failures", "endpoint": "/api/auth/verify-otp", "eventType": "auth_failure", "evidence": "Invalid OTP 2"},
            {"category": "otp_failures", "endpoint": "/api/auth/verify-otp", "eventType": "auth_failure", "evidence": "Invalid OTP 3"},
            {"category": "otp_failures", "endpoint": "/api/auth/verify-otp", "eventType": "auth_failure", "evidence": "Invalid OTP 4"},
        ],
        # Single vector (otp_failures max 8 pts) -> stays real
        "expected_route": "real",
        "expected_diverted": False,
        "max_score": 8.0,
    },
    "recon_probing": {
        "sessionId": "demo_sess_recon_probe",
        "ip": "198.51.100.110",
        "account": "recon_crawler@attacker.net",
        "steps": [
            {"category": "endpoint_enumeration", "endpoint": "/api/swagger.json", "eventType": "probe", "evidence": "Swagger probe"},
            {"category": "endpoint_enumeration", "endpoint": "/actuator/env", "eventType": "probe", "evidence": "Actuator probe"},
            {"category": "admin_access", "endpoint": "/wp-admin/login.php", "eventType": "probe", "evidence": "WP admin probe"},
            {"category": "admin_access", "endpoint": "/admin/system/console", "eventType": "probe", "evidence": "Console probe"},
            {"category": "secrets_probing", "endpoint": "/.env", "eventType": "secrets_probe", "evidence": ".env file probe"},
            {"category": "endpoint_enumeration", "endpoint": "/api/internal/dump", "eventType": "probe", "evidence": "Internal API crawl"},
        ],
    },
    "multivector_apt": {
        "sessionId": "demo_sess_multivector_apt",
        "ip": "198.51.100.222",
        "account": "apt_attacker@shadow-syndicate.org",
        "steps": [
            {"category": "endpoint_enumeration", "endpoint": "/api/v1/swagger", "eventType": "probe", "evidence": "Step 1: API specification scraping"},
            {"category": "login_failures", "endpoint": "/api/auth/login", "eventType": "auth_failure", "evidence": "Step 2: Dictionary password attack"},
            {"category": "otp_failures", "endpoint": "/api/auth/mfa", "eventType": "auth_failure", "evidence": "Step 3: Automated OTP token guessing"},
            {"category": "endpoint_enumeration", "endpoint": "/actuator/metrics", "eventType": "probe", "evidence": "Step 4: Metrics enumeration"},
            {"category": "admin_access", "endpoint": "/admin/system/console", "eventType": "probe", "evidence": "Step 5: Admin privilege escalation attempt"},
            {"category": "abnormal_rate", "endpoint": "/api/scan/batch", "eventType": "rate_spike", "evidence": "Step 6: Burst scanning frequency"},
            {"category": "secrets_probing", "endpoint": "/.env", "eventType": "secrets_probe", "evidence": "Step 7: Production secrets probe"},
            {"category": "database_access", "endpoint": "/api/customers/export", "eventType": "data_access", "evidence": "Step 8: Database dump IDOR attempt"},
        ],
        "expected_route": "decoy",
        "expected_diverted": True,
    },
}


@pytest.mark.asyncio
async def test_scenario_01_normal_visitor():
    """Scenario 1: Normal visitor generates benign telemetry and remains on REAL route."""
    sc = SCENARIOS["normal_visitor"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Reset session
        await client.post("/api/gateway/reset_session", json={"session_id": sc["sessionId"]})

        # Submit all steps sequentially
        for step in sc["steps"]:
            resp = await client.post(
                "/api/gateway/behaviour_event",
                json={
                    "session_id": sc["sessionId"],
                    "src_ip": sc["ip"],
                    "account_email": sc["account"],
                    "category": step["category"],
                    "endpoint": step["endpoint"],
                    "event_type": step["eventType"],
                    "evidence": step["evidence"],
                    "is_simulated": True,
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["current_route"] == "real"
            assert data["is_diverted"] is False


@pytest.mark.asyncio
async def test_scenario_02_brute_force_single_vector_safeguard():
    """Scenario 2: Brute force login attack hits max points (12.0) but remains on REAL because safeguard requires >= 2 categories."""
    sc = SCENARIOS["brute_force"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/gateway/reset_session", json={"session_id": sc["sessionId"]})

        last_resp = None
        for step in sc["steps"]:
            resp = await client.post(
                "/api/gateway/behaviour_event",
                json={
                    "session_id": sc["sessionId"],
                    "src_ip": sc["ip"],
                    "account_email": sc["account"],
                    "category": step["category"],
                    "endpoint": step["endpoint"],
                    "event_type": step["eventType"],
                    "evidence": step["evidence"],
                    "is_simulated": True,
                },
            )
            assert resp.status_code == 200
            last_resp = resp.json()

        assert last_resp is not None
        assert last_resp["current_route"] == "real"
        assert last_resp["is_diverted"] is False
        assert last_resp["current_risk_score"] <= sc["max_score"]


@pytest.mark.asyncio
async def test_scenario_03_otp_guessing_single_vector():
    """Scenario 3: OTP guessing attack caps at category maximum (8.0 pts) and stays on REAL."""
    sc = SCENARIOS["otp_guessing"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/gateway/reset_session", json={"session_id": sc["sessionId"]})

        last_resp = None
        for step in sc["steps"]:
            resp = await client.post(
                "/api/gateway/behaviour_event",
                json={
                    "session_id": sc["sessionId"],
                    "src_ip": sc["ip"],
                    "account_email": sc["account"],
                    "category": step["category"],
                    "endpoint": step["endpoint"],
                    "event_type": step["eventType"],
                    "evidence": step["evidence"],
                    "is_simulated": True,
                },
            )
            assert resp.status_code == 200
            last_resp = resp.json()

        assert last_resp is not None
        assert last_resp["current_route"] == "real"
        assert last_resp["is_diverted"] is False
        assert last_resp["current_risk_score"] <= sc["max_score"]


@pytest.mark.asyncio
async def test_scenario_04_recon_probing_escalation():
    """Scenario 4: Reconnaissance and probing escalates score across multiple categories."""
    sc = SCENARIOS["recon_probing"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/gateway/reset_session", json={"session_id": sc["sessionId"]})

        scores = []
        for step in sc["steps"]:
            resp = await client.post(
                "/api/gateway/behaviour_event",
                json={
                    "session_id": sc["sessionId"],
                    "src_ip": sc["ip"],
                    "account_email": sc["account"],
                    "category": step["category"],
                    "endpoint": step["endpoint"],
                    "event_type": step["eventType"],
                    "evidence": step["evidence"],
                    "is_simulated": True,
                },
            )
            assert resp.status_code == 200
            scores.append(resp.json()["current_risk_score"])

        # Score should monotonically escalate as more categories are hit
        assert scores[-1] > scores[0]


@pytest.mark.asyncio
async def test_scenario_05_multivector_apt_triggers_decoy_diversion():
    """Scenario 5: Multi-Vector APT triggers dynamic diversion from REAL to DECOY."""
    sc = SCENARIOS["multivector_apt"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/gateway/reset_session", json={"session_id": sc["sessionId"]})

        diversion_observed = False
        final_route = "real"

        for step in sc["steps"]:
            resp = await client.post(
                "/api/gateway/behaviour_event",
                json={
                    "session_id": sc["sessionId"],
                    "src_ip": sc["ip"],
                    "account_email": sc["account"],
                    "category": step["category"],
                    "endpoint": step["endpoint"],
                    "event_type": step["eventType"],
                    "evidence": step["evidence"],
                    "is_simulated": True,
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            if data["is_diverted"] or data["current_route"] == "decoy":
                diversion_observed = True
                final_route = data["current_route"]

        assert diversion_observed is True
        assert final_route == "decoy"
