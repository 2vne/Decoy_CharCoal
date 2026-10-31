from __future__ import annotations
import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport
import sqlalchemy as sa
from app.config import settings
from app.main import app
from app.models import Attacker, FunctionTargetEvent
from app.services.function_intelligence import (
    map_event_to_function,
    compute_bounded_function_risk,
    record_function_targeting,
    FUNCTION_METADATA,
)
from app.db import get_db, safe_migrate


class TestFunctionMapping:
    def test_explicit_target_function(self):
        res = map_event_to_function(
            event_type="api_call",
            raw={"target_function": "secrets_env"},
        )
        assert res is not None
        func, endpoint, evidence, conf, is_inf = res
        assert func == "secrets_env"
        assert conf == 1.0
        assert is_inf is False
        assert "[Observed]" in evidence

    def test_url_path_matching(self):
        res = map_event_to_function("http_request", url="/api/v1/auth/login")
        assert res is not None
        assert res[0] == "auth_login"
        assert res[3] == 0.90
        assert res[4] is False
        assert "[Observed]" in res[2]

        res = map_event_to_function("http_request", url="/api/auth/otp/verify")
        assert res is not None and res[0] == "auth_otp"

        res = map_event_to_function("http_request", url="/auth/password/reset")
        assert res is not None and res[0] == "auth_reset"

        res = map_event_to_function("http_request", url="/admin/dashboard")
        assert res is not None and res[0] == "admin_access"

        res = map_event_to_function("http_request", url="/checkout/pay/stripe")
        assert res is not None and res[0] == "payment_gateway"

        res = map_event_to_function("http_request", url="/api/v1/query/sql")
        assert res is not None and res[0] == "database_api"

        res = map_event_to_function("http_request", url="/.env")
        assert res is not None and res[0] == "secrets_env"

    def test_command_matching(self):
        res = map_event_to_function("command", command="cat .env")
        assert res is not None
        assert res[0] == "secrets_env"
        assert res[3] == 0.75
        assert res[4] is True
        assert "[Inferred]" in res[2]

        res = map_event_to_function("command", command="sudo su -")
        assert res is not None and res[0] == "admin_access"

        res = map_event_to_function("command", command="mysql -u root -p")
        assert res is not None and res[0] == "database_api"

    def test_port_matching(self):
        res = map_event_to_function("connection", dst_port=3306)
        assert res is not None
        assert res[0] == "database_api"
        assert res[3] == 0.65
        assert res[4] is True
        assert "[Inferred]" in res[2]

    def test_cowrie_ssh_port_not_mapped_to_web_login(self):
        # Crucial safety check: Cowrie SSH port 22 / login_failed MUST NOT map to web auth_login
        res = map_event_to_function("login_failed", honeypot="cowrie", dst_port=22)
        assert res is None

        res = map_event_to_function("connect", honeypot="cowrie", dst_port=2222)
        assert res is None

    def test_unmatched_fallback(self):
        res = map_event_to_function("misc", command="echo hello")
        assert res is None


class TestBoundedScoring:
    def test_empty_events(self):
        score, band, breakdown = compute_bounded_function_risk([])
        assert score == 0.0
        assert band == "low"
        assert breakdown["bounded_score"] == 0.0
        assert breakdown["risk_band"] == "low"

    def test_score_strictly_bounded_at_100(self):
        now = datetime.now(timezone.utc)
        # 50 rapid critical events that would blow past 100 in unbounded systems
        events = []
        for i in range(50):
            events.append({
                "target_function": "secrets_env" if i % 2 == 0 else "payment_gateway",
                "timestamp": now - timedelta(seconds=i),
                "attempts": 1,
            })
        score, band, breakdown = compute_bounded_function_risk(events, now=now)
        assert score <= 100.0
        assert score >= 75.0
        assert breakdown["bounded_score"] <= 100.0
        assert band == "high"

    def test_temporal_acceleration(self):
        now = datetime.now(timezone.utc)
        # 3 events in 20 seconds vs 3 events spaced across 12 minutes
        fast_events = [
            {"target_function": "auth_login", "timestamp": now - timedelta(seconds=15), "attempts": 1},
            {"target_function": "auth_otp", "timestamp": now - timedelta(seconds=10), "attempts": 1},
            {"target_function": "admin_access", "timestamp": now, "attempts": 1},
        ]
        slow_events = [
            {"target_function": "auth_login", "timestamp": now - timedelta(minutes=12), "attempts": 1},
            {"target_function": "auth_otp", "timestamp": now - timedelta(minutes=6), "attempts": 1},
            {"target_function": "admin_access", "timestamp": now, "attempts": 1},
        ]
        fast_score, _, fast_breakdown = compute_bounded_function_risk(fast_events, now=now)
        slow_score, _, slow_breakdown = compute_bounded_function_risk(slow_events, now=now)

        assert fast_score > slow_score
        assert fast_breakdown["temporal_multiplier"] > slow_breakdown["temporal_multiplier"]

    def test_sequence_synergy_detection(self):
        now = datetime.now(timezone.utc)
        synergy_events = [
            {"target_function": "auth_login", "timestamp": now - timedelta(seconds=20), "attempts": 1},
            {"target_function": "auth_otp", "timestamp": now - timedelta(seconds=10), "attempts": 1},
        ]
        non_synergy_events = [
            {"target_function": "auth_login", "timestamp": now - timedelta(seconds=20), "attempts": 1},
            {"target_function": "database_api", "timestamp": now - timedelta(seconds=10), "attempts": 1},
        ]
        _, _, syn_breakdown = compute_bounded_function_risk(synergy_events, now=now)
        _, _, non_breakdown = compute_bounded_function_risk(non_synergy_events, now=now)

        assert syn_breakdown["synergy_bonus"] > non_breakdown["synergy_bonus"]
        assert any("2FA Bypass" in syn for syn in syn_breakdown["synergies"])


@pytest.mark.asyncio
class TestFunctionIntelligenceServiceAndDB:
    async def test_record_function_targeting_observed(self, db):
        atk = Attacker(ip="198.51.100.42", risk_score=20.0, risk_band="low")
        db.add(atk)
        await db.flush()

        res = await record_function_targeting(
            db=db,
            attacker=atk,
            target_function="auth_login",
            target_endpoint="/api/v1/auth/login",
            attack_type="credential_stuffing",
            severity="medium",
            result="failed",
            attempts=5,
            honeypot_source="gateway",
            evidence="[Observed] Multiple invalid password attempts",
            confidence=0.90,
            is_simulated=False,
        )
        assert res is not None
        assert res.target_function == "auth_login"
        assert res.src_ip == "198.51.100.42"
        assert res.is_simulated is False
        assert res.confidence == 0.90

        # Check attacker update
        await db.refresh(atk)
        assert "auth_login" in atk.targeted_functions
        assert atk.function_risk_score > 0
        assert atk.function_risk_breakdown is not None
        assert "bounded_score" in atk.function_risk_breakdown

    async def test_simulated_event_does_not_pollute_real_attacker_risk_factors(self, db):
        # A real attacker exists with existing risk score
        atk = Attacker(ip="203.0.113.99", risk_score=25.0, risk_band="low", risk_factors=[])
        db.add(atk)
        await db.flush()

        # Simulate a high-impact critical attack
        res = await record_function_targeting(
            db=db,
            attacker=atk,
            target_function="secrets_env",
            target_endpoint="/.env",
            attack_type="simulated_probe",
            severity="critical",
            attempts=1,
            honeypot_source="simulation",
            evidence="[Simulated] Injected simulation test",
            confidence=1.0,
            is_simulated=True,
        )
        assert res.is_simulated is True

        await db.refresh(atk)
        # Ensure simulated attack did NOT add a 'function_targeting' factor into real risk_factors
        factors = [f.get("factor") for f in (atk.risk_factors or [])]
        assert "function_targeting" not in factors


@pytest.mark.asyncio
class TestFunctionIntelligenceAPI:
    async def test_get_functions_and_stats_public(self, db):
        async def override_get_db():
            yield db

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/intelligence/functions/stats")
            assert resp.status_code == 200
            data = resp.json()
            assert "functions" in data
            assert len(data["functions"]) == 7
            assert "observed_events_count" in data
            assert "simulated_events_count" in data

        app.dependency_overrides.clear()

    async def test_simulate_endpoint_requires_api_key(self, db):
        async def override_get_db():
            yield db

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            sim_payload = {
                "src_ip": "203.0.113.88",
                "target_function": "payment_gateway",
                "attack_type": "carding_probe",
                "target_endpoint": "/api/v1/payments/charge",
                "severity": "critical",
                "result": "blocked",
                "attempts": 3,
                "evidence": "Fake credit card test payload",
            }

            # 1. No API Key -> HTTP 401
            resp_no_auth = await client.post("/api/intelligence/functions/simulate", json=sim_payload)
            assert resp_no_auth.status_code == 401

            # 2. Invalid API Key -> HTTP 401
            resp_bad_auth = await client.post(
                "/api/intelligence/functions/simulate",
                json=sim_payload,
                headers={"X-API-Key": "wrong_key_123"},
            )
            assert resp_bad_auth.status_code == 401

            # 3. Valid API Key -> HTTP 200 & is_simulated == True
            resp_auth = await client.post(
                "/api/intelligence/functions/simulate",
                json=sim_payload,
                headers={"X-API-Key": settings.api_key},
            )
            assert resp_auth.status_code == 200
            sim_data = resp_auth.json()
            assert sim_data["target_function"] == "payment_gateway"
            assert sim_data["is_simulated"] is True

            # 4. List function events and verify is_simulated filter
            resp_list = await client.get("/api/intelligence/functions?is_simulated=true")
            assert resp_list.status_code == 200
            events_data = resp_list.json()
            assert len(events_data["events"]) >= 1
            assert events_data["events"][0]["is_simulated"] is True

        app.dependency_overrides.clear()

    async def test_safe_migrations(self, db):
        # Run safe_migrate to verify idempotency on existing connection
        await safe_migrate(db)
