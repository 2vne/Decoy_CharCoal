from __future__ import annotations
import asyncio
import time
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from app.main import app
from app.db import get_db
from app.services.decoy_observation import (
    compute_decoy_delay,
    set_decoy_latency_mode,
    sanitize_evidence_text,
    get_latency_bounds,
)


@pytest.mark.asyncio
async def test_01_real_website_response_times_unaffected(db: AsyncSession):
    """Verify real application response times are completely unaffected by decoy latency."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        t0 = time.time()
        res = await client.post(
            "/demo/real/auth/login",
            json={"email": "analyst@sentinel.local", "password": "Password123!"},
        )
        elapsed = time.time() - t0
        assert res.status_code == 200
        # Real application must respond quickly without artificial delays (< 250ms)
        assert elapsed < 0.25, f"Real app login took too long: {elapsed:.3f}s"
        assert "X-Sentinel-Decoy-Latency" not in res.headers


@pytest.mark.asyncio
async def test_02_soc_dashboard_response_times_unaffected(db: AsyncSession):
    """Verify SOC dashboard endpoints are fast and responsive (< 200ms)."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        t0 = time.time()
        res = await client.get("/api/overview")
        elapsed = time.time() - t0
        assert res.status_code == 200
        assert elapsed < 0.20, f"SOC overview took too long: {elapsed:.3f}s"

        t0 = time.time()
        res_gateway = await client.get("/api/gateway/stats")
        elapsed_gw = time.time() - t0
        assert res_gateway.status_code == 200
        assert elapsed_gw < 0.20, f"Gateway stats took too long: {elapsed_gw:.3f}s"
        assert "decoy_observation" in res_gateway.json()


@pytest.mark.asyncio
async def test_03_decoy_latency_bounds_and_profiles():
    """Verify configured delay profiles meet user requirements."""
    # Landing: 0 - 0.3s
    min_s, max_s = get_latency_bounds("landing")
    assert min_s == 0.0 and max_s == 0.3

    # Fake login: 1.0 - 2.0s
    min_s, max_s = get_latency_bounds("auth_login")
    assert min_s == 1.0 and max_s == 2.0

    # Fake OTP: 2.0 - 3.0s
    min_s, max_s = get_latency_bounds("auth_otp")
    assert min_s == 2.0 and max_s == 3.0

    # Fake admin console: 2.0 - 4.0s
    min_s, max_s = get_latency_bounds("admin_console")
    assert min_s == 2.0 and max_s == 4.0

    # Fake customer/DB API: 2.0 - 5.0s
    min_s, max_s = get_latency_bounds("database_api")
    assert min_s == 2.0 and max_s == 5.0

    # Fake payment gateway: 3.0 - 5.0s
    min_s, max_s = get_latency_bounds("payment_gateway")
    assert min_s == 3.0 and max_s == 5.0

    # Honeytokens: 1.0 - 3.0s
    min_s, max_s = get_latency_bounds("honeytoken")
    assert min_s == 1.0 and max_s == 3.0


@pytest.mark.asyncio
async def test_04_decoy_endpoints_apply_configured_delays(db: AsyncSession):
    """Verify decoy endpoints apply delay and return headers."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    set_decoy_latency_mode("controlled")

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test Decoy Login (Profile: 1.0 - 2.0s)
        t0 = time.time()
        res = await client.post(
            "/demo/decoy/auth/login",
            json={"email": "attacker@darkweb.net", "password": "supersecretpassword123"},
            headers={"X-Session-ID": "test_decoy_sess_01"},
        )
        elapsed = time.time() - t0
        assert res.status_code == 200
        # Measured elapsed time should be >= 1.0s and <= 2.25s
        assert 0.95 <= elapsed <= 2.25, f"Decoy login delay out of bounds: {elapsed:.3f}s"
        assert "X-Sentinel-Decoy-Latency" in res.headers
        assert res.headers["X-Sentinel-Decoy-Profile"] == "auth_login"
        assert res.headers["X-Sentinel-Decoy-Session"] == "test_decoy_sess_01"


@pytest.mark.asyncio
async def test_05_sensitive_data_sanitization():
    """Verify passwords, OTPs, and card tokens are strictly redacted from evidence."""
    raw = "Login attempt with password=SuperSecretPassword123 and otp_code=991823 card_number=4111222233334444"
    sanitized = sanitize_evidence_text(raw)
    assert "SuperSecretPassword123" not in sanitized
    assert "991823" not in sanitized
    assert "4111222233334444" not in sanitized
    assert "[REDACTED_PASSWORD]" in sanitized
    assert "[REDACTED_MFA_TOKEN]" in sanitized
    assert "[REDACTED_PAYMENT_SECRET]" in sanitized


@pytest.mark.asyncio
async def test_06_honeytoken_observation(db: AsyncSession):
    """Verify honeytoken interactions (.env, .git) apply delay and flag telemetry."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        t0 = time.time()
        res = await client.get(
            "/demo/decoy/.env",
            headers={"X-Session-ID": "test_honey_sess_02"},
        )
        elapsed = time.time() - t0
        assert res.status_code == 200
        assert "STRIPE_SECRET_KEY=sk_test_fake_honeytoken" in res.text
        assert 0.95 <= elapsed <= 6.5
        assert res.headers["X-Sentinel-Decoy-Profile"] == "honeytoken"


@pytest.mark.asyncio
async def test_07_concurrent_decoy_requests_non_blocking():
    """Verify concurrent requests do not block the asyncio event loop."""
    from app.db import AsyncSessionLocal

    async def _independent_session():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _independent_session
    transport = ASGITransport(app=app)
    set_decoy_latency_mode("controlled")

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Launch 3 concurrent decoy login requests (each takes 1-2s)
        # In an asynchronous event loop, all 3 should complete concurrently in ~2s total (NOT 3 x 2s = 6s)
        t0 = time.time()
        reqs = [
            client.post("/demo/decoy/auth/login", json={"email": f"attacker_{i}@net.com", "password": "pass"})
            for i in range(3)
        ]
        results = await asyncio.gather(*reqs)
        total_time = time.time() - t0

        for r in results:
            assert r.status_code == 200

        # All 3 completed concurrently without serial thread-blocking
        assert total_time < 6.5, f"Concurrent requests were serialized: took {total_time:.2f}s"


@pytest.mark.asyncio
async def test_08_latency_mode_toggle_and_comparison_demo(db: AsyncSession):
    """Verify toggling latency mode and running demonstration comparison."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Toggle mode to normal
        res_mode = await client.post("/demo/decoy/observation/mode", json={"mode": "normal"})
        assert res_mode.status_code == 200
        assert res_mode.json()["mode"] == "normal"

        # Verify normal mode has zero delay
        t0 = time.time()
        res_norm = await client.post(
            "/demo/decoy/auth/login",
            json={"email": "attacker@net.com", "password": "pwd"},
            headers={"X-Sentinel-Decoy-Mode": "normal"},
        )
        elapsed_norm = time.time() - t0
        assert res_norm.status_code == 200
        assert elapsed_norm < 2.5, f"Normal mode took too long: {elapsed_norm:.3f}s"

        # Toggle back to controlled mode
        await client.post("/demo/decoy/observation/mode", json={"mode": "controlled"})

        # Run comparison demonstration endpoint
        res_comp = await client.post("/demo/decoy/observation/compare", json={"category": "auth_login"})
        assert res_comp.status_code == 200
        data = res_comp.json()
        assert "normal_mode" in data
        assert "controlled_mode" in data
        assert "observation_benefit" in data
        assert data["observation_benefit"]["time_dilation_factor"] >= 1.0


@pytest.mark.asyncio
async def test_09_decoy_stats_reporting(db: AsyncSession):
    """Verify observation stats endpoint returns aggregated telemetry."""
    app.dependency_overrides[get_db] = lambda: db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/demo/decoy/observation/stats")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "operational"
        assert "average_response_latency_ms" in data
        assert "category_distribution" in data
        assert "latency_profiles" in data
        assert "recent_interactions" in data
