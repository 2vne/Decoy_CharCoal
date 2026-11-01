from __future__ import annotations
import asyncio
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.main import app
from app.db import get_db, AsyncSessionLocal
from app.models import Attacker, FunctionTargetEvent
from app.services.function_intelligence import (
    execute_demo_action,
    execute_demo_recon_sequence,
    stop_demo_simulation,
    reset_demo_session,
    get_demo_status,
    DEMO_ATTACKER_IP,
    DEMO_DEFAULT_SESSION,
)


@pytest.mark.asyncio
async def test_01_normal_function_access(db: AsyncSession):
    """Verify Normal Function Access produces an authorized, low-risk simulated event."""
    session_id = "test_fn_demo_normal"
    res = await execute_demo_action(
        db=db,
        action="normal",
        session_id=session_id,
        target_function="auth_login",
    )

    assert res["status"] == "success"
    assert res["action"] == "normal"
    assert res["session_id"] == session_id
    assert res["target_function"] == "auth_login"
    assert res["attempts"] == 1
    assert res["severity"] == "low"
    assert res["result"] == "authorized"
    assert res["is_simulated"] is True
    assert res["function_risk_score"] <= 25.0


@pytest.mark.asyncio
async def test_02_repeated_function_access_increments_attempts(db: AsyncSession):
    """Verify Repeated Function Access increments consecutive attempts for the same function."""
    session_id = "test_fn_demo_repeated"

    # First burst
    res1 = await execute_demo_action(
        db=db,
        action="repeated",
        session_id=session_id,
        target_function="auth_login",
    )
    attempts_1 = res1["attempts"]
    assert attempts_1 >= 2
    assert res1["result"] == "rate_limited"
    assert res1["is_simulated"] is True

    # Second burst should increment attempts
    res2 = await execute_demo_action(
        db=db,
        action="repeated",
        session_id=session_id,
        target_function="auth_login",
    )
    attempts_2 = res2["attempts"]
    assert attempts_2 > attempts_1, f"Attempts did not increment: {attempts_1} -> {attempts_2}"


@pytest.mark.asyncio
async def test_03_sensitive_function_probing(db: AsyncSession):
    """Verify Sensitive Function Probing triggers high severity and targets .env / secrets."""
    session_id = "test_fn_demo_sensitive"
    res = await execute_demo_action(
        db=db,
        action="sensitive_probe",
        session_id=session_id,
        target_function="secrets_env",
    )

    assert res["status"] == "success"
    assert res["action"] == "sensitive_probe"
    assert res["target_function"] == "secrets_env"
    assert res["severity"] == "critical"
    assert res["result"] == "blocked"
    assert res["is_simulated"] is True
    # Base weight for secrets_env is 30, so function risk score should reflect high impact
    assert res["function_risk_score"] >= 30.0


@pytest.mark.asyncio
async def test_04_multi_function_recon_and_synergies():
    """Verify Multi-Function Reconnaissance initiates 4 distinct function steps with synergies."""
    session_id = "test_fn_demo_recon"

    # Reset any previous state for this test session
    async with AsyncSessionLocal() as session:
        await reset_demo_session(db=session, session_id=session_id)

    res = await execute_demo_recon_sequence(session_id=session_id)
    assert res["status"] == "started"
    assert res["action"] == "multi_recon"
    assert res["steps_count"] == 4

    # Wait for sequence to complete
    await asyncio.sleep(1.5)

    # Verify events created in DB
    stmt = (
        select(FunctionTargetEvent)
        .where(
            FunctionTargetEvent.session_id == session_id,
            FunctionTargetEvent.is_simulated.is_(True),
        )
        .order_by(FunctionTargetEvent.timestamp.asc())
    )
    async with AsyncSessionLocal() as session:
        events_res = await session.execute(stmt)
        events = list(events_res.scalars().all())

    assert len(events) >= 3, f"Expected at least 3 events in recon sequence, got {len(events)}"
    functions_targeted = {e.target_function for e in events}
    assert "auth_login" in functions_targeted
    assert "auth_otp" in functions_targeted


@pytest.mark.asyncio
async def test_05_stop_simulation():
    """Verify Stop Simulation cancels the active background sequence."""
    session_id = "test_fn_demo_stop"
    await execute_demo_recon_sequence(session_id=session_id)

    stop_res = stop_demo_simulation(session_id=session_id)
    assert stop_res["status"] == "stopped"
    assert stop_res["session_id"] == session_id


@pytest.mark.asyncio
async def test_06_reset_isolated_demo_session(db: AsyncSession):
    """Verify Reset Demo Session purges only synthetic events and preserves genuine telemetry."""
    session_id = "test_fn_demo_reset"

    # 1. Create a genuine observed event (is_simulated = False)
    stmt_atk = select(Attacker).where(Attacker.ip == "203.0.113.88")
    atk_res = await db.execute(stmt_atk)
    real_atk = atk_res.scalar_one_or_none()
    if not real_atk:
        real_atk = Attacker(
            ip="203.0.113.88",
            status="active",
            risk_score=50.0,
            risk_band="medium",
        )
        db.add(real_atk)
        await db.flush()

    real_event = FunctionTargetEvent(
        attacker_id=real_atk.id,
        src_ip=real_atk.ip,
        target_function="auth_login",
        target_endpoint="/api/v1/auth/login",
        attack_type="observed_probe",
        severity="medium",
        result="failed",
        attempts=1,
        is_simulated=False,
    )
    db.add(real_event)
    await db.commit()
    real_event_id = real_event.id

    # 2. Create simulated demo event
    await execute_demo_action(
        db=db,
        action="sensitive_probe",
        session_id=session_id,
        target_function="secrets_env",
    )

    # 3. Reset demo session
    reset_res = await reset_demo_session(db=db, session_id=session_id)
    assert reset_res["status"] == "reset_complete"
    assert reset_res["cleared_events"] >= 1
    assert reset_res["function_risk_score"] == 0.0

    # 4. Verify genuine observed event is completely intact!
    chk_real = await db.get(FunctionTargetEvent, real_event_id)
    assert chk_real is not None, "Real observed event was incorrectly deleted during demo reset!"
    assert chk_real.is_simulated is False


@pytest.mark.asyncio
async def test_07_api_demo_endpoints(db: AsyncSession):
    """Verify HTTP API endpoints for manual demo controls."""
    async def _independent_session():
        async with AsyncSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _independent_session
    transport = ASGITransport(app=app)
    session_id = "test_fn_demo_api"

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Action Normal
        res_norm = await client.post(
            "/api/intelligence/functions/demo/action",
            json={"action": "normal", "target_function": "auth_login", "session_id": session_id},
        )
        assert res_norm.status_code == 200
        assert res_norm.json()["action"] == "normal"

        # 2. Action Repeated
        res_rep = await client.post(
            "/api/intelligence/functions/demo/action",
            json={"action": "repeated", "target_function": "auth_otp", "session_id": session_id},
        )
        assert res_rep.status_code == 200
        assert res_rep.json()["attempts"] >= 2

        # 3. Action Sensitive
        res_sens = await client.post(
            "/api/intelligence/functions/demo/action",
            json={"action": "sensitive_probe", "target_function": "secrets_env", "session_id": session_id},
        )
        assert res_sens.status_code == 200
        assert res_sens.json()["severity"] == "critical"

        # 4. Status
        res_stat = await client.get(
            f"/api/intelligence/functions/demo/status?session_id={session_id}"
        )
        assert res_stat.status_code == 200
        assert res_stat.json()["session_id"] == session_id

        # 5. Stop
        res_stop = await client.post(
            "/api/intelligence/functions/demo/stop",
            json={"session_id": session_id},
        )
        assert res_stop.status_code == 200
        assert res_stop.json()["status"] == "stopped"

        # 6. Reset
        res_reset = await client.post(
            "/api/intelligence/functions/demo/reset",
            json={"session_id": session_id},
        )
        assert res_reset.status_code == 200
        assert res_reset.json()["status"] == "reset_complete"
