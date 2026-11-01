from __future__ import annotations
import asyncio
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.config import settings
from app.services.pagerduty import (
    pagerduty_manager,
    dispatch_decoy_pagerduty_alert,
    dispatch_launch_control_pagerduty_alert,
)
from app.services.function_intelligence import execute_demo_action
from app.services.behaviour_risk import evaluate_routing_decision


@pytest.fixture(autouse=True)
def clean_pagerduty_state():
    """Clear in-memory PagerDuty registry between tests."""
    pagerduty_manager.clear_incidents()
    yield
    pagerduty_manager.clear_incidents()


@pytest.mark.asyncio
async def test_01_launch_control_generates_incident():
    """Scenario 1: Launch Control activation generates an incident."""
    incident = await dispatch_launch_control_pagerduty_alert(
        scenario="credential_stuffing",
        operator="soc_analyst_1",
        launch_id="test_launch_001",
        speed=1.0,
        is_simulated=True,
    )

    assert incident is not None
    assert incident["dedup_key"] == "sentinel_launch_test_launch_001"
    assert incident["status"] == "triggered"
    assert incident["priority"] in ("P1", "P2")
    assert "[SIMULATED]" in incident["title"]
    assert incident["is_simulated"] is True
    assert incident["event_count"] == 1


@pytest.mark.asyncio
async def test_02_simulation_starts_with_simulated_metadata():
    """Scenario 2: Starting a simulation creates [SIMULATED] incident with appropriate metadata."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/simulate/start",
            json={
                "scenario": "multivector_apt",
                "speed": 1.0,
                "operator": "lead_researcher",
                "launch_id": "apt_demo_run",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "started"
        assert data["scenario"] == "multivector_apt"

    # Allow background alert task a moment to settle
    await asyncio.sleep(0.05)

    incident = pagerduty_manager.get_incident("sentinel_launch_apt_demo_run")
    assert incident is not None
    assert "[SIMULATED]" in incident["title"]
    assert incident["priority"] == "P1"  # multivector_apt maps to critical P1
    assert incident["severity"] == "critical"
    assert incident["details"]["operator"] == "lead_researcher"


@pytest.mark.asyncio
async def test_03_decoy_admin_access_creates_p2_incident():
    """Scenario 3: Decoy admin access creates a P2 (error) incident."""
    session_id = "sess_admin_probe_001"
    incident = await dispatch_decoy_pagerduty_alert(
        session_id=session_id,
        src_ip="192.168.1.100",
        endpoint="/demo/decoy/admin/users",
        method="GET",
        category="admin_access",
        is_honeytoken=False,
        sanitized_evidence="Unauthorized probe to fake admin console",
    )

    assert incident is not None
    assert incident["dedup_key"] == f"sentinel_decoy_{session_id}"
    assert incident["priority"] == "P2"
    assert incident["severity"] == "error"
    assert incident["status"] == "triggered"
    assert "Admin" in incident["title"] or "HIGH" in incident["title"]


@pytest.mark.asyncio
async def test_04_decoy_payment_manipulation_creates_p1_incident():
    """Scenario 4: Decoy payment manipulation creates a P1 (critical) incident."""
    session_id = "sess_payment_probe_002"
    incident = await dispatch_decoy_pagerduty_alert(
        session_id=session_id,
        src_ip="192.168.1.105",
        endpoint="/demo/decoy/checkout/charge",
        method="POST",
        category="payment_tamper",
        is_honeytoken=False,
        sanitized_evidence="Tampered order amount to 0.00",
    )

    assert incident is not None
    assert incident["dedup_key"] == f"sentinel_decoy_{session_id}"
    assert incident["priority"] == "P1"
    assert incident["severity"] == "critical"
    assert "CRITICAL" in incident["title"]


@pytest.mark.asyncio
async def test_05_decoy_honeytoken_access_creates_p1_incident():
    """Scenario 5: Decoy honeytoken access (.env, secrets) creates a P1 (critical) incident."""
    session_id = "sess_honeytoken_003"
    incident = await dispatch_decoy_pagerduty_alert(
        session_id=session_id,
        src_ip="192.168.1.110",
        endpoint="/demo/decoy/.env",
        method="GET",
        category="secrets_env",
        is_honeytoken=True,
        sanitized_evidence="Access to fake production environment credentials",
    )

    assert incident is not None
    assert incident["dedup_key"] == f"sentinel_decoy_{session_id}"
    assert incident["priority"] == "P1"
    assert incident["severity"] == "critical"
    assert incident["details"]["is_honeytoken"] is True


@pytest.mark.asyncio
async def test_06_repeated_requests_update_incident_without_flooding():
    """Scenario 6: Repeated requests for the same session update the existing incident with the same dedup_key."""
    session_id = "sess_repeat_probe_004"
    endpoints = [
        "/demo/decoy/login",
        "/demo/decoy/login",
        "/demo/decoy/otp",
        "/demo/decoy/otp",
        "/demo/decoy/dashboard",
    ]

    for ep in endpoints:
        await dispatch_decoy_pagerduty_alert(
            session_id=session_id,
            src_ip="192.168.1.120",
            endpoint=ep,
            method="POST" if "login" in ep or "otp" in ep else "GET",
            category="auth_login" if "login" in ep else ("auth_otp" if "otp" in ep else "reconnaissance"),
        )

    all_incidents = pagerduty_manager.get_all_incidents()
    # Exactly one ticket for this session, no duplicate spam tickets
    matching = [i for i in all_incidents if i["dedup_key"] == f"sentinel_decoy_{session_id}"]
    assert len(matching) == 1

    single_incident = matching[0]
    assert single_incident["event_count"] == 5
    assert len(single_incident["history"]) == 5
    assert single_incident["status"] == "triggered"


@pytest.mark.asyncio
async def test_07_independent_sessions_create_separate_incidents():
    """Scenario 7: Independent sessions create separate incidents with distinct dedup_keys."""
    sess_a = "sess_attacker_alpha"
    sess_b = "sess_attacker_beta"

    inc_a = await dispatch_decoy_pagerduty_alert(
        session_id=sess_a,
        src_ip="10.0.0.1",
        endpoint="/demo/decoy/admin",
        method="GET",
        category="admin_access",
    )
    inc_b = await dispatch_decoy_pagerduty_alert(
        session_id=sess_b,
        src_ip="10.0.0.2",
        endpoint="/demo/decoy/checkout",
        method="POST",
        category="payment_tamper",
    )

    assert inc_a["dedup_key"] != inc_b["dedup_key"]
    assert inc_a["dedup_key"] == f"sentinel_decoy_{sess_a}"
    assert inc_b["dedup_key"] == f"sentinel_decoy_{sess_b}"

    all_incidents = pagerduty_manager.get_all_incidents()
    keys = {i["dedup_key"] for i in all_incidents}
    assert f"sentinel_decoy_{sess_a}" in keys
    assert f"sentinel_decoy_{sess_b}" in keys


@pytest.mark.asyncio
async def test_08_severity_escalates_when_threat_deepens():
    """Scenario 8: Severity escalates when threat deepens under the same dedup_key."""
    session_id = "sess_escalation_008"

    # Step 1: Initial reconnaissance (P3 warning)
    inc_step1 = await dispatch_decoy_pagerduty_alert(
        session_id=session_id,
        src_ip="172.16.0.50",
        endpoint="/demo/decoy/about",
        method="GET",
        category="reconnaissance",
    )
    assert inc_step1["priority"] == "P3"
    assert inc_step1["severity"] == "warning"

    # Step 2: Escalates to admin probe (P2 error)
    inc_step2 = await dispatch_decoy_pagerduty_alert(
        session_id=session_id,
        src_ip="172.16.0.50",
        endpoint="/demo/decoy/admin",
        method="GET",
        category="admin_access",
    )
    assert inc_step2["priority"] == "P2"
    assert inc_step2["severity"] == "error"
    assert inc_step2["event_count"] == 2

    # Step 3: Escalates to honeytoken breach (P1 critical)
    inc_step3 = await dispatch_decoy_pagerduty_alert(
        session_id=session_id,
        src_ip="172.16.0.50",
        endpoint="/demo/decoy/.env",
        method="GET",
        category="secrets_env",
        is_honeytoken=True,
    )
    assert inc_step3["priority"] == "P1"
    assert inc_step3["severity"] == "critical"
    assert inc_step3["event_count"] == 3
    assert len(inc_step3["history"]) == 3


@pytest.mark.asyncio
async def test_09_safe_fallback_when_api_unreachable_or_key_unset():
    """Scenario 9: Safe fallback and retry when PagerDuty API is unreachable or routing key is unset."""
    # Temporarily ensure routing key is empty
    orig_key = settings.pagerduty_routing_key
    try:
        settings.pagerduty_routing_key = ""
        dedup_key = "sentinel_test_fallback_009"
        incident = await pagerduty_manager.trigger_or_update_incident(
            dedup_key=dedup_key,
            summary="Testing safe local fallback",
            severity="warning",
            source="test_fallback",
        )

        assert incident is not None
        assert incident["delivery_status"] == "simulated"
        assert incident["status"] == "triggered"

        # Test Acknowledge API
        ack = await pagerduty_manager.acknowledge_incident(dedup_key, ack_by="test_operator")
        assert ack["status"] == "acknowledged"

        # Test Resolve API
        resolved = await pagerduty_manager.resolve_incident(dedup_key, resolved_by="test_operator")
        assert resolved["status"] == "resolved"
    finally:
        settings.pagerduty_routing_key = orig_key


@pytest.mark.asyncio
async def test_10_gateway_and_function_intelligence_unaffected(db: AsyncSession):
    """Scenario 10: Existing gateway and Function Intelligence remain completely unaffected."""
    # 1. Gateway route evaluation
    target_route, reason = evaluate_routing_decision(
        risk_score=85.0,
        independent_categories_count=2,
        active_categories=["unauthorized_admin", "secrets_access"],
        is_already_diverted=False,
    )
    assert target_route in ("real", "decoy")
    assert reason is not None

    # 2. Function Intelligence demo action execution
    fi_res = await execute_demo_action(
        db=db,
        action="normal",
        session_id="sess_fi_compat_check",
        target_function="auth_login",
    )
    assert fi_res["status"] == "success"
    assert fi_res["is_simulated"] is True
