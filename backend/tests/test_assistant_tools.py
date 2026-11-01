import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.db import AsyncSessionLocal, create_tables
from app.services.assistant import (
    ASSISTANT_TOOLS_SPEC,
    execute_tool,
    chat_with_assistant,
)


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await create_tables()


@pytest.mark.asyncio
async def test_assistant_tools_registered():
    """Verify all 9 read-only investigation tools are registered in specification."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/assistant/tools")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 9
        tool_names = [t["function"]["name"] for t in data["tools"]]
        assert "get_active_incidents" in tool_names
        assert "get_incident_details" in tool_names
        assert "get_visitor_session" in tool_names
        assert "get_session_event_history" in tool_names
        assert "get_gateway_status" in tool_names
        assert "get_function_intelligence" in tool_names
        assert "get_honeypot_activity" in tool_names
        assert "get_pagerduty_status" in tool_names
        assert "get_system_health" in tool_names


@pytest.mark.asyncio
async def test_tool_get_system_health():
    """Verify get_system_health executes and returns operational indicators."""
    async with AsyncSessionLocal() as db:
        res = await execute_tool("get_system_health", {}, db)
        assert "status" in res
        assert res["status"] == "operational"
        assert "open_incidents" in res
        assert "tracked_attackers" in res


@pytest.mark.asyncio
async def test_tool_get_active_incidents():
    """Verify get_active_incidents returns active incidents and PagerDuty cross-reference."""
    async with AsyncSessionLocal() as db:
        res = await execute_tool("get_active_incidents", {"limit": 5}, db)
        assert "incidents" in res
        assert "active_pagerduty_incidents" in res


@pytest.mark.asyncio
async def test_tool_get_gateway_status():
    """Verify get_gateway_status returns real vs decoy counts and monitored gateways."""
    async with AsyncSessionLocal() as db:
        res = await execute_tool("get_gateway_status", {}, db)
        assert "total_gateway_requests" in res
        assert "real_traffic_count" in res
        assert "decoy_traffic_count" in res
        assert "monitored_gateways" in res


@pytest.mark.asyncio
async def test_tool_get_function_intelligence():
    """Verify get_function_intelligence returns top targeted functions and risk weights."""
    async with AsyncSessionLocal() as db:
        res = await execute_tool("get_function_intelligence", {}, db)
        assert "top_targeted_functions" in res
        assert "all_function_stats" in res


@pytest.mark.asyncio
async def test_assistant_chat_status_inquiry():
    """Verify natural-language inquiry executes live tools without hallucinated data."""
    async with AsyncSessionLocal() as db:
        res = await chat_with_assistant("What is happening right now?", [], db)
        assert res is not None
        assert "reply" in res
        assert len(res["reply"]) > 50
        # Verify tools were executed
        executed_names = [t["tool"] for t in res["tools_executed"]]
        assert "get_system_health" in executed_names or "get_active_incidents" in executed_names
        assert res["meta"]["disclaimer"] == "AI suggestion, human review required"


@pytest.mark.asyncio
async def test_assistant_chat_dangerous_attacker_inquiry():
    """Verify assistant correctly identifies highest risk attackers."""
    async with AsyncSessionLocal() as db:
        res = await chat_with_assistant("Which attacker is the most dangerous?", [], db)
        assert res is not None
        assert "reply" in res
        assert len(res["reply"]) > 50


@pytest.mark.asyncio
async def test_assistant_security_action_confirmation():
    """Verify that action requesting a firewall block DEMANDS analyst confirmation."""
    async with AsyncSessionLocal() as db:
        res = await chat_with_assistant("Block IP 192.168.1.150", [], db)
        assert res["pending_action"] is not None
        assert res["pending_action"]["requires_confirmation"] is True
        assert res["pending_action"]["action_type"] == "block_ip"
        assert res["pending_action"]["target"] == "192.168.1.150"


@pytest.mark.asyncio
async def test_assistant_investigate_incident_correlation():
    """Verify that investigating an incident by title correlates telemetry rather than failing."""
    async with AsyncSessionLocal() as db:
        res = await chat_with_assistant("Investigate incident: CRITICAL: Function Attack - Secrets Env", [], db)
        assert res is not None
        assert "reply" in res
        reply = res["reply"]
        assert "Incident not found in database." not in reply
        assert "INCIDENT INVESTIGATION" in reply or "Executive Summary" in reply
        assert "Secrets" in reply or "secrets_env" in reply or "Target Function" in reply
        assert "Recommended Response" in reply or "Playbook Advisory" in reply


@pytest.mark.asyncio
async def test_assistant_investigate_with_live_function_telemetry():
    """Verify that live FunctionTargetEvent is correlated when investigating by function name."""
    from app.models import Attacker, FunctionTargetEvent
    import time
    test_ip = f"198.51.100.{int(time.time() * 1000) % 200 + 10}"
    async with AsyncSessionLocal() as db:
        att = Attacker(ip=test_ip, risk_score=88.0, risk_band="critical", intent="Credential Extraction")
        db.add(att)
        await db.flush()

        fte = FunctionTargetEvent(
            attacker_id=att.id,
            src_ip=test_ip,
            target_function="secrets_env",
            target_endpoint="/api/v1/secrets",
            attack_type="Sensitive Probe",
            severity="critical",
            result="intercepted",
            attempts=7,
        )
        db.add(fte)
        await db.commit()

        res = await chat_with_assistant("Investigate incident: Function Attack - Secrets Env", [], db)
        assert res is not None
        reply = res["reply"]
        assert test_ip in reply
        assert "CRITICAL" in reply
        assert "secrets_env" in reply or "Configuration & Secrets Exposure" in reply
        assert "Recommended Response" in reply
        assert "DECOY" in reply or "Decoy" in reply


@pytest.mark.asyncio
async def test_assistant_action_execution_flow():
    """Verify confirming a security action triggers authorized execution and audit trail."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Cancelled action
        cancel_resp = await client.post(
            "/api/assistant/confirm-action",
            json={
                "action_type": "reset_session",
                "payload": {"session_id": "test_sess"},
                "confirmed": False,
            },
        )
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["status"] == "cancelled"

        # 2. Confirmed session reset action
        exec_resp = await client.post(
            "/api/assistant/confirm-action",
            json={
                "action_type": "reset_session",
                "payload": {"session_id": "demo_session"},
                "confirmed": True,
            },
        )
        assert exec_resp.status_code == 200
        assert exec_resp.json()["status"] == "executed"

