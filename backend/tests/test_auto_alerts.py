"""
Tests for autonomous alert dispatching pipeline.
Verifies that attacks on functions and routes automatically trigger alerts
without any manual button interaction.
"""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db import get_db
from app.services.pagerduty import pagerduty_manager
from app.services.alert_dispatcher import trigger_autonomous_attack_alert


@pytest.mark.asyncio
async def test_autonomous_alert_dispatcher():
    """Verify that trigger_autonomous_attack_alert creates an incident and executes."""
    pagerduty_manager.clear_incidents()

    await trigger_autonomous_attack_alert(
        src_ip="203.0.113.199",
        target_function="secrets_env",
        target_endpoint="/demo/real/.env",
        attack_type="secrets_exfiltration",
        severity="critical",
        score=85.0,
        evidence="Direct unauthorized download attempt for .env",
        is_simulated=False,
        session_id="test_auto_alert_session_99",
        is_critical=True,
    )

    incidents = pagerduty_manager.get_all_incidents()
    assert len(incidents) >= 1
    inc = incidents[0]
    assert "test_auto_alert_session_99" in inc["dedup_key"]
    assert inc["priority"] == "P1"
    assert inc["severity"] == "critical"
    assert inc["status"] == "triggered"
    assert inc["history"][0]["details"]["target_function"] == "secrets_env"
