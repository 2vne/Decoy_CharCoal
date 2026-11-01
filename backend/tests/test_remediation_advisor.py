from __future__ import annotations
from datetime import datetime, timezone, timedelta
import pytest
import pytest_asyncio
from app.config import settings
from app.models import Gateway, AdvisoryStepStatus, Incident
from app.services.playbook_loader import (
    load_playbooks,
    get_all_playbooks,
    match_playbooks,
    PlaybookModel,
)
from app.services.remediation import (
    generate_template_advisory,
    generate_remediation_advisory,
    mask_secrets,
    DISCLAIMER_TEXT,
    MANDATORY_CAVEATS,
)
from app.services.gateway_lifecycle import (
    is_in_watch_mode,
    check_gateway_reattack,
    on_gateway_attack,
    check_safe_to_reopen,
)
from app.services.behaviour_risk import evaluate_routing_decision


def test_playbook_loader_and_schema():
    """Validates that all playbooks in YAML load and conform to Pydantic schema."""
    playbooks = load_playbooks()
    assert len(playbooks) >= 11, f"Expected at least 11 playbooks, found {len(playbooks)}"

    required_ids = [
        "pb_credential_stuffing",
        "pb_secrets_exposure",
        "pb_payment_gateway_attack",
        "pb_admin_panel",
        "pb_api_abuse",
        "pb_data_exfil",
        "pb_malware_ingress",
        "pb_persistence",
        "pb_lateral_movement",
        "pb_recon_scan",
        "pb_reattack_after_restore",
    ]
    for pb_id in required_ids:
        assert pb_id in playbooks, f"Missing required playbook: {pb_id}"
        pb = playbooks[pb_id]
        assert isinstance(pb, PlaybookModel)
        assert pb.title
        assert pb.severity in ["critical", "high", "medium", "low"]
        assert len(pb.immediate_actions) > 0
        assert len(pb.before_reopening) > 0
        assert len(pb.references) > 0


def test_trigger_matching():
    """Tests multi-vector trigger matching: category, MITRE technique, and reattack flag."""
    # 1. Payment gateway trigger
    matched = match_playbooks(categories=["payment_gateway"])
    matched_ids = [p.id for p in matched]
    assert "pb_payment_gateway_attack" in matched_ids

    # 2. Credential stuffing via MITRE T1110
    matched_mitre = match_playbooks(mitre_techniques=["T1110"])
    assert "pb_credential_stuffing" in [p.id for p in matched_mitre]

    # 3. Special re-attack trigger
    matched_reattack = match_playbooks(categories=["payment_gateway"], is_reattack=True)
    reattack_ids = [p.id for p in matched_reattack]
    assert "pb_reattack_after_restore" in reattack_ids
    assert reattack_ids[0] == "pb_reattack_after_restore", "Reattack playbook should be ranked first"


def test_template_advisory_shape():
    """Validates that template advisory strictly conforms to all required keys and constraints."""
    playbooks = get_all_playbooks()
    sample_pbs = [playbooks["pb_payment_gateway_attack"], playbooks["pb_reattack_after_restore"]]
    adv = generate_template_advisory(
        matched_playbooks=sample_pbs,
        attacker_ip="198.51.100.42",
        risk_score=85.0,
        is_reattack=True,
        evidence_table={"payment_gateway": ["ev_101", "ev_102"]},
        suggested_owner="Last modified by: Alice (alice@example.com)",
        gateway_name="Payment Gateway",
    )

    # Assert required top-level keys
    required_keys = [
        "disclaimer", "likely_causes", "immediate_actions", "before_reopening",
        "staged_reopen_plan", "monitoring_after_restore", "long_term_fixes",
        "reattack_risk", "confidence", "caveats", "suggested_owner"
    ]
    for k in required_keys:
        assert k in adv, f"Missing required key in advisory: {k}"

    # Rules verification
    assert adv["disclaimer"] == DISCLAIMER_TEXT
    assert "AI suggestion, human review required" in adv["disclaimer"]

    # Verify likely root cause phrasing
    for cause in adv["likely_causes"]:
        assert "likely" in cause["text"].lower()
        assert 0.0 <= cause["confidence"] <= 1.0
        assert "evidence_event_ids" in cause

    # Verify all action items carry valid playbook_id
    for action in adv["immediate_actions"] + adv["before_reopening"] + adv["monitoring_after_restore"] + adv["long_term_fixes"]:
        assert action["playbook_id"] in playbooks, f"Action missing valid playbook_id: {action}"
        assert action["step"]
        assert action["why"]

    # Verify staged reopen plan
    assert len(adv["staged_reopen_plan"]) >= 2
    for phase in adv["staged_reopen_plan"]:
        assert "phase" in phase
        assert "traffic_percent" in phase
        assert "exit_criteria" in phase

    # Verify mandatory caveats
    for mc in MANDATORY_CAVEATS:
        assert mc in adv["caveats"]


def test_secret_masking():
    """Validates that passwords, bearer tokens, and API keys are masked."""
    raw_str = "Connecting with password=SuperSecretPassword123! and Authorization: Bearer eyJhbGciOi..."
    masked_str = mask_secrets(raw_str)
    assert "SuperSecretPassword123!" not in masked_str
    assert "password=[MASKED]" in masked_str
    assert "Bearer [MASKED]" in masked_str

    raw_dict = {
        "api_key": "SK1234567890123456789012",
        "nested": {"token": "my_secret_token_val"},
    }
    masked_dict = mask_secrets(raw_dict)
    assert masked_dict["api_key"] == "api_key=[MASKED]" or "[MASKED" in masked_dict["api_key"]
    assert "my_secret_token_val" not in str(masked_dict)


@pytest.mark.asyncio
async def test_reattack_window_logic(db):
    """Tests gateway lifecycle transition to 'attacked' and re-attack detection."""
    now = datetime.now(timezone.utc)
    gw = Gateway(
        id="payment_test",
        name="Test Payment Gateway",
        endpoint_prefix="/api/payment_test",
        owner_team="payments_team",
        status="operational",
        status_history=[],
    )
    db.add(gw)
    await db.commit()

    # 1. Initial attack
    attack_req = {"path": "/api/payment_test", "method": "POST", "src_ip": "1.2.3.4"}
    res1 = await on_gateway_attack(gw, risk_score=65.0, attack_request=attack_req, db=db, now=now)
    assert gw.status == "attacked"
    assert gw.reattack_after_restore is False
    assert gw.reattack_count == 0

    # 2. Operator restores gateway -> starts WATCH WINDOW
    gw.status = "restored"
    gw.restored_at = now
    gw.watch_until = now + timedelta(minutes=settings.watch_window_min)
    await db.commit()

    # Verify watch mode is active
    in_watch, remaining = is_in_watch_mode(gw, now)
    assert in_watch is True
    assert remaining > 0

    # 3. Second attack occurs during watch window -> triggers RE-ATTACK
    res2 = await on_gateway_attack(gw, risk_score=75.0, attack_request=attack_req, db=db, now=now + timedelta(minutes=5))
    assert gw.status == "attacked"
    assert gw.reattack_after_restore is True
    assert gw.reattack_count == 1
    assert res2["is_reattack"] is True


def test_watch_window_threshold_drop():
    """Tests that active WATCH MODE lowers decoy routing threshold by configured percentage."""
    # Default threshold 70.0; with 20% drop -> 56.0
    # In normal mode with risk 60.0 (below 70.0): routes to real
    route_normal, _ = evaluate_routing_decision(
        risk_score=60.0,
        independent_categories_count=2,
        active_categories=["payment_gateway", "secrets_probing"],
        is_watch_mode=False,
    )
    assert route_normal == "real"

    # In watch mode with risk 60.0 (exceeds lowered threshold 56.0): routes to decoy!
    route_watch, reason_watch = evaluate_routing_decision(
        risk_score=60.0,
        independent_categories_count=2,
        active_categories=["payment_gateway", "secrets_probing"],
        is_watch_mode=True,
    )
    assert route_watch == "decoy"
    assert "[WATCH MODE]" in reason_watch


@pytest.mark.asyncio
async def test_step_status_persistence(db):
    """Tests persistence and updating of advisory step execution statuses."""
    now = datetime.now(timezone.utc)
    step = AdvisoryStepStatus(
        step_id="imm_rotate_keys_01",
        incident_id="inc_123",
        gateway_id="payment",
        status="pending",
        note="Awaiting security team sign-off",
        updated_at=now,
    )
    db.add(step)
    await db.commit()

    assert step.status == "pending"

    # Update to done
    step.status = "done"
    step.note = "Credentials rotated successfully"
    step.updated_at = datetime.now(timezone.utc)
    await db.commit()

    assert step.status == "done"


@pytest.mark.asyncio
async def test_verify_fix_gate(db):
    """Tests that 'safe to reopen' indicator stays AMBER (False) until verification passes."""
    now = datetime.now(timezone.utc)
    gw = Gateway(
        id="admin_test",
        name="Admin Gateway Test",
        endpoint_prefix="/admin",
        owner_team="platform_team",
        status="fixing",
        status_history=[],
        last_verify_result=None,
    )
    db.add(gw)
    await db.commit()

    # 1. Before verification: safe_to_reopen MUST be False
    is_safe, reasons = await check_safe_to_reopen(gw, db)
    assert is_safe is False
    assert any("verification" in r.lower() for r in reasons)

    # 2. Failed verification: safe_to_reopen remains False
    gw.last_verify_result = {"status": "failed", "details": "Tripwire still fired", "timestamp": now.isoformat()}
    await db.commit()
    is_safe2, _ = await check_safe_to_reopen(gw, db)
    assert is_safe2 is False

    # 3. Passed verification: safe_to_reopen becomes True
    gw.last_verify_result = {"status": "passed", "details": "Tripwire blocked, fix verified", "timestamp": now.isoformat()}
    await db.commit()
    is_safe3, reasons3 = await check_safe_to_reopen(gw, db)
    assert is_safe3 is True
    assert len(reasons3) == 0

