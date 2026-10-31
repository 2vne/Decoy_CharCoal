from __future__ import annotations
import pytest
from app.models import Attacker, Event, Incident, ResponseAction
from app.services.ai_investigation import run_ai_investigation
from app.services.exposure import evaluate_exposure_budget, update_exposure_asset_threshold
from app.services.integrity import compute_chain_hash_for_event, compute_raw_hash, verify_event_raw_hash
from app.services.ioc import extract_iocs, format_iocs_csv, format_iocs_stix
from app.services.prediction import predict_attacker_propagation
from app.services.reports import generate_incident_pdf, generate_summary_report_data
from app.services.whatif import simulate_whatif


@pytest.mark.asyncio
class TestAdvancedFeatures:
    async def test_integrity_raw_and_chain_hash(self, db):
        raw_data = {"test": "payload", "cmd": "whoami"}
        event_id = "test-uuid-001"
        h1 = compute_raw_hash(raw_data, event_id)
        assert len(h1) == 64
        # Deterministic
        assert h1 == compute_raw_hash(raw_data, event_id)

        chain_hash, prev_hash = await compute_chain_hash_for_event(
            db=db,
            raw_hash=h1,
            event_id=event_id,
            timestamp_str="2026-10-31T12:00:00Z",
        )
        assert len(chain_hash) == 64
        assert prev_hash == "0" * 64

    async def test_ai_investigation_template(self, db):
        atk = Attacker(
            ip="203.0.113.55",
            risk_score=88.0,
            risk_band="critical",
            honeypots_touched=["cowrie", "opencanary"],
            commands=["whoami", "cat /etc/passwd"],
            intent="credential_theft",
        )
        db.add(atk)
        await db.flush()

        inc = Incident(
            attacker_id=atk.id,
            title=f"Critical Threat: {atk.ip}",
            status="new",
            risk_score_at_creation=88.0,
            root_cause={"factors": ["Brute force", "Command execution"]},
            blast_radius={"honeypots": ["cowrie", "opencanary"]},
        )
        db.add(inc)
        await db.flush()

        inv = await run_ai_investigation(db, inc.id)
        assert inv["incident_id"] == inc.id
        assert "what_happened" in inv
        assert "why_dangerous" in inv
        assert len(inv["recommended_actions"]) > 0
        assert inv["confidence"] >= 0.8

    async def test_whatif_simulator(self, db):
        atk = Attacker(
            ip="198.51.100.99",
            risk_score=95.0,
            risk_band="critical",
            honeypots_touched=["cowrie", "opencanary"],
        )
        db.add(atk)
        await db.flush()

        res = await simulate_whatif(
            db=db,
            attacker_id=atk.id,
            action="block",
            at_stage="recon",
        )
        assert res["actual_risk"] == 95.0
        assert res["projected_risk"] <= 10.0
        assert res["risk_reduction_pct"] > 80.0
        assert len(res["counterfactual_comparison"]) == 5

    async def test_propagation_prediction(self, db):
        atk = Attacker(
            ip="192.0.2.77",
            risk_score=75.0,
            honeypots_touched=["cowrie"],
        )
        db.add(atk)
        await db.flush()

        pred = await predict_attacker_propagation(db, atk.id)
        assert pred["attacker_id"] == atk.id
        assert len(pred["likely_next_targets"]) > 0
        top = pred["likely_next_targets"][0]
        assert "probability" in top
        assert "decoy" in top
        assert top["probability"] > 0.6

    async def test_exposure_budget(self, db):
        assets = await evaluate_exposure_budget(db)
        assert len(assets) == 4
        assert any(a["name"] == "Core Customer Database" for a in assets)

        updated = await update_exposure_asset_threshold(db, assets[0]["id"], 99.0)
        assert updated.threshold == 99.0

    async def test_ioc_export(self, db):
        atk = Attacker(
            ip="203.0.113.88",
            risk_score=85.0,
            urls=["http://malware.org/loader.sh"],
            hashes=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            honeypots_touched=["cowrie"],
        )
        db.add(atk)
        await db.flush()

        iocs = await extract_iocs(db)
        assert any(i["value"] == "203.0.113.88" for i in iocs)
        assert any("loader.sh" in i["value"] for i in iocs)

        csv_str = format_iocs_csv(iocs)
        assert "source_ip" in csv_str
        assert "203.0.113.88" in csv_str

        stix_bundle = format_iocs_stix(iocs)
        assert stix_bundle["type"] == "bundle"
        assert len(stix_bundle["objects"]) >= 3

    async def test_report_pdf_generation(self, db):
        inc = Incident(
            title="Breach Attempt INC-999",
            status="investigating",
            risk_score_at_creation=85.0,
            root_cause={"factors": ["Brute force"]},
            blast_radius={"honeypots": ["cowrie"]},
        )
        db.add(inc)
        await db.flush()

        pdf_bytes = generate_incident_pdf(
            incident=inc,
            attacker=None,
            events=[],
            mitre_list=[],
            kc_list=[],
            actions=[],
        )
        assert pdf_bytes.startswith(b"%PDF")
        assert len(pdf_bytes) > 1000

