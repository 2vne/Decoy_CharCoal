from __future__ import annotations
import pytest
from app.services.risk import compute_risk, score_to_band


class TestScoreToBand:
    def test_low_band(self):
        assert score_to_band(0) == "low"
        assert score_to_band(25) == "low"

    def test_medium_band(self):
        assert score_to_band(26) == "medium"
        assert score_to_band(50) == "medium"

    def test_high_band(self):
        assert score_to_band(51) == "high"
        assert score_to_band(75) == "high"

    def test_critical_band(self):
        assert score_to_band(76) == "critical"
        assert score_to_band(100) == "critical"


class TestComputeRisk:
    def test_empty_returns_zero(self):
        score, factors, band = compute_risk(
            event_types=[],
            classifications=[],
            honeypots_touched=[],
            decoy_types=[],
            is_repeat=False,
            is_anomaly=False,
        )
        assert score == 0.0
        assert band == "low"
        assert factors == []

    def test_scan_adds_10(self):
        score, factors, band = compute_risk(
            event_types=["scan"],
            classifications=[None],
            honeypots_touched=["cowrie"],
            decoy_types=["external"],
            is_repeat=False,
            is_anomaly=False,
        )
        assert score == 10.0
        assert any(f["factor"] == "scan" for f in factors)

    def test_login_success_adds_20(self):
        score, factors, band = compute_risk(
            event_types=["login_success"],
            classifications=[None],
            honeypots_touched=["cowrie"],
            decoy_types=["external"],
            is_repeat=False,
            is_anomaly=False,
        )
        assert score == 20.0
        assert any(f["factor"] == "login_success" for f in factors)

    def test_internal_decoy_adds_25(self):
        score, factors, band = compute_risk(
            event_types=["connect"],
            classifications=[None],
            honeypots_touched=["cowrie"],
            decoy_types=["internal"],
            is_repeat=False,
            is_anomaly=False,
        )
        assert score == 25.0
        assert any(f["factor"] == "internal_decoy" for f in factors)

    def test_capped_at_100(self):
        score, factors, band = compute_risk(
            event_types=["scan", "login_success", "file_download"],
            classifications=["brute_force", "recon", "persistence_attempt"],
            honeypots_touched=["cowrie", "opencanary", "dionaea"],
            decoy_types=["internal"],
            is_repeat=True,
            is_anomaly=True,
            related_high_risk=True,
            external_reputation=75.0,
        )
        assert score == 100.0
        assert band == "critical"

    def test_brute_force_factor(self):
        score, factors, band = compute_risk(
            event_types=[],
            classifications=["brute_force"],
            honeypots_touched=["cowrie"],
            decoy_types=["external"],
            is_repeat=False,
            is_anomaly=False,
        )
        assert score == 20.0
        assert any(f["factor"] == "brute_force" for f in factors)

    def test_repeat_attacker_adds_10(self):
        score, factors, band = compute_risk(
            event_types=[],
            classifications=[],
            honeypots_touched=["cowrie"],
            decoy_types=["external"],
            is_repeat=True,
            is_anomaly=False,
        )
        assert score == 10.0
        assert any(f["factor"] == "repeat_attacker" for f in factors)

    def test_multi_honeypot_adds_15(self):
        score, factors, band = compute_risk(
            event_types=[],
            classifications=[],
            honeypots_touched=["cowrie", "opencanary"],
            decoy_types=["external"],
            is_repeat=False,
            is_anomaly=False,
        )
        assert score == 15.0
        assert any(f["factor"] == "multi_honeypot" for f in factors)

