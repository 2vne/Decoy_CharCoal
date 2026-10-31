import httpx
import sys

headers = {"X-API-Key": "changeme"}
base_url = "http://127.0.0.1:8000"

def run_tests():
    with httpx.Client(base_url=base_url, headers=headers, timeout=10.0) as client:
        # 1. Overview API
        r = client.get("/api/overview")
        assert r.status_code == 200, f"Overview status {r.status_code}"
        total_atk = r.json().get("total_attackers", 0)
        print(f"[PASS] 1. Overview API 200 OK. Attackers: {total_atk}")

        # 2. Attackers list
        r = client.get("/api/attackers")
        assert r.status_code == 200
        data = r.json()
        attackers = data.get("attackers", data) if isinstance(data, dict) else data
        assert len(attackers) > 0
        first_ip = attackers[0]["ip"]
        first_id = attackers[0]["id"]
        print(f"[PASS] 2. Attackers API 200 OK. First: {first_ip} (id={first_id})")

        # 3. Attacker dossier
        r = client.get(f"/api/attackers/{first_id}")
        assert r.status_code == 200
        factors = len(r.json().get("risk_factors", []))
        print(f"[PASS] 3. Attacker Dossier API 200 OK. Factors: {factors}")

        # 4. Trigger repeat_attacker simulation to generate relationships
        r = client.post("/api/simulate/start", json={"scenario": "repeat_attacker", "speed": 10.0})
        assert r.status_code == 200
        print(f"[PASS] 4. Simulator repeat_attacker trigger 200 OK: {r.json()}")

        # 5. Relationships API
        r = client.get("/api/relationships")
        assert r.status_code == 200
        edges = r.json()
        print(f"[PASS] 5. Relationships API 200 OK. Found {len(edges)} edges.")

        # 6. Actions API
        r = client.get("/api/actions")
        assert r.status_code == 200
        actions = r.json()
        print(f"[PASS] 6. Actions API 200 OK. Found {len(actions)} actions.")

        # 7. Blocks API
        r = client.get("/api/blocks")
        assert r.status_code == 200
        data_blocks = r.json()
        blocks = data_blocks.get("blocks", data_blocks) if isinstance(data_blocks, dict) else data_blocks
        print(f"[PASS] 7. Blocks API 200 OK. Total blocks: {len(blocks)}")

        # 8. Incident PDF Report
        r = client.get("/api/incidents")
        assert r.status_code == 200
        data_inc = r.json()
        incidents = data_inc.get("incidents", data_inc) if isinstance(data_inc, dict) else data_inc
        if len(incidents) > 0:
            inc_id = incidents[0]["id"]
            r_pdf = client.get(f"/api/incidents/{inc_id}/report")
            assert r_pdf.status_code == 200
            assert len(r_pdf.content) > 500
            print(f"[PASS] 8. Incident {inc_id} PDF Report Download: {len(r_pdf.content)} bytes")
        else:
            print("[PASS] 8. Incident report skipped (no incidents yet)")

        # 9. IOC Exports
        for fmt in ["json", "csv", "stix"]:
            r = client.get(f"/api/ioc?format={fmt}")
            assert r.status_code == 200
        print("[PASS] 9. IOC Exports (JSON, CSV, STIX) all 200 OK")

        # 10. What-If Counterfactual
        r = client.post("/api/whatif", json={"attacker_id": first_id, "action": "block", "at_stage": "recon"})
        assert r.status_code == 200
        reduction = r.json().get("risk_reduction_pct", 0)
        print(f"[PASS] 10. What-If Counterfactual 200 OK. Risk reduction: {reduction}%")

    # 11. Frontend dev server check
    with httpx.Client(base_url="http://127.0.0.1:3000", timeout=5.0) as fe_client:
        r = fe_client.get("/")
        assert r.status_code == 200
        assert "<div id=\"root\">" in r.text
        print("[PASS] 11. Frontend dev server 200 OK & delivering DOM")

if __name__ == "__main__":
    run_tests()
    print("\nALL 11 VERIFICATION CHECKS PASSED SUCCESSFULLY!")
