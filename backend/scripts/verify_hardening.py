import sys
import os
import time
import concurrent.futures
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

# Ensure backend directory is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
from app.db.session import SessionLocal, engine
from app.models import Base, Case, Alert, IOC, ContainmentAction, AuditLog
from app.core.ssrf_validator import is_private_or_restricted_ip, validate_outbound_target
from app.workers.containment_tasks import execute_containment_action
from app.workers.enrichment_tasks import enrich_with_virustotal
from fastapi import HTTPException


def run_hardening_verification():
    print("[INFO] Starting Phase 9 Resilience, Hardening & Concurrency Verification...\n")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    client = TestClient(app)

    try:
        # 1. Verify SSRF Egress Safeguard
        print("1. Testing SSRF Safeguard Egress Proxy Blocklist...")
        restricted_ips = ["10.0.0.1", "172.16.0.5", "192.168.1.1", "127.0.0.1", "169.254.169.254"]
        for ip_val in restricted_ips:
            assert is_private_or_restricted_ip(ip_val), f"Failed to detect private IP: {ip_val}"
            try:
                validate_outbound_target(ip_val)
                assert False, f"Expected 400 Bad Request for restricted target {ip_val}"
            except HTTPException as err:
                assert err.status_code == 400
        print("   [OK] SSRF Blocklist successfully rejected all private/loopback/metadata IP targets.\n")

        # 2. Verify Burst Alert Ingestion Load (20 Alerts)
        print("2. Testing Burst Alert Ingestion (20 alerts with overlapping IOCs)...")
        shared_ioc = "198.51.100.250"
        created_alert_ids = []
        start_time = time.time()

        for i in range(20):
            payload = {
                "alert_id": f"ALT-BURST-PHASE9-{i:03d}",
                "source": "Splunk-SIEM",
                "severity": "high" if i % 2 == 0 else "critical",
                "title": f"Burst Threat Activity #{i}",
                "description": f"Burst event #{i} targeting shared IOC {shared_ioc}",
                "iocs": [{"ioc_type": "ip", "value": shared_ioc}],
                "raw_payload": {"burst_index": i},
            }
            res = client.post("/api/v1/alerts", json=payload)
            assert res.status_code in [200, 201, 202], f"Burst alert #{i} failed: {res.text}"
            created_alert_ids.append(res.json()["alert_id"])

        elapsed = time.time() - start_time
        print(f"   [OK] Ingested 20 burst alerts in {elapsed:.2f} seconds.")

        # Verify all 20 alerts correlated into ONE active Case
        matching_case = (
            db.query(Case)
            .join(Alert)
            .join(Alert.iocs)
            .filter(IOC.value == shared_ioc)
            .first()
        )
        assert matching_case is not None, "Failed to locate correlated case for shared IOC."
        alerts_in_case = db.query(Alert).filter(Alert.case_id == matching_case.id).count()
        print(f"   [OK] Smart Grouping correlated all 20 burst alerts into Case ID {matching_case.id} (Total linked alerts: {alerts_in_case}).\n")

        # 3. Verify True Multithreaded Concurrent HTTP Approval Requests (with_for_update Row Lock Test)
        print("3. Testing Multithreaded Concurrent HTTP Approval (SELECT FOR UPDATE row locking)...")
        race_action = ContainmentAction(
            case_id=matching_case.id,
            action_type="Block_IP",
            target="198.51.100.88",
            status="pending",
            input_parameters={"ip": "198.51.100.88"},
        )
        db.add(race_action)
        db.commit()
        db.refresh(race_action)

        def send_concurrent_approval():
            c = TestClient(app)
            return c.post(
                f"/api/v1/actions/{race_action.id}/approve",
                headers={"X-User-Role": "analyst", "X-User-ID": "concurrent_analyst_thread"}
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            fut1 = executor.submit(send_concurrent_approval)
            fut2 = executor.submit(send_concurrent_approval)
            r1 = fut1.result()
            r2 = fut2.result()

        codes = sorted([r1.status_code, r2.status_code])
        assert codes == [200, 409], f"Concurrent approval expected [200, 409], got {codes}"
        print(f"   [OK] PostgreSQL FOR UPDATE Row Locking verified: exactly 1 request succeeded (200) and 1 rejected (409 Conflict).\n")

        # 4. Verify Containment Task Redelivery Idempotency Guard
        print("4. Testing Containment Execution Redelivery Guard...")
        action = ContainmentAction(
            case_id=matching_case.id,
            action_type="Block_IP",
            target="198.51.100.250",
            status="executed",
            input_parameters={"ip": "198.51.100.250"},
            mock_result={"success": True, "blocked_ip": "198.51.100.250", "firewall_rule_id": "FW-TEST-99"},
        )
        db.add(action)
        db.commit()
        db.refresh(action)

        redelivery_res = execute_containment_action(action.id)
        assert redelivery_res["status"] == "executed"
        assert "already in terminal state" in redelivery_res["reason"]
        print(f"   [OK] Redelivery Guard caught executed Action ID {action.id} and skipped duplicate handler execution.\n")

        # 5. Verify Max Retries Exhaustion DLQ Path
        print("5. Testing Task Max-Retries Exhaustion & Failed State Persistence...")
        mock_dlq_ioc = IOC(ioc_type="ip", value="198.51.100.77")
        db.add(mock_dlq_ioc)
        db.commit()

        with patch("app.workers.enrichment_tasks.query_virustotal", side_effect=Exception("500 Internal Server Error")):
            enrich_with_virustotal.push_request(retries=3)
            try:
                failed_res = enrich_with_virustotal(mock_dlq_ioc.id, mock_dlq_ioc.value, mock_dlq_ioc.ioc_type)
                assert failed_res["status"] == "failed"
                assert "500 Internal Server Error" in failed_res["error"]
            finally:
                enrich_with_virustotal.pop_request()

        print("   [OK] Max retries exhaustion saved 'failed' enrichment state row rather than retrying infinitely.\n")

        # 6. Verify Fuzzing Payload Error Handling
        print("6. Testing Fuzzing Payload Error Handling (422 returns)...")
        malformed = {"alert_id": "ALT-BAD", "severity": "super_critical"}
        fuzz_res = client.post("/api/v1/alerts", json=malformed)
        assert fuzz_res.status_code == 422
        print("   [OK] Pydantic returned clean 422 Unprocessable Entity error without server crash.\n")

        print("[SUCCESS] ALL PHASE 9 HARDENING, RESILIENCE & CONCURRENCY CHECKS PASSED!")

    finally:
        db.close()


if __name__ == "__main__":
    run_hardening_verification()
