import unittest
import concurrent.futures
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.exc import IntegrityError

from app.main import app
from app.models.base import Base
from app.models.case import Case
from app.models.alert import Alert
from app.models.ioc import IOC
from app.models.containment import ContainmentAction
from app.api.routes.actions import get_db as get_actions_db
from app.api.routes.alerts import get_db as get_alerts_db
from app.core.ssrf_validator import is_private_or_restricted_ip, validate_outbound_target
from app.workers.containment_tasks import execute_containment_action
from app.workers.enrichment_tasks import enrich_with_virustotal
from fastapi import HTTPException

test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


class TestPhase9(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=test_engine)
        self.db = TestSessionLocal()
        app.dependency_overrides[get_actions_db] = override_get_db
        app.dependency_overrides[get_alerts_db] = override_get_db
        self.client = TestClient(app)

        # Mock Celery tasks to prevent Redis network retries during local unit tests
        self.celery_delay_patcher = patch("app.workers.containment_tasks.execute_containment_action.delay")
        self.mock_celery_delay = self.celery_delay_patcher.start()
        
        self.enrich_delay_patcher = patch("app.services.alert_service.enrich_alert_task.delay")
        self.mock_enrich_delay = self.enrich_delay_patcher.start()

    def tearDown(self):
        self.celery_delay_patcher.stop()
        self.enrich_delay_patcher.stop()
        app.dependency_overrides.clear()
        self.db.close()
        Base.metadata.drop_all(bind=test_engine)

    def test_ssrf_validator_blocklist(self):
        """Verify SSRF validator blocks private RFC1918, loopback, and Cloud metadata IPs."""
        blocked_targets = [
            "10.0.0.1",
            "172.16.5.10",
            "192.168.1.100",
            "127.0.0.1",
            "169.254.169.254",  # AWS/Azure metadata
            "http://127.0.0.1:8000/secret",
            "https://10.0.0.5/admin",
        ]
        for target in blocked_targets:
            self.assertTrue(is_private_or_restricted_ip(target) or target.startswith("http"))
            with self.assertRaises(HTTPException) as cm:
                validate_outbound_target(target)
            self.assertEqual(cm.exception.status_code, 400)
            self.assertIn("SSRF Safeguard Violation", cm.exception.detail)

        # Valid public target
        valid_public = "8.8.8.8"
        self.assertFalse(is_private_or_restricted_ip(valid_public))
        self.assertEqual(validate_outbound_target(valid_public), "8.8.8.8")

    def test_ioc_value_uniqueness_constraint(self):
        """Verify DB-level unique constraint on IOC value prevents duplicate IOC rows."""
        ioc1 = IOC(ioc_type="ip", value="198.51.100.55")
        self.db.add(ioc1)
        self.db.commit()

        ioc2 = IOC(ioc_type="ip", value="198.51.100.55")
        self.db.add(ioc2)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_alert_fuzzing_malformed_payloads(self):
        """Verify API fuzzing with malformed payloads yields clean 422 errors without 500 server crashes."""
        fuzz_payloads = [
            {},  # Empty
            {"source": "EDR"},  # Missing required fields
            {"alert_id": 12345, "source": "SIEM", "title": "Test"},  # Wrong field types
            {
                "alert_id": "ALT-FUZZ-01",
                "source": "SIEM",
                "severity": "high",
                "title": "Bad IOC Type",
                "iocs": "not_a_list",  # iocs must be list
            },
        ]
        for payload in fuzz_payloads:
            res = self.client.post("/api/v1/alerts", json=payload)
            self.assertEqual(res.status_code, 422, f"Payload {payload} did not return 422. Got {res.status_code}: {res.text}")

    @patch("app.workers.containment_tasks.SessionLocal")
    def test_concurrent_approval_race_condition(self, mock_session):
        """Verify approval status transition yields 200 OK for first request and 409 Conflict on double approval."""
        mock_session.side_effect = lambda: TestSessionLocal()
        case = Case(title="Race Condition Case", status="open")
        self.db.add(case)
        self.db.commit()

        action = ContainmentAction(
            case_id=case.id,
            action_type="Block_IP",
            target="198.51.100.11",
            status="pending",
            input_parameters={"ip": "198.51.100.11"}
        )
        self.db.add(action)
        self.db.commit()

        res1 = self.client.post(
            f"/api/v1/actions/{action.id}/approve",
            headers={"X-User-Role": "analyst", "X-User-ID": "analyst_1"}
        )
        self.assertEqual(res1.status_code, 200)

        res2 = self.client.post(
            f"/api/v1/actions/{action.id}/approve",
            headers={"X-User-Role": "analyst", "X-User-ID": "analyst_2"}
        )
        self.assertEqual(res2.status_code, 409)

    @patch("app.workers.enrichment_tasks.query_virustotal")
    @patch("app.workers.enrichment_tasks.SessionLocal")
    def test_max_retries_exhaustion_lands_in_failed_state(self, mock_session, mock_vt):
        """Verify Celery task exhausting max retries saves a failed status record rather than retrying indefinitely or vanishing."""
        mock_session.side_effect = lambda: TestSessionLocal()
        mock_vt.side_effect = Exception("Persistent API Failure 500")

        ioc = IOC(ioc_type="ip", value="198.51.100.99")
        self.db.add(ioc)
        self.db.commit()

        enrich_with_virustotal.push_request(retries=3)
        try:
            result = enrich_with_virustotal(ioc.id, ioc.value, ioc.ioc_type)
            self.assertEqual(result["status"], "failed")
            self.assertIn("Persistent API Failure", result["error"])
        finally:
            enrich_with_virustotal.pop_request()

    @patch("app.workers.containment_tasks.SessionLocal")
    def test_containment_redelivery_idempotency_guard(self, mock_session):
        """Verify redelivery guard in Celery containment worker skips re-execution for executed or denied actions."""
        mock_session.side_effect = lambda: TestSessionLocal()

        case = Case(title="Redelivery Test Case", status="open")
        self.db.add(case)
        self.db.commit()

        action = ContainmentAction(
            case_id=case.id,
            action_type="Block_IP",
            target="198.51.100.22",
            status="executed",  # Already in executed terminal state
            input_parameters={"ip": "198.51.100.22"},
            mock_result={"success": True, "blocked_ip": "198.51.100.22"},
        )
        self.db.add(action)
        self.db.commit()

        # Simulate redelivery of executed task
        redelivery_res = execute_containment_action(action.id)
        self.assertEqual(redelivery_res["status"], "executed")
        self.assertIn("already in terminal state", redelivery_res["reason"])


if __name__ == "__main__":
    unittest.main()
