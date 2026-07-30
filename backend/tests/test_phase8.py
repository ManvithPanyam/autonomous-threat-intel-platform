import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.models.base import Base
from app.models.case import Case
from app.models.alert import Alert
from app.models.ioc import IOC
from app.models.containment import ContainmentAction
from app.models.audit_log import AuditLog
from app.api.routes.actions import get_db
from app.services.recommendation_service import generate_containment_recommendations
from app.workers.containment_tasks import execute_containment_action

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


class TestPhase8(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=test_engine)
        self.db = TestSessionLocal()
        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Mock Celery delay to prevent Redis network retries during local unit tests
        self.celery_delay_patcher = patch("app.workers.containment_tasks.execute_containment_action.delay")
        self.mock_celery_delay = self.celery_delay_patcher.start()

    def tearDown(self):
        self.celery_delay_patcher.stop()
        app.dependency_overrides.clear()
        self.db.close()
        Base.metadata.drop_all(bind=test_engine)

    def test_recommendation_generation(self):
        """Verify rule-based recommendation generator creates pending actions."""
        case = Case(
            title="Test C2 Case",
            status="open",
            severity_score=85,
            severity_tier="Critical",
            technique_id="T1059.001",
        )
        self.db.add(case)
        self.db.commit()

        alert = Alert(
            case_id=case.id,
            alert_id="a-p8-rec",
            source="Splunk",
            severity="high",
            title="PowerShell Execution",
            description="PowerShell process established outbound connection to 198.51.100.10",
            raw_payload={},
        )
        self.db.add(alert)
        self.db.commit()

        ioc = IOC(ioc_type="ip", value="198.51.100.10")
        self.db.add(ioc)
        self.db.commit()
        alert.iocs.append(ioc)
        self.db.commit()

        actions = generate_containment_recommendations(self.db, case.id)
        self.assertGreaterEqual(len(actions), 2)
        
        action_types = [a.action_type for a in actions]
        self.assertIn("Block_IP", action_types)
        self.assertIn("Auto_Ticket", action_types)
        
        for a in actions:
            self.assertEqual(a.status, "pending")

    def test_rbac_readonly_forbidden(self):
        """Verify readonly role receives 403 Forbidden on approve or deny attempts."""
        case = Case(title="RBAC Case", status="open")
        self.db.add(case)
        self.db.commit()

        action = ContainmentAction(case_id=case.id, action_type="Block_IP", target="1.1.1.1", status="pending")
        self.db.add(action)
        self.db.commit()

        res_approve = self.client.post(
            f"/api/v1/actions/{action.id}/approve",
            headers={"X-User-Role": "readonly", "X-User-ID": "guest"}
        )
        self.assertEqual(res_approve.status_code, 403)

        res_deny = self.client.post(
            f"/api/v1/actions/{action.id}/deny",
            json={"denial_reason": "Not allowed"},
            headers={"X-User-Role": "readonly", "X-User-ID": "guest"}
        )
        self.assertEqual(res_deny.status_code, 403)

    def test_approve_flow_and_conflict(self):
        """Verify happy path approval and 409 Conflict on double approval."""
        case = Case(title="Approval Case", status="open")
        self.db.add(case)
        self.db.commit()

        action = ContainmentAction(case_id=case.id, action_type="Block_IP", target="10.0.0.5", status="pending")
        self.db.add(action)
        self.db.commit()

        # Approve
        res = self.client.post(
            f"/api/v1/actions/{action.id}/approve",
            headers={"X-User-Role": "analyst", "X-User-ID": "analyst_sam"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "approved")
        self.assertEqual(data["operator_id"], "analyst_sam")

        # Double Approval Attempt -> 409 Conflict
        res_conflict = self.client.post(
            f"/api/v1/actions/{action.id}/approve",
            headers={"X-User-Role": "analyst", "X-User-ID": "analyst_sam"}
        )
        self.assertEqual(res_conflict.status_code, 409)

    def test_deny_flow(self):
        """Verify happy path denial flow."""
        case = Case(title="Denial Case", status="open")
        self.db.add(case)
        self.db.commit()

        action = ContainmentAction(case_id=case.id, action_type="Host_Isolation", target="SERVER-01", status="pending")
        self.db.add(action)
        self.db.commit()

        res = self.client.post(
            f"/api/v1/actions/{action.id}/deny",
            json={"denial_reason": "Production database host"},
            headers={"X-User-Role": "admin", "X-User-ID": "admin_root"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "denied")
        self.assertEqual(data["denial_reason"], "Production database host")

    @patch("app.workers.containment_tasks.SessionLocal")
    def test_celery_execution_success_and_failure(self, mock_session):
        """Verify Celery task execution for approved action success and mock failure paths."""
        mock_session.side_effect = lambda: TestSessionLocal()

        case = Case(title="Celery Exec Case", status="open")
        self.db.add(case)
        self.db.commit()

        # Action 1: Valid Target
        action_valid = ContainmentAction(case_id=case.id, action_type="Block_IP", target="198.51.100.5", status="approved")
        # Action 2: Invalid Target for Failure Simulation
        action_invalid = ContainmentAction(case_id=case.id, action_type="Block_IP", target="invalid_target", status="approved")
        self.db.add_all([action_valid, action_invalid])
        self.db.commit()

        res_valid = execute_containment_action(action_valid.id)
        self.assertEqual(res_valid["status"], "executed")
        self.assertTrue(res_valid["result"]["success"])

        res_invalid = execute_containment_action(action_invalid.id)
        self.assertEqual(res_invalid["status"], "failed")
        self.assertFalse(res_invalid["result"]["success"])


if __name__ == "__main__":
    unittest.main()
