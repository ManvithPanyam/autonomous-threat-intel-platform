import sys
import os
from fastapi.testclient import TestClient

# Ensure backend directory is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
from app.db.session import SessionLocal, engine
from app.models import Base, Case, Alert, IOC, ContainmentAction, AuditLog
from app.services.recommendation_service import generate_containment_recommendations
from app.workers.containment_tasks import execute_containment_action


def run_verification():
    print("[INFO] Starting Phase 8 Human Approval & Containment Workflow Verification...\n")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    client = TestClient(app)

    try:
        # 1. Create Test Case with Alert & IOC
        case = Case(
            title="Incident: Lateral Movement & C2 Activity",
            description="Powershell execution and RDP beaconing detected on critical host",
            status="open",
            severity="critical",
            severity_score=90,
            severity_tier="Critical",
            technique_id="T1021.002",
            technique_name="SMB/Windows Admin Shares",
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        alert = Alert(
            case_id=case.id,
            alert_id="ALT-PHASE8-001",
            source="EDR-Defender",
            severity="critical",
            title="Suspicious RDP & PowerShell Lateral Movement",
            description="PowerShell process established RDP connection to 198.51.100.99",
            raw_payload={"details": "lateral movement"}
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        from app.services.ioc import get_or_create_ioc
        ioc = get_or_create_ioc(db, "ip", "198.51.100.99")
        alert.iocs.append(ioc)
        db.commit()

        print(f"[OK] Created Test Case ID {case.id} with IOC {ioc.value}.")

        # 2. Generate Recommendations (Pending State)
        recs = generate_containment_recommendations(db, case.id)
        print(f"[OK] Generated {len(recs)} pending ContainmentAction recommendations.")
        for r in recs:
            print(f"   - Action ID: {r.id} | Type: {r.action_type} | Target: {r.target} | Status: {r.status}")

        # 3. Test API List Actions
        list_res = client.get(f"/api/v1/cases/{case.id}/actions")
        assert list_res.status_code == 200, f"List actions failed: {list_res.text}"
        actions_json = list_res.json()
        print(f"[OK] GET /api/v1/cases/{case.id}/actions returned {len(actions_json)} actions via REST API.\n")

        # Select actions
        block_ip_action = next(a for a in recs if a.action_type == "Block_IP")
        host_iso_action = next(a for a in recs if a.action_type == "Host_Isolation")

        # 4. Test RBAC Readonly Rejection (403 Forbidden)
        readonly_res = client.post(
            f"/api/v1/actions/{block_ip_action.id}/approve",
            headers={"X-User-Role": "readonly", "X-User-ID": "auditor_bob"}
        )
        assert readonly_res.status_code == 403, f"Expected 403 for readonly role, got {readonly_res.status_code}"
        print("[OK] Verified RBAC 403 Forbidden rejection for 'readonly' user role.")

        # 5. Test Analyst Approval Flow (POST /api/v1/actions/{id}/approve)
        approve_res = client.post(
            f"/api/v1/actions/{block_ip_action.id}/approve",
            headers={"X-User-Role": "analyst", "X-User-ID": "analyst_alice"}
        )
        assert approve_res.status_code == 200, f"Approve failed: {approve_res.text}"
        approved_data = approve_res.json()
        assert approved_data["status"] == "approved"
        assert approved_data["operator_id"] == "analyst_alice"
        print(f"[OK] POST /api/v1/actions/{block_ip_action.id}/approve succeeded (Status: {approved_data['status']}, Operator: {approved_data['operator_id']}).")

        # 6. Test Double Approval Conflict (409 Conflict)
        double_approve = client.post(
            f"/api/v1/actions/{block_ip_action.id}/approve",
            headers={"X-User-Role": "analyst", "X-User-ID": "analyst_alice"}
        )
        assert double_approve.status_code == 409, f"Expected 409 Conflict on double approval, got {double_approve.status_code}"
        print("[OK] Verified 409 Conflict rejection on double-approval attempt.")

        # 7. Test Analyst Denial Flow (POST /api/v1/actions/{id}/deny)
        deny_res = client.post(
            f"/api/v1/actions/{host_iso_action.id}/deny",
            json={"denial_reason": "Host belongs to Domain Controller — manual mitigation required"},
            headers={"X-User-Role": "analyst", "X-User-ID": "analyst_alice"}
        )
        assert deny_res.status_code == 200, f"Deny failed: {deny_res.text}"
        denied_data = deny_res.json()
        assert denied_data["status"] == "denied"
        assert denied_data["denial_reason"] == "Host belongs to Domain Controller — manual mitigation required"
        print(f"[OK] POST /api/v1/actions/{host_iso_action.id}/deny succeeded (Status: {denied_data['status']}, Reason: {denied_data['denial_reason']}).\n")

        # 8. Execute Celery Containment Task synchronously for approved action
        exec_res = execute_containment_action(block_ip_action.id)
        print(f"[OK] Celery Execution Task completed (Status: {exec_res['status']}).")
        print(f"   Mock Result Payload: {exec_res['result']}\n")

        # 9. Verify Audit Trail in DB
        audit_entries = (
            db.query(AuditLog)
            .filter(AuditLog.case_id == case.id)
            .order_by(AuditLog.created_at.asc())
            .all()
        )
        print(f"--- AUDIT LOG TRAIL ({len(audit_entries)} records) ---")
        for entry in audit_entries:
            print(f"   - [ID: {entry.id}] Actor: {entry.actor} | Action: {entry.action} | Action ID: {entry.action_id}")
        print("--------------------------------------------------\n")

        assert len(audit_entries) >= 4, f"Expected at least 4 audit trail records, got {len(audit_entries)}"
        print("[SUCCESS] HUMAN APPROVAL & RESPONSE WORKFLOW VERIFICATION PASSED SUCCESSFULLY!")

    finally:
        db.close()


if __name__ == "__main__":
    run_verification()
