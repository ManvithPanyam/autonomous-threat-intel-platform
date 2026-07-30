import uuid
from datetime import datetime, timezone
from celery import shared_task

from app.db.session import SessionLocal
from app.models.containment import ContainmentAction
from app.services.audit_service import create_audit_entry


def mock_block_ip(target: str) -> dict:
    if target in ["invalid_target", "fail_ip", "0.0.0.0"]:
        return {
            "success": False,
            "error": f"Invalid or restricted IP target '{target}'",
            "firewall_rule_id": None,
        }
    rule_id = f"FW-RULE-{uuid.uuid4().hex[:8].upper()}"
    return {
        "success": True,
        "action": "Block_IP",
        "blocked_ip": target,
        "firewall_rule_id": rule_id,
        "status": "applied",
    }


def mock_host_isolation(target: str) -> dict:
    if target in ["invalid_target", "fail_host"]:
        return {
            "success": False,
            "error": f"Host '{target}' not reachable or invalid agent ID",
            "quarantine_id": None,
        }
    quarantine_id = f"EDR-Q-{uuid.uuid4().hex[:8].upper()}"
    return {
        "success": True,
        "action": "Host_Isolation",
        "isolated_host": target,
        "quarantine_id": quarantine_id,
        "network_state": "quarantined",
    }


def mock_auto_ticket(case_id: int, target: str) -> dict:
    if target in ["invalid_target", "fail_ticket"]:
        return {
            "success": False,
            "error": f"Ticketing integration payload rejected for case '{case_id}'",
            "ticket_id": None,
        }
    ticket_id = f"TICK-{case_id}-9942"
    return {
        "success": True,
        "action": "Auto_Ticket",
        "ticket_id": ticket_id,
        "system": "Jira-SOC",
        "status": "created",
    }


@shared_task(
    bind=True,
    name="containment.execute_action",
)
def execute_containment_action(self, action_id: int):
    db = SessionLocal()
    try:
        action = db.query(ContainmentAction).with_for_update().filter(ContainmentAction.id == action_id).first()
        if not action:
            print(f"[CONTAINMENT] Action ID {action_id} not found.")
            return {"status": "not_found", "action_id": action_id}

        # Redelivery & State Idempotency Guard: Never re-run actions in terminal state
        if action.status in ["executed", "failed", "denied"]:
            print(f"[CONTAINMENT] Action ID {action_id} is already in state '{action.status}'. Skipping re-execution (Redelivery Guard).")
            return {
                "status": action.status,
                "action_id": action_id,
                "reason": f"Action already in terminal state '{action.status}'",
                "result": action.mock_result,
            }

        # Defensive check: Only execute approved actions
        if action.status != "approved":
            print(f"[CONTAINMENT] Action ID {action_id} status is '{action.status}' (not 'approved'). Aborting execution.")
            return {"status": "skipped", "reason": f"Action status is '{action.status}'"}


        # Transition -> executing
        before_executing = {
            "id": action.id,
            "status": action.status,
            "target": action.target,
        }
        action.status = "executing"
        db.commit()
        db.refresh(action)

        after_executing = {
            "id": action.id,
            "status": action.status,
            "target": action.target,
        }
        create_audit_entry(
            db=db,
            actor=action.operator_id or "system_celery_worker",
            action="Action_Executing",
            case_id=action.case_id,
            action_id=action.id,
            before_state=before_executing,
            after_state=after_executing,
        )

        # Dispatch to mock handler
        action_type = (action.action_type or "").replace("_", "").lower()
        target = action.target or ""

        if "blockip" in action_type:
            mock_res = mock_block_ip(target)
        elif "hostisolation" in action_type or "isolate" in action_type:
            mock_res = mock_host_isolation(target)
        elif "ticket" in action_type:
            mock_res = mock_auto_ticket(action.case_id, target)
        else:
            mock_res = {"success": False, "error": f"Unknown action type '{action.action_type}'"}

        before_final = {
            "id": action.id,
            "status": action.status,
        }

        if mock_res.get("success"):
            action.status = "executed"
            action.executed_at = datetime.now(timezone.utc)
            action.mock_result = mock_res
            db.commit()

            after_final = {
                "id": action.id,
                "status": action.status,
                "executed_at": action.executed_at.isoformat(),
                "mock_result": mock_res,
            }
            create_audit_entry(
                db=db,
                actor=action.operator_id or "system_celery_worker",
                action="Action_Executed",
                case_id=action.case_id,
                action_id=action.id,
                before_state=before_final,
                after_state=after_final,
            )
        else:
            action.status = "failed"
            action.executed_at = datetime.now(timezone.utc)
            action.mock_result = mock_res
            db.commit()

            after_final = {
                "id": action.id,
                "status": action.status,
                "error": mock_res.get("error"),
                "mock_result": mock_res,
            }
            create_audit_entry(
                db=db,
                actor=action.operator_id or "system_celery_worker",
                action="Action_Failed",
                case_id=action.case_id,
                action_id=action.id,
                before_state=before_final,
                after_state=after_final,
            )

        return {
            "status": action.status,
            "action_id": action_id,
            "result": mock_res,
        }

    except Exception as exc:
        db.rollback()
        raise exc
    finally:
        db.close()
