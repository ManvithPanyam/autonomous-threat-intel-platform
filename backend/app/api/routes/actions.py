from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.db.session import SessionLocal
from app.models.case import Case
from app.models.containment import ContainmentAction
from app.api.schemas.containment import ActionDenyRequest, ContainmentActionResponse
from app.core.auth import require_analyst_or_admin, UserContext
from app.services.audit_service import create_audit_entry

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/cases/{case_id}/actions", response_model=List[ContainmentActionResponse])
def get_case_containment_actions(case_id: int, db: Session = Depends(get_db)):
    """
    List all ContainmentAction records for a given case.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case ID {case_id} not found.")
    
    actions = db.query(ContainmentAction).filter(ContainmentAction.case_id == case_id).all()
    return actions

@router.post("/actions/{action_id}/approve", response_model=ContainmentActionResponse)
def approve_containment_action(
    action_id: int,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(require_analyst_or_admin),
):
    """
    Approves a pending containment action (requires analyst or admin role).
    Transitions status: pending -> approved, logs audit trail, and triggers background execution task.
    """
    query = db.query(ContainmentAction)
    if db.bind and db.bind.dialect.name != "sqlite":
        query = query.with_for_update()
    action = query.filter(ContainmentAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail=f"ContainmentAction ID {action_id} not found.")


    if action.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Action ID {action_id} cannot be approved from current status '{action.status}'. Action must be 'pending'.",
        )

    before_state = {
        "id": action.id,
        "case_id": action.case_id,
        "action_type": action.action_type,
        "target": action.target,
        "status": action.status,
    }

    action.status = "approved"
    action.approved_at = datetime.now(timezone.utc)
    action.operator_id = current_user.user_id
    action.operator_email = f"{current_user.user_id}@platform.local"
    db.commit()
    db.refresh(action)

    after_state = {
        "id": action.id,
        "status": action.status,
        "approved_at": action.approved_at.isoformat(),
        "operator_id": action.operator_id,
    }

    # Record Audit Trail
    create_audit_entry(
        db=db,
        actor=current_user.user_id,
        action="Case_Approval",
        case_id=action.case_id,
        action_id=action.id,
        before_state=before_state,
        after_state=after_state,
    )

    # Trigger Celery Containment Task
    try:
        from app.workers.containment_tasks import execute_containment_action
        execute_containment_action.delay(action.id)
    except Exception as exc:
        print(f"[API] [WARNING] Failed to queue Celery containment task for Action ID {action.id}: {exc}")

    return action

@router.post("/actions/{action_id}/deny", response_model=ContainmentActionResponse)
def deny_containment_action(
    action_id: int,
    payload: ActionDenyRequest,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(require_analyst_or_admin),
):
    """
    Denies a pending containment action (requires analyst or admin role).
    Transitions status: pending -> denied, records denial reason, and logs audit trail.
    """
    query = db.query(ContainmentAction)
    if db.bind and db.bind.dialect.name != "sqlite":
        query = query.with_for_update()
    action = query.filter(ContainmentAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail=f"ContainmentAction ID {action_id} not found.")


    if action.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Action ID {action_id} cannot be denied from current status '{action.status}'. Action must be 'pending'.",
        )

    before_state = {
        "id": action.id,
        "case_id": action.case_id,
        "action_type": action.action_type,
        "target": action.target,
        "status": action.status,
    }

    action.status = "denied"
    action.denied_at = datetime.now(timezone.utc)
    action.denial_reason = payload.denial_reason
    action.operator_id = current_user.user_id
    action.operator_email = f"{current_user.user_id}@platform.local"
    db.commit()
    db.refresh(action)

    after_state = {
        "id": action.id,
        "status": action.status,
        "denied_at": action.denied_at.isoformat(),
        "denial_reason": action.denial_reason,
        "operator_id": action.operator_id,
    }

    # Record Audit Trail
    create_audit_entry(
        db=db,
        actor=current_user.user_id,
        action="Case_Denial",
        case_id=action.case_id,
        action_id=action.id,
        before_state=before_state,
        after_state=after_state,
    )

    return action
