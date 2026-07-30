from typing import Any
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog

def create_audit_entry(
    db: Session,
    actor: str,
    action: str,
    case_id: int | None = None,
    action_id: int | None = None,
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
) -> AuditLog:
    """
    Creates an immutable AuditLog entry recording state transitions.
    """
    audit_entry = AuditLog(
        case_id=case_id,
        action_id=action_id,
        actor=actor,
        action=action,
        before_state=before_state,
        after_state=after_state,
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry
