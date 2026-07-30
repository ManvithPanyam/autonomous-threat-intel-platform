from sqlalchemy.orm import Session
from app.models.case import Case
from app.models.containment import ContainmentAction
from app.services.audit_service import create_audit_entry

def generate_containment_recommendations(db: Session, case_id: int) -> list[ContainmentAction]:
    """
    Generates rule-based pending response action recommendations for a Case.
    Does NOT execute actions — all recommendations are created in 'pending' status for HITL review.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise ValueError(f"Case ID {case_id} not found.")

    created_actions = []

    # Helper to check if duplicate pending recommendation exists
    def recommendation_exists(action_type: str, target: str) -> bool:
        return db.query(ContainmentAction).filter(
            ContainmentAction.case_id == case_id,
            ContainmentAction.action_type == action_type,
            ContainmentAction.target == target,
            ContainmentAction.status == "pending"
        ).first() is not None

    # Rule 1: Flagged IP IOCs -> Recommend Block_IP
    ip_iocs = set()
    for alert in case.alerts:
        for ioc in alert.iocs:
            if ioc.ioc_type.lower() == "ip":
                ip_iocs.add(ioc.value)

    for ip_val in ip_iocs:
        if not recommendation_exists("Block_IP", ip_val):
            action = ContainmentAction(
                case_id=case.id,
                action_type="Block_IP",
                target=ip_val,
                status="pending",
                input_parameters={"ip": ip_val, "reason": "High reputation threat IOC flagged in incident"},
            )
            db.add(action)
            db.commit()
            db.refresh(action)
            
            create_audit_entry(
                db=db,
                actor="system_recommendation_engine",
                action="Recommendation_Generated",
                case_id=case.id,
                action_id=action.id,
                before_state=None,
                after_state={
                    "id": action.id,
                    "action_type": action.action_type,
                    "target": action.target,
                    "status": action.status,
                },
            )
            created_actions.append(action)

    # Rule 2: Lateral Movement / PowerShell / RDP -> Recommend Host_Isolation
    technique_id = case.technique_id or ""
    technique_name = case.technique_name or ""
    desc_str = (case.description or "").lower()
    
    if (
        "T1021" in technique_id
        or "T1059" in technique_id
        or "lateral movement" in technique_name.lower()
        or "powershell" in desc_str
        or "rdp" in desc_str
    ):
        host_target = f"HOST-{case.id}-ENDPOINT"
        if not recommendation_exists("Host_Isolation", host_target):
            action = ContainmentAction(
                case_id=case.id,
                action_type="Host_Isolation",
                target=host_target,
                status="pending",
                input_parameters={"hostname": host_target, "technique": technique_id or technique_name},
            )
            db.add(action)
            db.commit()
            db.refresh(action)

            create_audit_entry(
                db=db,
                actor="system_recommendation_engine",
                action="Recommendation_Generated",
                case_id=case.id,
                action_id=action.id,
                before_state=None,
                after_state={
                    "id": action.id,
                    "action_type": action.action_type,
                    "target": action.target,
                    "status": action.status,
                },
            )
            created_actions.append(action)

    # Rule 3: Critical or High Severity -> Recommend Auto_Ticket
    severity_tier = (case.severity_tier or case.severity or "").capitalize()
    if severity_tier in ["Critical", "High"] or (case.severity_score or case.score or 0) >= 60:
        ticket_target = f"CASE-{case.id}"
        if not recommendation_exists("Auto_Ticket", ticket_target):
            action = ContainmentAction(
                case_id=case.id,
                action_type="Auto_Ticket",
                target=ticket_target,
                status="pending",
                input_parameters={"case_id": case.id, "severity": severity_tier},
            )
            db.add(action)
            db.commit()
            db.refresh(action)

            create_audit_entry(
                db=db,
                actor="system_recommendation_engine",
                action="Recommendation_Generated",
                case_id=case.id,
                action_id=action.id,
                before_state=None,
                after_state={
                    "id": action.id,
                    "action_type": action.action_type,
                    "target": action.target,
                    "status": action.status,
                },
            )
            created_actions.append(action)

    return created_actions
