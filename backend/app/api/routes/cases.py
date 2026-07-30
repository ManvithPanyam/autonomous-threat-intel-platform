from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, joinedload
from typing import List, Optional

from app.db.session import SessionLocal
from app.models.case import Case
from app.models.alert import Alert
from app.models.ioc import IOC, alert_iocs
from app.models.containment import ContainmentAction

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/")
def list_cases(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity_tier_filter: Optional[str] = Query(None, alias="severity_tier"),
    db: Session = Depends(get_db),
):
    """
    List all cases with optional status and severity_tier filters, including alert count and pending action count.
    """
    query = db.query(Case)

    if status_filter:
        query = query.filter(Case.status == status_filter)
    if severity_tier_filter:
        query = query.filter(Case.severity_tier == severity_tier_filter)

    cases = query.order_by(Case.severity_score.desc().nullslast(), Case.created_at.desc()).all()

    result = []
    for c in cases:
        pending_actions_count = (
            db.query(ContainmentAction)
            .filter(ContainmentAction.case_id == c.id, ContainmentAction.status == "pending")
            .count()
        )
        total_alerts_count = db.query(Alert).filter(Alert.case_id == c.id).count()

        effective_score = c.severity_score if c.severity_score is not None else (c.score or 0)
        if c.severity_tier:
            effective_tier = c.severity_tier
        elif effective_score >= 80:
            effective_tier = "Critical"
        elif effective_score >= 60:
            effective_tier = "High"
        elif effective_score >= 35:
            effective_tier = "Medium"
        else:
            effective_tier = "Low"

        result.append(
            {
                "id": c.id,
                "title": c.title,
                "description": c.description,
                "status": c.status,
                "severity": c.severity,
                "score": c.score,
                "severity_score": effective_score,
                "severity_tier": effective_tier,
                "severity_explanation": c.severity_explanation,
                "technique_id": c.technique_id,

                "technique_name": c.technique_name,
                "analyst_summary": c.analyst_summary,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "updated_at": c.updated_at.isoformat() if c.updated_at else None,
                "pending_actions_count": pending_actions_count,
                "total_alerts_count": total_alerts_count,
            }
        )

    return result


@router.get("/{case_id}")
def get_case_detail(case_id: int, db: Session = Depends(get_db)):
    """
    Retrieve full case details including linked alerts, IOCs with enrichments, MITRE mapping,
    severity breakdown, AI analyst summary, and containment actions.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case ID {case_id} not found.")

    # 1. Fetch linked alerts
    alerts = db.query(Alert).filter(Alert.case_id == case.id).order_by(Alert.created_at.desc()).all()
    alerts_data = []
    alert_ids = [a.id for a in alerts]

    for a in alerts:
        alerts_data.append(
            {
                "id": a.id,
                "alert_id": a.alert_id,
                "source": a.source,
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "raw_payload": a.raw_payload,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
        )

    # 2. Fetch linked IOCs with latest enrichments
    iocs_data = []
    if alert_ids:
        iocs = (
            db.query(IOC)
            .join(alert_iocs, alert_iocs.c.ioc_id == IOC.id)
            .filter(alert_iocs.c.alert_id.in_(alert_ids))
            .distinct()
            .all()
        )

        for ioc in iocs:
            enrichments_data = []
            for e in ioc.enrichments:
                enrichments_data.append(
                    {
                        "id": e.id,
                        "source": e.source,
                        "status": e.status,
                        "summary_score": e.summary_score,
                        "raw_response": e.raw_response,
                        "created_at": e.created_at.isoformat() if e.created_at else None,
                    }
                )

            iocs_data.append(
                {
                    "id": ioc.id,
                    "ioc_type": ioc.ioc_type,
                    "value": ioc.value,
                    "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                    "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                    "enrichments": enrichments_data,
                }
            )

    # 3. Fetch Containment Actions
    actions = (
        db.query(ContainmentAction)
        .filter(ContainmentAction.case_id == case.id)
        .order_by(ContainmentAction.requested_at.asc())
        .all()
    )
    actions_data = []
    for act in actions:
        actions_data.append(
            {
                "id": act.id,
                "case_id": act.case_id,
                "action_type": act.action_type,
                "target": act.target,
                "status": act.status,
                "input_parameters": act.input_parameters,
                "mock_result": act.mock_result,
                "approved_at": act.approved_at.isoformat() if act.approved_at else None,
                "denied_at": act.denied_at.isoformat() if act.denied_at else None,
                "executed_at": act.executed_at.isoformat() if act.executed_at else None,
                "operator_id": act.operator_id,
                "operator_email": act.operator_email,
                "denial_reason": act.denial_reason,
                "requested_at": act.requested_at.isoformat() if act.requested_at else None,
            }
        )

    effective_score = case.severity_score if case.severity_score is not None else (case.score or 0)
    if case.severity_tier:
        effective_tier = case.severity_tier
    elif effective_score >= 80:
        effective_tier = "Critical"
    elif effective_score >= 60:
        effective_tier = "High"
    elif effective_score >= 35:
        effective_tier = "Medium"
    else:
        effective_tier = "Low"

    return {
        "id": case.id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "severity": case.severity,
        "score": case.score,
        "severity_score": effective_score,
        "severity_tier": effective_tier,
        "severity_explanation": case.severity_explanation,
        "technique_id": case.technique_id,

        "technique_name": case.technique_name,
        "analyst_summary": case.analyst_summary,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "alerts": alerts_data,
        "iocs": iocs_data,
        "containment_actions": actions_data,
    }
