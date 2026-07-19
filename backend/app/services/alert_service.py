from sqlalchemy.orm import Session
from app.api.schemas.alert import AlertCreate
from app.models.alert import Alert
from app.models.case import Case
from app.models.ioc import IOC
from app.services.ioc import get_or_create_ioc
from app.core.celery_app import enrich_alert_task

def create_ingested_alert(db: Session, alert_in: AlertCreate) -> Alert:
    # 1. Parse and normalize all IOCs
    normalized_iocs = []
    for ioc_data in alert_in.iocs:
        ioc_obj = get_or_create_ioc(db, ioc_data.ioc_type, ioc_data.value)
        normalized_iocs.append(ioc_obj)

    # 2. Check for active cases (status != 'resolved') that share any of these IOCs
    ioc_ids = [ioc.id for ioc in normalized_iocs]
    matching_case = None
    
    if ioc_ids:
        matching_case = (
            db.query(Case)
            .join(Alert)
            .join(Alert.iocs)
            .filter(Case.status != "resolved")
            .filter(IOC.id.in_(ioc_ids))
            .first()
        )

    # 3. Handle Case allocation
    if matching_case:
        case_id = matching_case.id
        print(f"[INGESTION] Found existing active Case ID {case_id} sharing matching IOCs. Grouping alert.")
    else:
        new_case = Case(
            title=f"Incident: {alert_in.title}",
            description=alert_in.description or f"Automated case created for alert: {alert_in.title}",
            status="open",
            severity=alert_in.severity
        )
        db.add(new_case)
        db.commit()
        db.refresh(new_case)
        case_id = new_case.id
        print(f"[INGESTION] No matching active Case found. Created new Case ID {case_id}.")

    # 4. Save Alert
    alert = Alert(
        case_id=case_id,
        alert_id=alert_in.alert_id,
        source=alert_in.source,
        severity=alert_in.severity,
        title=alert_in.title,
        description=alert_in.description,
        raw_payload=alert_in.raw_payload
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    # 5. Link Alert to normalized IOCs
    for ioc_obj in normalized_iocs:
        alert.iocs.append(ioc_obj)
    db.commit()
    db.refresh(alert)

    # 6. Trigger Asynchronous Celery Enrichment Task
    try:
        enrich_alert_task.delay(alert.id)
        print(f"[INGESTION] Triggered async Celery task for Alert ID: {alert.id}")
    except Exception as e:
        print(f"[INGESTION] [WARNING] Failed to queue Celery task: {str(e)}")

    return alert
