from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.schemas.alert import AlertCreate
from app.services.alert_service import create_ingested_alert

router = APIRouter()

@router.post("/", status_code=status.HTTP_202_ACCEPTED)
def ingest_alert(alert_in: AlertCreate, db: Session = Depends(get_db)):
    """
    Ingests raw threat alert payloads, validates schema, auto-groups into a case,
    and triggers asynchronous threat indicator enrichment in the background.
    """
    alert = create_ingested_alert(db, alert_in)
    return {
        "status": "accepted",
        "alert_id": alert.id,
        "case_id": alert.case_id
    }
