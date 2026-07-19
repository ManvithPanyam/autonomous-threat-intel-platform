from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "threatintel",
    broker=settings.REDIS_URL,
    backend=settings.CELERY_BROKER_URL,  # simple backend config matching settings
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

@celery_app.task(name="app.workers.enrich_alert_task")
def enrich_alert_task(alert_id: int):
    """
    Placeholder Celery task for asynchronous alert enrichment and correlation.
    To be fully implemented in Phase 5.
    """
    print(f"[CELERY MOCK] Received request to enrich Alert ID: {alert_id}")
    return {"status": "queued", "alert_id": alert_id}
