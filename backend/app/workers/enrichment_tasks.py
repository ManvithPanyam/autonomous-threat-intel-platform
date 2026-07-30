import asyncio
from celery import shared_task
from app.db.session import SessionLocal
from app.services.enrichment import (
    get_cached_enrichment,
    save_enrichment,
    query_virustotal,
    query_abuseipdb,
)


def _extract_vt_summary_score(res: dict) -> int | None:
    if not isinstance(res, dict):
        return None
    data = res.get("data")
    if isinstance(data, dict):
        attributes = data.get("attributes")
        if isinstance(attributes, dict):
            stats = attributes.get("last_analysis_stats")
            if isinstance(stats, dict):
                return stats.get("malicious", 0)
    return None


def _extract_abuseipdb_summary_score(res: dict) -> int | None:
    if not isinstance(res, dict):
        return None
    data = res.get("data")
    if isinstance(data, dict):
        return data.get("abuseConfidenceScore")
    return None


@shared_task(
    bind=True,
    max_retries=3,
    rate_limit="4/m",
    name="enrichment.query_virustotal",
)
def enrich_with_virustotal(self, ioc_id: int, ioc_value: str, ioc_type: str):
    db = SessionLocal()
    try:
        cached = get_cached_enrichment(db, ioc_id, "virustotal")
        if cached:
            return {"status": "cached", "ioc_id": ioc_id, "source": "virustotal"}

        res = query_virustotal(ioc_type, ioc_value)
        score = _extract_vt_summary_score(res)
        row = save_enrichment(
            db=db,
            ioc_id=ioc_id,
            source="virustotal",
            raw_response=res,
            status="success",
            summary_score=score,
        )
        return {"status": "success", "enrichment_id": row.id}
    except Exception as exc:
        db.rollback()
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=2 ** self.request.retries)
        row = save_enrichment(
            db=db,
            ioc_id=ioc_id,
            source="virustotal",
            raw_response={"error": str(exc)},
            status="failed",
            summary_score=None,
        )
        return {"status": "failed", "error": str(exc)}
    finally:
        db.close()


@shared_task(
    bind=True,
    max_retries=3,
    rate_limit="60/m",
    name="enrichment.query_abuseipdb",
)
def enrich_with_abuseipdb(self, ioc_id: int, ioc_value: str, ioc_type: str):
    if ioc_type != "ip":
        return {"status": "skipped", "reason": "not an IP"}

    db = SessionLocal()
    try:
        cached = get_cached_enrichment(db, ioc_id, "abuseipdb")
        if cached:
            return {"status": "cached", "ioc_id": ioc_id, "source": "abuseipdb"}

        res = query_abuseipdb(ioc_type, ioc_value)
        score = _extract_abuseipdb_summary_score(res)
        row = save_enrichment(
            db=db,
            ioc_id=ioc_id,
            source="abuseipdb",
            raw_response=res,
            status="success",
            summary_score=score,
        )
        return {"status": "success", "enrichment_id": row.id}
    except Exception as exc:
        db.rollback()
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=2 ** self.request.retries)
        row = save_enrichment(
            db=db,
            ioc_id=ioc_id,
            source="abuseipdb",
            raw_response={"error": str(exc)},
            status="failed",
            summary_score=None,
        )
        return {"status": "failed", "error": str(exc)}
    finally:
        db.close()
