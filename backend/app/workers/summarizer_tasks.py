import asyncio
from celery import shared_task
from app.db.session import SessionLocal
from app.models.case import Case
from app.models.llm_log import LLMPromptLog
from app.services.llm.factory import get_llm_provider, get_fallback_provider
from app.services.llm.prompt_builder import build_case_prompt

def assemble_case_data(db, case_id: int) -> dict:
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise ValueError(f"Case ID {case_id} not found.")

    alerts_data = []
    seen_ioc_ids = set()
    iocs_data = []

    for alert in case.alerts:
        alerts_data.append({
            "id": alert.id,
            "title": alert.title,
            "description": alert.description,
            "source": alert.source,
            "severity": alert.severity,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        })

        for ioc in alert.iocs:
            if ioc.id in seen_ioc_ids:
                continue
            seen_ioc_ids.add(ioc.id)

            latest_enrichment = None
            if ioc.enrichments:
                sorted_enr = sorted(ioc.enrichments, key=lambda e: e.created_at or 0, reverse=True)
                latest_enr_obj = sorted_enr[0]
                latest_enrichment = {
                    "source": latest_enr_obj.source,
                    "reputation_score": latest_enr_obj.summary_score,
                    "status": latest_enr_obj.status,
                }

            iocs_data.append({
                "id": ioc.id,
                "indicator": ioc.value,
                "indicator_type": ioc.ioc_type,
                "source": latest_enrichment["source"] if latest_enrichment else "N/A",
                "reputation_score": latest_enrichment["reputation_score"] if latest_enrichment else 0,
                "status": latest_enrichment["status"] if latest_enrichment else "none",
            })

    return {
        "id": case.id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "severity_score": case.severity_score or case.score or 0,
        "severity_tier": case.severity_tier or case.severity or "Low",
        "severity_explanation": case.severity_explanation,
        "technique_id": case.technique_id,
        "technique_name": case.technique_name,
        "matched_via": "lookup" if case.technique_id else "fallback",
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "alerts": alerts_data,
        "iocs": iocs_data,
    }


@shared_task(
    bind=True,
    max_retries=3,
    name="summarizer.summarize_case",
)
def summarize_case_task(self, case_id: int):
    db = SessionLocal()
    try:
        case_data = assemble_case_data(db, case_id)
        prompt_text = build_case_prompt(case_data)
        
        primary_provider = get_llm_provider()
        summary_result = None
        used_provider = primary_provider.provider_name

        try:
            summary_result = asyncio.run(primary_provider.summarize_case(case_data))
        except Exception as exc:
            print(f"[SUMMARIZER] Primary provider ({used_provider}) attempt failed: {exc}")
            current_retries = getattr(getattr(self, "request", None), "retries", 0)
            max_retries = getattr(self, "max_retries", 3)
            if current_retries < max_retries:
                try:
                    raise self.retry(exc=exc, countdown=2 ** current_retries)
                except Exception as retry_err:
                    # If called outside Celery worker context, proceed to fallback
                    pass

            print(f"[SUMMARIZER] Executing fallback provider ({get_fallback_provider().provider_name}).")
            fallback_provider = get_fallback_provider()
            used_provider = fallback_provider.provider_name
            summary_result = asyncio.run(fallback_provider.summarize_case(case_data))


        # Write result to Case.analyst_summary
        case = db.query(Case).filter(Case.id == case_id).first()
        if case and summary_result:
            case.analyst_summary = summary_result.summary_markdown
            
            # Log to llm_prompt_logs table
            log_entry = LLMPromptLog(
                case_id=case_id,
                provider=summary_result.provider or used_provider,
                model=summary_result.model,
                prompt=prompt_text,
                response=summary_result.summary_markdown,
                tokens_used=summary_result.tokens_used,
                latency_ms=summary_result.latency_ms,
            )
            db.add(log_entry)
            db.commit()

        # Trigger Containment Action Recommendation Generator
        try:
            from app.services.recommendation_service import generate_containment_recommendations
            generate_containment_recommendations(db, case_id)
        except Exception as rec_err:
            print(f"[SUMMARIZER] [WARNING] Failed to generate containment recommendations for Case ID {case_id}: {rec_err}")


        return {
            "status": "success",
            "case_id": case_id,
            "provider": summary_result.provider if summary_result else used_provider,
            "model": summary_result.model if summary_result else "unknown",
            "tokens_used": summary_result.tokens_used if summary_result else 0,
            "latency_ms": summary_result.latency_ms if summary_result else 0,
        }

    except Exception as exc:
        db.rollback()
        raise exc
    finally:
        db.close()
