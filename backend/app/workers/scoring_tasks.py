from celery import shared_task
from app.db.session import SessionLocal
from app.models.case import Case
from app.services.mitre_mapper import map_to_mitre
from app.services.scoring import calculate_severity_score


@shared_task(name="scoring.score_case")
def score_case(
    case_id: int,
    alert_signature: str,
    alert_description: str,
    vt_score: int | None,
    abuse_score: int | None,
):
    db = SessionLocal()
    try:
        mitre_result = map_to_mitre(alert_signature, alert_description)
        scoring_result = calculate_severity_score(
            mitre_result["base_severity"], vt_score, abuse_score
        )

        case = db.query(Case).filter(Case.id == case_id).first()
        if case:
            case.technique_id = mitre_result["technique_id"]
            case.technique_name = mitre_result["technique_name"]
            case.severity_score = scoring_result["score"]
            case.severity_tier = scoring_result["tier"]
            case.severity_explanation = scoring_result["explanation"]
            case.score = scoring_result["score"]
            case.severity = scoring_result["tier"].lower()
            db.commit()

        # Trigger AI Summarizer Task
        try:
            from app.workers.summarizer_tasks import summarize_case_task
            summarize_case_task.delay(case_id)
        except Exception as e:
            print(f"[SCORING] [WARNING] Failed to queue AI summarizer task for Case ID {case_id}: {str(e)}")

        return {
            "status": "success",
            "case_id": case_id,
            "score": scoring_result["score"],
            "tier": scoring_result["tier"],
            "technique_id": mitre_result["technique_id"],
        }
    finally:
        db.close()

