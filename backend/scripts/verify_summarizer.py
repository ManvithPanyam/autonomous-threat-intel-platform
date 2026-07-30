import sys
import os

# Ensure backend directory is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import SessionLocal, engine
from app.models import Base, Case, Alert, IOC, Enrichment, LLMPromptLog
from app.workers.summarizer_tasks import summarize_case_task


def run_verification():
    print("[INFO] Starting Phase 7 AI Incident Summarizer Verification...\n")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # Create test Case
        case = Case(
            title="Incident: Suspicious PowerShell Beaconing",
            description="Automated case created for outbound beaconing alert",
            status="open",
            severity="high",
            score=82,
            technique_id="T1059.001",
            technique_name="PowerShell",
            severity_score=82,
            severity_tier="Critical",
            severity_explanation="Technique base severity contributed 30 pts. VirusTotal detections contributed 27 pts. AbuseIPDB confidence contributed 25 pts.",
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        # Create test Alert
        alert = Alert(
            case_id=case.id,
            alert_id="ALT-VERIFY-007",
            source="EDR-Defender",
            severity="high",
            title="Suspicious Outbound PowerShell Execution",
            description="PowerShell process established outbound C2 channel to 198.51.100.45",
            raw_payload={"details": "beaconing detected"}
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        # Create test IOC & Enrichment
        from app.services.ioc import get_or_create_ioc
        ioc = get_or_create_ioc(db, "ip", "198.51.100.45")

        alert.iocs.append(ioc)
        db.commit()

        enrichment = Enrichment(
            ioc_id=ioc.id,
            source="virustotal",
            status="success",
            summary_score=45,
            raw_response={"data": {"attributes": {"last_analysis_stats": {"malicious": 45}}}},
        )
        db.add(enrichment)
        db.commit()

        print(f"[OK] Created Test Case ID {case.id} with linked Alert ID {alert.id} and IOC {ioc.value}.")
        print("[OK] Running summarize_case_task synchronously...\n")

        res = summarize_case_task(case.id)

        print(f"[OK] Execution Result Status: {res.get('status')}")
        print(f"[OK] Provider Used: {res.get('provider')}")
        print(f"[OK] Model Used: {res.get('model')}")
        print(f"[OK] Tokens Used: {res.get('tokens_used')}")
        print(f"[OK] Latency: {res.get('latency_ms')} ms\n")

        db.refresh(case)
        print("--- GENERATED ANALYST SUMMARY ---")
        print(case.analyst_summary)
        print("---------------------------------\n")

        # Verify DB LLMPromptLog entry
        log_entry = (
            db.query(LLMPromptLog)
            .filter(LLMPromptLog.case_id == case.id)
            .order_by(LLMPromptLog.created_at.desc())
            .first()
        )

        assert log_entry is not None, "LLMPromptLog entry was not created!"
        print(f"[OK] Verified LLMPromptLog created in DB (ID: {log_entry.id}, Provider: {log_entry.provider}, Model: {log_entry.model})")
        print("\n[SUCCESS] AI INCIDENT SUMMARIZER VERIFICATION PASSED SUCCESSFULLY!")

    finally:
        db.close()


if __name__ == "__main__":
    run_verification()
