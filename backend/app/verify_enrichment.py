import sys
import os

# Ensure backend directory is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import SessionLocal
from app.models.ioc import IOC
from app.models.enrichment import Enrichment
from app.services.ioc import get_or_create_ioc
from app.workers.enrichment_tasks import enrich_with_virustotal, enrich_with_abuseipdb


def run_verification():
    print("🚀 Starting Enrichment Celery Task Verification...")

    db = SessionLocal()
    try:
        # Create or fetch a test IOC (45.155.205.233)
        test_ip = "45.155.205.233"
        ioc = get_or_create_ioc(db, "ip", test_ip)
        print(f"   Using test IOC: ID={ioc.id}, Type={ioc.ioc_type}, Value={ioc.value}")

        # Run enrich_with_virustotal task directly
        print("\n1. Executing enrich_with_virustotal task...")
        vt_res = enrich_with_virustotal(ioc.id, ioc.value, ioc.ioc_type)
        print(f"   VirusTotal Task Result: {vt_res}")

        # Run enrich_with_abuseipdb task directly
        print("\n2. Executing enrich_with_abuseipdb task...")
        abuse_res = enrich_with_abuseipdb(ioc.id, ioc.value, ioc.ioc_type)
        print(f"   AbuseIPDB Task Result: {abuse_res}")

        # Query database for enrichment records
        print("\n3. Querying enrichments table...")
        enrichments = (
            db.query(Enrichment)
            .filter(Enrichment.ioc_id == ioc.id)
            .all()
        )

        assert len(enrichments) >= 1, "Expected at least 1 enrichment record created."
        print(f"   Found {len(enrichments)} enrichment records for IOC ID {ioc.id}:")

        for e in enrichments:
            print(
                f"   - ID: {e.id} | Source: {e.source} | Status: {e.status} | "
                f"Summary Score: {e.summary_score} | Created At: {e.created_at}"
            )
            assert e.status in ("success", "cached", "failed"), f"Unexpected status: {e.status}"

        print("\n🎉 ENRICHMENT VERIFICATION PASSED SUCCESSFULLY!")
    finally:
        db.close()


if __name__ == "__main__":
    run_verification()
