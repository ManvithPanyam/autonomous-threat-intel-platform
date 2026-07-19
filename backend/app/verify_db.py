import sys
import os

# Ensure the app module can be found
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session
from app.db.session import engine, SessionLocal
from app.models import Base, Case, Alert, IOC, Enrichment, ContainmentAction
from app.services.ioc import get_or_create_ioc

def test_database_flow():
    print("Initializing test database connection...")
    
    # Wipe tables to ensure clean state
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    db: Session = SessionLocal()
    try:
        print("1. Creating a new threat investigation Case...")
        case = Case(
            title="Suspicious Outbound C2 Traffic",
            description="Investigating potential Cobalt Strike beaconing activity.",
            status="under_investigation",
            severity="high"
        )
        db.add(case)
        db.commit()
        db.refresh(case)
        print(f"   Case created with ID: {case.id}")
        
        print("2. Ingesting raw Alert...")
        alert = Alert(
            case_id=case.id,
            alert_id="evt-100412",
            source="Firewall-Analyzer",
            severity="high",
            title="Outbound connection to known malicious IP",
            description="Alert triggered due to outbound traffic to 198.51.100[.]42.",
            raw_payload={
                "event_type": "network_flow",
                "bytes_transferred": 10240,
                "destination_ip": "198.51.100.42",
                "destination_port": 443
            }
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        print(f"   Alert created with ID: {alert.id}")

        print("3. Parsing, Normalizing, and Storing IOC...")
        raw_ip = "198.51.100[.]42"
        ioc = get_or_create_ioc(db, "ip", raw_ip)
        
        # Link Alert to IOC
        alert.iocs.append(ioc)
        db.commit()
        print(f"   IOC linked to Alert. IOC ID: {ioc.id}, Value: {ioc.value}")

        print("4. Appending Threat Intel Enrichment...")
        enrichment = Enrichment(
            ioc_id=ioc.id,
            source="VirusTotal",
            raw_response={
                "malicious_votes": 48,
                "harmless_votes": 2,
                "reputation": "malicious",
                "category": "command_and_control"
            }
        )
        db.add(enrichment)
        db.commit()
        db.refresh(enrichment)
        print(f"   Enrichment record created. ID: {enrichment.id}")

        print("5. Initiating Containment Action...")
        action = ContainmentAction(
            case_id=case.id,
            action_type="block_ip",
            status="pending",
            input_parameters={"ip_address": ioc.value}
        )
        db.add(action)
        db.commit()
        db.refresh(action)
        print(f"   Containment Action logged in pending status. ID: {action.id}")

        print("6. Verifying Normalization and Deduplication Logic (ADR 0004)...")
        
        # Test Case 1: Same IP already exists in DB
        dup_ip = get_or_create_ioc(db, "ip", "198.51.100.42")
        assert dup_ip.id == ioc.id
        print("   ✓ Exact IP match correctly deduplicated.")

        dup_ip_defanged = get_or_create_ioc(db, "ip", "198.51.100[.]42  ")
        assert dup_ip_defanged.id == ioc.id
        print("   ✓ Defanged and padded IP match correctly deduplicated.")

        # Test Case 2: Mixed-case domain and protocol normalization
        domain_1 = get_or_create_ioc(db, "domain", "MALICIOUS[.]com")
        domain_2 = get_or_create_ioc(db, "domain", "https://malicious.com/some/path")
        assert domain_1.value == "malicious.com"
        assert domain_2.id == domain_1.id
        print("   ✓ Mixed-case, defanged domain and URL paths successfully resolved to single IOC domain record.")

        # Test Case 3: Mixed-case hash deduplication
        hash_1 = get_or_create_ioc(db, "hash_sha256", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
        hash_2 = get_or_create_ioc(db, "hash_sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert hash_1.value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert hash_2.id == hash_1.id
        print("   ✓ Upper and lower case hashes successfully resolved to single lowercase hash record.")

        # Total unique IOC count check
        total_iocs = db.query(IOC).count()
        assert total_iocs == 3  # The IP, the domain, and the hash
        print(f"   ✓ Total unique IOC count matches expected: {total_iocs}")

        # Verification Queries
        print("\n--- Running Relation Verification Queries ---")
        queried_case = db.query(Case).filter_by(id=case.id).first()
        assert queried_case is not None
        assert len(queried_case.alerts) == 1
        print("   ✓ Case -> Alerts relationship validated.")
        
        queried_alert = queried_case.alerts[0]
        assert len(queried_alert.iocs) == 1
        print("   ✓ Alert -> IOC relationship validated.")
        
        queried_ioc = queried_alert.iocs[0]
        assert len(queried_ioc.enrichments) == 1
        print("   ✓ IOC -> Enrichments relationship validated.")
        
        queried_enrichment = queried_ioc.enrichments[0]
        assert queried_enrichment.source == "VirusTotal"
        assert queried_enrichment.raw_response["reputation"] == "malicious"
        print("   ✓ Enrichment content validated.")

        assert len(queried_case.containment_actions) == 1
        assert queried_case.containment_actions[0].action_type == "block_ip"
        print("   ✓ Case -> Containment Actions relationship validated.")
        
        print("\n🎉 DATABASE & DEDUPLICATION FLOW VERIFICATION SUCCESSFUL!")

    except Exception as e:
        print(f"\n❌ VERIFICATION FAILED: {str(e)}")
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    test_database_flow()
