import sys
import os

# Ensure the app module can be found
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session
from app.db.session import engine, SessionLocal
from app.models import Base, Case, Alert, IOC, Enrichment, ContainmentAction

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

        print("3. Parsing and Normalizing IOC...")
        raw_ip = "198.51.100[.]42"
        # Normalize: strip defanging brackets
        normalized_ip = raw_ip.replace("[", "").replace("]", "").strip()
        print(f"   Normalized '{raw_ip}' -> '{normalized_ip}'")
        
        # Check uniqueness & insert
        ioc = db.query(IOC).filter_by(ioc_type="ip", value=normalized_ip).first()
        if not ioc:
            ioc = IOC(ioc_type="ip", value=normalized_ip)
            db.add(ioc)
            db.commit()
            db.refresh(ioc)
        
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
            input_parameters={"ip_address": normalized_ip}
        )
        db.add(action)
        db.commit()
        db.refresh(action)
        print(f"   Containment Action logged in pending status. ID: {action.id}")

        # Verification Queries
        print("\n--- Running Verification Queries ---")
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
        
        print("\n🎉 DATABASE FLOW VERIFICATION SUCCESSFUL!")

    except Exception as e:
        print(f"\n❌ VERIFICATION FAILED: {str(e)}")
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    test_database_flow()
