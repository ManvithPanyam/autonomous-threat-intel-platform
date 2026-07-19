import sys
import os
import json
import urllib.request
import urllib.error

# Ensure the app module can be found for DB checking
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import SessionLocal
from app.models import Case, Alert, IOC

def send_alert(payload: dict) -> dict:
    url = "http://localhost:8000/api/v1/alerts/"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, 
        data=data, 
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.read().decode('utf-8')}")
        sys.exit(1)
    except Exception as e:
        print(f"Connection Error: {str(e)}")
        sys.exit(1)

def run_verification():
    print("🚀 Starting Ingestion & Smart Grouping API verification...")

    # Clear DB tables to start fresh
    db = SessionLocal()
    try:
        db.query(IOC).delete()
        db.query(Alert).delete()
        db.query(Case).delete()
        db.commit()
        print("   Wiped existing alerts and cases for a clean test run.")
    finally:
        db.close()

    # Payload 1
    alert_1 = {
        "alert_id": "evt-c2-9988",
        "source": "CrowdStrike",
        "severity": "critical",
        "title": "Cobalt Strike Beaconing Activity",
        "description": "High frequency outbound beacons detected to a known C2 server.",
        "iocs": [
            {"ioc_type": "ip", "value": "203.0.113[.]10"},
            {"ioc_type": "domain", "value": "BAD-C2[.]net"}
        ],
        "raw_payload": {"bytes": 4096}
    }

    print("\n1. Ingesting first Alert (Cobalt Strike Beaconing)...")
    res1 = send_alert(alert_1)
    print(f"   Response: {res1}")
    assert res1["status"] == "accepted"
    case_1_id = res1["case_id"]
    alert_1_id = res1["alert_id"]
    print(f"   ✓ Alert 1 accepted. Grouped in Case ID: {case_1_id}")

    # Payload 2 (Shares IOC 'BAD-C2[.]net' via protocol and path URL)
    alert_2 = {
        "alert_id": "evt-c2-9989",
        "source": "Splunk",
        "severity": "critical",
        "title": "Proxy logs match C2 domain",
        "description": "Outbound HTTP request detected to http://bad-c2.net/some/path.",
        "iocs": [
            {"ioc_type": "domain", "value": "http://bad-c2.net/some/path"}
        ],
        "raw_payload": {"bytes": 2048}
    }

    print("\n2. Ingesting second Alert correlating on IOC 'bad-c2.net'...")
    res2 = send_alert(alert_2)
    print(f"   Response: {res2}")
    assert res2["status"] == "accepted"
    case_2_id = res2["case_id"]
    alert_2_id = res2["alert_id"]
    
    # Assert that smart grouping linked both alerts to the same Case
    assert case_1_id == case_2_id, f"Error: Alerts were not grouped into the same Case! Case 1: {case_1_id}, Case 2: {case_2_id}"
    print(f"   ✓ Smart Grouping succeeded! Alert 2 grouped in existing Case ID: {case_2_id}")

    # Payload 3 (A fresh unrelated alert with different IOCs)
    alert_3 = {
        "alert_id": "evt-malware-1100",
        "source": "Windows-Defender",
        "severity": "medium",
        "title": "Adware Executable Blocked",
        "description": "Suspicious adware binary blocked in downloads folder.",
        "iocs": [
            {"ioc_type": "hash_sha256", "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
        ],
        "raw_payload": {"action_taken": "quarantined"}
    }

    print("\n3. Ingesting third unrelated Alert (Adware Blocked)...")
    res3 = send_alert(alert_3)
    print(f"   Response: {res3}")
    assert res3["status"] == "accepted"
    case_3_id = res3["case_id"]
    assert case_3_id != case_1_id, "Error: Unrelated alert incorrectly grouped in the same Case!"
    print(f"   ✓ Alert 3 grouped in new Case ID: {case_3_id}")

    # Double check database records
    db = SessionLocal()
    try:
        cases_in_db = db.query(Case).all()
        assert len(cases_in_db) == 2, f"Expected 2 cases, got {len(cases_in_db)}"
        
        alerts_in_db = db.query(Alert).all()
        assert len(alerts_in_db) == 3, f"Expected 3 alerts, got {len(alerts_in_db)}"
        
        iocs_in_db = db.query(IOC).all()
        # IOCs: 1. ip: 203.0.113.10, 2. domain: bad-c2.net, 3. hash: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        assert len(iocs_in_db) == 3, f"Expected 3 unique IOCs in DB, got {len(iocs_in_db)}"
        
        print("\n🎉 ALL API INGESTION AND SMART GROUPING VERIFICATIONS PASSED!")
    finally:
        db.close()

if __name__ == "__main__":
    run_verification()
