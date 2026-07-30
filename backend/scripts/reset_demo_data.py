import sys
import os
from datetime import datetime, timezone

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import SessionLocal
from app.models.case import Case
from app.models.alert import Alert
from app.models.ioc import IOC
from app.models.containment import ContainmentAction
from app.models.audit_log import AuditLog
from app.models.enrichment import Enrichment
from app.models.mitre import MITRETechnique
from app.models.llm_log import LLMPromptLog



def reset_and_seed_demo_data():
    db = SessionLocal()
    try:
        print("[RESET] Cleaning existing database records for demo reset...")
        db.query(AuditLog).delete()
        db.query(LLMPromptLog).delete()
        db.query(ContainmentAction).delete()
        db.query(Alert).delete()
        db.query(Enrichment).delete()
        db.query(Case).delete()
        db.query(IOC).delete()
        db.commit()

        print("[SEED] Creating curated threat cases for live demo...")

        # IOCs
        ioc_ip = IOC(ioc_type="ip", value="198.51.100.45")
        ioc_hash = IOC(ioc_type="hash_sha256", value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        ioc_domain = IOC(ioc_type="domain", value="bad-c2-server.net")
        db.add_all([ioc_ip, ioc_hash, ioc_domain])
        db.commit()

        # Case 1: Critical Lateral Movement & C2 Activity (Pending HITL Actions)
        case1 = Case(
            title="Incident: Lateral Movement & C2 Activity",
            description="PowerShell execution and outbound C2 beaconing detected on critical Domain Controller.",
            status="open",
            severity="critical",
            score=90,
            severity_score=90,
            severity_tier="Critical",
            severity_explanation="Technique base severity contributed 36 pts. VirusTotal detections contributed 27 pts (63 engines flagged). AbuseIPDB confidence contributed 27 pts (90% confidence).",
            technique_id="T1021.002",
            technique_name="SMB/Windows Admin Shares",
            analyst_summary="### Executive Summary\nOn July 29, 2026, EDR-Defender triggered a High-Severity alert indicating suspicious outbound PowerShell execution and SMB lateral movement from host `HOST-DC-01` to external C2 infrastructure (`198.51.100.45`).\n\n### Risk & Severity Rationale\nThis incident carries a **Critical** rating (Score: **90/100**). Indicator `198.51.100.45` is flagged by 63 VirusTotal engines and carries a 90% AbuseIPDB malicious confidence score.\n\n### Recommended Containment Actions\n1. **Block IP**: Quarantine external IP `198.51.100.45` on edge firewalls.\n2. **Host Isolation**: Quarantine host `HOST-DC-01` in EDR.\n3. **Auto-Ticket**: Open critical SOC incident ticket in Jira.",
            created_at=datetime.now(timezone.utc)
        )
        db.add(case1)
        db.commit()
        db.refresh(case1)

        # Alert for Case 1
        alert1 = Alert(
            case_id=case1.id,
            alert_id="evt-rdp-9901",
            source="CrowdStrike EDR",
            severity="critical",
            title="Suspicious Outbound PowerShell & SMB Activity",
            description="PowerShell process established outbound connection to 198.51.100.45 and attempted SMB share mounting.",
            raw_payload={"process": "powershell.exe", "remote_ip": "198.51.100.45", "target_host": "HOST-DC-01"}
        )
        db.add(alert1)
        db.commit()
        alert1.iocs.append(ioc_ip)
        alert1.iocs.append(ioc_domain)
        db.commit()

        # Enrichments for IOCs
        enr_ip = Enrichment(
            ioc_id=ioc_ip.id,
            source="VirusTotal",
            raw_response={"malicious": 63, "suspicious": 2},
            summary_score=63,
            status="success"
        )
        enr_abuse = Enrichment(
            ioc_id=ioc_ip.id,
            source="AbuseIPDB",
            raw_response={"abuseConfidenceScore": 90},
            summary_score=90,
            status="success"
        )

        db.add_all([enr_ip, enr_abuse])
        db.commit()

        # Containment Actions for Case 1
        act1 = ContainmentAction(
            case_id=case1.id,
            action_type="Block_IP",
            target="198.51.100.45",
            status="pending",
            input_parameters={"ip": "198.51.100.45", "duration": "permanent"}
        )
        act2 = ContainmentAction(
            case_id=case1.id,
            action_type="Host_Isolation",
            target="HOST-DC-01",
            status="pending",
            input_parameters={"hostname": "HOST-DC-01"}
        )
        act3 = ContainmentAction(
            case_id=case1.id,
            action_type="Auto_Ticket",
            target=f"CASE-{case1.id}",
            status="pending",
            input_parameters={"priority": "P1-Critical"}
        )
        db.add_all([act1, act2, act3])
        db.commit()

        # Case 2: High Credential Access Attempt
        case2 = Case(
            title="Incident: Credential Dumping via LSASS Read",
            description="Mimikatz-style process memory access detected on host WORKSTATION-12.",
            status="open",
            severity="high",
            score=68,
            severity_score=68,
            severity_tier="High",
            severity_explanation="Technique base severity contributed 28 pts. VirusTotal detections contributed 20 pts. AbuseIPDB confidence contributed 20 pts.",
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            analyst_summary="### Executive Summary\nCredential access behavior detected on `WORKSTATION-12`. Process attempted LSASS memory handle access.\n\n### Recommended Actions\n1. **Host Isolation**: Quarantine `WORKSTATION-12`.\n2. **Auto-Ticket**: Dispatch tier-2 analyst investigation.",
            created_at=datetime.now(timezone.utc)
        )
        db.add(case2)
        db.commit()

        # Case 3: Low Adware Execution
        case3 = Case(
            title="Incident: Adware Executable Blocked",
            description="Potentially unwanted program (PUP) execution blocked by defender in Downloads directory.",
            status="open",
            severity="low",
            score=15,
            severity_score=15,
            severity_tier="Low",
            severity_explanation="Technique base severity contributed 10 pts. No malicious threat-intel indicators flagged.",
            technique_id="T1204",
            technique_name="User Execution",
            analyst_summary="### Summary\nLow-risk adware executable blocked by local host defense policy. No further containment required.",
            created_at=datetime.now(timezone.utc)
        )
        db.add(case3)
        db.commit()

        print("[SUCCESS] Demo dataset successfully seeded into PostgreSQL!")

    finally:
        db.close()


if __name__ == "__main__":
    reset_and_seed_demo_data()
