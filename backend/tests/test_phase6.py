import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.session import engine, SessionLocal
from app.models.base import Base
from app.models.case import Case
from app.models.alert import Alert
from app.models.ioc import IOC
from app.models.mitre import MITRETechnique, alert_mitre_techniques
from app.api.schemas.alert import AlertCreate, IOCIn
from app.services.alert_service import create_ingested_alert
from app.services.mitre_service import map_alert_to_mitre_techniques, calculate_case_score

class TestPhase6(unittest.TestCase):
    def setUp(self):
        # Create schema if not exists
        Base.metadata.create_all(bind=engine)
        self.connection = engine.connect()
        # Clean tables to isolate test data
        with self.connection.begin():
            self.connection.execute(Base.metadata.tables['alert_mitre_techniques'].delete())
            self.connection.execute(Base.metadata.tables['alert_iocs'].delete())
            self.connection.execute(Base.metadata.tables['enrichments'].delete())
            self.connection.execute(Base.metadata.tables['mitre_techniques'].delete())
            self.connection.execute(IOC.__table__.delete())
            self.connection.execute(Alert.__table__.delete())
            self.connection.execute(Case.__table__.delete())
        
        # Start transaction
        self.transaction = self.connection.begin()
        self.db = SessionLocal(bind=self.connection)

    def tearDown(self):
        self.db.close()
        self.transaction.rollback()
        self.connection.close()

    def test_alert_mitre_mapping_heuristics(self):
        """Verify that alert descriptions/titles match MITRE techniques deterministically."""
        # Create an alert
        alert = Alert(
            alert_id="a-mitre-1",
            source="Defender",
            severity="medium",
            title="Credential stuffing attack detected",
            description="Multiple failed login attempts from a single IP address mimicking a brute force pattern.",
            raw_payload={}
        )
        self.db.add(alert)
        self.db.commit()

        mapped = map_alert_to_mitre_techniques(self.db, alert)
        
        # Verify it mapped to T1110 (Brute Force)
        self.assertEqual(len(mapped), 1)
        self.assertEqual(mapped[0].technique_id, "T1110")
        self.assertEqual(mapped[0].tactic, "Credential Access")
        self.assertEqual(mapped[0].name, "Brute Force")

    def test_case_severity_escalation_lateral_movement(self):
        """Verify case severity escalates to High when Lateral Movement technique matches."""
        # Create alert that matches Lateral Movement
        alert_in = AlertCreate(
            alert_id="a-lat-1",
            source="Splunk",
            severity="medium", # base weight 3
            title="Lateral movement via Remote Desktop",
            description="Suspicious RDP activity detected internally.",
            iocs=[],
            raw_payload={}
        )
        
        with patch("app.services.alert_service.enrich_alert_task.delay") as mock_delay:
            alert = create_ingested_alert(self.db, alert_in)
            
            # Retrieve the created Case
            case = self.db.query(Case).filter(Case.id == alert.case_id).first()
            self.assertIsNotNone(case)
            
            map_alert_to_mitre_techniques(self.db, alert)
            calculate_case_score(self.db, case.id)

            # Score = base (3) + MITRE lateral movement weight (3) = 6 (Medium)
            self.assertEqual(case.score, 6)
            self.assertEqual(case.severity, "medium")

            # Let's adjust alert to make base severity high (6)
            # Score = base (6) + MITRE lateral movement weight (3) = 9 (High)
            alert.severity = "high"
            self.db.commit()
            calculate_case_score(self.db, case.id)
            
            self.assertEqual(case.score, 9)
            self.assertEqual(case.severity, "high")

    def test_case_severity_escalation_exfiltration(self):
        """Verify case severity escalates to Critical when Exfiltration technique matches."""
        # Create alert that matches Exfiltration
        alert_in = AlertCreate(
            alert_id="a-exf-1",
            source="Splunk",
            severity="high", # base weight 6
            title="Data upload detected",
            description="Large exfiltration of document archives to mega.nz.",
            iocs=[],
            raw_payload={}
        )
        
        with patch("app.services.alert_service.enrich_alert_task.delay") as mock_delay:
            alert = create_ingested_alert(self.db, alert_in)
            
            case = self.db.query(Case).filter(Case.id == alert.case_id).first()
            self.assertIsNotNone(case)
            
            map_alert_to_mitre_techniques(self.db, alert)
            calculate_case_score(self.db, case.id)

            # Score = base (6) + MITRE exfiltration weight (4) = 10 (High)
            self.assertEqual(case.score, 10)
            self.assertEqual(case.severity, "high")

            # Adjust alert base to critical (9)
            # Score = base (9) + MITRE exfiltration weight (4) = 13 (Critical)
            alert.severity = "critical"
            self.db.commit()
            calculate_case_score(self.db, case.id)
            
            self.assertEqual(case.score, 13)
            self.assertEqual(case.severity, "critical")

if __name__ == "__main__":
    unittest.main()
