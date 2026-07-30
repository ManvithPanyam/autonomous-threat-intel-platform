import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.session import engine, SessionLocal
from app.models.base import Base
from app.models.case import Case
from app.models.alert import Alert
from app.models.ioc import IOC
from app.models.enrichment import Enrichment
from app.api.schemas.alert import AlertCreate, IOCIn
from app.services.alert_service import create_ingested_alert
from app.services.enrichment import enrich_ioc, RateLimitException, get_cached_enrichment, save_enrichment

from app.core.celery_app import celery_app

class TestPhase5(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        celery_app.conf.update(
            broker_url="memory://",
            result_backend="cache+memory://",
            task_always_eager=True,
            task_eager_propagates=True,
        )

    def setUp(self):

        # Bind to the real engine, create tables if not exists
        Base.metadata.create_all(bind=engine)
        self.connection = engine.connect()
        # Clean tables within a transaction block to ensure isolation and commit
        with self.connection.begin():
            self.connection.execute(Base.metadata.tables['alert_iocs'].delete())
            self.connection.execute(Base.metadata.tables['enrichments'].delete())
            self.connection.execute(IOC.__table__.delete())
            self.connection.execute(Alert.__table__.delete())
            self.connection.execute(Case.__table__.delete())
        # Begin a transaction for the test case itself
        self.transaction = self.connection.begin()
        # Bind SessionLocal to this connection
        self.db = SessionLocal(bind=self.connection)

    def tearDown(self):
        self.db.close()
        # Roll back transaction to keep DB clean
        self.transaction.rollback()
        self.connection.close()

    def test_case_correlation_time_window(self):
        """Verify that alerts do not correlate to active cases older than 7 days."""
        # Create an active case and update its updated_at to 8 days ago
        old_case = Case(
            title="Old Case",
            status="open",
            severity="high"
        )
        self.db.add(old_case)
        self.db.commit()
        
        # Inject old date manually using SQL
        self.db.execute(
            Case.__table__.update()
            .where(Case.id == old_case.id)
            .values(updated_at=datetime.now(timezone.utc) - timedelta(days=8))
        )
        self.db.commit()
        self.db.refresh(old_case)

        # Add an alert to that case with an IOC
        ioc = IOC(ioc_type="ip", value="1.1.1.1")
        self.db.add(ioc)
        self.db.commit()
        
        old_alert = Alert(
            case_id=old_case.id,
            alert_id="alert-1",
            source="test",
            severity="high",
            title="Old Alert",
            raw_payload={}
        )
        self.db.add(old_alert)
        self.db.commit()
        old_alert.iocs.append(ioc)
        self.db.commit()

        # Ingest a new alert with the same IOC
        new_alert_in = AlertCreate(
            alert_id="alert-2",
            source="test",
            severity="high",
            title="New Alert",
            description="Testing time window",
            iocs=[IOCIn(ioc_type="ip", value="1.1.1.1")],
            raw_payload={}
        )
        
        with patch("app.services.alert_service.enrich_alert_task.delay") as mock_delay:
            result_alert = create_ingested_alert(self.db, new_alert_in)
            self.assertNotEqual(result_alert.case_id, old_case.id)
            # A new case should have been created
            self.assertEqual(self.db.query(Case).count(), 2)

    def test_case_correlation_multiple_matching_cases(self):
        """Verify alert links to the most recently updated case when multiple match."""
        # Case A: Older
        case_a = Case(title="Case A", status="open", severity="high")
        self.db.add(case_a)
        self.db.commit()
        self.db.execute(
            Case.__table__.update()
            .where(Case.id == case_a.id)
            .values(updated_at=datetime.now(timezone.utc) - timedelta(days=3))
        )
        self.db.commit()

        # Case B: Newer
        case_b = Case(title="Case B", status="open", severity="high")
        self.db.add(case_b)
        self.db.commit()
        self.db.execute(
            Case.__table__.update()
            .where(Case.id == case_b.id)
            .values(updated_at=datetime.now(timezone.utc) - timedelta(days=1))
        )
        self.db.commit()

        # Add IOCs to both cases
        ioc_a = IOC(ioc_type="ip", value="1.1.1.1")
        ioc_b = IOC(ioc_type="ip", value="2.2.2.2")
        self.db.add_all([ioc_a, ioc_b])
        self.db.commit()

        alert_a = Alert(case_id=case_a.id, alert_id="a1", source="t", severity="h", title="A", raw_payload={})
        alert_b = Alert(case_id=case_b.id, alert_id="b1", source="t", severity="h", title="B", raw_payload={})
        self.db.add_all([alert_a, alert_b])
        self.db.commit()
        alert_a.iocs.append(ioc_a)
        alert_b.iocs.append(ioc_b)
        self.db.commit()

        # New alert containing BOTH IOCs
        new_alert_in = AlertCreate(
            alert_id="c1",
            source="test",
            severity="high",
            title="Overlapping Alert",
            description="Testing multiple matches",
            iocs=[
                IOCIn(ioc_type="ip", value="1.1.1.1"),
                IOCIn(ioc_type="ip", value="2.2.2.2")
            ],
            raw_payload={}
        )

        with patch("app.services.alert_service.enrich_alert_task.delay") as mock_delay:
            result_alert = create_ingested_alert(self.db, new_alert_in)
            # Should link to case_b because it has the newer updated_at timestamp (1 day ago vs 3 days ago)
            self.assertEqual(result_alert.case_id, case_b.id)

    def test_enrichment_caching_and_api_queries(self):
        """Verify that enrichment checks cache and queries external APIs on cache miss."""
        ioc = IOC(ioc_type="ip", value="8.8.8.8")
        self.db.add(ioc)
        self.db.commit()

        # Mock API calls
        with patch("app.services.enrichment.query_virustotal") as mock_vt, \
             patch("app.services.enrichment.query_abuseipdb") as mock_abuse:
            
            mock_vt.return_value = {"vt_data": "ok"}
            mock_abuse.return_value = {"abuse_data": "ok"}

            # 1. First run: Cache miss, queries APIs
            results = enrich_ioc(self.db, ioc)
            self.assertEqual(results["virustotal"], {"vt_data": "ok"})
            self.assertEqual(results["abuseipdb"], {"abuse_data": "ok"})
            self.assertEqual(mock_vt.call_count, 1)
            self.assertEqual(mock_abuse.call_count, 1)

            # Check that database has saved the enrichments
            enrichments_in_db = self.db.query(Enrichment).filter_by(ioc_id=ioc.id).all()
            self.assertEqual(len(enrichments_in_db), 2)

            # 2. Second run: Cache hit, should not query APIs again
            mock_vt.reset_mock()
            mock_abuse.reset_mock()
            
            results_cached = enrich_ioc(self.db, ioc)
            self.assertEqual(results_cached["virustotal"], {"vt_data": "ok"})
            self.assertEqual(results_cached["abuseipdb"], {"abuse_data": "ok"})
            self.assertEqual(mock_vt.call_count, 0)
            self.assertEqual(mock_abuse.call_count, 0)

    def test_enrichment_ttl_boundary(self):
        """Verify that cache hits under 24h work, but expired cache refetches."""
        ioc = IOC(ioc_type="ip", value="9.9.9.9")
        self.db.add(ioc)
        self.db.commit()

        # Save an expired cache entry (25 hours ago)
        expired_enrichment = Enrichment(
            ioc_id=ioc.id,
            source="virustotal",
            raw_response={"vt_data": "expired"}
        )
        self.db.add(expired_enrichment)
        self.db.commit()
        # Set created_at to 25 hours ago
        self.db.execute(
            Enrichment.__table__.update()
            .where(Enrichment.id == expired_enrichment.id)
            .values(created_at=datetime.now(timezone.utc) - timedelta(hours=25))
        )
        self.db.commit()

        with patch("app.services.enrichment.query_virustotal") as mock_vt, \
             patch("app.services.enrichment.query_abuseipdb") as mock_abuse:
            mock_vt.return_value = {"vt_data": "new"}
            mock_abuse.return_value = {"abuse_data": "new"}

            # Because virustotal is expired (> 24h), it should refetch
            results = enrich_ioc(self.db, ioc)
            self.assertEqual(results["virustotal"], {"vt_data": "new"})
            self.assertEqual(mock_vt.call_count, 1)

    def test_celery_task_retry_on_429(self):
        """Verify Celery task raises a Retry exception if 429 Rate Limit occurs."""
        from app.workers.enrichment_tasks import enrich_with_virustotal
        from celery.exceptions import Retry

        with patch("app.workers.enrichment_tasks.query_virustotal", side_effect=Exception("429 Rate Limit")):
            with patch("app.workers.enrichment_tasks.SessionLocal", return_value=self.db):
                with patch.object(enrich_with_virustotal, "retry", side_effect=Retry("task retried")) as mock_retry:
                    with self.assertRaises(Retry):
                        enrich_with_virustotal(1, "8.8.8.8", "ip")
                    self.assertEqual(mock_retry.call_count, 1)




if __name__ == "__main__":
    unittest.main()
