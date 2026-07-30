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
        Base.metadata.create_all(bind=engine)
        self.connection = engine.connect()
        with self.connection.begin():
            self.connection.execute(Base.metadata.tables['alert_iocs'].delete())
            self.connection.execute(Base.metadata.tables['enrichments'].delete())
            self.connection.execute(IOC.__table__.delete())
            self.connection.execute(Alert.__table__.delete())
            self.connection.execute(Case.__table__.delete())
        self.transaction = self.connection.begin()
        self.db = SessionLocal(bind=self.connection)

    def tearDown(self):
        self.db.close()
        self.transaction.rollback()
        self.connection.close()

    def test_case_correlation_time_window(self):
        """Verify that alerts do not correlate to resolved cases."""
        old_case = Case(
            title="Resolved Case",
            status="resolved",
            severity="high"
        )
        self.db.add(old_case)
        self.db.commit()

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

        new_alert_in = AlertCreate(
            alert_id="alert-2",
            source="test",
            severity="high",
            title="New Alert",
            description="Testing status window",
            iocs=[IOCIn(ioc_type="ip", value="1.1.1.1")],
            raw_payload={}
        )
        
        with patch("app.services.alert_service.enrich_alert_task.delay") as mock_delay:
            result_alert = create_ingested_alert(self.db, new_alert_in)
            self.assertNotEqual(result_alert.case_id, old_case.id)
            self.assertEqual(self.db.query(Case).count(), 2)

    def test_case_correlation_multiple_matching_cases(self):
        """Verify alert links to an active case sharing matching IOCs."""
        case_a = Case(title="Case A", status="open", severity="high")
        self.db.add(case_a)
        self.db.commit()

        ioc_a = IOC(ioc_type="ip", value="1.1.1.1")
        self.db.add(ioc_a)
        self.db.commit()

        alert_a = Alert(case_id=case_a.id, alert_id="a1", source="t", severity="h", title="A", raw_payload={})
        self.db.add(alert_a)
        self.db.commit()
        alert_a.iocs.append(ioc_a)
        self.db.commit()

        new_alert_in = AlertCreate(
            alert_id="c1",
            source="test",
            severity="high",
            title="Overlapping Alert",
            description="Testing multiple matches",
            iocs=[
                IOCIn(ioc_type="ip", value="1.1.1.1"),
            ],
            raw_payload={}
        )

        with patch("app.services.alert_service.enrich_alert_task.delay") as mock_delay:
            result_alert = create_ingested_alert(self.db, new_alert_in)
            self.assertEqual(result_alert.case_id, case_a.id)

    def test_enrichment_caching_and_api_queries(self):
        """Verify that enrichment checks cache and queries external APIs on cache miss."""
        ioc = IOC(ioc_type="ip", value="8.8.8.8")
        self.db.add(ioc)
        self.db.commit()

        with patch("app.services.enrichment.query_virustotal") as mock_vt, \
             patch("app.services.enrichment.query_abuseipdb") as mock_abuse:
            
            mock_vt.return_value = {"vt_data": "ok"}
            mock_abuse.return_value = {"abuse_data": "ok"}

            results = enrich_ioc(self.db, ioc)
            self.assertEqual(results["virustotal"], {"vt_data": "ok"})
            self.assertEqual(results["abuseipdb"], {"abuse_data": "ok"})
            self.assertEqual(mock_vt.call_count, 1)
            self.assertEqual(mock_abuse.call_count, 1)

            enrichments_in_db = self.db.query(Enrichment).filter_by(ioc_id=ioc.id).all()
            self.assertEqual(len(enrichments_in_db), 2)

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

        expired_enrichment = Enrichment(
            ioc_id=ioc.id,
            source="virustotal",
            raw_response={"vt_data": "expired"}
        )
        self.db.add(expired_enrichment)
        self.db.commit()
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
