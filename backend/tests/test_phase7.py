import unittest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import engine, SessionLocal
from app.models.base import Base
from app.models.case import Case
from app.models.alert import Alert
from app.models.ioc import IOC
from app.models.enrichment import Enrichment
from app.models.llm_log import LLMPromptLog
from app.services.llm import (
    BaseLLMProvider,
    LLMSummaryResult,
    GeminiProvider,
    ClaudeProvider,
    OpenAIProvider,
    get_llm_provider,
    get_fallback_provider,
)
from app.services.llm.prompt_builder import build_case_prompt
from app.workers.summarizer_tasks import summarize_case_task, assemble_case_data


class TestPhase7(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=engine)
        self.connection = engine.connect()
        with self.connection.begin():
            self.connection.execute(LLMPromptLog.__table__.delete())
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

    def test_provider_factory(self):
        """Verify LLM factory returns correct primary and fallback providers."""
        gemini = get_llm_provider("gemini")
        self.assertIsInstance(gemini, GeminiProvider)

        claude = get_llm_provider("claude")
        self.assertIsInstance(claude, ClaudeProvider)

        openai = get_llm_provider("openai")
        self.assertIsInstance(openai, OpenAIProvider)

        fallback = get_fallback_provider()
        self.assertIsInstance(fallback, ClaudeProvider)

    def test_prompt_builder(self):
        """Verify prompt builder formats case metadata, alerts, IOCs, and MITRE fields correctly."""
        case_data = {
            "id": 101,
            "status": "open",
            "created_at": "2026-07-27T21:00:00Z",
            "severity_score": 85,
            "severity_tier": "Critical",
            "severity_explanation": "Base severity 85.",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "matched_via": "lookup",
            "alerts": [
                {
                    "title": "Outbound C2 Beaconing",
                    "description": "High frequency beaconing",
                    "source": "EDR",
                    "event_type": "network",
                }
            ],
            "iocs": [
                {
                    "indicator": "203.0.113.5",
                    "indicator_type": "ip",
                    "source": "virustotal",
                    "reputation_score": 50,
                    "status": "success",
                }
            ],
        }

        prompt = build_case_prompt(case_data)
        self.assertIn("Case ID: 101", prompt)
        self.assertIn("Critical", prompt)
        self.assertIn("T1071", prompt)
        self.assertIn("203.0.113.5", prompt)

    @patch("httpx.AsyncClient.post")
    def test_gemini_provider_mocked(self, mock_post):
        """Verify GeminiProvider makes REST call and parses response correctly."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": "### Analyst Incident Summary\n**Executive Summary**: C2 beaconing detected."
                            }
                        ]
                    }
                }
            ],
            "usageMetadata": {"totalTokenCount": 150},
        }
        mock_post.return_value = mock_response

        provider = GeminiProvider(api_key="test_mock_key")
        case_data = {"id": 1, "severity_score": 90, "severity_tier": "Critical"}

        result = asyncio.run(provider.summarize_case(case_data))
        self.assertIsInstance(result, LLMSummaryResult)
        self.assertEqual(result.provider, "gemini")
        self.assertIn("C2 beaconing detected", result.summary_markdown)
        self.assertEqual(result.tokens_used, 150)

    @patch("app.workers.summarizer_tasks.get_llm_provider")
    def test_summarize_case_task_success(self, mock_get_provider):
        """Verify summarize_case_task executes, updates Case.analyst_summary and writes DB log."""
        mock_provider = MagicMock()
        mock_provider.provider_name = "gemini"
        mock_provider.summarize_case = AsyncMock(
            return_value=LLMSummaryResult(
                summary_markdown="### Incident Summary\n**Executive Summary**: Malicious activity detected.",
                tokens_used=120,
                latency_ms=350,
                model="gemini-1.5-flash",
                provider="gemini",
            )
        )
        mock_get_provider.return_value = mock_provider

        # Setup test case in DB
        case = Case(
            title="Test Case Phase 7",
            status="open",
            severity_score=75,
            severity_tier="High",
        )
        self.db.add(case)
        self.db.commit()

        # Execute task
        res = summarize_case_task(case.id)
        self.assertEqual(res["status"], "success")

        # Verify DB updates
        self.db.refresh(case)
        self.assertIn("Malicious activity detected", case.analyst_summary)

        log = self.db.query(LLMPromptLog).filter(LLMPromptLog.case_id == case.id).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.provider, "gemini")
        self.assertEqual(log.tokens_used, 120)

    @patch("app.workers.summarizer_tasks.get_fallback_provider")
    @patch("app.workers.summarizer_tasks.get_llm_provider")
    def test_summarize_case_task_fallback(self, mock_get_provider, mock_get_fallback):
        """Verify task falls back to secondary provider when primary fails."""
        primary_mock = MagicMock()
        primary_mock.provider_name = "gemini"
        primary_mock.summarize_case = AsyncMock(side_effect=RuntimeError("500 Server Error"))
        mock_get_provider.return_value = primary_mock

        fallback_mock = MagicMock()
        fallback_mock.provider_name = "claude"
        fallback_mock.summarize_case = AsyncMock(
            return_value=LLMSummaryResult(
                summary_markdown="### Fallback Summary\nGenerated via Claude fallback.",
                tokens_used=90,
                latency_ms=200,
                model="claude-3-5-sonnet-20241022",
                provider="claude",
            )
        )
        mock_get_fallback.return_value = fallback_mock

        case = Case(title="Fallback Test Case", status="open", severity_score=60)
        self.db.add(case)
        self.db.commit()

        # Run task with max_retries set to 0 on task instance mock if needed, or catch retries
        with patch.object(summarize_case_task, "max_retries", 0):
            res = summarize_case_task(case.id)

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["provider"], "claude")

        self.db.refresh(case)
        self.assertIn("Generated via Claude fallback", case.analyst_summary)


if __name__ == "__main__":
    unittest.main()
