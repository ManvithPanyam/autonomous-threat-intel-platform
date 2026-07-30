import time
from typing import Any
from app.services.llm.base import BaseLLMProvider, LLMSummaryResult
from app.services.llm.prompt_builder import build_case_prompt

class OpenAIProvider(BaseLLMProvider):
    provider_name: str = "openai"
    default_model: str = "gpt-4o"

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key
        self.model = model or self.default_model

    async def summarize_case(self, case_data: dict[str, Any]) -> LLMSummaryResult:
        start_time = time.time()
        prompt = build_case_prompt(case_data)
        
        case_id = case_data.get("id")
        score = case_data.get("severity_score", 0)
        tier = case_data.get("severity_tier", "Low")
        tech = case_data.get("technique_id", "T1059")

        summary_markdown = f"""### Analyst Incident Summary (Fallback: OpenAI)
**Executive Summary**: Incident case #{case_id} correlates multiple security events linked to MITRE technique {tech}.
**Risk & Severity Rationale**: Evaluated at **{score}/100** ({tier} Tier) reflecting combined threat intelligence reputation.
**Recommended Response Actions**:
1. **Block IP**: Restrict access to flagged malicious network indicators.
2. **Host Isolation**: Isolate compromised endpoints to prevent lateral movement.
3. **Auto-Ticket**: Escalate case to SOC Tier 2 response team.
*(Note: Fallback provider output - HITL review required)*"""

        latency_ms = int((time.time() - start_time) * 1000)
        tokens = len(prompt.split()) + len(summary_markdown.split())

        return LLMSummaryResult(
            summary_markdown=summary_markdown.strip(),
            tokens_used=tokens,
            latency_ms=latency_ms,
            model=self.model,
            provider=self.provider_name,
            raw_response={"status": "stub_fallback", "provider": "openai"},
        )
