from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

@dataclass
class LLMSummaryResult:
    summary_markdown: str
    tokens_used: int
    latency_ms: int
    model: str
    provider: str
    raw_response: dict[str, Any] | None = None

class BaseLLMProvider(ABC):
    provider_name: str = "base"
    default_model: str = "base-model"

    @abstractmethod
    async def summarize_case(self, case_data: dict[str, Any]) -> LLMSummaryResult:
        """
        Asynchronously generates an analyst-facing markdown summary for a security Case.
        """
        pass
