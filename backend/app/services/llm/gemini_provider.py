import time
import os
import httpx
from typing import Any
from app.core.config import settings
from app.services.llm.base import BaseLLMProvider, LLMSummaryResult
from app.services.llm.prompt_builder import SYSTEM_PROMPT, build_case_prompt

class GeminiProvider(BaseLLMProvider):
    provider_name: str = "gemini"
    default_model: str = "gemini-flash-latest"

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or settings.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY")
        self.model = model or os.getenv("GEMINI_MODEL", self.default_model)

    async def summarize_case(self, case_data: dict[str, Any]) -> LLMSummaryResult:
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not configured")

        user_prompt = build_case_prompt(case_data)
        combined_prompt = f"{SYSTEM_PROMPT}\n\n{user_prompt}"

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": combined_prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 1000
            }
        }

        start_time = time.time()
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, json=payload)

        latency_ms = int((time.time() - start_time) * 1000)

        if response.status_code == 429:
            raise RuntimeError(f"Gemini API rate limit exceeded (429): {response.text}")
        elif response.status_code >= 500:
            raise RuntimeError(f"Gemini API server error ({response.status_code}): {response.text}")
        elif response.status_code != 200:
            raise RuntimeError(f"Gemini API error ({response.status_code}): {response.text}")

        res_json = response.json()
        summary_markdown = ""
        tokens_used = 0

        try:
            candidates = res_json.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    summary_markdown = parts[0].get("text", "")
            
            usage = res_json.get("usageMetadata", {})
            tokens_used = usage.get("totalTokenCount", len(combined_prompt.split()) + len(summary_markdown.split()))
        except Exception as parse_err:
            summary_markdown = res_json.get("text", str(res_json))

        return LLMSummaryResult(
            summary_markdown=summary_markdown.strip(),
            tokens_used=tokens_used,
            latency_ms=latency_ms,
            model=self.model,
            provider=self.provider_name,
            raw_response=res_json,
        )
