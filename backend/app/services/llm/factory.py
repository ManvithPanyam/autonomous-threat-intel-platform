from app.services.llm.base import BaseLLMProvider
from app.services.llm.gemini_provider import GeminiProvider
from app.services.llm.claude_provider import ClaudeProvider
from app.services.llm.openai_provider import OpenAIProvider

_providers: dict[str, type[BaseLLMProvider]] = {
    "gemini": GeminiProvider,
    "claude": ClaudeProvider,
    "openai": OpenAIProvider,
}

def get_llm_provider(provider_name: str = "gemini") -> BaseLLMProvider:
    """
    Returns an instance of the requested primary LLM provider (defaults to Gemini).
    """
    provider_cls = _providers.get(provider_name.lower(), GeminiProvider)
    return provider_cls()

def get_fallback_provider(preferred_fallback: str = "claude") -> BaseLLMProvider:
    """
    Returns an instance of the fallback LLM provider (defaults to Claude).
    """
    provider_cls = _providers.get(preferred_fallback.lower(), ClaudeProvider)
    return provider_cls()
