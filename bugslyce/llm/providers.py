"""Provider selection helpers for optional future LLM support."""

from __future__ import annotations

from bugslyce.llm.base import LLMProvider
from bugslyce.llm.none import NoLLMProvider


FUTURE_PROVIDERS = {"gemini", "openai", "anthropic", "ollama"}


class LLMProviderNotImplementedError(RuntimeError):
    """Raised when a future provider is configured before implementation exists."""


def get_llm_provider(provider_name: str | None, model: str | None = None) -> LLMProvider:
    """Return a provider implementation for the configured provider name."""

    provider = (provider_name or "none").strip().lower() or "none"
    if provider == "none":
        return NoLLMProvider()
    if provider in FUTURE_PROVIDERS:
        raise LLMProviderNotImplementedError(
            f"LLM provider '{provider}' is configured but not implemented yet. "
            "Use 'bugslyce config reset' to return to no-LLM mode."
        )
    raise LLMProviderNotImplementedError(
        f"LLM provider '{provider}' is not recognised. "
        "Use 'bugslyce config reset' to return to no-LLM mode."
    )
