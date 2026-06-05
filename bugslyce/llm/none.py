"""No-op LLM provider used for deterministic mode."""

from __future__ import annotations

from bugslyce.llm.base import LLMResult


class NoLLMProvider:
    """Provider implementation that never makes external calls."""

    name = "none"

    def is_available(self) -> bool:
        """No-LLM mode is always available."""

        return True

    def generate_report_enhancement(self, triage_context: dict) -> LLMResult:
        """Return a no-op result and leave deterministic output unchanged."""

        return LLMResult(
            provider=self.name,
            model=None,
            content="",
            used=False,
            warnings=["LLM provider is set to none; deterministic report only."],
        )
