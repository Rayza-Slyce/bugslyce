"""Base interfaces for optional future LLM providers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class LLMResult:
    """Result returned by an optional LLM provider."""

    provider: str
    model: str | None
    content: str
    used: bool
    warnings: list[str]


class LLMProvider(Protocol):
    """Minimal interface future provider implementations should satisfy."""

    name: str

    def is_available(self) -> bool:
        """Return whether the provider can be used in the current environment."""

    def generate_report_enhancement(self, triage_context: dict) -> LLMResult:
        """Return optional report enhancement content for minimized triage context."""
