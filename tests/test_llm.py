"""Tests for no-LLM provider abstraction and minimized context."""

from __future__ import annotations

import json
from pathlib import Path

from bugslyce.core.project import build_project_state
from bugslyce.llm.none import NoLLMProvider
from bugslyce.llm.prompt_builder import build_minimised_triage_context, estimate_context_size
from bugslyce.llm.providers import LLMProviderNotImplementedError, get_llm_provider
from bugslyce.triage.candidates import generate_candidates


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"
FORBIDDEN_TERMS = (
    "vulnerable",
    "confirmed vulnerability",
    "exploitable",
    "exploit this",
    "pwned",
    "compromised",
    "breached",
    "owned",
)


def _basic_saas_state_and_candidates():
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    return state, generate_candidates(state)


def test_no_llm_provider_is_available() -> None:
    provider = NoLLMProvider()

    assert provider.name == "none"
    assert provider.is_available() is True


def test_provider_factory_returns_no_llm_for_none_and_empty() -> None:
    assert isinstance(get_llm_provider("none"), NoLLMProvider)
    assert isinstance(get_llm_provider(""), NoLLMProvider)
    assert isinstance(get_llm_provider(None), NoLLMProvider)


def test_provider_factory_future_providers_fail_gracefully() -> None:
    for provider_name in ("gemini", "openai", "anthropic", "ollama"):
        try:
            get_llm_provider(provider_name)
        except LLMProviderNotImplementedError as exc:
            assert provider_name in str(exc)
            assert "not implemented yet" in str(exc)
        else:
            raise AssertionError(f"{provider_name} should not be implemented in this phase")


def test_no_llm_provider_returns_used_false_without_external_behavior() -> None:
    provider = NoLLMProvider()
    result = provider.generate_report_enhancement({"project_name": "demo"})

    assert result.provider == "none"
    assert result.model is None
    assert result.content == ""
    assert result.used is False
    assert result.warnings == ["LLM provider is set to none; deterministic report only."]


def test_minimised_context_includes_counts_and_candidates() -> None:
    state, candidates = _basic_saas_state_and_candidates()

    context = build_minimised_triage_context(state, candidates)

    assert context["project_name"] == "basic_saas"
    assert context["asset_count"] == len(state.assets)
    assert context["endpoint_count"] == len(state.endpoints)
    assert context["candidate_count"] == len(candidates)
    assert context["top_candidates"]
    assert context["top_candidates"][0]["id"].startswith("CAND-")


def test_minimised_context_caps_endpoint_and_evidence_detail() -> None:
    state, candidates = _basic_saas_state_and_candidates()

    context = build_minimised_triage_context(
        state,
        candidates,
        max_candidates=2,
        max_endpoints_per_candidate=1,
        max_evidence=3,
    )

    assert len(context["top_candidates"]) == 2
    assert all(len(candidate["affected_endpoints"]) <= 1 for candidate in context["top_candidates"])
    assert len(context["evidence_summary"]) == 3


def test_minimised_context_contains_language_rules_and_privacy_note() -> None:
    state, candidates = _basic_saas_state_and_candidates()

    context = build_minimised_triage_context(state, candidates)

    assert "manual review" in context["language_rules"]["prefer"]
    assert context["language_rules"]["avoid"]
    assert context["privacy_note"] == "Raw recon files are not included by default."


def test_estimated_context_size_is_positive_integer() -> None:
    state, candidates = _basic_saas_state_and_candidates()
    context = build_minimised_triage_context(state, candidates)

    size = estimate_context_size(context)

    assert isinstance(size, int)
    assert size > 0


def test_no_forbidden_language_in_no_llm_result_or_context() -> None:
    state, candidates = _basic_saas_state_and_candidates()
    provider = NoLLMProvider()
    result = provider.generate_report_enhancement({})
    context = build_minimised_triage_context(state, candidates)

    text = json.dumps(
        {
            "result": {
                "content": result.content,
                "warnings": result.warnings,
            },
            "context": context,
        },
        sort_keys=True,
    ).lower()

    assert not any(term in text for term in FORBIDDEN_TERMS)
