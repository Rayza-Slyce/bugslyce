"""Language safety tests for generated triage text."""

from __future__ import annotations

from pathlib import Path

from bugslyce.core.models import Candidate
from bugslyce.core.project import build_project_state
from bugslyce.reports.markdown import render_markdown_report
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


def test_candidate_language_avoids_forbidden_terms() -> None:
    candidates: list[Candidate] = []
    for fixture_dir in FIXTURES_ROOT.iterdir():
        if fixture_dir.is_dir():
            candidates.extend(generate_candidates(build_project_state(fixture_dir)))

    text = "\n".join(
        "\n".join(
            [
                candidate.title,
                candidate.rationale,
                candidate.kill_switch_guidance or "",
                *candidate.suggested_manual_validation,
            ]
        )
        for candidate in candidates
    ).lower()

    assert not any(term in text for term in FORBIDDEN_TERMS)


def test_markdown_report_language_avoids_forbidden_terms() -> None:
    reports: list[str] = []
    for fixture_name in ("basic_saas", "lab_raw_recon_pack"):
        state = build_project_state(FIXTURES_ROOT / fixture_name)
        candidates = generate_candidates(state)
        reports.append(render_markdown_report(state, candidates))
    report = "\n".join(reports).lower()

    assert not any(term in report for term in FORBIDDEN_TERMS)
