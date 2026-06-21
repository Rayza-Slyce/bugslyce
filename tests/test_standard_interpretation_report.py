"""Internal Standard interpretation report helper tests."""

from __future__ import annotations

from copy import deepcopy
import inspect

from bugslyce.core.models import Candidate, Evidence, HTTPArtifact, ProjectState
from bugslyce.recon.modes import get_recon_mode
from bugslyce.reports.markdown import render_markdown_report
from bugslyce.reports.standard_interpretation import (
    StandardInterpretationReport,
    render_standard_interpretation_report,
)


def test_helper_returns_report_dataclass_with_markdown_and_metadata() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-ROBOTS"],
                tags=[],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])

    assert isinstance(report, StandardInterpretationReport)
    assert report.markdown.startswith("# BugSlyce Recon Pack")
    assert report.sources_analyzed == 1
    assert report.review_lead_count == 1
    assert report.interpretation_assembly.sources_analyzed == 1
    assert report.manual_review_leads_markdown is not None


def test_helper_places_manual_review_leads_after_operator_summary_before_scope() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-ROBOTS"],
                tags=[],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])

    assert "## Manual Review Leads" in report.markdown
    assert report.markdown.index("## Operator Summary") < report.markdown.index(
        "## Manual Review Leads"
    )
    assert report.markdown.index("## Manual Review Leads") < report.markdown.index(
        "## Scope Summary"
    )
    assert "LEAD-0001" in report.markdown
    assert "not proof of vulnerability" in report.markdown


def test_robots_artifact_renders_robots_review_lead() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-ROBOTS"],
                tags=[],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])

    assert "- Category: robots" in report.markdown
    assert "- Field: disallow" in report.markdown
    assert "Disallowed path contains high-signal wording. Manual review recommended." in report.markdown


def test_html_source_artifact_renders_html_source_review_lead() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="flag clue is in the source",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-HTML"],
                tags=[],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])

    assert "- Category: html_source" in report.markdown
    assert "- Item type: html_comment" in report.markdown
    assert "HTML comment contains clue-like wording." in report.markdown


def test_generic_encoded_body_renders_transform_review_lead() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/api/status",
                artifact_type="text_body",
                value='{"secret":"L2hpZGRlbi9mbGFn"}',
                source_file="body.txt",
                evidence_ids=["EVID-ART-TEXT"],
                tags=[],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])

    assert "- Category: artefact" in report.markdown
    assert "Possible encoded or transformed artefact detected." in report.markdown
    assert "- Decoded/derived preview: `/hidden/flag`" in report.markdown


def test_empty_project_state_renders_safe_empty_manual_review_section() -> None:
    state = _project_state()

    report = render_standard_interpretation_report(state, [])

    assert "## Manual Review Leads" in report.markdown
    assert "No interpretation review leads were generated from the provided evidence." in report.markdown
    assert "No vulnerabilities found" not in report.markdown
    assert "target is clean" not in report.markdown.lower()


def test_default_report_rendering_still_omits_manual_review_leads() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-ROBOTS"],
                tags=[],
            )
        ]
    )

    markdown = render_markdown_report(state, [])

    assert "## Manual Review Leads" not in markdown


def test_helper_does_not_mutate_project_state_or_candidates() -> None:
    state = _project_state(
        evidence=[
            Evidence(
                id="EVID-NOTE-0001",
                source_file="notes.md",
                evidence_type="note",
                value="Operator note: secret L2hpZGRlbi9mbGFn",
                context={"item_number": 1},
            )
        ]
    )
    candidates = [
        Candidate(
            id="CAND-0001",
            candidate_type="manual_context",
            title="Manual context",
            priority="low",
            rationale="Context only.",
            affected_assets=[],
            affected_endpoints=[],
            evidence_ids=["EVID-NOTE-0001"],
            suggested_manual_validation=["Review manually."],
            kill_switch_guidance=None,
        )
    ]
    state_before = deepcopy(state)
    candidates_before = deepcopy(candidates)

    render_standard_interpretation_report(state, candidates)

    assert state == state_before
    assert candidates == candidates_before


def test_helper_does_not_call_write_project_outputs() -> None:
    import bugslyce.reports.standard_interpretation as module

    source = inspect.getsource(module)

    assert "write_project_outputs" not in source


def test_quick_and_standard_available_deep_unavailable() -> None:
    assert get_recon_mode("quick").internal_profile == "lab-safe-tiny"
    assert get_recon_mode("quick").is_available
    assert get_recon_mode("standard").internal_profile == "standard-bounded"
    assert get_recon_mode("standard").is_available
    assert not get_recon_mode("deep").is_available


def _project_state(
    *,
    http_artifacts: list[HTTPArtifact] | None = None,
    evidence: list[Evidence] | None = None,
) -> ProjectState:
    return ProjectState(
        project_name="standard-report-test",
        input_dir="/tmp/standard-report-test",
        processed_files=[],
        scope_summary="No scope file parsed.",
        assets=[],
        http_services=[],
        endpoints=[],
        port_services=[],
        http_artifacts=http_artifacts or [],
        discovered_paths=[],
        recon_summary=None,
        recon_manifest=None,
        evidence=evidence or [],
        warnings=[],
        generated_at="2026-06-21T00:00:00Z",
    )
