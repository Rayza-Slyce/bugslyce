"""Offline Standard interpretation assembly tests."""

from __future__ import annotations

from copy import deepcopy

from bugslyce.core.models import Evidence, HTTPArtifact, ProjectState
from bugslyce.recon.modes import get_recon_mode
from bugslyce.recon.standard_interpretation import (
    assemble_standard_interpretation_from_project_state,
)
from bugslyce.reports.markdown import render_markdown_report


def test_empty_project_state_produces_empty_safe_assembly() -> None:
    state = _project_state()

    assembly = assemble_standard_interpretation_from_project_state(state)

    assert assembly.sources == ()
    assert assembly.sources_analyzed == 0
    assert assembly.review_lead_count == 0
    assert assembly.collection.review_leads == ()
    assert assembly.manual_review_leads_markdown is not None
    assert "## Manual Review Leads" in assembly.manual_review_leads_markdown
    assert "No interpretation review leads were generated" in assembly.manual_review_leads_markdown
    assert "No vulnerabilities found" not in assembly.manual_review_leads_markdown


def test_robots_artifact_produces_robots_review_lead_through_full_chain() -> None:
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

    assembly = assemble_standard_interpretation_from_project_state(state)

    assert assembly.sources_analyzed == 1
    assert assembly.review_lead_count == 1
    lead = assembly.review_leads[0]
    assert lead.lead_id == "LEAD-0001"
    assert lead.category == "robots"
    assert lead.field_name == "disallow"
    assert "## Manual Review Leads" in (assembly.manual_review_leads_markdown or "")
    assert "LEAD-0001" in (assembly.manual_review_leads_markdown or "")


def test_html_source_evidence_produces_html_review_lead_through_full_chain() -> None:
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

    assembly = assemble_standard_interpretation_from_project_state(state)

    assert assembly.sources[0].source_kind == "html"
    assert assembly.review_leads[0].category == "html_source"
    assert assembly.review_leads[0].item_type == "html_comment"
    assert "HTML comment contains clue-like wording." in (
        assembly.manual_review_leads_markdown or ""
    )


def test_generic_encoded_text_produces_artefact_review_lead_through_full_chain() -> None:
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

    assembly = assemble_standard_interpretation_from_project_state(state)

    assert assembly.sources[0].source_kind == "response_body"
    assert assembly.review_leads[0].category == "artefact"
    assert assembly.review_leads[0].lead_type == "possible_transform"
    assert assembly.review_leads[0].decoded_preview == "/hidden/flag"
    assert "Possible encoded or transformed artefact detected." in (
        assembly.manual_review_leads_markdown or ""
    )


def test_notes_evidence_is_included_when_supported_by_mapper() -> None:
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

    assembly = assemble_standard_interpretation_from_project_state(state)

    assert assembly.sources[0].source_kind == "notes"
    assert assembly.sources[0].source_id == "EVID-NOTE-0001"
    assert assembly.review_leads[0].lead_id == "LEAD-0001"
    assert assembly.review_leads[0].category == "artefact"
    assert "LEAD-0001" in (assembly.manual_review_leads_markdown or "")


def test_render_markdown_false_disables_manual_review_markdown() -> None:
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

    assembly = assemble_standard_interpretation_from_project_state(
        state,
        render_markdown=False,
    )

    assert assembly.review_lead_count == 1
    assert assembly.collection.manual_review_leads_markdown is None
    assert assembly.manual_review_leads_markdown is None


def test_assembly_does_not_mutate_project_state() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="secret clue",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-HTML"],
                tags=[],
            )
        ]
    )
    before = deepcopy(state)

    assemble_standard_interpretation_from_project_state(state)

    assert state == before


def test_current_report_generation_remains_unchanged_by_default() -> None:
    state = _project_state()

    report = render_markdown_report(state, [])

    assert "## Manual Review Leads" not in report


def test_quick_standard_and_deep_availability() -> None:
    assert get_recon_mode("quick").internal_profile == "lab-safe-tiny"
    assert get_recon_mode("quick").is_available
    assert get_recon_mode("standard").internal_profile == "standard-bounded"
    assert get_recon_mode("standard").is_available
    assert get_recon_mode("deep").is_available


def _project_state(
    *,
    http_artifacts: list[HTTPArtifact] | None = None,
    evidence: list[Evidence] | None = None,
) -> ProjectState:
    return ProjectState(
        project_name="standard-interpretation-test",
        input_dir="/tmp/standard-interpretation-test",
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
