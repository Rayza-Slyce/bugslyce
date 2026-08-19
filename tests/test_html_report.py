"""Tests for the self-contained offline HTML evidence report."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from html import unescape
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import pytest

from bugslyce.reports import html as html_module
from bugslyce.cli import main
from bugslyce.core.project import build_project_state
from bugslyce.reports.html import (
    build_html_report_model,
    render_html_report,
    write_html_report,
    write_project_html_report,
)
from bugslyce.reports.human_triage import (
    build_human_triage_brief,
    render_human_triage_brief_markdown,
)
from bugslyce.reports.markdown import export_project_state_json, render_markdown_report
from bugslyce.reports.operator_summary import (
    OperatorSummary,
    OperatorSummaryLead,
    build_operator_summary,
)
from bugslyce.reports.investigation_context import (
    RELATED,
    InvestigationContextBacklink,
    InvestigationContextItem,
    InvestigationContextSources,
)
from bugslyce.reports.investigation_context_presentation import (
    build_investigation_context_presentation_index,
)
from bugslyce.reports.analysis_coverage import (
    ANALYSIS_COVERAGE_FILENAME,
    AnalysisCoverageExecutionEvidence,
    AnalysisCoverageOutcome,
    AnalysisCoverageUnit,
    write_analysis_coverage_artifact,
)
from bugslyce.reports.operator_report_view import build_operator_report_view
from bugslyce.recon.collection_confidence import render_collection_confidence_markdown
from bugslyce.recon.deep_source_route_collection_export import (
    deep_source_route_collection_result_to_dict,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
    DeepSourceRouteSkippedItem,
)
from bugslyce.recon.deep_metadata_collection_export import (
    write_deep_metadata_collection_artifacts,
)
from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
)
from bugslyce.recon.deep_response_similarity_review import (
    render_deep_response_similarity_review_markdown,
)
from bugslyce.recon.standard_interpretation import (
    assemble_standard_interpretation_from_project_state,
)
from bugslyce.triage.candidates import generate_candidates


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def test_html_report_renders_existing_structured_review_data(tmp_path: Path) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    output = tmp_path / "report.html"

    written = write_html_report(pack, output)

    html = written.read_text(encoding="utf-8")
    assert written == output
    assert "BugSlyce Evidence Report" in html
    assert "Reconnaissance review leads are observations, not confirmed vulnerabilities." in html
    assert "Operator summary" in html
    assert "Manual review leads" in html
    assert "Routes and provenance" in html
    assert "HTTP evidence" in html
    assert "Evidence records" in html
    assert "project_state.json" in html
    assert "High-port HTTP service review" in html
    assert 'id="report-search"' in html
    assert 'data-status="200"' in html
    assert "<details" in html


def test_html_model_renders_only_available_investigation_context_semantics(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "shared-semantic-view")
    model = build_html_report_model(pack)

    html = render_html_report(model)
    html_with_empty_semantics = render_html_report(
        replace(
            model,
            operator_report_view=build_operator_report_view(model.operator_summary),
        )
    )

    assert model.operator_report_view.primary_anchor_ids == tuple(
        lead.lead_id for lead in model.operator_summary.ranked_leads
    )
    assert len(model.operator_report_view.investigation_context.primary_contexts) == len(
        model.operator_summary.ranked_leads
    )
    if any(
        context.context_items
        for context in model.operator_report_view.investigation_context.primary_contexts
    ):
        assert "Investigation context" in html
    assert "Investigation context" not in html_with_empty_semantics
    assert "Analysis coverage" in html
    assert "Analysis coverage" in html_with_empty_semantics


def test_html_model_prefers_persisted_analysis_coverage_over_legacy_reconstruction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _write_deep_interpretation_pack(tmp_path / "persisted-coverage")
    evidence = (
        AnalysisCoverageExecutionEvidence(
            unit=AnalysisCoverageUnit(
                capability="deep_parameter_inventory",
                source_role="shallow_route_followup",
                source_id="DEEP-PARAM-SOURCE-0006",
            ),
            input_membership_proven=True,
            invocation_proven=True,
            completed=True,
            finding_count=2,
            finding_identity="username\x00password",
        ),
    )
    write_analysis_coverage_artifact(pack, evidence)

    monkeypatch.setattr(
        "bugslyce.reports.html_model.coverage_evidence_from_initial_retained_javascript_routes",
        lambda *_args, **_kwargs: pytest.fail(
            "Persisted Analysis Coverage must not be merged with legacy reconstruction."
        ),
    )

    html = render_html_report(build_html_report_model(pack))

    assert "Analysed · Finding present" in html
    assert "DEEP-PARAM-SOURCE-0006" in html
    assert "2 findings" in html


def test_html_model_treats_empty_persisted_analysis_coverage_as_authoritative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _write_deep_interpretation_pack(tmp_path / "empty-persisted-coverage")
    write_analysis_coverage_artifact(pack, ())

    monkeypatch.setattr(
        "bugslyce.reports.html_model.coverage_evidence_from_initial_retained_javascript_routes",
        lambda *_args, **_kwargs: pytest.fail(
            "Present empty persisted coverage must remain authoritative."
        ),
    )

    html = render_html_report(build_html_report_model(pack))

    assert "No source-attributable analysis coverage claims" in html


def test_html_model_without_analysis_coverage_artifact_keeps_legacy_reconstruction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _write_deep_interpretation_pack(tmp_path / "legacy-coverage")
    assert not (pack / ANALYSIS_COVERAGE_FILENAME).exists()

    legacy_evidence = (
        AnalysisCoverageExecutionEvidence(
            unit=AnalysisCoverageUnit(
                capability="deep_initial_retained_javascript_route_extraction",
                source_role="initial_html",
                source_id="LEGACY-COVERAGE-SOURCE",
            ),
            input_membership_proven=True,
            invocation_proven=True,
            completed=True,
            finding_count=1,
            finding_identity="/legacy-route",
        ),
    )

    monkeypatch.setattr(
        "bugslyce.reports.html_model.coverage_evidence_from_initial_retained_javascript_routes",
        lambda *_args, **_kwargs: legacy_evidence,
    )

    html = render_html_report(build_html_report_model(pack))

    assert "Analysed · Finding present" in html
    assert "LEGACY-COVERAGE-SOURCE" in html
    assert "1 finding" in html


def test_html_model_rejects_malformed_present_analysis_coverage_artifact(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "malformed-analysis-coverage")
    (pack / ANALYSIS_COVERAGE_FILENAME).write_text(
        "{\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="could not parse analysis_coverage.json",
    ):
        build_html_report_model(pack)


def test_html_model_rejects_unsupported_analysis_coverage_schema(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "unsupported-analysis-coverage")
    (pack / ANALYSIS_COVERAGE_FILENAME).write_text(
        json.dumps(
            {
                "schema_version": 2,
                "generated_by": "bugslyce.analysis_coverage",
                "evidence": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="schema_version"):
        build_html_report_model(pack)


def test_html_report_renders_only_supplied_analysis_coverage_claims(
    tmp_path: Path,
) -> None:
    model = build_html_report_model(_write_current_pack(tmp_path / "coverage"))
    summary = OperatorSummary(review_first=[], low_signal=[], coverage=[])
    view = build_operator_report_view(
        summary,
        coverage_evidence=(
            AnalysisCoverageExecutionEvidence(
                unit=AnalysisCoverageUnit(
                    "deep_initial_retained_javascript_route_extraction",
                    "initial_html",
                    "https://example.test/search?a=1&b=2",
                ),
                input_membership_proven=True,
                invocation_proven=True,
                completed=True,
                finding_count=1,
                finding_identity="INITIAL-ROUTE-1",
            ),
            AnalysisCoverageExecutionEvidence(
                unit=AnalysisCoverageUnit(
                    "project_pipeline_step", "deep", "STEP-NOOP"
                ),
                not_run_outcome=AnalysisCoverageOutcome.NO_OP_NOT_APPLICABLE,
            ),
            AnalysisCoverageExecutionEvidence(
                unit=AnalysisCoverageUnit(
                    "controlled", "retained_source", "SOURCE-REUSED"
                ),
                input_membership_proven=True,
                invocation_proven=True,
                completed=True,
                finding_count=0,
                reused_completed_result=True,
            ),
            AnalysisCoverageExecutionEvidence(
                unit=AnalysisCoverageUnit(
                    "controlled",
                    "retained_source",
                    '<script>alert(1)</script> [controlled](javascript:alert(1))',
                ),
            ),
        ),
    )

    html = render_html_report(
        replace(model, operator_summary=summary, operator_report_view=view)
    )

    assert html.count('id="analysis-coverage"') == 1
    assert html.count('href="#analysis-coverage"') == 1
    assert "Analysed · Finding present" in html
    assert "Not run · Not applicable" in html
    assert "Unknown" in html
    assert "1 finding" in html
    assert "https://example.test/search?a=1&amp;b=2" in html
    assert "Exact execution proof unavailable" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert '<dt>Execution</dt><dd>Reused completed result</dd>' in html
    assert '<dt>Execution</dt><dd>Execution: reused completed result</dd>' not in html
    assert "No source-attributable analysis coverage claims" not in html
    assert "safe" not in html[html.index('id="analysis-coverage"'):html.index('id="human-triage"')].lower()


def test_html_review_first_renders_context_with_resolving_evidence_navigation(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "investigation-context")
    model = build_html_report_model(pack)
    evidence_id = model.project_state.evidence[0].id
    lead = OperatorSummaryLead(
        title='Controlled <context> "lead"',
        why="Inspect retained evidence.",
        endpoints=["https://example.test/search?tenant=alpha"],
        evidence_ids=[evidence_id],
        next_action="Review offline.",
        signal="direct",
        score=1,
        lead_type="controlled_context",
        lead_id="LEAD-CONTEXT",
        rank=1,
    )
    summary = OperatorSummary(review_first=[lead], low_signal=[], coverage=[])
    view = build_operator_report_view(
        summary,
        investigation_sources=InvestigationContextSources(
            evidence=tuple(model.project_state.evidence),
        ),
    )
    model = replace(model, operator_summary=summary, operator_report_view=view)

    html = render_html_report(model)
    context = view.investigation_context.primary_contexts[0]
    evidence_reference = next(
        reference
        for reference in context.navigation_references
        if reference.target_kind == "evidence"
    )

    assert "Investigation context" in html
    assert 'Controlled &lt;context&gt; &quot;lead&quot;' in html
    assert f'id="{context.anchor_reference.anchor_token}"' in html
    assert f'href="#{evidence_reference.anchor_token}"' in html
    assert f'id="{evidence_reference.anchor_token}"' in html
    assert f'href="#{context.anchor_reference.anchor_token}"' in html
    assert "Analysis coverage" in html
    generated_links = re.findall(r'href="#(ctx-[^"]+)"', html)
    for anchor in generated_links:
        assert html.count(f'id="{anchor}"') == 1


def test_html_exact_route_navigation_resolves_both_directions(tmp_path: Path) -> None:
    model = build_html_report_model(_write_current_pack(tmp_path / "route-navigation"))
    route = model.route_groups[0].url
    lead = OperatorSummaryLead(
        title="Controlled route context",
        why="Inspect the represented route.",
        endpoints=[route],
        evidence_ids=[],
        next_action="Review offline.",
        signal="direct",
        score=1,
        lead_type="controlled_context",
        lead_id="LEAD-ROUTE",
        rank=1,
    )
    summary = OperatorSummary(review_first=[lead], low_signal=[], coverage=[])
    view = build_operator_report_view(summary)
    context = view.investigation_context.primary_contexts[0]
    context = replace(
        context,
        context_items=(
            InvestigationContextItem(
                "represented_route",
                RELATED,
                "route_relationship",
                "",
                "Exact represented route",
                route,
                (),
                (),
                (),
                (),
                (),
            ),
        ),
    )
    assembly = replace(
        view.investigation_context,
        primary_contexts=(context,),
        route_backlinks=(
            InvestigationContextBacklink(route, (context.anchor_reference,)),
        ),
    )
    view = replace(view, investigation_context=assembly)
    index = build_investigation_context_presentation_index(assembly)
    route_anchor = index.route_reference_by_url[route].anchor_token

    html = render_html_report(
        replace(model, operator_summary=summary, operator_report_view=view)
    )

    assert f'href="#{route_anchor}"' in html
    assert html.count(f'id="{route_anchor}"') == 1
    assert f'href="#{context.anchor_reference.anchor_token}"' in html


def test_html_report_renders_shared_human_triage_source_context(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "human-triage-source-context")
    state_path = pack / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["project_state"]["http_artifacts"].extend(
        [
            {
                "url": "https://portal.example.test/",
                "artifact_type": "hidden_element",
                "value": "credential-context",
                "source_file": "raw/homepage.html",
                "evidence_ids": ["EVID-TRIAGE-HIDDEN"],
                "tags": ["encoded_or_hidden_artifact"],
            },
            {
                "url": "https://portal.example.test/",
                "artifact_type": "encoded_like_artifact",
                "value": "Q29uZmlnUmV2aWV3VG9rZW4xMjM0NTY=",
                "source_file": "raw/homepage.html",
                "evidence_ids": ["EVID-TRIAGE-ENCODED"],
                "tags": ["encoded_or_hidden_artifact"],
            },
        ]
    )
    state_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    model = build_html_report_model(pack)
    html = render_html_report(model)
    markdown = render_human_triage_brief_markdown(
        model.human_triage_brief,
        include_ranked_leads=False,
    )

    assert 'id="human-triage"' in html
    assert "Supporting triage evidence" in html
    assert "Supporting evidence prompts (not ranked)" in html
    assert "Evidence values worth noting" in html
    assert 'data-category="human_triage"' in html
    assert '<option value="human_triage">Human triage</option>' in html
    for value in (
        "Source credential/context clue group observed",
        "credential-context",
        "Q29uZmlnUmV2aWV3VG9rZW4xMjM0NTY=",
        "EVID-TRIAGE-HIDDEN",
        "EVID-TRIAGE-ENCODED",
        "https://portal.example.test/",
    ):
        assert value in html
        assert value in markdown


def test_html_report_renders_human_authored_source_comment_prompt(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "human-triage-comment")
    state_path = pack / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["project_state"]["http_artifacts"].append(
        {
            "url": "https://portal.example.test/releases.html",
            "artifact_type": "html_comment",
            "value": "Ops team: rotate the staging certificate before deployment",
            "source_file": "raw/releases.html",
            "evidence_ids": ["EVID-TRIAGE-COMMENT"],
            "tags": [],
        }
    )
    state_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    model = build_html_report_model(pack)
    html = render_html_report(model)

    assert "Human-authored source comment observed" in html
    assert "Ops team: rotate the staging certificate before deployment" in html
    assert "https://portal.example.test/releases.html" in html
    assert "EVID-TRIAGE-COMMENT" in html


def test_html_human_triage_does_not_duplicate_canonical_lead_ids(
    tmp_path: Path,
) -> None:
    model = build_html_report_model(_write_current_pack(tmp_path / "no-lead-duplication"))
    html = render_html_report(model)

    for lead in model.operator_summary.ranked_leads:
        assert html.count(lead.lead_id) == 1


def test_html_reconstructs_same_manual_review_groups_as_markdown(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "review-occurrence-groups")
    state_path = pack / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["project_state"]["http_artifacts"].append(
        {
            "url": "https://portal.example.test/",
            "artifact_type": "response_body",
            "value": (
                '<html>\n<a href="/archive/backup.zip">one</a>\n'
                '<a href="/archive/backup.zip">two</a>\n</html>'
            ),
            "source_file": "raw/homepage.html",
            "evidence_ids": ["EVID-REPEATED-REFERENCE"],
            "tags": [],
        }
    )
    state_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    model = build_html_report_model(pack)
    assembly = assemble_standard_interpretation_from_project_state(
        model.project_state
    )
    html = unescape(render_html_report(model))

    assert model.review_leads == assembly.review_leads
    assert model.review_occurrence_groups == (
        assembly.collection.review_occurrence_groups
    )
    group = next(
        group
        for group in model.review_occurrence_groups
        if group.raw_value == "/archive/backup.zip"
    )
    assert group.occurrence_count == 2
    assert group.review_lead_ids == tuple(
        lead.lead_id
        for lead in model.review_leads
        if lead.raw_value == "/archive/backup.zip"
    )
    assert tuple(member.line_number for member in group.members) == (2, 3)
    assert group.group_id in html
    assert "Occurrence count</dt><dd>2" in html
    assert (
        f"{group.review_lead_ids[0]}: line 2; evidence EVID-REPEATED-REFERENCE"
        in html
    )
    assert (
        f"{group.review_lead_ids[1]}: line 3; evidence EVID-REPEATED-REFERENCE"
        in html
    )
    assert "/archive/backup.zip" in html


def test_html_reconstructs_conventional_password_form_without_suspicious_group(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "ordinary-password-control")
    state_path = pack / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["project_state"]["http_artifacts"].append(
        {
            "url": "https://portal.example.test/login",
            "artifact_type": "input",
            "value": "name=password;type=password",
            "source_file": "raw/login.html",
            "evidence_ids": ["EVID-ORDINARY-PASSWORD-CONTROL"],
            "tags": [],
        }
    )
    state_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    model = build_html_report_model(pack)
    html = unescape(render_html_report(model))

    artifact = next(
        item
        for item in model.project_state.http_artifacts
        if item.evidence_ids == ["EVID-ORDINARY-PASSWORD-CONTROL"]
    )
    assert artifact.value == "name=password;type=password"
    assert "name=password;type=password" in html
    assert not any(
        group.lead_type == "html_suspicious_attribute_review"
        and "EVID-ORDINARY-PASSWORD-CONTROL" in group.evidence_ids
        for group in model.review_occurrence_groups
    )
    assert "Suspicious HTML id/class/name contains clue-like wording" not in html


def test_html_report_missing_input_or_required_state_fails_clearly(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="input directory does not exist"):
        build_html_report_model(tmp_path / "missing")

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="required artefact is missing: project_state.json"):
        build_html_report_model(empty)


def test_html_report_rejects_malformed_required_and_present_deep_artefacts(
    tmp_path: Path,
) -> None:
    malformed_state = tmp_path / "malformed-state"
    malformed_state.mkdir()
    (malformed_state / "project_state.json").write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="could not parse project_state.json"):
        build_html_report_model(malformed_state)

    malformed_deep = _write_current_pack(tmp_path / "malformed-deep")
    (malformed_deep / "deep_source_route_collection.json").write_text(
        "[]\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="deep source/route collection payload"):
        build_html_report_model(malformed_deep)

    malformed_orchestration = _write_deep_interpretation_pack(
        tmp_path / "malformed-orchestration"
    )
    (malformed_orchestration / "deep_recon_orchestration.json").write_text(
        "{\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="could not parse deep_recon_orchestration.json"):
        build_html_report_model(malformed_orchestration)



def test_html_model_promotes_distinctive_access_boundary_offline(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "access-boundary-pack")
    repeated_hash = "a" * 64
    collection = DeepSourceRouteCollectionResult(
        collected=(
            _deep_item(
                "https://portal.example.test/fallback-a",
                500,
                repeated_hash,
                preview="<html><title>Request failed</title></html>",
                evidence_ids=("EVID-FALLBACK-A",),
            ),
            _deep_item(
                "https://portal.example.test/fallback-b",
                500,
                repeated_hash,
                preview="<html><title>Request failed</title></html>",
                evidence_ids=("EVID-FALLBACK-B",),
            ),
            _deep_item(
                "https://portal.example.test/fallback-c",
                500,
                repeated_hash,
                preview="<html><title>Request failed</title></html>",
                evidence_ids=("EVID-FALLBACK-C",),
            ),
            _deep_item(
                "https://portal.example.test/admin",
                401,
                "b" * 64,
                preview=(
                    "<html><title>Authentication required: bearer token missing"
                    "</title></html>"
                ),
                evidence_ids=("EVID-ACCESS-401",),
            ),
        ),
        skipped=(),
        total_considered=4,
        total_collected=4,
        total_skipped=0,
    )
    (pack / "deep_source_route_collection.json").write_text(
        json.dumps(
            deep_source_route_collection_result_to_dict(collection),
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    model = build_html_report_model(pack)
    access = next(
        lead
        for lead in model.operator_summary.ranked_leads
        if lead.lead_type == "distinctive_access_boundary_response"
    )

    assert access.score == 86
    assert access.endpoints == ["https://portal.example.test/admin"]
    assert access.evidence_ids == ["EVID-ACCESS-401"]
    assert access.rank < next(
        lead.rank
        for lead in model.operator_summary.ranked_leads
        if lead.lead_type == "high_port_http_service"
    )

def test_html_report_escapes_hostile_target_controlled_values(tmp_path: Path) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    state_path = pack / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    state = payload["project_state"]
    state["project_name"] = '<script>alert("project")</script>'
    state["http_services"][0]["title"] = '</title><img src=x onerror="alert(1)">'
    state["endpoints"][0]["path"] = '"><svg onload=alert(2)>'
    state["endpoints"][0]["url"] = "javascript:alert(3)"
    state["evidence"][0]["value"] = "<script>alert(4)</script> &lt;img onerror=alert(5)&gt;"
    state["http_artifacts"].append(
        {
            "url": "https://example.test/<img src=x onerror=alert(6)>",
            "artifact_type": "html_comment",
            "value": '<iframe srcdoc="<script>alert(7)</script>"></iframe>',
            "source_file": 'raw/\" onmouseover=\"alert(8).html',
            "evidence_ids": ["EVID-HOSTILE-0001"],
            "tags": ["source_evidence"],
        }
    )
    state_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    hostile_collection = DeepSourceRouteCollectionResult(
        collected=(
            _deep_item(
                "https://example.test/hostile",
                200,
                "c" * 64,
                headers=(("Server", '<img src=x onerror="alert(9)">'),),
                preview="%3Cscript%3Ealert(10)%3C/script%3E",
                evidence_ids=("EVID-HOSTILE-HEADER-0001",),
            ),
        ),
        skipped=(),
        total_considered=1,
        total_collected=1,
        total_skipped=0,
    )
    (pack / "deep_source_route_collection.json").write_text(
        json.dumps(
            deep_source_route_collection_result_to_dict(hostile_collection),
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    html = render_html_report(build_html_report_model(pack))

    for unsafe in (
        '<script>alert("project")</script>',
        '</title><img src=x onerror="alert(1)">',
        '"><svg onload=alert(2)>',
        '<script>alert(4)</script>',
        '<iframe srcdoc="<script>alert(7)</script>"></iframe>',
        '<img src=x onerror="alert(9)">',
    ):
        assert unsafe not in html
    assert '&lt;script&gt;alert(&quot;' in html
    assert "&lt;svg onload=alert(2)&gt;" in html
    assert 'href="javascript:' not in html.lower()
    assert 'src="javascript:' not in html.lower()
    assert "javascript:alert(3)" in html
    assert "%3Cscript%3Ealert(10)%3C/script%3E" in html


def test_html_report_has_no_external_assets_or_network_code(tmp_path: Path) -> None:
    html = render_html_report(build_html_report_model(_write_current_pack(tmp_path / "pack")))

    lowered = html.lower()
    assert "<link" not in lowered
    assert "<img" not in lowered
    assert "fetch(" not in lowered
    assert "xmlhttprequest" not in lowered
    assert "websocket" not in lowered
    assert 'src="http' not in lowered
    assert 'href="http' not in lowered
    assert "file://" not in lowered
    assert "default-src 'none'" in lowered
    assert "unsafe-inline" not in lowered
    assert "style-src 'sha256-" in lowered
    assert "script-src 'sha256-" in lowered


def test_html_report_rebuilds_existing_deep_review_models(tmp_path: Path) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    repeated_hash = "a" * 64
    collection = DeepSourceRouteCollectionResult(
        collected=(
            _deep_item(
                "https://portal.example.test/login",
                302,
                repeated_hash,
                headers=(("Location", "/dashboard"),),
                evidence_ids=("EVID-REDIRECT-0001",),
            ),
            _deep_item(
                "https://portal.example.test/dashboard",
                200,
                "b" * 64,
                preview="<title>Existing dashboard title</title>",
                evidence_ids=("EVID-DASHBOARD-0001",),
            ),
            _deep_item(
                "https://portal.example.test/missing-a",
                404,
                repeated_hash,
                evidence_ids=("EVID-MISSING-0001",),
            ),
            _deep_item(
                "https://portal.example.test/missing-b",
                404,
                repeated_hash,
                evidence_ids=("EVID-MISSING-0002",),
            ),
        ),
        skipped=(
            DeepSourceRouteSkippedItem(
                url="https://portal.example.test/capped",
                method="GET",
                reason="policy_blocked",
                source="source_route_coverage",
                evidence_ids=("EVID-SKIPPED-0001",),
            ),
            DeepSourceRouteSkippedItem(
                url="https://portal.example.test/budget-capped",
                method="GET",
                reason="per_origin_limit_exceeded",
                source="source_route_coverage",
                evidence_ids=("EVID-SKIPPED-0002",),
            ),
        ),
        total_considered=6,
        total_collected=4,
        total_skipped=2,
    )
    (pack / "deep_source_route_collection.json").write_text(
        json.dumps(deep_source_route_collection_result_to_dict(collection), sort_keys=True),
        encoding="utf-8",
    )

    html = render_html_report(build_html_report_model(pack))

    assert "Existing dashboard title" in html
    assert "Successful 2xx content promoted for priority review" in html
    assert "Redirect and authentication-flow review" in html
    assert "Route relationships" in html
    assert "Response similarity" in html
    assert "Exact repeated non-empty body hash" in html
    assert "EVID-REDIRECT-0001" in html
    assert "Warnings and skipped collection" in html
    assert "Blocked by Deep collection policy" in html
    assert "Per-service request budget exhausted" in html
    assert "EVID-SKIPPED-0001" in html
    _assert_category_filter_complete(html)


def test_html_and_markdown_share_request_reflecting_family_facts(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    urls = tuple(
        f"https://app.example.test/missing-{index:02d}"
        for index in range(1, 8)
    ) + (
        "https://app.example.test/missing-08?"
        + "&".join(
            f"long-safe-parameter-name-{index:02d}=value-{index:02d}"
            for index in range(1, 7)
        ),
    )
    collection = DeepSourceRouteCollectionResult(
        collected=tuple(
            _deep_item(
                url,
                500,
                f"distinct-raw-hash-{index}",
                preview=_request_reflecting_html(url),
                evidence_ids=(f"EVID-FAMILY-{index}",),
            )
            for index, url in enumerate(urls, start=1)
        ),
        skipped=(),
        total_considered=8,
        total_collected=8,
        total_skipped=0,
    )
    collection_path = pack / "deep_source_route_collection.json"
    collection_path.write_text(
        json.dumps(
            deep_source_route_collection_result_to_dict(collection),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    before = collection_path.read_bytes()

    model = build_html_report_model(pack)
    markdown = render_deep_response_similarity_review_markdown(
        model.similarity_review
    )
    html = render_html_report(model)

    family = next(
        group
        for group in model.similarity_review.groups
        if group.category == "request_reflecting_template_group"
    )
    assert family.member_count == 8
    assert family.representative_requested_url == urls[0]
    for expected in (
        family.group_id,
        family.reason,
        family.representative_requested_url,
        *family.fingerprint_ids,
        *family.requested_urls,
        *family.evidence_ids,
    ):
        assert expected in markdown
        assert expected in unescape(html)
    assert collection_path.read_bytes() == before


def test_html_report_is_deterministic_and_preserves_existing_reasoning(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    model = build_html_report_model(pack)

    first = render_html_report(model)
    second = render_html_report(build_html_report_model(pack))

    assert first == second
    assert model.candidates
    assert model.candidates[0].rationale in first
    assert model.operator_summary.review_first[0].why in first


def test_canonical_ranked_leads_match_human_triage_markdown_and_html(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    model = build_html_report_model(pack)
    endpoints = tuple(
        f"https://app.example.test/review/{index:02d}" for index in range(10)
    )
    evidence_ids = tuple(f"EVID-CANONICAL-{index:04d}" for index in range(10))
    summary = build_operator_summary(
        model.project_state,
        list(model.candidates),
        additional_leads=(
            OperatorSummaryLead(
                title="Neutral canonical review",
                why="Directly retained records support bounded offline review.",
                endpoints=list(reversed(endpoints)),
                evidence_ids=list(reversed(evidence_ids)),
                next_action="Review the retained artefacts offline.",
                signal="direct retained evidence",
                score=999,
                lead_type="direct_evidence_review",
            ),
        ),
    )
    brief = build_human_triage_brief(
        model.project_state,
        list(model.candidates),
        ranked_leads=summary.review_first,
    )
    triage = render_human_triage_brief_markdown(brief)
    embedded_triage = render_human_triage_brief_markdown(
        brief,
        include_ranked_leads=False,
    )
    markdown = render_markdown_report(
        model.project_state,
        list(model.candidates),
        human_triage_brief_markdown=embedded_triage,
        operator_summary=summary,
    )
    html = unescape(render_html_report(replace(model, operator_summary=summary)))

    lead_ids = [lead.lead_id for lead in summary.review_first]
    assert [lead.lead_id for lead in brief.ranked_leads] == lead_ids
    for rendered in (triage, markdown, html):
        positions = [rendered.index(lead_id) for lead_id in lead_ids]
        assert positions == sorted(positions)
    for lead in summary.review_first:
        for value in (
            lead.lead_id,
            lead.lead_type,
            lead.title,
            lead.rationale,
            lead.suggested_next_action,
            lead.signal,
        ):
            assert value in markdown
            assert value in html
        assert lead.lead_id in triage
        assert lead.lead_type in triage
        assert lead.title in triage
    for value in (*endpoints, *evidence_ids):
        assert value in markdown
        assert value in html


def test_html_report_writes_only_requested_output_and_preserves_input(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    output = output_dir / "review.html"
    before = _tree_hashes(pack)

    write_html_report(pack, output)

    assert _tree_hashes(pack) == before
    assert [path.relative_to(output_dir).as_posix() for path in output_dir.rglob("*")] == [
        "review.html"
    ]

    state_path = pack / "project_state.json"
    state_bytes = state_path.read_bytes()
    with pytest.raises(ValueError, match="output path must be outside the input directory"):
        write_html_report(pack, state_path)
    assert state_path.read_bytes() == state_bytes


def test_project_html_report_reuses_renderer_and_writes_canonical_local_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    model = object()
    calls: list[object] = []
    monkeypatch.setattr(
        html_module,
        "build_html_report_model",
        lambda input_dir: calls.append(input_dir) or model,
    )
    monkeypatch.setattr(
        html_module,
        "render_html_report",
        lambda value: calls.append(value) or "<html>fixture</html>\n",
    )

    output = write_project_html_report(pack)

    assert output == pack / "report.html"
    assert output.read_text(encoding="utf-8") == "<html>fixture</html>\n"
    assert calls == [pack.resolve(), model]
    assert output.stat().st_mode & 0o777 == 0o600


def test_project_html_report_is_deterministic_and_confined(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")

    output = write_project_html_report(pack)
    first = output.read_bytes()
    write_project_html_report(pack)

    assert output.read_bytes() == first
    with pytest.raises(ValueError, match="must be"):
        write_project_html_report(pack, Path("../outside.html"))
    assert not (tmp_path / "outside.html").exists()

    output.write_text("unrelated local file\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not recognised as BugSlyce-owned"):
        write_project_html_report(pack)
    assert output.read_text(encoding="utf-8") == "unrelated local file\n"


def test_project_html_report_rejects_symlink_and_cleans_failed_atomic_write(
    tmp_path: Path,
    monkeypatch,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    output = pack / "report.html"
    outside = tmp_path / "outside.html"
    outside.write_text("outside\n", encoding="utf-8")
    try:
        output.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    with pytest.raises(ValueError, match="symbolic link"):
        write_project_html_report(pack)
    assert outside.read_text(encoding="utf-8") == "outside\n"
    output.unlink()

    monkeypatch.setattr(
        html_module.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("fixture replace failure")),
    )
    with pytest.raises(OSError, match="fixture replace failure"):
        write_project_html_report(pack)
    assert not output.exists()
    assert list(pack.glob(".report.html.*.tmp")) == []


def test_html_report_rejects_new_output_beneath_input_before_any_write(
    tmp_path: Path,
    capsys,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    before = _tree_hashes(pack)
    output = pack / "report.html"

    exit_code = main(
        ["report", "html", "--input-dir", str(pack), "--output", str(output)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "output path must be outside the input directory" in captured.err
    assert not output.exists()
    assert _tree_hashes(pack) == before


def test_html_report_rejects_normalised_and_symlinked_paths_beneath_input(
    tmp_path: Path,
    monkeypatch,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    child = pack / "child"
    child.mkdir()
    before = _tree_hashes(pack)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="output path must be outside the input directory"):
        write_html_report(Path("pack"), Path("pack/child/../normalised.html"))
    assert not (pack / "normalised.html").exists()
    with pytest.raises(ValueError, match="output path must be outside the input directory"):
        write_html_report(Path("pack"), Path("pack"))

    alias = tmp_path / "pack-alias"
    try:
        alias.symlink_to(pack, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")
    with pytest.raises(ValueError, match="output path must be outside the input directory"):
        write_html_report(Path("pack"), Path("pack-alias/symlinked.html"))
    assert not (pack / "symlinked.html").exists()
    assert _tree_hashes(pack) == before


def test_html_report_allows_and_overwrites_requested_output_outside_input(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    output = tmp_path / "review.html"

    write_html_report(pack, output)
    first = output.read_bytes()
    output.write_text("replace this existing output", encoding="utf-8")
    write_html_report(pack, output)

    assert output.read_bytes() == first
    assert b"replace this existing output" not in output.read_bytes()


def test_html_report_overview_counts_unique_exact_route_urls(tmp_path: Path) -> None:
    model = build_html_report_model(_write_current_pack(tmp_path / "pack"))
    expected = len(
        {item.url for item in model.project_state.endpoints}
        | {item.url for item in model.project_state.discovered_paths}
    )
    record_sum = len(model.project_state.endpoints) + len(model.project_state.discovered_paths)

    html = render_html_report(model)

    assert expected < record_sum
    grouped_count = sum(
        group.origin_group in {"assessed", "external", "relative"}
        for group in model.route_groups
    )
    assert grouped_count == expected
    assert "<span>Assessed-origin URLs</span>" in html
    assert "<span>External references</span>" in html
    assert "<span>Relative / unclassified</span>" in html
    assert f"<span>Routes</span><strong>{record_sum}</strong>" not in html


def test_html_report_category_filter_covers_every_rendered_record(tmp_path: Path) -> None:
    html = render_html_report(build_html_report_model(_write_current_pack(tmp_path / "pack")))
    option_categories = _assert_category_filter_complete(html)

    assert {
        "form_or_parameter",
        "gobuster",
        "html",
        "nmap",
        "operator_summary",
    } <= option_categories


def test_html_report_reconstructs_persisted_deep_operator_summary_and_disclosures(
    tmp_path: Path,
) -> None:
    pack = _write_deep_interpretation_pack(tmp_path / "pack")

    model = build_html_report_model(pack)
    html = render_html_report(model)

    titles = [lead.title for lead in model.operator_summary.review_first]
    assert titles[:2] == [
        "Structured operational configuration observed",
        "Routes disclosed by structured JSON response",
    ]
    assert "Successfully collected Deep content available offline" in titles
    assert "Structured operational configuration observed in response body" in html
    assert "Relative routes disclosed by structured JSON" in html
    for route in ("/api/user", "/api/jobs", "/api/applications"):
        assert route in html
    assert "No request was generated from these values." in html
    assert "1 successful 2xx response was promoted for priority content review" in html
    assert "Operator summary reconstructed from complete structured Deep inputs" in html


def test_html_report_marks_missing_deep_orchestration_as_partial(tmp_path: Path) -> None:
    pack = _write_deep_interpretation_pack(tmp_path / "pack")
    (pack / "deep_recon_orchestration.json").unlink()

    html = render_html_report(build_html_report_model(pack))

    assert "Operator summary reconstructed from available structured inputs" in html
    assert "deep_recon_orchestration.json" in html
    assert "complete structured Deep inputs" not in html


def test_html_report_marks_missing_deep_source_collection_as_partial(tmp_path: Path) -> None:
    pack = _write_deep_interpretation_pack(tmp_path / "pack")
    (pack / "deep_source_route_collection.json").unlink()

    model = build_html_report_model(pack)
    html = render_html_report(model)

    assert "Operator summary reconstructed from available structured inputs" in html
    assert "deep_source_route_collection.json" in html
    assert "complete structured Deep inputs" not in html
    assert "Successfully collected Deep content available offline" not in {
        lead.title for lead in model.operator_summary.review_first
    }


def test_html_report_marks_both_missing_deep_inputs_as_partial(tmp_path: Path) -> None:
    pack = _write_deep_interpretation_pack(tmp_path / "pack")
    state_path = pack / "project_state.json"
    state_payload = json.loads(state_path.read_text(encoding="utf-8"))
    state_payload["project_state"]["recon_manifest"]["profile"] = "full-profile"
    state_path.write_text(
        json.dumps(state_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (pack / "deep_recon_orchestration.json").unlink()
    (pack / "deep_source_route_collection.json").unlink()

    html = render_html_report(build_html_report_model(pack))

    assert "Operator summary reconstructed from available structured inputs" in html
    assert "deep_recon_orchestration.json" in html
    assert "deep_source_route_collection.json" in html
    assert "complete structured Deep inputs" not in html


def test_html_report_non_deep_pack_does_not_require_deep_summary_inputs(
    tmp_path: Path,
) -> None:
    html = render_html_report(build_html_report_model(_write_current_pack(tmp_path / "pack")))

    assert "Operator summary reconstructed from available structured inputs" not in html
    assert "complete structured Deep inputs" not in html


def test_html_report_marks_older_partial_summary_fallback_explicitly(tmp_path: Path) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    state_path = pack / "project_state.json"
    state_payload = json.loads(state_path.read_text(encoding="utf-8"))
    state_payload["project_state"]["recon_manifest"].pop("profile")
    state_path.write_text(
        json.dumps(state_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    collection = DeepSourceRouteCollectionResult(
        collected=(
            _deep_item(
                "https://portal.example.test/retained",
                200,
                "c" * 64,
                evidence_ids=("EVID-OLDER-DEEP",),
            ),
        ),
        skipped=(),
        total_considered=1,
        total_collected=1,
        total_skipped=0,
    )
    (pack / "deep_source_route_collection.json").write_text(
        json.dumps(deep_source_route_collection_result_to_dict(collection), sort_keys=True),
        encoding="utf-8",
    )

    html = render_html_report(build_html_report_model(pack))

    assert "Operator summary reconstructed from available structured inputs" in html
    assert "deep_recon_orchestration.json" in html


def test_html_report_groups_exact_route_observations_by_origin_without_data_loss(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    state_path = pack / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    state = payload["project_state"]
    state["http_services"] = [
        {
            "url": "http://192.0.2.10/",
            "hostname": "192.0.2.10",
            "status_code": 200,
            "title": "Primary",
            "technologies": [],
            "content_length": 10,
            "evidence_ids": ["EVID-SVC-80"],
            "tags": [],
        },
        {
            "url": "http://192.0.2.10:8080/",
            "hostname": "192.0.2.10",
            "status_code": 200,
            "title": "Secondary",
            "technologies": [],
            "content_length": 10,
            "evidence_ids": ["EVID-SVC-8080"],
            "tags": [],
        },
    ]
    state["endpoints"] = [
        {
            "url": "http://192.0.2.10/shared",
            "hostname": "192.0.2.10",
            "path": "/shared",
            "query_params": [],
            "evidence_ids": ["EVID-ENDPOINT"],
            "tags": [],
        },
        {
            "url": "http://192.0.2.10:8080/admin",
            "hostname": "192.0.2.10",
            "path": "/admin",
            "query_params": [],
            "evidence_ids": ["EVID-8080"],
            "tags": [],
        },
        {
            "url": "https://external.example.test/reference",
            "hostname": "external.example.test",
            "path": "/reference",
            "query_params": [],
            "evidence_ids": ["EVID-EXTERNAL"],
            "tags": [],
        },
        {
            "url": "/relative/value",
            "hostname": "",
            "path": "/relative/value",
            "query_params": [],
            "evidence_ids": ["EVID-RELATIVE"],
            "tags": [],
        },
    ]
    state["discovered_paths"] = [
        {
            "url": "http://192.0.2.10/shared",
            "status_code": 200,
            "content_length": 20,
            "redirect_location": None,
            "source": "/tmp/source-a.txt",
            "evidence_ids": [f"EVID-SHARED-{index:02d}" for index in range(1, 12)],
            "tags": [],
        },
        {
            "url": "http://192.0.2.10/shared",
            "status_code": 302,
            "content_length": 0,
            "redirect_location": "/login",
            "source": "/var/review/source-a.txt",
            "evidence_ids": ["EVID-REDIRECT"],
            "tags": [],
        },
    ]
    state_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    html = render_html_report(build_html_report_model(pack))

    assert html.count('<summary class="route-url">http://192.0.2.10/shared</summary>') == 1
    assert 'data-categories="discovered_path endpoint" data-status="200 302"' in html
    assert "Assessed-origin URLs" in html
    assert "http://192.0.2.10:8080/admin" in html
    assert "External references" in html
    assert "https://external.example.test/reference" in html
    assert "Relative or unclassified values" in html
    assert "/relative/value" in html
    assert "200" in html and "302" in html and "/login" in html
    for evidence_id in ["EVID-ENDPOINT", "EVID-REDIRECT", "EVID-SHARED-11"]:
        assert evidence_id in html
    assert "13 evidence IDs" in html
    assert "source-a.txt" in html
    assert "/tmp/source-a.txt" in html
    assert "/var/review/source-a.txt" in html


@pytest.mark.parametrize(
    "url",
    (
        "http://unknown.example.test/application",
        "https://unknown.example.test/application",
    ),
)
def test_html_report_does_not_classify_absolute_urls_without_assessed_origins_as_external(
    tmp_path: Path,
    url: str,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    _write_route_records(
        pack,
        http_services=[],
        urls=(url,),
    )

    model = build_html_report_model(pack)
    html = render_html_report(model)

    assert _route_group_counts(model) == {"assessed": 0, "external": 0, "relative": 1}
    assert f'<summary class="route-url">{url}</summary>' in html
    assert "<h3>Relative or unclassified values <span class=\"count\">(1)</span></h3>" in html
    assert "<h3>External references" not in html


def test_html_report_keeps_relative_and_malformed_values_unclassified_without_origins(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    urls = ("/relative/value", "https://[not-an-ipv6-address")
    _write_route_records(pack, http_services=[], urls=urls)

    model = build_html_report_model(pack)
    html = render_html_report(model)

    assert _route_group_counts(model) == {"assessed": 0, "external": 0, "relative": 2}
    for url in urls:
        assert url in html


def test_html_report_classifies_origins_only_when_assessed_origins_exist(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    urls = (
        "http://192.0.2.10/matching-default",
        "http://192.0.2.10:80/matching-explicit",
        "https://192.0.2.10/other-scheme",
        "http://192.0.2.10:8080/other-port",
        "https://external.example.test/reference",
    )
    _write_route_records(
        pack,
        http_services=(
            _http_service_payload("http://192.0.2.10/"),
            _http_service_payload("http://192.0.2.10:8080/"),
            _http_service_payload("https://192.0.2.10:443/"),
        ),
        urls=urls,
    )

    model = build_html_report_model(pack)

    groups = {group.url: group.origin_group for group in model.route_groups}
    assert groups == {
        "http://192.0.2.10/matching-default": "assessed",
        "http://192.0.2.10:80/matching-explicit": "assessed",
        "https://192.0.2.10/other-scheme": "assessed",
        "http://192.0.2.10:8080/other-port": "assessed",
        "https://external.example.test/reference": "external",
    }
    assert _route_group_counts(model) == {"assessed": 4, "external": 1, "relative": 0}


def test_html_report_origin_classification_keeps_scheme_and_port_matching_strict(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    urls = (
        "http://192.0.2.10:80/matching-default-port",
        "https://192.0.2.10/scheme-mismatch",
        "http://192.0.2.10:8080/non-default-port",
        "https://192.0.2.10:443/explicit-https-default",
    )
    _write_route_records(
        pack,
        http_services=(
            _http_service_payload("http://192.0.2.10/"),
            _http_service_payload("https://192.0.2.10/"),
        ),
        urls=urls,
    )

    model = build_html_report_model(pack)
    groups = {group.url: group.origin_group for group in model.route_groups}

    assert groups == {
        "http://192.0.2.10:80/matching-default-port": "assessed",
        "https://192.0.2.10/scheme-mismatch": "assessed",
        "http://192.0.2.10:8080/non-default-port": "external",
        "https://192.0.2.10:443/explicit-https-default": "assessed",
    }

    http_only_pack = _write_current_pack(tmp_path / "http-only-pack")
    _write_route_records(
        http_only_pack,
        http_services=(_http_service_payload("http://192.0.2.10/"),),
        urls=("https://192.0.2.10/scheme-mismatch",),
    )
    http_only_model = build_html_report_model(http_only_pack)
    assert http_only_model.route_groups[0].origin_group == "external"


def test_html_report_humanises_labels_keeps_raw_values_and_renders_robots(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    state_path = pack / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    state = payload["project_state"]
    state["http_artifacts"].extend(
        [
            {
                "url": "https://example.test/robots.txt",
                "artifact_type": "robots_value",
                "value": "Disallow: /private",
                "source_file": "/tmp/evidence/robots.txt",
                "evidence_ids": ["EVID-ROBOTS-0001"],
                "tags": ["source_route_collection"],
            },
            {
                "url": "https://example.test/app.js",
                "artifact_type": "script_or_asset",
                "value": '<script onload="alert(1)">',
                "source_file": "raw/app.js",
                "evidence_ids": ["EVID-JS-0001"],
                "tags": [
                    "candidate_default_template_group",
                    "credential_like_artifact_review",
                    "hidden_element",
                    "kill_switch",
                ],
            },
        ]
    )
    state["evidence"].append(
        {
            "id": "EVID-LABEL-0001",
            "source_file": "raw/labels.txt",
            "evidence_type": "http_json_api_url",
            "value": "label presentation",
            "context": {},
        }
    )
    state_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    html = render_html_report(build_html_report_model(pack))

    assert 'data-category="script_or_asset"' in html
    assert "Script or asset" in html
    assert "Robots value" in html
    assert "Source route collection" in html
    assert "Candidate default template group" in html
    assert "Credential like artefact review" in html
    assert "Hidden element" in html
    assert "Kill switch" in html
    assert "HTTP JSON API URL" in html
    assert 'data-category="http_json_api_url"' in html
    assert "Disallow: /private" in html
    assert "EVID-ROBOTS-0001" in html
    assert "robots.txt" in html and "/tmp/evidence/robots.txt" in html
    assert "Show all 1</summary>" not in html
    assert '<script onload="alert(1)">' not in html


def test_html_report_humanises_visible_identifier_fields_without_changing_raw_values(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    state_path = pack / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["candidates"][0]["priority"] = "kill_switch"
    payload["project_state"]["endpoints"][0]["query_params"] = ["page"]
    state_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    collection = DeepSourceRouteCollectionResult(
        collected=(
            _deep_item(
                "https://portal.example.test/old",
                302,
                "a" * 64,
                headers=(("Location", "/login"),),
                evidence_ids=("EVID-REDIRECT-LABEL",),
            ),
        ),
        skipped=(
            DeepSourceRouteSkippedItem(
                url="https://portal.example.test/search?query=bounded",
                method="GET",
                reason="query_string_not_allowed",
                source="source_route_coverage",
                evidence_ids=("EVID-SKIPPED-LABEL",),
            ),
        ),
        total_considered=2,
        total_collected=1,
        total_skipped=1,
    )
    (pack / "deep_source_route_collection.json").write_text(
        json.dumps(deep_source_route_collection_result_to_dict(collection), sort_keys=True),
        encoding="utf-8",
    )

    html = render_html_report(build_html_report_model(pack))

    for label in (
        "Kill switch",
        "Deep source route collection",
        "Source route collection",
        "Query-bearing route excluded by policy",
        "Source route coverage",
        "Same origin",
        "Redirect to auth path",
        "Query parameter names",
    ):
        assert label in html
    assert 'data-category="form_or_parameter"' in html
    assert 'data-category="redirect_auth_flow"' in html
    assert 'data-category="intentionally_bounded"' in html
    assert '<option value="intentionally_bounded">Intentionally bounded</option>' in html
    assert '<option value="form_or_parameter">Form or parameter</option>' in html
    assert "https://portal.example.test/search?query=bounded" in html
    assert "EVID-REDIRECT-LABEL" in html


def test_html_report_requires_structured_metadata_result_for_completed_delegation(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    collection = DeepSourceRouteCollectionResult(
        collected=(),
        skipped=(
            DeepSourceRouteSkippedItem(
                url="https://portal.example.test/sitemap.xml",
                method="GET",
                reason="metadata_request",
                source="metadata_coverage",
                evidence_ids=("EVID-DELEGATION",),
            ),
            DeepSourceRouteSkippedItem(
                url="https://portal.example.test/large",
                method="GET",
                reason="response_too_large",
                source="source_route_coverage",
                evidence_ids=("EVID-LARGE",),
            ),
        ),
        total_considered=2,
        total_collected=0,
        total_skipped=2,
    )
    (pack / "deep_source_route_collection.json").write_text(
        json.dumps(deep_source_route_collection_result_to_dict(collection), sort_keys=True),
        encoding="utf-8",
    )
    write_deep_metadata_collection_artifacts(
        DeepMetadataCollectionResult(
            collected=(
                DeepMetadataCollectedItem(
                    url="https://portal.example.test/sitemap.xml",
                    method="GET",
                    status_code=200,
                    final_url="https://portal.example.test/sitemap.xml",
                    headers=(("Content-Type", "application/xml"),),
                    body_preview="<urlset/>",
                    body_sha256="a" * 64,
                    body_bytes=9,
                    elapsed_seconds=0.1,
                    source="metadata_coverage",
                    reason="planned_uncollected_metadata",
                    evidence_ids=("EVID-METADATA",),
                ),
            ),
            skipped=(),
            total_considered=1,
            total_collected=1,
            total_skipped=0,
        ),
        pack,
    )

    model = build_html_report_model(pack)
    notice = next(
        item
        for item in model.confidence_notices
        if item.notice_id == "CONFIDENCE-DEEP-SOURCE-ROUTES"
    )
    html = render_html_report(model)

    assert ("metadata_completed", 1) in notice.counts
    assert ("metadata_uncollected", 0) in notice.counts
    assert ("response_too_large", 1) in notice.counts
    assert notice.evidence_ids == (
        "EVID-DELEGATION",
        "EVID-LARGE",
        "EVID-METADATA",
    )
    assert "completed by Deep metadata collection" in html
    assert "body-size limit" in html


def test_html_and_markdown_share_truthful_deep_collection_facts(tmp_path: Path) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    collection = DeepSourceRouteCollectionResult(
        collected=(
            _deep_item(
                "https://portal.example.test/docs",
                200,
                "a" * 64,
                evidence_ids=("EVID-DOCS",),
            ),
            _deep_item(
                "https://portal.example.test/private",
                401,
                "b" * 64,
                evidence_ids=("EVID-PRIVATE",),
            ),
        ),
        skipped=(
            DeepSourceRouteSkippedItem(
                url="https://portal.example.test/large-file",
                method="GET",
                reason="response_too_large",
                source="source_route_coverage",
                evidence_ids=("EVID-LARGE",),
            ),
            DeepSourceRouteSkippedItem(
                url="https://portal.example.test/blocked",
                method="GET",
                reason="policy_blocked",
                source="source_route_coverage",
                evidence_ids=("EVID-BLOCKED",),
            ),
        ),
        total_considered=4,
        total_collected=2,
        total_skipped=2,
    )
    (pack / "deep_source_route_collection.json").write_text(
        json.dumps(deep_source_route_collection_result_to_dict(collection), sort_keys=True),
        encoding="utf-8",
    )

    model = build_html_report_model(pack)
    markdown = render_collection_confidence_markdown(model.confidence_notices)
    html = render_html_report(model)

    assert markdown is not None
    shared_facts = (
        "collected 2 source/route response records",
        "1 successful 2xx response was promoted for priority content review",
        "excluded 1 response under the body-size limit",
        "policy_blocked",
    )
    for fact in shared_facts:
        assert fact in markdown
        assert fact in html


def _write_deep_interpretation_pack(root: Path) -> Path:
    pack = _write_current_pack(root)
    state_path = pack / "project_state.json"
    state_payload = json.loads(state_path.read_text(encoding="utf-8"))
    state_payload["project_state"]["recon_manifest"]["profile"] = "deep-bounded"
    state_path.write_text(
        json.dumps(state_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    collection = DeepSourceRouteCollectionResult(
        collected=(
            _deep_item(
                "https://portal.example.test/api/",
                200,
                "a" * 64,
                headers=(("Content-Type", "application/json"),),
                preview='{"routes":["/api/user","/api/jobs","/api/applications"]}',
                evidence_ids=("EVID-PATH-JSON",),
            ),
        ),
        skipped=(),
        total_considered=1,
        total_collected=1,
        total_skipped=0,
    )
    (pack / "deep_source_route_collection.json").write_text(
        json.dumps(deep_source_route_collection_result_to_dict(collection), sort_keys=True),
        encoding="utf-8",
    )
    (pack / "deep_recon_orchestration.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "deep_mode_enabled": True,
                "structured_body_disclosures": [
                    {
                        "category": "structured_configuration_body",
                        "title": "Structured operational configuration observed in response body",
                        "source_urls": ["https://portal.example.test/config"],
                        "final_response_urls": ["https://portal.example.test/config"],
                        "evidence_ids": ["EVID-CONFIG"],
                        "observed_values": [],
                        "evidence_excerpt": ["<VirtualHost *:80>", "ServerName portal.example.test"],
                        "source_body_sha256": "b" * 64,
                    },
                    {
                        "category": "structured_json_routes",
                        "title": "Relative routes disclosed by structured JSON",
                        "source_urls": ["https://portal.example.test/api/"],
                        "final_response_urls": ["https://portal.example.test/api/"],
                        "evidence_ids": ["EVID-PATH-JSON"],
                        "observed_values": ["/api/user", "/api/jobs", "/api/applications"],
                        "evidence_excerpt": [],
                        "source_body_sha256": "a" * 64,
                    },
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (pack / "recon_status.json").write_text(
        json.dumps(
            {"latest_execution": {"pipeline_profile": "deep-bounded"}},
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return pack


def _write_route_records(
    pack: Path,
    *,
    http_services: list[dict[str, object]] | tuple[dict[str, object], ...],
    urls: tuple[str, ...],
) -> None:
    state_path = pack / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    state = payload["project_state"]
    state["http_services"] = list(http_services)
    state["endpoints"] = [
        {
            "url": url,
            "hostname": "",
            "path": url,
            "query_params": [],
            "evidence_ids": [f"EVID-ROUTE-{index:04d}"],
            "tags": [],
        }
        for index, url in enumerate(urls, start=1)
    ]
    state["discovered_paths"] = []
    state_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _http_service_payload(url: str) -> dict[str, object]:
    return {
        "url": url,
        "hostname": "192.0.2.10",
        "status_code": 200,
        "title": "Synthetic",
        "technologies": [],
        "content_length": 0,
        "evidence_ids": ["EVID-SERVICE"],
        "tags": [],
    }


def _route_group_counts(model: object) -> dict[str, int]:
    return {
        group: sum(route.origin_group == group for route in model.route_groups)
        for group in ("assessed", "external", "relative")
    }


def _assert_category_filter_complete(html: str) -> set[str]:
    rendered_categories = {
        value for value in re.findall(r'data-category="([^"]*)"', html) if value
    }
    option_categories = {
        value for value in re.findall(r'<option value="([^"]*)">', html) if value
    }

    assert rendered_categories <= option_categories
    return option_categories


def test_cli_report_html_help_and_generation(tmp_path: Path, capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["report", "html", "--help"])
    help_output = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce report html" in help_output.out
    assert "--input-dir" in help_output.out
    assert "--output" in help_output.out

    pack = _write_current_pack(tmp_path / "pack")
    output = tmp_path / "review.html"
    exit_code = main(
        ["report", "html", "--input-dir", str(pack), "--output", str(output)]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert output.is_file()
    assert str(output) in captured.out
    assert "No network requests were made." in captured.out


def test_cli_report_html_reports_safe_errors_without_writing(tmp_path: Path, capsys) -> None:
    output = tmp_path / "review.html"

    exit_code = main(
        [
            "report",
            "html",
            "--input-dir",
            str(tmp_path / "missing"),
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Error: input directory does not exist" in captured.err
    assert "No network requests were made." in captured.err
    assert not output.exists()


def _write_current_pack(root: Path) -> Path:
    root.mkdir()
    state = build_project_state(FIXTURES_ROOT / "lab_raw_recon_pack")
    candidates = generate_candidates(state)
    (root / "project_state.json").write_text(
        export_project_state_json(state, candidates), encoding="utf-8"
    )
    return root


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _deep_item(
    url: str,
    status: int,
    body_hash: str,
    *,
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html"),),
    preview: str = "retained response preview",
    evidence_ids: tuple[str, ...],
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=status,
        final_url=url,
        headers=headers,
        body_preview=preview,
        body_sha256=body_hash,
        body_bytes=len(preview.encode("utf-8")),
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="existing structured review input",
        evidence_ids=evidence_ids,
    )


def _request_reflecting_html(url: str) -> str:
    path = urlsplit(url).path
    return (
        "<html><head><meta charset='utf-8'>"
        f"<title>Request failed for {path}</title>"
        "<style>html,body{margin:0;padding:0}main{display:block}"
        ".message{font-family:sans-serif;color:#222}</style></head>"
        "<body><main><h1>Request could not be completed</h1>"
        f"<p class='message'>The requested resource {path} was not handled.</p>"
        "<a href='/public/help'>Documentation</a>"
        "</main></body></html>"
    )



def test_html_model_restores_persisted_smb_shares_into_canonical_ranking(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "persisted-smb-share")
    state_path = pack / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    state = payload["project_state"]

    state["port_services"].append(
        {
            "host": "files.example.test",
            "port": 31337,
            "protocol": "tcp",
            "state": "open",
            "service": "microsoft-ds",
            "product": None,
            "version": None,
            "source_file": "nmap-services-all.txt",
            "evidence_ids": ["EVID-PORT-SMB"],
            "tags": [],
        }
    )
    state["smb_shares"] = [
        {
            "host": "files.example.test",
            "port": 31337,
            "share_name": "nt4wrksv",
            "share_type": "Disk",
            "comment": "",
            "source_file": "smb-shares-files.example.test-31337-guest.txt",
            "trigger_service_names": ["microsoft-ds"],
            "trigger_evidence_ids": ["EVID-PORT-SMB"],
            "trigger_source_files": ["nmap-services-all.txt"],
            "evidence_ids": ["EVID-SMB-0004"],
            "tags": [],
        }
    ]

    state_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    model = build_html_report_model(pack)

    assert len(model.project_state.smb_shares) == 1
    share = model.project_state.smb_shares[0]
    assert share.share_name == "nt4wrksv"
    assert share.share_type == "Disk"
    assert share.port == 31337
    assert share.evidence_ids == ["EVID-SMB-0004"]

    lead = next(
        item
        for item in model.operator_summary.ranked_leads
        if item.lead_type == "smb_disk_share_review"
    )
    assert lead.title == "SMB Disk share observed for review: nt4wrksv"
    assert lead.endpoints == ["files.example.test:31337/tcp"]
    assert lead.evidence_ids == ["EVID-SMB-0004"]

    html = unescape(render_html_report(model))
    assert "SMB Disk share observed for review: nt4wrksv" in html
    assert "EVID-SMB-0004" in html


def test_html_model_accepts_legacy_state_without_smb_shares(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "legacy-without-smb-shares")
    state_path = pack / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))

    payload["project_state"].pop("smb_shares", None)

    state_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    model = build_html_report_model(pack)

    assert model.project_state.smb_shares == []
