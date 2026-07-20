"""Tests for Phase 93C Deep orchestration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from bugslyce.core.project import build_project_state
from bugslyce.core.sensitive_evidence import (
    DEEP_SENSITIVE_EVIDENCE_NOTICE,
    is_generic_sensitive_retention_note,
)
from bugslyce.project_session import build_project_runbook, scaffold_project
from bugslyce.recon.deep_orchestration import (
    DEEP_RECON_ORCHESTRATION_JSON,
    DEEP_RECON_REVIEW_MARKDOWN,
    DEEP_RECON_RUNBOOK_MARKDOWN,
    STAGE_ORDER,
    build_deep_recon_orchestration,
    write_deep_recon_orchestration_artifacts,
)
from bugslyce.recon.deep_shallow_route_followup import (
    DeepShallowRouteFollowupCollectedItem,
    DeepShallowRouteFollowupResult,
    DeepShallowRouteFollowupResultSummaryCounts,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)
from bugslyce.reports.markdown import render_markdown_report
from bugslyce.triage.candidates import generate_candidates


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def test_builder_produces_all_stages_and_preserves_inputs() -> None:
    source = _source_result(_source_item())
    shallow = _shallow_result(_shallow_item())
    before = (source, shallow)

    result = build_deep_recon_orchestration(source, shallow)

    assert (source, shallow) == before
    assert result.stage_order == STAGE_ORDER
    assert tuple(stage for stage, _count in result.stage_counts) == STAGE_ORDER
    assert result.collection_review_bundle is not None
    assert result.http_fingerprint_summary is not None
    assert result.redirect_auth_flow_review is not None
    assert result.response_similarity_review is not None
    assert result.html_route_extraction is not None
    assert result.javascript_route_extraction is not None
    assert result.shallow_route_followup is shallow
    assert result.form_inventory is not None
    assert result.parameter_inventory is not None
    assert result.deep_profile_selected is False
    assert result.deep_collection_completed is None
    assert result.deep_offline_review_completed is True
    assert tuple(
        item.canonical_url for item in result.successful_content_reviews
    ) == ("http://example.test/source",)
    assert "Bounded Deep collection completion is not established." in result.deep_recon_markdown


def test_successful_content_reviews_are_built_from_persisted_collection_fields() -> None:
    item = _source_item(
        url="https://portal.example.test/public/notice.txt",
        headers=(("Content-Type", "text/plain"),),
        body=b"Retained release notice.",
        evidence_ids=("EVID-DEEP-NOTICE",),
    )

    result = build_deep_recon_orchestration(
        _source_result(item),
        _shallow_result(),
    )

    assert len(result.successful_content_reviews) == 1
    review = result.successful_content_reviews[0]
    assert review.canonical_url == item.url
    assert review.status_code == 200
    assert review.content_type == "text/plain"
    assert review.body_preview == "Retained release notice."
    assert review.evidence_ids == ("EVID-DEEP-NOTICE",)
    assert review.artefact_references == (
        "deep_source_route_collection.json",
    )


def test_dependency_inputs_are_threaded_to_form_and_parameter_inventory(monkeypatch) -> None:
    import bugslyce.recon.deep_orchestration as orchestration

    source = _source_result(_source_item())
    shallow = _shallow_result(_shallow_item())
    original_form = orchestration.build_deep_form_inventory
    original_parameter = orchestration.build_deep_parameter_inventory
    captured: dict[str, object] = {}

    def capture_form(source_collection, shallow_followups):
        captured["form_source"] = source_collection
        captured["form_shallow"] = shallow_followups
        return original_form(source_collection, shallow_followups)

    def capture_parameter(source_collection, shallow_followups, html_extraction, javascript_extraction):
        captured["parameter_source"] = source_collection
        captured["parameter_shallow"] = shallow_followups
        captured["parameter_html"] = html_extraction
        captured["parameter_javascript"] = javascript_extraction
        return original_parameter(
            source_collection,
            shallow_followups,
            html_extraction,
            javascript_extraction,
        )

    monkeypatch.setattr(orchestration, "build_deep_form_inventory", capture_form)
    monkeypatch.setattr(orchestration, "build_deep_parameter_inventory", capture_parameter)

    result = orchestration.build_deep_recon_orchestration(source, shallow)

    assert captured["form_source"] is source
    assert captured["form_shallow"] is shallow
    assert captured["parameter_source"] is source
    assert captured["parameter_shallow"] is shallow
    assert captured["parameter_html"] is result.html_route_extraction
    assert captured["parameter_javascript"] is result.javascript_route_extraction


def test_combined_report_markdown_is_ordered_once_and_deterministic() -> None:
    result = build_deep_recon_orchestration(
        _source_result(_source_item()),
        _shallow_result(_shallow_item()),
    )
    second = build_deep_recon_orchestration(
        _source_result(_source_item()),
        _shallow_result(_shallow_item()),
    )
    headings = (
        "## Deep Collection Review Bundle",
        "## Deep HTTP Fingerprint Summary",
        "## Deep Redirect/Auth-Flow Review",
        "## Deep Response Similarity Review",
        "## Deep HTML Route Extraction",
        "## Deep JavaScript Route Extraction",
        "## Deep Shallow Route Follow-up Results",
        "## Deep Form Inventory",
        "## Deep Parameter Inventory",
    )

    assert result.deep_recon_markdown == second.deep_recon_markdown
    assert result.deep_recon_markdown.endswith("\n")
    assert not result.deep_recon_markdown.endswith("\n\n")
    for heading in headings:
        assert result.deep_recon_markdown.count(heading) == 1
    positions = [result.deep_recon_markdown.index(heading) for heading in headings]
    assert positions == sorted(positions)
    assert "Static HTML form structure observed" in result.deep_recon_markdown


def test_compact_runbook_contains_counts_safety_and_not_full_report() -> None:
    result = build_deep_recon_orchestration(
        _source_result(_source_item()),
        _shallow_result(_shallow_item()),
    )
    runbook = result.deep_recon_runbook_markdown

    assert runbook.startswith("## Deep Recon Review Guide\n")
    assert runbook.endswith("\n")
    assert "## Deep HTTP Fingerprint Summary" not in runbook
    assert "```bash" not in runbook
    assert "payload" not in runbook.lower()
    assert "vulnerability found" not in runbook.lower()
    for index, stage_id in enumerate(result.stage_order, start=1):
        assert f"{index}. `{stage_id}`" in runbook
        assert f"- `{stage_id}`:" in runbook
    for expected in (
        "No network requests were made by orchestration.",
        "No form submission was performed by orchestration.",
        "No form action was fetched by orchestration.",
        "No JavaScript was executed by orchestration.",
        "No parameter value was replayed, guessed, or mutated by orchestration.",
        "No confirmed vulnerability claim is made by orchestration.",
        "Deep profile selection is not established by this standalone offline orchestration.",
        "Deep offline review orchestration completed for the supplied result.",
    ):
        assert expected in runbook
    assert len(result.safety_notes) == len(set(result.safety_notes))
    assert result.deep_recon_markdown.count(DEEP_SENSITIVE_EVIDENCE_NOTICE) == 1
    assert runbook.count(DEEP_SENSITIVE_EVIDENCE_NOTICE) == 1
    assert "see the `report.md`" not in result.deep_recon_markdown
    assert "see the `report.md`" not in runbook


def test_composite_runbook_qualifies_parameter_retention_to_inventory_stage() -> None:
    source = _source_item(url="http://example.test/view?record_id=7")
    result = build_deep_recon_orchestration(
        _source_result(source),
        _shallow_result(),
    )
    runbook = result.deep_recon_runbook_markdown

    assert "Phase 92B" not in result.deep_recon_markdown
    assert "Phase 92B" not in runbook
    assert "No parameter value was retained" not in runbook
    assert "Deep parameter-inventory stage" in runbook
    assert source.url == "http://example.test/view?record_id=7"


def test_individual_deep_stage_notes_do_not_repeat_generic_retention_policy() -> None:
    from bugslyce.recon.deep_http_fingerprint_summary import (
        SAFETY_NOTES as FINGERPRINT_NOTES,
    )
    from bugslyce.recon.deep_metadata_collector import SAFETY_NOTES as METADATA_NOTES
    from bugslyce.recon.deep_redirect_auth_flow_review import (
        SAFETY_NOTES as REDIRECT_NOTES,
    )
    from bugslyce.recon.deep_shallow_route_followup import (
        RESULT_SAFETY_NOTES as SHALLOW_NOTES,
    )
    from bugslyce.recon.deep_source_route_collector import (
        SAFETY_NOTES as SOURCE_NOTES,
    )

    for notes in (
        METADATA_NOTES,
        SOURCE_NOTES,
        FINGERPRINT_NOTES,
        REDIRECT_NOTES,
        SHALLOW_NOTES,
    ):
        assert not any(is_generic_sensitive_retention_note(note) for note in notes)
        assert all("report.md" not in note for note in notes)


def test_pure_builder_creates_no_files(tmp_path: Path) -> None:
    before = set(tmp_path.iterdir())

    build_deep_recon_orchestration(_source_result(_source_item()), _shallow_result())

    assert set(tmp_path.iterdir()) == before


def test_writer_creates_three_deterministic_artifacts(tmp_path: Path) -> None:
    result = build_deep_recon_orchestration(
        _source_result(_source_item(body=b"<html><form><input name='token' value='SECRET_VALUE'></form></html>")),
        _shallow_result(_shallow_item()),
    )

    paths = write_deep_recon_orchestration_artifacts(result, tmp_path)

    assert paths == (
        tmp_path / DEEP_RECON_REVIEW_MARKDOWN,
        tmp_path / DEEP_RECON_RUNBOOK_MARKDOWN,
        tmp_path / DEEP_RECON_ORCHESTRATION_JSON,
    )
    assert paths[0].read_text(encoding="utf-8") == result.deep_recon_markdown
    assert paths[1].read_text(encoding="utf-8") == result.deep_recon_runbook_markdown
    payload = json.loads(paths[2].read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert payload["stage_order"] == list(STAGE_ORDER)
    assert payload["report_markdown_file"] == DEEP_RECON_REVIEW_MARKDOWN
    assert payload["runbook_markdown_file"] == DEEP_RECON_RUNBOOK_MARKDOWN
    assert payload["no_network_requests_made"] is True
    assert payload["deep_mode_enabled"] is False
    before = tuple(path.read_bytes() for path in paths)
    with pytest.raises(ValueError, match="authoritative orchestration result"):
        write_deep_recon_orchestration_artifacts(
            result,
            tmp_path,
            force=True,
            deep_mode_enabled=True,
        )
    assert tuple(path.read_bytes() for path in paths) == before
    compatible_paths = write_deep_recon_orchestration_artifacts(
        result,
        tmp_path,
        force=True,
        deep_mode_enabled=False,
    )
    assert tuple(path.read_bytes() for path in compatible_paths) == before
    public_json = paths[2].read_text(encoding="utf-8")
    assert "SECRET_VALUE" not in public_json
    assert "<form" not in public_json
    assert str(tmp_path) not in public_json
    assert public_json.endswith("\n")
    assert write_deep_recon_orchestration_artifacts(result, tmp_path, force=True)[2].read_bytes() == paths[2].read_bytes()


def test_selected_deep_profile_records_completed_collection_and_offline_review(
    tmp_path: Path,
) -> None:
    body = json.dumps({"navigation": {"routes": ["/v3/records", "/v3/search"]}}).encode()
    result = build_deep_recon_orchestration(
        _source_result(
            _source_item(
                url="https://example.test/navigation.json",
                headers=(("Content-Type", "application/json"),),
                body=body,
                evidence_ids=("EVID-JSON",),
            )
        ),
        _shallow_result(),
        deep_profile_selected=True,
        deep_collection_completed=True,
    )

    paths = write_deep_recon_orchestration_artifacts(result, tmp_path)
    payload = json.loads(paths[2].read_text(encoding="utf-8"))

    assert result.deep_profile_selected is True
    assert result.deep_collection_completed is True
    assert result.deep_offline_review_completed is True
    assert "Deep profile selected: yes (`deep-bounded`)." in result.deep_recon_markdown
    assert "Bounded Deep collection completed" in result.deep_recon_markdown
    assert "Deep mode was not enabled" not in result.deep_recon_markdown
    assert payload["deep_mode_enabled"] is True
    assert payload["deep_profile_selected"] is True
    assert payload["deep_collection_completed"] is True
    assert payload["deep_offline_review_completed"] is True
    assert payload["structured_body_disclosures"] == [
        {
            "category": "structured_json_routes",
            "evidence_excerpt": [],
            "evidence_ids": ["EVID-JSON"],
            "final_response_urls": ["https://example.test/navigation.json"],
            "observed_values": ["/v3/records", "/v3/search"],
            "source_body_sha256": hashlib.sha256(body).hexdigest(),
            "source_urls": ["https://example.test/navigation.json"],
            "title": "Relative routes disclosed by structured JSON",
        }
    ]
    assert result.deep_recon_markdown.count("`/v3/records`") == 1
    assert result.deep_recon_markdown.count("`/v3/search`") == 1


def test_configuration_secret_is_redacted_across_human_review_layers() -> None:
    from bugslyce.project_pipeline import _deep_operator_summary_leads

    secret = "retained-target-secret-918273"
    body = (
        "server_name = application.example.test\n"
        "listen_port = 8443\n"
        f"session_token = {secret}\n"
        "document_root = /srv/application/current\n"
    ).encode()
    source_item = _source_item(
        url="https://example.test/runtime-settings",
        headers=(("Content-Type", "text/plain"),),
        body=body,
        evidence_ids=("EVID-CONFIG-SECRET",),
    )
    result = build_deep_recon_orchestration(
        _source_result(source_item),
        _shallow_result(),
        deep_profile_selected=True,
        deep_collection_completed=True,
    )
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    report = render_markdown_report(
        state,
        generate_candidates(state),
        operator_summary_leads=_deep_operator_summary_leads(result),
    )

    assert secret in source_item.body.decode()
    assert secret in source_item.body_preview
    assert secret not in result.deep_recon_markdown
    assert secret not in report
    assert "session_token = [REDACTED]" in result.deep_recon_markdown
    assert "session_token = [REDACTED]" in report
    assert "document_root = /srv/application/current" in result.deep_recon_markdown
    assert result.deep_recon_markdown.count(
        "`document_root = /srv/application/current`"
    ) == 1


def test_standalone_offline_review_does_not_claim_collection_completed(
    tmp_path: Path,
) -> None:
    result = build_deep_recon_orchestration(
        _source_result(_source_item()),
        _shallow_result(),
    )

    paths = write_deep_recon_orchestration_artifacts(result, tmp_path)
    payload = json.loads(paths[2].read_text(encoding="utf-8"))

    assert result.deep_profile_selected is False
    assert result.deep_collection_completed is None
    assert result.deep_offline_review_completed is True
    assert payload["deep_mode_enabled"] is False
    assert payload["deep_collection_completed"] is None
    assert payload["deep_offline_review_completed"] is True
    assert "collection completion is not established" in result.deep_recon_markdown


def test_explicit_non_deep_incomplete_collection_state_is_rendered_consistently(
    tmp_path: Path,
) -> None:
    result = build_deep_recon_orchestration(
        _source_result(_source_item()),
        _shallow_result(),
        deep_profile_selected=False,
        deep_collection_completed=False,
    )

    paths = write_deep_recon_orchestration_artifacts(result, tmp_path)
    payload = json.loads(paths[2].read_text(encoding="utf-8"))

    assert payload["deep_profile_selected"] is False
    assert payload["deep_collection_completed"] is False
    assert payload["deep_offline_review_completed"] is True
    assert "Bounded Deep collection is recorded as not completed." in (
        result.deep_recon_markdown
    )


def test_legacy_false_flag_does_not_override_authoritative_completed_deep_state(
    tmp_path: Path,
) -> None:
    result = build_deep_recon_orchestration(
        _source_result(_source_item()),
        _shallow_result(),
        deep_profile_selected=True,
        deep_collection_completed=True,
    )

    paths = write_deep_recon_orchestration_artifacts(result, tmp_path)
    before = tuple(path.read_bytes() for path in paths)
    with pytest.raises(ValueError, match="authoritative orchestration result"):
        write_deep_recon_orchestration_artifacts(
            result,
            tmp_path,
            force=True,
            deep_mode_enabled=False,
        )
    assert tuple(path.read_bytes() for path in paths) == before
    payload = json.loads(paths[2].read_text(encoding="utf-8"))

    assert payload["deep_mode_enabled"] is True
    assert payload["deep_profile_selected"] is True
    assert payload["deep_collection_completed"] is True


def test_legacy_true_flag_cannot_enable_standalone_orchestration(
    tmp_path: Path,
) -> None:
    result = build_deep_recon_orchestration(
        _source_result(_source_item()),
        _shallow_result(),
    )
    paths = write_deep_recon_orchestration_artifacts(result, tmp_path)
    before = tuple(path.read_bytes() for path in paths)

    with pytest.raises(ValueError, match="authoritative orchestration result"):
        write_deep_recon_orchestration_artifacts(
            result,
            tmp_path,
            force=True,
            deep_mode_enabled=True,
        )

    assert tuple(path.read_bytes() for path in paths) == before
    payload = json.loads(paths[2].read_text(encoding="utf-8"))
    markdown = paths[0].read_text(encoding="utf-8")
    assert payload["deep_mode_enabled"] is False
    assert payload["deep_profile_selected"] is False
    assert "Deep profile selection is not established" in markdown


def test_structured_disclosure_machine_output_keeps_redirect_provenance(
    tmp_path: Path,
) -> None:
    body = json.dumps({"routes": ["/service/health"]}).encode()
    source_item = _source_item(
        url="https://example.test/catalogue",
        final_url="https://example.test/catalogue/",
        headers=(("Content-Type", "application/json"),),
        body=body,
        evidence_ids=("EVID-REDIRECT-JSON",),
    )
    result = build_deep_recon_orchestration(
        _source_result(source_item),
        _shallow_result(),
        deep_profile_selected=True,
        deep_collection_completed=True,
    )

    paths = write_deep_recon_orchestration_artifacts(result, tmp_path)
    payload = json.loads(paths[2].read_text(encoding="utf-8"))
    disclosure = payload["structured_body_disclosures"][0]

    assert disclosure["source_urls"] == ["https://example.test/catalogue"]
    assert disclosure["final_response_urls"] == ["https://example.test/catalogue/"]
    assert "Final response URLs: `https://example.test/catalogue/`" in result.deep_recon_markdown


def test_existing_shallow_json_body_is_reviewed_without_planning_more_requests() -> None:
    body = json.dumps(
        {"related": ["/v4/records", "/v4/summary"]},
    ).encode()
    shallow = _shallow_item(
        url="https://example.test/shallow-data.json",
        headers=(("Content-Type", "application/json"),),
        body=body,
        evidence_ids=("EVID-SHALLOW-JSON",),
    )

    result = build_deep_recon_orchestration(
        _source_result(),
        _shallow_result(shallow),
        deep_profile_selected=True,
    )
    lead = next(
        item
        for item in result.source_route_collection_review.review_leads
        if item.category == "structured_json_routes"
    )

    assert lead.urls == ("https://example.test/shallow-data.json",)
    assert lead.observed_values == ("/v4/records", "/v4/summary")
    assert lead.evidence_ids == ("EVID-SHALLOW-JSON",)
    assert result.source_route_collection_review.total_collected == 0
    assert result.shallow_route_followup.summary_counts.requests_planned == 1
    assert "not requested by this review" in lead.reason


def test_writer_refuses_overwrite_and_validates_before_writing(tmp_path: Path) -> None:
    result = build_deep_recon_orchestration(_source_result(_source_item()), _shallow_result())
    existing = tmp_path / DEEP_RECON_RUNBOOK_MARKDOWN
    existing.write_text("keep\n", encoding="utf-8")

    with pytest.raises(ValueError, match="already exists"):
        write_deep_recon_orchestration_artifacts(result, tmp_path)

    assert existing.read_text(encoding="utf-8") == "keep\n"
    assert not (tmp_path / DEEP_RECON_REVIEW_MARKDOWN).exists()
    assert not (tmp_path / DEEP_RECON_ORCHESTRATION_JSON).exists()


def test_writer_rejects_non_directory_output(tmp_path: Path) -> None:
    result = build_deep_recon_orchestration(_source_result(_source_item()), _shallow_result())
    output_file = tmp_path / "not-dir"
    output_file.write_text("x\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not a directory"):
        write_deep_recon_orchestration_artifacts(result, output_file)


def test_phase_93_seams_accept_orchestration_outputs(tmp_path: Path) -> None:
    result = build_deep_recon_orchestration(
        _source_result(_source_item()),
        _shallow_result(_shallow_item()),
    )
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    report = render_markdown_report(
        state,
        candidates,
        deep_recon_markdown=result.deep_recon_markdown,
    )

    assert report.count("## Deep Collection Review Bundle") == 1
    assert report.index("## Operator Summary") < report.index("## Deep Collection Review Bundle")
    assert report.index("## Deep Collection Review Bundle") < report.index("## Scope Summary")

    scaffold = scaffold_project("deep-seam", "10.10.10.10", tmp_path / "projects")
    runbook = build_project_runbook(
        Path(scaffold.project_file),
        deep_recon_runbook_markdown=result.deep_recon_runbook_markdown,
    ).content
    assert runbook.count("## Deep Recon Review Guide") == 1
    assert runbook.index("## Suggested Next Command") < runbook.index("## Deep Recon Review Guide")
    assert runbook.index("## Deep Recon Review Guide") < runbook.index("## Typical Safe Workflow")

    export_input = _export_input(tmp_path)
    written_paths = write_deep_recon_orchestration_artifacts(result, export_input)
    output_zip = tmp_path / "pack.zip"
    export_recon_evidence_pack(
        export_input,
        output_zip,
        deep_evidence_paths=written_paths,
    )
    with zipfile.ZipFile(output_zip) as archive:
        names = archive.namelist()
    for path in written_paths:
        assert names.count(f"raw/{path.name}") == 1


def test_mode_invariants_remain_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True


def test_module_does_not_import_collectors_or_network_clients() -> None:
    source = (Path(__file__).resolve().parents[1] / "bugslyce" / "recon" / "deep_orchestration.py").read_text(encoding="utf-8")

    for forbidden in (
        "collect_deep_source_routes",
        "collect_deep_shallow_route_followups",
        "requests.",
        "httpx.",
        "urllib.request",
        "socket.",
        "subprocess",
        "glob(",
        "rglob(",
    ):
        assert forbidden not in source


def _source_result(*items: DeepSourceRouteCollectedItem) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _source_item(
    *,
    url: str = "http://example.test/source",
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html"),),
    body: bytes = b"<html><a href='/admin?token=secret'>Admin</a><script>const route='/api?token=secret';</script><form action='/login?next=secret'><input name='user' value='secret'></form></html>",
    body_preview: str = "",
    evidence_ids: tuple[str, ...] = ("EVID-SOURCE",),
    final_url: str | None = None,
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=final_url or url,
        headers=headers,
        body_preview=body_preview or body.decode("utf-8", errors="replace")[:500],
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.1,
        source="source_route_coverage",
        reason="test source",
        evidence_ids=evidence_ids,
        body=body,
    )


def _shallow_result(*items: DeepShallowRouteFollowupCollectedItem) -> DeepShallowRouteFollowupResult:
    return DeepShallowRouteFollowupResult(
        collected=tuple(items),
        skipped=(),
        summary_counts=DeepShallowRouteFollowupResultSummaryCounts(
            requests_planned=len(items),
            responses_collected=len(items),
            requests_skipped_or_failed=0,
            fetch_errors=0,
            invalid_fetch_responses=0,
            responses_too_large=0,
        ),
        safety_notes=(),
    )


def _shallow_item(
    *,
    url: str = "http://example.test/follow",
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html"),),
    body: bytes = b"<html><form action='/follow-login'><input name='shallow'></form></html>",
    evidence_ids: tuple[str, ...] = ("EVID-SHALLOW",),
    body_preview: str = "",
) -> DeepShallowRouteFollowupCollectedItem:
    return DeepShallowRouteFollowupCollectedItem(
        request_id="DEEP-SHALLOW-REQ-0001",
        requested_url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=headers,
        body_preview=body_preview or body.decode("utf-8", errors="replace")[:500],
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.2,
        source_model_kinds=("html_route",),
        source_route_candidate_ids=("DEEP-HTML-ROUTE-0001",),
        query_parameter_names=("token",),
        evidence_ids=evidence_ids,
        interpretation="Collected via deterministic test fixture.",
        body=body,
    )


def _export_input(tmp_path: Path) -> Path:
    input_dir = tmp_path / "recon"
    input_dir.mkdir()
    (input_dir / "report.md").write_text("# Report\n", encoding="utf-8")
    (input_dir / "project_state.json").write_text("{}\n", encoding="utf-8")
    (input_dir / "scope.md").write_text("## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "scope_file": "scope.md",
                "profile": "lab-tcp-full",
                "artifacts": [],
            }
        ),
        encoding="utf-8",
    )
    return input_dir
