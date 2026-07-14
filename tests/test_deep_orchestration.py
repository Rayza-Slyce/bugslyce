"""Tests for Phase 93C Deep orchestration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from bugslyce.core.project import build_project_state
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
        "No parameter value was retained, replayed, guessed, or mutated by orchestration.",
        "No confirmed vulnerability claim is made by orchestration.",
        "Deep mode was not enabled.",
    ):
        assert expected in runbook
    assert len(result.safety_notes) == len(set(result.safety_notes))


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
    public_json = paths[2].read_text(encoding="utf-8")
    assert "SECRET_VALUE" not in public_json
    assert "<form" not in public_json
    assert str(tmp_path) not in public_json
    assert public_json.endswith("\n")
    assert write_deep_recon_orchestration_artifacts(result, tmp_path, force=True)[2].read_bytes() == paths[2].read_bytes()


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
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=headers,
        body_preview=body_preview,
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
    body: bytes = b"<html><form action='/follow-login'><input name='shallow'></form></html>",
    evidence_ids: tuple[str, ...] = ("EVID-SHALLOW",),
) -> DeepShallowRouteFollowupCollectedItem:
    return DeepShallowRouteFollowupCollectedItem(
        request_id="DEEP-SHALLOW-REQ-0001",
        requested_url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=(("Content-Type", "text/html"),),
        body_preview="",
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
