"""Deep-only static JavaScript analysis of manifest-retained initial HTML."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

from bugslyce.core.models import Evidence
from bugslyce.core.project import build_project_state
from bugslyce.reports.html_model import build_html_report_model
from bugslyce.reports.markdown import export_project_state_json
from bugslyce.recon.deep_initial_retained_javascript_route_extraction import (
    build_deep_initial_retained_javascript_route_extraction,
)
from bugslyce.recon.deep_orchestration import build_deep_recon_orchestration
from bugslyce.recon.deep_javascript_route_extraction import (
    build_deep_javascript_route_extraction,
)
from bugslyce.recon.deep_parameter_inventory import build_deep_parameter_inventory
from bugslyce.recon.deep_shallow_route_followup import (
    DeepShallowRouteFollowupResult,
    DeepShallowRouteFollowupResultSummaryCounts,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.modes import DEEP_RECON_BOUNDS


def test_retained_initial_inline_script_produces_typed_route_with_provenance(
    tmp_path: Path,
) -> None:
    state = _state(
        tmp_path,
        {
            "homepage.html": '<html><script>fetch("/service/status")</script></html>',
        },
    )

    result = build_deep_initial_retained_javascript_route_extraction(state)

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.candidate_id == "DEEP-JS-INITIAL-ROUTE-0001"
    assert candidate.safe_candidate == "/service/status"
    assert candidate.safe_resolved_url == "https://example.test/service/status"
    assert candidate.source_observations[0].source_role == "initial_retained_html"
    assert candidate.source_observations[0].manifest_file == "homepage.html"
    assert candidate.source_observations[0].safe_document_url == "https://example.test/"
    # An inline script has no compact HTTPArtifact/evidence record today. The
    # adapter preserves the authoritative manifest source instead of minting
    # an unsupported evidence ID.
    assert candidate.source_observations[0].evidence_ids == ()
    assert candidate.source_observations[0].source_body_sha256


def test_adapter_preserves_existing_static_fail_closed_semantics(tmp_path: Path) -> None:
    state = _state(
        tmp_path,
        {
            "homepage.html": (
                "<html><script>"
                "const good = '/api/items?tenant=blue';"
                "const dynamic = '/api/' + identifier;"
                "const static = '/assets/app.js';"
                "</script></html>"
            ),
            "ordinary.html": "<html><p>plain text only</p></html>",
        },
    )

    result = build_deep_initial_retained_javascript_route_extraction(state)

    assert [candidate.safe_candidate for candidate in result.candidates] == [
        "/api/items?tenant",
        "/assets/app.js",
    ]
    route = result.candidates[0]
    assert route.query_parameter_names == ("tenant",)
    assert "blue" not in repr(result)
    assert result.summary_counts.dynamic_concatenation_strings_skipped == 1


def test_same_retained_observation_is_not_processed_twice_but_independent_sources_remain(
    tmp_path: Path,
) -> None:
    body = '<html><script>fetch("/api/shared")</script></html>'
    state = _state(
        tmp_path,
        {
            "first.html": body,
            "second.html": body,
        },
        manifest_entries=(
            {"type": "html", "file": "first.html", "url": "https://example.test/one"},
            {"type": "html", "file": "first.html", "url": "https://example.test/one"},
            {"type": "html", "file": "second.html", "url": "https://example.test/two"},
        ),
    )

    result = build_deep_initial_retained_javascript_route_extraction(state)

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.occurrence_count == 2
    assert tuple(item.manifest_file for item in candidate.source_observations) == (
        "first.html",
        "second.html",
    )
    assert tuple(item.safe_document_url for item in candidate.source_observations) == (
        "https://example.test/one",
        "https://example.test/two",
    )
    assert result.summary_counts.duplicate_retained_observations_skipped == 1


def test_exact_initial_source_already_represented_by_deep_collection_is_not_emitted_twice(
    tmp_path: Path,
) -> None:
    body = b'<html><script>fetch("/api/shared")</script></html>'
    state = _state(tmp_path, {"homepage.html": body.decode("utf-8")})
    source_collection = _source_collection(
        DeepSourceRouteCollectedItem(
            url="https://example.test/",
            method="GET",
            status_code=200,
            final_url="https://example.test/",
            headers=(("Content-Type", "text/html"),),
            body_preview="",
            body_sha256=sha256(body).hexdigest(),
            body_bytes=len(body),
            elapsed_seconds=0.0,
            source="source_route_coverage",
            reason="fixture",
            evidence_ids=("EVID-DEEP",),
            body=body,
        )
    )

    initial = build_deep_initial_retained_javascript_route_extraction(
        state,
        source_collection,
    )
    existing = build_deep_javascript_route_extraction(source_collection)

    assert len(existing.candidates) == 1
    assert existing.candidates[0].candidate_id == "DEEP-JS-ROUTE-0001"
    assert initial.candidates == ()
    assert initial.summary_counts.already_represented_by_deep_collection_skipped == 1


def test_identical_body_at_different_document_urls_keeps_relative_routes_distinct(
    tmp_path: Path,
) -> None:
    body = '<html><script>fetch("api/status")</script></html>'
    state = _state(
        tmp_path,
        {"one.html": body, "two.html": body},
        manifest_entries=(
            {"type": "html", "file": "one.html", "url": "https://example.test/app/"},
            {"type": "html", "file": "two.html", "url": "https://example.test/admin/"},
        ),
    )

    result = build_deep_initial_retained_javascript_route_extraction(state)

    assert {candidate.safe_resolved_url for candidate in result.candidates} == {
        "https://example.test/app/api/status",
        "https://example.test/admin/api/status",
    }
    assert len(
        {
            item.source_body_sha256
            for candidate in result.candidates
            for item in candidate.source_observations
        }
    ) == 1


def test_source_identity_does_not_use_redacted_query_semantics_as_a_dedupe_key(
    tmp_path: Path,
) -> None:
    body = '<html><script>fetch("/api/shared")</script></html>'
    state = _state(
        tmp_path,
        {"homepage.html": body},
        manifest_entries=(
            {
                "type": "html",
                "file": "homepage.html",
                "url": "https://example.test/?tenant=blue",
            },
            {
                "type": "html",
                "file": "homepage.html",
                "url": "https://example.test/?tenant=red",
            },
        ),
    )

    result = build_deep_initial_retained_javascript_route_extraction(state)

    assert len(result.candidates) == 1
    assert len(result.candidates[0].source_observations) == 2
    assert result.summary_counts.duplicate_retained_observations_skipped == 0


def test_missing_or_oversized_initial_html_fails_closed(tmp_path: Path) -> None:
    state = _state(
        tmp_path,
        {"homepage.html": '<html><script>fetch("/api/kept")</script></html>'},
    )
    (tmp_path / "homepage.html").unlink()

    result = build_deep_initial_retained_javascript_route_extraction(state)

    assert result.candidates == ()
    assert result.summary_counts.unreadable_or_missing_sources_skipped == 1


def test_oversized_initial_html_is_rejected_before_complete_body_read(
    tmp_path: Path,
    monkeypatch,
) -> None:
    body = (
        b"<html><script>fetch('/service/status')</script>"
        + b" " * DEEP_RECON_BOUNDS.max_body_bytes
    )
    state = _state(tmp_path, {"homepage.html": body.decode("utf-8")})
    oversized_path = tmp_path / "homepage.html"
    reads: list[Path] = []
    original_read_bytes = Path.read_bytes

    def fail_if_oversized_read(path: Path) -> bytes:
        if path == oversized_path:
            reads.append(path)
            raise AssertionError("oversized initial HTML was fully read")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fail_if_oversized_read)

    result = build_deep_initial_retained_javascript_route_extraction(state)

    assert reads == []
    assert result.candidates == ()
    assert result.summary_counts.oversized_sources_skipped == 1


def test_initial_html_at_deep_body_bound_remains_analyzable(tmp_path: Path) -> None:
    prefix = '<html><script>fetch("/service/status")</script>'
    body = prefix + " " * (DEEP_RECON_BOUNDS.max_body_bytes - len(prefix))
    state = _state(tmp_path, {"homepage.html": body})

    result = build_deep_initial_retained_javascript_route_extraction(state)

    assert [candidate.safe_candidate for candidate in result.candidates] == [
        "/service/status"
    ]
    assert result.summary_counts.retained_html_sources_scanned == 1
    assert result.summary_counts.oversized_sources_skipped == 0


def test_unrelated_same_file_evidence_is_not_route_or_parameter_provenance(
    tmp_path: Path,
) -> None:
    state = _state(
        tmp_path,
        {
            "homepage.html": (
                '<html><script>fetch("/service/status?token=blue")</script></html>'
            ),
        },
    )
    state = replace(
        state,
        evidence=[
            Evidence(
                id="EVID-TITLE",
                source_file="homepage.html",
                evidence_type="page_title",
                value="Ordinary page title",
                context={},
            ),
            Evidence(
                id="EVID-LINK",
                source_file="homepage.html",
                evidence_type="link",
                value="/docs/help",
                context={},
            ),
            Evidence(
                id="EVID-COMMENT",
                source_file="homepage.html",
                evidence_type="html_comment",
                value="ordinary comment",
                context={},
            ),
        ],
    )

    initial = build_deep_initial_retained_javascript_route_extraction(state)
    candidate = initial.candidates[0]
    source = candidate.source_observations[0]
    orchestration = build_deep_recon_orchestration(
        _empty_source_collection(),
        _empty_shallow_followups(),
        initial_retained_javascript_route_extraction=initial,
    )
    token = next(
        parameter
        for parameter in orchestration.parameter_inventory.parameters
        if parameter.name == "token"
    )

    assert candidate.evidence_ids == ()
    assert source.evidence_ids == ()
    assert token.evidence_ids == ()
    assert token.observations[0].evidence_ids == ()
    assert source.manifest_file == "homepage.html"
    assert source.safe_document_url == "https://example.test/"
    assert source.source_body_sha256
    assert source.source_id.startswith("INITIAL-RETAINED-HTML-")


def test_initial_retained_query_route_threads_through_deep_orchestration_only(
    tmp_path: Path,
) -> None:
    state = _state(
        tmp_path,
        {
            "homepage.html": (
                '<html><script>fetch("/service/status?tenant=blue")</script></html>'
            ),
        },
    )
    initial = build_deep_initial_retained_javascript_route_extraction(state)

    result = build_deep_recon_orchestration(
        _empty_source_collection(),
        _empty_shallow_followups(),
        initial_retained_javascript_route_extraction=initial,
    )

    candidate = result.initial_retained_javascript_route_extraction.candidates[0]
    assert candidate.safe_resolved_url == "https://example.test/service/status?tenant"
    tenant = next(
        parameter
        for parameter in result.parameter_inventory.parameters
        if parameter.name == "tenant"
    )
    assert tenant.contexts == ("initial_retained_javascript_route_query",)
    observation = tenant.observations[0]
    assert observation.initial_retained_candidate_id == candidate.candidate_id
    assert observation.initial_retained_source_observation == candidate.source_observations[0]
    assert candidate.candidate_id in tenant.source_ids
    assert candidate.source_observations[0].source_id in tenant.source_ids
    assert "blue" not in repr(result)
    report = result.deep_recon_markdown
    assert "blue" not in report
    assert report.index("## Deep Shallow Route Follow-up Results") < report.index(
        "## Deep Initial Retained HTML JavaScript Route Analysis"
    ) < report.index("## Deep Post-follow-up JavaScript Route Analysis")
    assert "No network request was made or planned by this analysis." in report


def test_offline_project_state_reconstruction_rebuilds_initial_route_analysis(
    tmp_path: Path,
) -> None:
    state = _state(
        tmp_path,
        {"homepage.html": '<html><script>fetch("/service/status")</script></html>'},
    )
    (tmp_path / "project_state.json").write_text(
        export_project_state_json(state, []),
        encoding="utf-8",
    )

    offline_state = build_html_report_model(tmp_path).project_state

    assert build_deep_initial_retained_javascript_route_extraction(
        offline_state
    ) == build_deep_initial_retained_javascript_route_extraction(state)


def test_high_cardinality_static_routes_remain_bounded_by_retained_body_size(
    tmp_path: Path,
) -> None:
    script = ";".join(f'fetch("/api/item-{index}")' for index in range(300))
    state = _state(tmp_path, {"homepage.html": f"<script>{script}</script>"})

    result = build_deep_initial_retained_javascript_route_extraction(state)

    assert len(result.candidates) == 300
    assert result.summary_counts.candidate_occurrences_found == 300
    assert all(len(candidate.source_observations) == 1 for candidate in result.candidates)


def test_initial_retained_adapter_uses_existing_deep_source_file_bound(
    tmp_path: Path,
) -> None:
    total = DEEP_RECON_BOUNDS.max_source_files + 1
    files = {
        f"page-{index:03d}.html": "<html><p>no static route</p></html>"
        for index in range(total)
    }
    state = _state(
        tmp_path,
        files,
        manifest_entries=tuple(
            {
                "type": "html",
                "file": name,
                "url": f"https://example.test/{name}",
            }
            for name in sorted(files)
        ),
    )

    result = build_deep_initial_retained_javascript_route_extraction(state)

    assert result.candidates == ()
    assert result.summary_counts.manifest_html_sources_considered == total
    assert result.summary_counts.retained_html_sources_scanned == (
        DEEP_RECON_BOUNDS.max_source_files
    )
    assert result.summary_counts.source_limit_sources_skipped == 1


def test_initial_retained_adapter_is_permutation_stable_and_has_no_network_input(
    tmp_path: Path,
) -> None:
    state = _state(
        tmp_path,
        {
            "z.html": '<html><script>fetch("/z")</script></html>',
            "a.html": '<html><script>fetch("/a")</script></html>',
        },
        manifest_entries=(
            {"type": "html", "file": "z.html", "url": "https://example.test/z"},
            {"type": "html", "file": "a.html", "url": "https://example.test/a"},
        ),
    )
    reversed_state = _state(
        tmp_path / "reversed",
        {
            "z.html": '<html><script>fetch("/z")</script></html>',
            "a.html": '<html><script>fetch("/a")</script></html>',
        },
        manifest_entries=(
            {"type": "html", "file": "a.html", "url": "https://example.test/a"},
            {"type": "html", "file": "z.html", "url": "https://example.test/z"},
        ),
    )

    assert build_deep_initial_retained_javascript_route_extraction(
        reversed_state
    ) == build_deep_initial_retained_javascript_route_extraction(state)


def _state(
    root: Path,
    files: dict[str, str],
    *,
    manifest_entries: tuple[dict[str, str], ...] | None = None,
):
    root.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        (root / name).write_text(body, encoding="utf-8")
    entries = manifest_entries or tuple(
        {
            "type": "html",
            "file": name,
            "url": "https://example.test/",
        }
        for name in sorted(files)
    )
    (root / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "example.test",
                "artifacts": list(entries),
            }
        ),
        encoding="utf-8",
    )
    return build_project_state(root)


def _empty_source_collection() -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=(),
        skipped=(),
        total_considered=0,
        total_collected=0,
        total_skipped=0,
    )


def _source_collection(
    *items: DeepSourceRouteCollectedItem,
) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _empty_shallow_followups() -> DeepShallowRouteFollowupResult:
    return DeepShallowRouteFollowupResult(
        collected=(),
        skipped=(),
        summary_counts=DeepShallowRouteFollowupResultSummaryCounts(
            requests_planned=0,
            responses_collected=0,
            requests_skipped_or_failed=0,
            fetch_errors=0,
            invalid_fetch_responses=0,
            responses_too_large=0,
        ),
        safety_notes=(),
    )
