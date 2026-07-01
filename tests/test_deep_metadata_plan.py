"""Tests for the pure Deep common metadata request planner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugslyce.project_pipeline import run_project_pipeline
from bugslyce.recon.deep_metadata_plan import (
    DEEP_METADATA_PATHS,
    DeepMetadataPlan,
    DeepMetadataRequest,
    DeepMetadataService,
    build_deep_metadata_request_plan,
    export_deep_metadata_plan_json,
    render_deep_metadata_plan_markdown,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)
from bugslyce.recon.planner import build_recon_plan


def test_empty_input_produces_zero_requests_and_non_executable_guarantees() -> None:
    plan = build_deep_metadata_request_plan(())

    assert isinstance(plan, DeepMetadataPlan)
    assert plan.requests == ()
    assert plan.skipped_services == ()
    assert plan.bounds == {
        "max_services": 50,
        "metadata_paths_per_service": len(DEEP_METADATA_PATHS),
    }
    assert "No network requests are performed." in plan.non_executable_guarantees
    assert "`deep-bounded` remains non-executable." in plan.non_executable_guarantees


@pytest.mark.parametrize(
    "service_url",
    ("http://example.test", "https://example.test"),
)
def test_http_and_https_services_produce_fixed_metadata_requests(service_url: str) -> None:
    plan = build_deep_metadata_request_plan(
        (DeepMetadataService(url=service_url, source="unit-test"),)
    )

    assert [request.request_id for request in plan.requests] == [
        f"deep-meta-{index:04d}" for index in range(1, len(DEEP_METADATA_PATHS) + 1)
    ]
    assert [request.path for request in plan.requests] == [
        path for path, _category, _reason in DEEP_METADATA_PATHS
    ]
    assert {request.method for request in plan.requests} == {"GET"}
    assert {request.source for request in plan.requests} == {"unit-test"}


def test_service_path_is_normalised_to_origin_root() -> None:
    plan = build_deep_metadata_request_plan(
        (DeepMetadataService(url="https://Example.TEST/app/path?x=1#frag", source="service"),)
    )

    assert plan.requests[0] == DeepMetadataRequest(
        request_id="deep-meta-0001",
        service_url="https://example.test/",
        method="GET",
        url="https://example.test/robots.txt",
        path="/robots.txt",
        category="robots",
        reason="Common robots.txt policy and clue source.",
        source="service",
    )
    assert all(request.url.startswith("https://example.test/") for request in plan.requests)
    assert all("/app/" not in request.url for request in plan.requests)


def test_duplicate_origins_are_deduped_and_first_seen_order_is_preserved() -> None:
    plan = build_deep_metadata_request_plan(
        (
            DeepMetadataService(url="https://b.example/app", source="first-b"),
            DeepMetadataService(url="http://a.example:8080/root", source="first-a"),
            DeepMetadataService(url="https://B.EXAMPLE/other", source="duplicate-b"),
        )
    )

    first_origin_requests = plan.requests[: len(DEEP_METADATA_PATHS)]
    second_origin_requests = plan.requests[len(DEEP_METADATA_PATHS) :]
    assert {request.service_url for request in first_origin_requests} == {"https://b.example/"}
    assert {request.service_url for request in second_origin_requests} == {"http://a.example:8080/"}
    assert [(skip.url, skip.reason) for skip in plan.skipped_services] == [
        ("https://B.EXAMPLE/other", "duplicate_origin")
    ]


def test_planned_urls_remain_same_origin() -> None:
    plan = build_deep_metadata_request_plan(
        (
            DeepMetadataService(url="https://example.test:8443/app", source="service-a"),
            DeepMetadataService(url="http://192.0.2.10:8080/", source="service-b"),
        )
    )

    for request in plan.requests:
        assert request.url.startswith(request.service_url.rstrip("/") + "/")


def test_unsupported_malformed_and_empty_urls_are_skipped() -> None:
    plan = build_deep_metadata_request_plan(
        (
            DeepMetadataService(url="", source="empty"),
            DeepMetadataService(url="ftp://example.test", source="ftp"),
            DeepMetadataService(url="file:///tmp/robots.txt", source="file"),
            DeepMetadataService(url="javascript:alert(1)", source="javascript"),
            DeepMetadataService(url="http://", source="missing-host"),
            DeepMetadataService(url="http://example.test:bad/", source="bad-port"),
        )
    )

    assert plan.requests == ()
    assert [(skip.source, skip.reason) for skip in plan.skipped_services] == [
        ("empty", "empty_url"),
        ("ftp", "unsupported_scheme"),
        ("file", "unsupported_scheme"),
        ("javascript", "unsupported_scheme"),
        ("missing-host", "malformed_url"),
        ("bad-port", "malformed_url"),
    ]


def test_service_limit_is_enforced_with_deterministic_skip_reason() -> None:
    plan = build_deep_metadata_request_plan(
        (
            DeepMetadataService(url="https://one.example", source="one"),
            DeepMetadataService(url="https://two.example", source="two"),
            DeepMetadataService(url="https://three.example", source="three"),
        ),
        max_services=2,
    )

    assert len(plan.requests) == 2 * len(DEEP_METADATA_PATHS)
    assert plan.bounds["max_services"] == 2
    assert [(skip.url, skip.reason) for skip in plan.skipped_services] == [
        ("https://three.example", "service_limit_exceeded")
    ]


def test_export_json_is_deterministic_serialisable_and_non_executable() -> None:
    plan = build_deep_metadata_request_plan(
        (DeepMetadataService(url="https://example.test/app", source="unit-test"),)
    )

    first = export_deep_metadata_plan_json(plan)
    second = export_deep_metadata_plan_json(plan)

    assert first == second
    assert json.loads(json.dumps(first, sort_keys=True)) == first
    assert first["schema_version"] == 1
    assert first["request_count"] == len(DEEP_METADATA_PATHS)
    assert first["skipped_service_count"] == 0
    assert _walk_keys(first).isdisjoint(
        {"argv", "command_preview", "execute", "subprocess"}
    )


def test_markdown_rendering_is_deterministic_and_includes_counts_and_guarantees() -> None:
    plan = build_deep_metadata_request_plan(
        (DeepMetadataService(url="https://example.test/app", source="unit-test"),)
    )

    first = render_deep_metadata_plan_markdown(plan)
    second = render_deep_metadata_plan_markdown(plan)

    assert first == second
    assert first.startswith("# Deep Common Metadata Request Plan\n")
    assert f"- Planned requests: {len(DEEP_METADATA_PATHS)}" in first
    assert "- Skipped services: 0" in first
    assert "`deep-meta-0001` `GET` https://example.test/robots.txt" in first
    assert "No network requests are performed." in first
    assert "No output files are created." in first


def test_planner_export_and_renderer_create_no_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    plan = build_deep_metadata_request_plan(
        (DeepMetadataService(url="https://example.test", source="unit-test"),)
    )
    export_deep_metadata_plan_json(plan)
    render_deep_metadata_plan_markdown(plan)

    assert list(tmp_path.iterdir()) == []


def test_deep_bounded_remains_rejected_by_planner_and_project_pipeline(
    tmp_path: Path,
) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n- 10.10.10.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported recon profile"):
        build_recon_plan("10.10.10.10", scope, tmp_path / "output", "deep-bounded")

    with pytest.raises(ValueError, match="Unsupported project pipeline profile"):
        run_project_pipeline(tmp_path / "missing-project.json", "deep-bounded")


def test_deep_remains_unavailable_and_quick_standard_mappings_are_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is False


def _walk_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for nested in value.values():
            keys.update(_walk_keys(nested))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for nested in value:
            keys.update(_walk_keys(nested))
        return keys
    return set()
