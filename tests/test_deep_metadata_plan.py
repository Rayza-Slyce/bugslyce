"""Tests for the pure Deep common metadata request planner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugslyce.core.models import (
    DiscoveredPath,
    Endpoint,
    HTTPArtifact,
    HTTPService,
    ProjectState,
)
from bugslyce.recon.deep_metadata_plan import (
    DEEP_METADATA_PATHS,
    DeepMetadataPlan,
    DeepMetadataRequest,
    DeepMetadataService,
    build_deep_metadata_request_plan,
    build_deep_metadata_plan_from_project_state,
    build_deep_metadata_services_from_project_state,
    export_deep_metadata_plan_json,
    render_deep_metadata_plan_markdown,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
    resolve_executable_profile,
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
    assert "`deep-bounded` remains bounded and scope-conscious." in plan.non_executable_guarantees


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


def test_project_state_without_http_urls_produces_empty_metadata_plan() -> None:
    state = _project_state()

    services = build_deep_metadata_services_from_project_state(state)
    plan = build_deep_metadata_plan_from_project_state(state)

    assert services == ()
    assert plan.requests == ()
    assert plan.skipped_services == ()


def test_project_state_http_service_produces_metadata_service_and_plan() -> None:
    state = _project_state(
        http_services=[
            HTTPService(
                url="http://example.test/",
                hostname="example.test",
                status_code=200,
                title="Example",
                technologies=[],
                content_length=123,
                evidence_ids=["EVID-HTTP-0001"],
                tags=[],
            )
        ]
    )

    services = build_deep_metadata_services_from_project_state(state)
    plan = build_deep_metadata_plan_from_project_state(state)

    assert services == (
        DeepMetadataService(
            url="http://example.test/",
            source="project-state:http-service",
        ),
    )
    assert len(plan.requests) == len(DEEP_METADATA_PATHS)
    assert plan.requests[0].url == "http://example.test/robots.txt"
    assert plan.requests[0].source == "project-state:http-service"


def test_project_state_https_service_with_path_is_planned_from_origin_root() -> None:
    state = _project_state(
        http_services=[
            HTTPService(
                url="https://example.test/app",
                hostname="example.test",
                status_code=200,
                title=None,
                technologies=[],
                content_length=None,
                evidence_ids=["EVID-HTTP-0001"],
                tags=[],
            )
        ]
    )

    plan = build_deep_metadata_plan_from_project_state(state)

    assert plan.requests[0].service_url == "https://example.test/"
    assert plan.requests[0].url == "https://example.test/robots.txt"
    assert all("/app/robots.txt" not in request.url for request in plan.requests)


def test_project_state_adapter_preserves_first_seen_source_order_before_planner_dedupe() -> None:
    state = _project_state(
        http_services=[
            HTTPService(
                url="https://one.example/",
                hostname="one.example",
                status_code=200,
                title=None,
                technologies=[],
                content_length=None,
                evidence_ids=["EVID-HTTP-0001"],
                tags=[],
            )
        ],
        endpoints=[
            Endpoint(
                url="https://two.example/login",
                hostname="two.example",
                path="/login",
                query_params=[],
                evidence_ids=["EVID-URL-0001"],
                tags=[],
            ),
            Endpoint(
                url="https://one.example/admin",
                hostname="one.example",
                path="/admin",
                query_params=[],
                evidence_ids=["EVID-URL-0002"],
                tags=[],
            ),
        ],
    )

    services = build_deep_metadata_services_from_project_state(state)
    plan = build_deep_metadata_request_plan(services)

    assert services == (
        DeepMetadataService("https://one.example/", "project-state:http-service"),
        DeepMetadataService("https://two.example/login", "project-state:endpoint"),
        DeepMetadataService("https://one.example/admin", "project-state:endpoint"),
    )
    assert [request.service_url for request in plan.requests[:16:8]] == [
        "https://one.example/",
        "https://two.example/",
    ]
    assert [(skip.url, skip.reason) for skip in plan.skipped_services] == [
        ("https://one.example/admin", "duplicate_origin")
    ]


def test_project_state_adapter_uses_http_artifact_and_discovered_path_labels() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="https://artifact.example/robots.txt",
                artifact_type="robots",
                value="User-agent: *",
                source_file="robots.txt",
                evidence_ids=["EVID-HTTP-ARTIFACT-0001"],
                tags=[],
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url="https://path.example/hidden/",
                status_code=200,
                content_length=42,
                redirect_location=None,
                source="gobuster",
                evidence_ids=["EVID-PATH-0001"],
                tags=[],
            )
        ],
    )

    services = build_deep_metadata_services_from_project_state(state)
    plan = build_deep_metadata_request_plan(services)

    assert services == (
        DeepMetadataService(
            url="https://artifact.example/robots.txt",
            source="project-state:http-artifact",
        ),
        DeepMetadataService(
            url="https://path.example/hidden/",
            source="project-state:discovered-path",
        ),
    )
    assert [request.source for request in plan.requests[:16:8]] == [
        "project-state:http-artifact",
        "project-state:discovered-path",
    ]


def test_project_state_adapter_ignores_non_http_and_malformed_values() -> None:
    state = _project_state(
        endpoints=[
            Endpoint(
                url="ftp://example.test/path",
                hostname="example.test",
                path="/path",
                query_params=[],
                evidence_ids=["EVID-URL-0001"],
                tags=[],
            ),
            Endpoint(
                url="http://",
                hostname="",
                path="",
                query_params=[],
                evidence_ids=["EVID-URL-0002"],
                tags=[],
            ),
            Endpoint(
                url="javascript:alert(1)",
                hostname="",
                path="",
                query_params=[],
                evidence_ids=["EVID-URL-0003"],
                tags=[],
            ),
        ],
        http_artifacts=[
            HTTPArtifact(
                url="/tmp/robots.txt",
                artifact_type="robots",
                value="/tmp/robots.txt",
                source_file="robots.txt",
                evidence_ids=["EVID-HTTP-ARTIFACT-0001"],
                tags=[],
            )
        ],
    )

    services = build_deep_metadata_services_from_project_state(state)
    plan = build_deep_metadata_request_plan(services)

    assert services == ()
    assert plan.requests == ()


def test_project_state_adapter_creates_no_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    state = _project_state(
        http_services=[
            HTTPService(
                url="https://example.test/",
                hostname="example.test",
                status_code=None,
                title=None,
                technologies=[],
                content_length=None,
                evidence_ids=[],
                tags=[],
            )
        ]
    )

    services = build_deep_metadata_services_from_project_state(state)
    plan = build_deep_metadata_plan_from_project_state(state)
    export_deep_metadata_plan_json(plan)

    assert services
    assert plan.requests
    assert list(tmp_path.iterdir()) == []


def test_deep_bounded_remains_rejected_by_static_recon_planner(
    tmp_path: Path,
) -> None:
    scope = tmp_path / "scope.md"
    scope.write_text("# Scope\n\n- 10.10.10.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported recon profile"):
        build_recon_plan("10.10.10.10", scope, tmp_path / "output", "deep-bounded")


def test_deep_is_available_and_quick_standard_mappings_are_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert resolve_executable_profile("deep") == "deep-bounded"


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


def _project_state(
    *,
    http_services: list[HTTPService] | None = None,
    endpoints: list[Endpoint] | None = None,
    http_artifacts: list[HTTPArtifact] | None = None,
    discovered_paths: list[DiscoveredPath] | None = None,
) -> ProjectState:
    return ProjectState(
        project_name="unit",
        input_dir="",
        processed_files=[],
        scope_summary="No scope",
        assets=[],
        http_services=http_services or [],
        endpoints=endpoints or [],
        port_services=[],
        http_artifacts=http_artifacts or [],
        discovered_paths=discovered_paths or [],
        recon_summary=None,
        recon_manifest=None,
        evidence=[],
        warnings=[],
        generated_at="2026-07-01T00:00:00Z",
    )
