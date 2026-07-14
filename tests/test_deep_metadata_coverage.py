"""Tests for offline Deep metadata coverage summaries."""

from __future__ import annotations

from bugslyce.core.models import (
    DiscoveredPath,
    Endpoint,
    HTTPArtifact,
    HTTPService,
    ProjectState,
)
from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_metadata_coverage import (
    DeepMetadataCoverageItem,
    DeepMetadataCoverageSummary,
    build_deep_metadata_coverage_from_project_state,
    render_deep_metadata_coverage_markdown,
)
from bugslyce.recon.deep_metadata_plan import DEEP_METADATA_PATHS
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_empty_project_state_produces_safe_empty_summary() -> None:
    summary = build_deep_metadata_coverage_from_project_state(_project_state())
    rendered = render_deep_metadata_coverage_markdown(summary)

    assert isinstance(summary, DeepMetadataCoverageSummary)
    assert summary.items == ()
    assert summary.planned_count == 0
    assert summary.collected_count == 0
    assert summary.observed_count == 0
    assert summary.planned_uncollected_count == 0
    assert rendered.startswith("## Deep Metadata Coverage\n")
    assert "It does not fetch URLs and does not execute Deep Recon." in rendered


def test_http_service_produces_planned_metadata_urls_for_origin() -> None:
    summary = build_deep_metadata_coverage_from_project_state(
        _project_state(
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
    )

    assert summary.planned_count == len(DEEP_METADATA_PATHS)
    assert summary.planned_uncollected_count == len(DEEP_METADATA_PATHS)
    assert summary.items[0].url == "https://example.test/robots.txt"
    assert summary.items[0].status == "planned_uncollected"
    assert all(item.planned for item in summary.items)


def test_collected_robots_artifact_marks_planned_robots_url_collected() -> None:
    summary = build_deep_metadata_coverage_from_project_state(
        _project_state(
            http_artifacts=[
                HTTPArtifact(
                    url="http://example.test/robots.txt",
                    artifact_type="robots",
                    value="robots-example.txt",
                    source_file="robots-example.txt",
                    evidence_ids=["EVID-ART-0001"],
                    tags=["robots_artifact"],
                )
            ]
        )
    )

    robots = _item(summary, "http://example.test/robots.txt")
    assert robots.status == "collected"
    assert robots.category == "robots"
    assert robots.evidence_ids == ("EVID-ART-0001",)
    assert robots.collected is True


def test_collected_robots_value_counts_as_collected_robots_coverage() -> None:
    summary = build_deep_metadata_coverage_from_project_state(
        _project_state(
            http_artifacts=[
                HTTPArtifact(
                    url="http://example.test/robots.txt",
                    artifact_type="robots_value",
                    value="Wubbalubbadubdub",
                    source_file="robots-example.txt",
                    evidence_ids=["EVID-ART-0002"],
                    tags=["robots_artifact"],
                )
            ]
        )
    )

    robots = _item(summary, "http://example.test/robots.txt")
    assert robots.status == "collected"
    assert robots.evidence_ids == ("EVID-ART-0002",)
    assert summary.collected_count == 1


def test_discovered_security_txt_marks_metadata_url_collected() -> None:
    summary = build_deep_metadata_coverage_from_project_state(
        _project_state(
            discovered_paths=[
                _path("https://example.test/security.txt", "EVID-PATH-0001")
            ]
        )
    )

    security = _item(summary, "https://example.test/security.txt")
    assert security.status == "collected"
    assert security.category == "security"
    assert security.evidence_ids == ("EVID-PATH-0001",)


def test_endpoint_metadata_reference_is_observed() -> None:
    summary = build_deep_metadata_coverage_from_project_state(
        _project_state(
            endpoints=[
                Endpoint(
                    url="https://example.test/sitemap.xml",
                    hostname="example.test",
                    path="/sitemap.xml",
                    query_params=[],
                    evidence_ids=["EVID-URL-0001"],
                    tags=[],
                )
            ]
        )
    )

    sitemap = _item(summary, "https://example.test/sitemap.xml")
    assert sitemap.status == "observed"
    assert sitemap.category == "sitemap"
    assert sitemap.evidence_ids == ("EVID-URL-0001",)
    assert summary.observed_count == 1


def test_planned_absent_metadata_paths_are_planned_uncollected() -> None:
    summary = build_deep_metadata_coverage_from_project_state(
        _project_state(
            http_services=[
                HTTPService(
                    url="https://example.test/",
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
    )

    assert _item(summary, "https://example.test/humans.txt").status == "planned_uncollected"
    assert _item(summary, "https://example.test/favicon.ico").status == "planned_uncollected"


def test_unknown_non_metadata_paths_are_ignored_as_evidence() -> None:
    summary = build_deep_metadata_coverage_from_project_state(
        _project_state(
            http_artifacts=[
                HTTPArtifact(
                    url="https://example.test/admin",
                    artifact_type="html_comment",
                    value="comment",
                    source_file="homepage.html",
                    evidence_ids=["EVID-ART-0001"],
                    tags=[],
                )
            ]
        )
    )

    assert all(item.url != "https://example.test/admin" for item in summary.items)
    assert summary.collected_count == 0
    assert summary.planned_count == len(DEEP_METADATA_PATHS)


def test_http_and_https_metadata_urls_remain_distinct() -> None:
    summary = build_deep_metadata_coverage_from_project_state(
        _project_state(
            http_services=[
                HTTPService(
                    url="http://example.test/",
                    hostname="example.test",
                    status_code=200,
                    title=None,
                    technologies=[],
                    content_length=None,
                    evidence_ids=["EVID-HTTP-0001"],
                    tags=[],
                ),
                HTTPService(
                    url="https://example.test/",
                    hostname="example.test",
                    status_code=200,
                    title=None,
                    technologies=[],
                    content_length=None,
                    evidence_ids=["EVID-HTTP-0002"],
                    tags=[],
                ),
            ]
        )
    )

    urls = [item.url for item in summary.items]
    assert "http://example.test/robots.txt" in urls
    assert "https://example.test/robots.txt" in urls
    assert summary.planned_count == 2 * len(DEEP_METADATA_PATHS)


def test_duplicate_metadata_evidence_merges_evidence_ids_stably() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="HTTP://Example.TEST/robots.txt#fragment",
                artifact_type="robots",
                value="robots-example.txt",
                source_file="robots-example.txt",
                evidence_ids=["EVID-ART-0001"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="robots_value",
                value="remember-this",
                source_file="robots-example.txt",
                evidence_ids=["EVID-ART-0002", "EVID-ART-0001"],
                tags=[],
            ),
        ]
    )

    first = build_deep_metadata_coverage_from_project_state(state)
    second = build_deep_metadata_coverage_from_project_state(state)

    assert first == second
    robots = _item(first, "http://example.test/robots.txt")
    assert robots.status == "collected"
    assert robots.evidence_ids == ("EVID-ART-0001", "EVID-ART-0002")
    assert [(item.status, item.url) for item in first.items[:2]] == [
        ("collected", "http://example.test/robots.txt"),
        ("planned_uncollected", "http://example.test/sitemap.xml"),
    ]


def test_renderer_includes_sections_counts_and_safety_wording() -> None:
    summary = build_deep_metadata_coverage_from_project_state(
        _project_state(
            http_artifacts=[
                HTTPArtifact(
                    url="http://example.test/robots.txt",
                    artifact_type="robots_value",
                    value="remember-this",
                    source_file="robots-example.txt",
                    evidence_ids=["EVID-ART-0001"],
                    tags=[],
                )
            ]
        )
    )

    rendered = render_deep_metadata_coverage_markdown(summary)
    lowered = rendered.lower()

    assert rendered.startswith("## Deep Metadata Coverage\n")
    assert "- Planned metadata URLs: 8" in rendered
    assert "- Collected metadata URLs: 1" in rendered
    assert "- Planned but uncollected: 7" in rendered
    assert "### Collected" in rendered
    assert "### Planned But Uncollected" in rendered
    assert "does not fetch URLs" in rendered
    assert "does not execute Deep Recon" in rendered
    assert "Uncollected does not imply absence" in rendered
    assert "Do not fetch missing URLs from this summary unless explicitly authorised and in scope" in rendered
    for forbidden in (
        "vulnerability found",
        "exploit",
        "credentials found",
        "password found",
        "bypass",
        "report automatically",
    ):
        assert forbidden not in lowered


def test_renderer_suppresses_duplicate_origin_skip_noise() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="robots_value",
                value="remember-this",
                source_file="robots-example.txt",
                evidence_ids=["EVID-ART-0001"],
                tags=[],
            ),
            *[
                HTTPArtifact(
                    url=f"http://example.test/assets/{index}.png",
                    artifact_type="script_or_asset",
                    value=f"/assets/{index}.png",
                    source_file="homepage.html",
                    evidence_ids=[f"EVID-NOISE-{index:04d}"],
                    tags=["static_asset"],
                )
                for index in range(1, 72)
            ],
        ]
    )

    summary = build_deep_metadata_coverage_from_project_state(state)
    rendered = render_deep_metadata_coverage_markdown(summary)

    assert summary.skipped_count == 71
    assert "- Skipped: 71" in rendered
    assert "### Suppressed Planner Skips" in rendered
    assert "`duplicate_origin`: 71 duplicate source URL(s) suppressed" in rendered
    assert "planner-origin skips, not missing metadata coverage" in rendered
    assert "### Planned But Uncollected" in rendered
    assert "http://example.test/assets/1.png" not in rendered
    assert "http://example.test/assets/71.png" not in rendered
    assert rendered.count("duplicate_origin") == 1
    assert rendered.count("- `http://example.test/assets/") == 0


def test_renderer_keeps_non_duplicate_skipped_reasons_visible() -> None:
    summary = DeepMetadataCoverageSummary(
        items=(
            DeepMetadataCoverageItem(
                url="ftp://example.test/robots.txt",
                path="/robots.txt",
                status="skipped",
                category="robots",
                source="unit-test",
                evidence_ids=(),
                planned=False,
                collected=False,
                reason="unsupported_scheme",
            ),
            DeepMetadataCoverageItem(
                url="http://example.test/robots.txt",
                path="/robots.txt",
                status="skipped",
                category="robots",
                source="unit-test",
                evidence_ids=(),
                planned=False,
                collected=False,
                reason="duplicate_origin",
            ),
        ),
        planned_count=0,
        collected_count=0,
        observed_count=0,
        planned_uncollected_count=0,
        skipped_count=2,
    )

    rendered = render_deep_metadata_coverage_markdown(summary)

    assert "### Skipped" in rendered
    assert "ftp://example.test/robots.txt" in rendered
    assert "unsupported_scheme" in rendered
    assert "### Suppressed Planner Skips" in rendered
    assert "`duplicate_origin`: 1 duplicate source URL(s) suppressed" in rendered
    assert "- `http://example.test/robots.txt` - robots - reason: duplicate_origin" not in rendered


def test_mode_enablement_remains_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _item(summary: DeepMetadataCoverageSummary, url: str):
    for item in summary.items:
        if item.url == url:
            return item
    raise AssertionError(f"missing coverage item for {url}")


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


def _path(url: str, evidence_id: str) -> DiscoveredPath:
    return DiscoveredPath(
        url=url,
        status_code=200,
        content_length=10,
        redirect_location=None,
        source="unit-test",
        evidence_ids=[evidence_id],
        tags=[],
    )
