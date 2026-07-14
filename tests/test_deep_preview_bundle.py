"""Tests for offline Deep preview bundle summaries."""

from __future__ import annotations

from bugslyce.core.models import (
    DiscoveredPath,
    Endpoint,
    HTTPArtifact,
    ProjectState,
)
from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_preview_bundle import (
    DeepPreviewBundle,
    build_deep_preview_bundle_from_project_state,
    render_deep_preview_bundle_markdown,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_empty_project_state_produces_safe_empty_bundle() -> None:
    bundle = build_deep_preview_bundle_from_project_state(_project_state())
    rendered = render_deep_preview_bundle_markdown(bundle)

    assert isinstance(bundle, DeepPreviewBundle)
    assert bundle.metadata_review.leads == ()
    assert bundle.metadata_coverage.items == ()
    assert bundle.source_route_coverage.items == ()
    assert bundle.priorities == ()
    assert bundle.summary_counts["generated_priorities"] == 0
    assert rendered.startswith("## Deep Preview Bundle\n")
    assert "does not fetch URLs, run live recon, or execute Deep Recon" in rendered
    assert "prioritisation view, not a finding list" in rendered
    assert "Review-only priority; not a confirmed finding." in rendered
    assert "Deep Recon was not executed." in rendered


def test_bundle_summary_counts_reflect_existing_preview_summaries() -> None:
    bundle = build_deep_preview_bundle_from_project_state(
        _project_state(
            http_artifacts=[
                _artifact(
                    "http://example.test/robots.txt",
                    "robots_value",
                    "remember-this",
                    "EVID-ART-0001",
                )
            ],
            discovered_paths=[
                _path("http://example.test/login.php", "EVID-PATH-0001"),
            ],
        )
    )

    assert bundle.summary_counts["metadata_review_leads"] == 1
    assert bundle.summary_counts["metadata_planned_urls"] == 8
    assert bundle.summary_counts["metadata_collected_urls"] == 1
    assert bundle.summary_counts["metadata_planned_uncollected_urls"] == 7
    assert bundle.summary_counts["discovered_unfetched_routes"] == 1
    assert bundle.summary_counts["metadata_context_routes"] == 1
    assert bundle.summary_counts["generated_priorities"] == len(bundle.priorities)


def test_priorities_are_deterministic_ordered_and_stable() -> None:
    state = _project_state(
        http_artifacts=[
            _artifact("http://example.test/login.php", "form", "form", "EVID-ART-0001"),
            _artifact("http://example.test/robots.txt", "robots_value", "remember-this", "EVID-ART-0002"),
        ],
        discovered_paths=[
            _path("http://example.test/portal.php", "EVID-PATH-0001"),
            _path("http://example.test/server-status", "EVID-PATH-0002"),
            _path("http://example.test/api/v1/users", "EVID-PATH-0003"),
        ],
    )

    first = build_deep_preview_bundle_from_project_state(state)
    second = build_deep_preview_bundle_from_project_state(state)

    assert first == second
    assert [priority.priority_id for priority in first.priorities[:5]] == [
        "DEEP-PREV-0001",
        "DEEP-PREV-0002",
        "DEEP-PREV-0003",
        "DEEP-PREV-0004",
        "DEEP-PREV-0005",
    ]
    assert [priority.category for priority in first.priorities[:5]] == [
        "auth_route_review",
        "auth_route_review",
        "admin_status_route_review",
        "api_route_review",
        "metadata_clue_review",
    ]
    assert first.priorities[0].related_urls == ("http://example.test/login.php",)
    assert first.priorities[1].related_urls == ("http://example.test/portal.php",)


def test_priority_list_is_bounded_to_twelve() -> None:
    bundle = build_deep_preview_bundle_from_project_state(
        _project_state(
            discovered_paths=[
                _path(f"http://example.test/login-{index}", f"EVID-PATH-{index:04d}")
                for index in range(1, 30)
            ]
        )
    )

    assert len(bundle.priorities) == 12
    assert bundle.priorities[-1].priority_id == "DEEP-PREV-0012"
    assert bundle.summary_counts["generated_priorities"] == 12


def test_priority_evidence_and_urls_are_merged_stably() -> None:
    bundle = build_deep_preview_bundle_from_project_state(
        _project_state(
            http_artifacts=[
                _artifact("http://example.test/login.php", "form", "form", "EVID-ART-0001"),
                _artifact("http://example.test/login.php", "input", "input", "EVID-ART-0002"),
            ],
            discovered_paths=[
                _path("http://example.test/login.php", "EVID-PATH-0001"),
            ],
        )
    )

    priority = bundle.priorities[0]
    assert priority.category == "auth_route_review"
    assert priority.related_urls == ("http://example.test/login.php",)
    assert priority.related_evidence_ids == (
        "EVID-ART-0001",
        "EVID-ART-0002",
        "EVID-PATH-0001",
    )


def test_metadata_gap_priority_is_low_context_only() -> None:
    bundle = build_deep_preview_bundle_from_project_state(
        _project_state(
            discovered_paths=[
                _path("http://example.test/login.php", "EVID-PATH-0001"),
            ]
        )
    )

    gap = next(priority for priority in bundle.priorities if priority.category == "metadata_gap_review")
    assert "coverage gaps only" in gap.reason
    assert gap.source_sections == ("metadata_coverage",)


def test_metadata_gaps_are_grouped_into_one_priority_with_stable_urls() -> None:
    bundle = build_deep_preview_bundle_from_project_state(
        _project_state(
            discovered_paths=[
                _path("http://example.test/login.php", "EVID-PATH-0001"),
            ]
        )
    )

    gaps = [
        priority for priority in bundle.priorities
        if priority.category == "metadata_gap_review"
    ]

    assert len(gaps) == 1
    assert gaps[0].title == "Metadata coverage gaps observed"
    assert gaps[0].related_urls == (
        "http://example.test/robots.txt",
        "http://example.test/sitemap.xml",
        "http://example.test/security.txt",
        "http://example.test/.well-known/security.txt",
        "http://example.test/humans.txt",
        "http://example.test/crossdomain.xml",
        "http://example.test/clientaccesspolicy.xml",
        "http://example.test/favicon.ico",
    )
    assert bundle.summary_counts["metadata_planned_uncollected_urls"] == 8


def test_rendered_grouped_metadata_gap_compacts_related_urls() -> None:
    bundle = build_deep_preview_bundle_from_project_state(
        _project_state(
            discovered_paths=[
                _path("http://example.test/login.php", "EVID-PATH-0001"),
            ]
        )
    )

    rendered = render_deep_preview_bundle_markdown(bundle)

    assert "Metadata coverage gaps observed" in rendered
    assert "`http://example.test/robots.txt`" in rendered
    assert "`http://example.test/crossdomain.xml`" in rendered
    assert "`http://example.test/clientaccesspolicy.xml`" not in rendered
    assert "`http://example.test/favicon.ico`" not in rendered
    assert "... +2 more" in rendered
    assert rendered.count("Metadata coverage gaps observed") == 1


def test_priority_order_keeps_metadata_gaps_after_higher_signal_items() -> None:
    bundle = build_deep_preview_bundle_from_project_state(
        _project_state(
            http_artifacts=[
                _artifact("http://example.test/login.php", "form", "form", "EVID-ART-0001"),
                _artifact("http://example.test/robots.txt", "robots_value", "remember-this", "EVID-ART-0002"),
                _artifact("http://example.test/", "html_comment", "note", "EVID-ART-0003"),
            ],
            discovered_paths=[
                _path("http://example.test/portal.php", "EVID-PATH-0001"),
                _path("http://example.test/server-status", "EVID-PATH-0002"),
            ],
        )
    )

    assert [(priority.priority_id, priority.category) for priority in bundle.priorities[:6]] == [
        ("DEEP-PREV-0001", "auth_route_review"),
        ("DEEP-PREV-0002", "auth_route_review"),
        ("DEEP-PREV-0003", "admin_status_route_review"),
        ("DEEP-PREV-0004", "metadata_clue_review"),
        ("DEEP-PREV-0005", "source_context_review"),
        ("DEEP-PREV-0006", "metadata_gap_review"),
    ]


def test_static_context_is_not_promoted_by_default() -> None:
    bundle = build_deep_preview_bundle_from_project_state(
        _project_state(
            endpoints=[
                Endpoint(
                    url="http://example.test/assets/app.js",
                    hostname="example.test",
                    path="/assets/app.js",
                    query_params=[],
                    evidence_ids=["EVID-URL-0001"],
                    tags=[],
                )
            ]
        )
    )

    assert all(priority.category != "static_context_review" for priority in bundle.priorities)
    assert bundle.summary_counts["static_directory_context_routes"] == 1


def test_renderer_includes_counts_priorities_compact_evidence_and_safety() -> None:
    bundle = build_deep_preview_bundle_from_project_state(
        _project_state(
            http_artifacts=[
                _artifact(
                    "http://example.test/login.php",
                    "keyword_hit",
                    f"value-{index}",
                    f"EVID-ART-{index:04d}",
                )
                for index in range(1, 15)
            ]
        )
    )
    rendered = render_deep_preview_bundle_markdown(bundle)
    lowered = rendered.lower()

    assert rendered.startswith("## Deep Preview Bundle\n")
    assert "### Summary" in rendered
    assert "### Manual Review Priorities" in rendered
    assert "- Body/source collected routes: 1" in rendered
    assert "#### DEEP-PREV-0001" in rendered
    assert "`EVID-ART-0001`" in rendered
    assert "`EVID-ART-0006`" in rendered
    assert "`EVID-ART-0007`" not in rendered
    assert "... +8 more" in rendered
    assert "does not fetch URLs" in rendered
    assert "run live recon" in rendered
    assert "execute Deep Recon" in rendered
    assert "prioritisation view, not a finding list" in rendered
    assert "Review-only priority; not a confirmed finding." in rendered
    assert (
        "Do not fetch URLs, submit forms, authenticate, brute force, exploit, "
        "or test routes from this summary unless explicitly authorised and in scope"
    ) in rendered
    assert "Deep Recon was not executed." in rendered
    for forbidden in (
        "vulnerability found",
        "vulnerable",
        "exploit found",
        "credentials found",
        "password found",
        "login bypass",
        "report automatically",
        "confirmed exposure",
    ):
        assert forbidden not in lowered


def test_mode_enablement_remains_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is True
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _project_state(
    *,
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
        http_services=[],
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


def _artifact(
    url: str,
    artifact_type: str,
    value: str,
    evidence_id: str,
) -> HTTPArtifact:
    return HTTPArtifact(
        url=url,
        artifact_type=artifact_type,
        value=value,
        source_file="unit.html",
        evidence_ids=[evidence_id],
        tags=[],
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
