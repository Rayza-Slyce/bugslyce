"""Tests for offline Deep source/route coverage summaries."""

from __future__ import annotations

from bugslyce.core.models import (
    DiscoveredPath,
    Endpoint,
    HTTPArtifact,
    HTTPService,
    ProjectState,
)
from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_source_route_coverage import (
    DeepSourceRouteCoverageSummary,
    build_deep_source_route_coverage_from_project_state,
    render_deep_source_route_coverage_markdown,
)
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_empty_project_state_produces_safe_empty_summary() -> None:
    summary = build_deep_source_route_coverage_from_project_state(_project_state())
    rendered = render_deep_source_route_coverage_markdown(summary)

    assert isinstance(summary, DeepSourceRouteCoverageSummary)
    assert summary.items == ()
    assert summary.body_collected_count == 0
    assert summary.headers_collected_count == 0
    assert summary.discovered_unfetched_count == 0
    assert summary.referenced_only_count == 0
    assert summary.static_noise_count == 0
    assert summary.metadata_context_count == 0
    assert rendered.startswith("## Deep Source/Route Coverage\n")
    assert "It does not fetch URLs and does not execute Deep Recon." in rendered


def test_body_source_artifacts_mark_route_body_collected() -> None:
    summary = build_deep_source_route_coverage_from_project_state(
        _project_state(
            http_artifacts=[
                _artifact("http://example.test/login.php", "page_title", "Login", "EVID-ART-0001"),
                _artifact("http://example.test/login.php", "form", "form", "EVID-ART-0002"),
                _artifact(
                    "http://example.test/login.php",
                    "input",
                    "name=username;type=text",
                    "EVID-ART-0003",
                ),
                _artifact(
                    "http://example.test/login.php",
                    "keyword_hit",
                    "login",
                    "EVID-ART-0004",
                ),
            ]
        )
    )

    item = _item(summary, "http://example.test/login.php")
    assert item.status == "body_collected"
    assert item.category == "auth_route"
    assert item.signals == ("page_title", "form", "input", "keyword_hit")
    assert item.evidence_ids == (
        "EVID-ART-0001",
        "EVID-ART-0002",
        "EVID-ART-0003",
        "EVID-ART-0004",
    )
    assert summary.body_collected_count == 1


def test_admin_status_route_is_categorised() -> None:
    summary = build_deep_source_route_coverage_from_project_state(
        _project_state(
            discovered_paths=[
                _path("http://example.test/server-status", "EVID-PATH-0001")
            ]
        )
    )

    item = _item(summary, "http://example.test/server-status")
    assert item.status == "discovered_unfetched"
    assert item.category == "admin_or_status_route"


def test_discovered_path_without_body_source_is_unfetched() -> None:
    summary = build_deep_source_route_coverage_from_project_state(
        _project_state(
            discovered_paths=[_path("http://example.test/portal.php", "EVID-PATH-0001")]
        )
    )

    item = _item(summary, "http://example.test/portal.php")
    assert item.status == "discovered_unfetched"
    assert item.category == "auth_route"
    assert summary.discovered_unfetched_count == 1


def test_endpoint_only_route_is_referenced_only() -> None:
    summary = build_deep_source_route_coverage_from_project_state(
        _project_state(
            endpoints=[
                Endpoint(
                    url="http://example.test/manual",
                    hostname="example.test",
                    path="/manual",
                    query_params=[],
                    evidence_ids=["EVID-URL-0001"],
                    tags=[],
                )
            ]
        )
    )

    item = _item(summary, "http://example.test/manual")
    assert item.status == "referenced_only"
    assert item.category == "application_route"
    assert item.evidence_ids == ("EVID-URL-0001",)


def test_http_service_root_is_headers_collected() -> None:
    summary = build_deep_source_route_coverage_from_project_state(
        _project_state(
            http_services=[
                HTTPService(
                    url="https://example.test/",
                    hostname="example.test",
                    status_code=200,
                    title="Home",
                    technologies=["nginx"],
                    content_length=123,
                    evidence_ids=["EVID-HTTP-0001"],
                    tags=[],
                )
            ]
        )
    )

    item = _item(summary, "https://example.test/")
    assert item.status == "headers_collected"
    assert item.category == "application_route"
    assert item.signals == ("http_service", "status:200", "title")


def test_static_assets_are_static_noise() -> None:
    summary = build_deep_source_route_coverage_from_project_state(
        _project_state(
            endpoints=[
                Endpoint(
                    url="http://example.test/assets/bootstrap.min.css",
                    hostname="example.test",
                    path="/assets/bootstrap.min.css",
                    query_params=[],
                    evidence_ids=["EVID-URL-0001"],
                    tags=[],
                )
            ]
        )
    )

    item = _item(summary, "http://example.test/assets/bootstrap.min.css")
    assert item.status == "static_noise"
    assert item.category == "static_asset"
    assert summary.static_noise_count == 1


def test_bare_static_directories_are_static_context_not_reviewable_routes() -> None:
    static_paths = ("/assets", "/assets/", "/static", "/images", "/icons", "/img", "/css", "/js")
    summary = build_deep_source_route_coverage_from_project_state(
        _project_state(
            http_artifacts=[
                _artifact(f"http://example.test{path}", "page_title", "Index", f"EVID-ART-{index:04d}")
                for index, path in enumerate(static_paths, start=1)
            ]
        )
    )
    rendered = render_deep_source_route_coverage_markdown(summary)

    assert summary.static_noise_count == len({path.rstrip("/") for path in static_paths})
    assert "### Static / Directory Context" in rendered
    assert "### Reviewable Application Routes" not in rendered
    for path in ("/assets", "/static", "/images", "/icons", "/img", "/css", "/js"):
        item = _item(summary, f"http://example.test{path}")
        assert item.status == "static_noise"
        assert item.category == "static_asset"


def test_metadata_routes_are_metadata_context() -> None:
    summary = build_deep_source_route_coverage_from_project_state(
        _project_state(
            discovered_paths=[_path("http://example.test/robots.txt", "EVID-PATH-0001")]
        )
    )

    item = _item(summary, "http://example.test/robots.txt")
    assert item.status == "metadata_context"
    assert item.category == "metadata_route"
    assert summary.metadata_context_count == 1


def test_expanded_auth_admin_and_api_classification_terms() -> None:
    urls = (
        ("http://example.test/sso/callback", "auth_route"),
        ("http://example.test/forgot-password", "auth_route"),
        ("http://example.test/reset-password", "auth_route"),
        ("http://example.test/admin", "admin_or_status_route"),
        ("http://example.test/manage", "admin_or_status_route"),
        ("http://example.test/console", "admin_or_status_route"),
        ("http://example.test/backoffice", "admin_or_status_route"),
        ("http://example.test/internal", "admin_or_status_route"),
        ("http://example.test/actuator/health", "admin_or_status_route"),
        ("http://example.test/metrics", "admin_or_status_route"),
        ("http://example.test/api/v1/users", "api_route"),
        ("http://example.test/graphql", "api_route"),
        ("http://example.test/swagger", "api_route"),
        ("http://example.test/openapi.json", "api_route"),
        ("http://example.test/api-docs", "api_route"),
    )
    summary = build_deep_source_route_coverage_from_project_state(
        _project_state(
            discovered_paths=[
                _path(url, f"EVID-PATH-{index:04d}")
                for index, (url, _category) in enumerate(urls, start=1)
            ]
        )
    )

    for url, category in urls:
        assert _item(summary, url).category == category


def test_duplicate_url_evidence_merges_stably() -> None:
    summary = build_deep_source_route_coverage_from_project_state(
        _project_state(
            discovered_paths=[_path("http://example.test/login.php", "EVID-PATH-0001")],
            http_artifacts=[
                _artifact("http://example.test/login.php", "form", "form", "EVID-ART-0001"),
                _artifact(
                    "http://example.test/login.php",
                    "input",
                    "name=password;type=password",
                    "EVID-ART-0002",
                ),
            ],
        )
    )

    assert len(summary.items) == 1
    item = summary.items[0]
    assert item.status == "body_collected"
    assert item.category == "auth_route"
    assert item.evidence_ids == ("EVID-ART-0001", "EVID-ART-0002", "EVID-PATH-0001")
    assert item.signals == ("form", "input", "discovered_path")


def test_renderer_compacts_long_evidence_lists_but_model_preserves_all() -> None:
    summary = build_deep_source_route_coverage_from_project_state(
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

    item = _item(summary, "http://example.test/login.php")
    rendered = render_deep_source_route_coverage_markdown(summary)

    assert len(item.evidence_ids) == 14
    assert item.evidence_ids[-1] == "EVID-ART-0014"
    assert "`EVID-ART-0001`" in rendered
    assert "`EVID-ART-0006`" in rendered
    assert "`EVID-ART-0007`" not in rendered
    assert "`EVID-ART-0014`" not in rendered
    assert "... +8 more" in rendered


def test_query_variants_merge_but_http_and_https_remain_distinct() -> None:
    summary = build_deep_source_route_coverage_from_project_state(
        _project_state(
            endpoints=[
                Endpoint(
                    url="http://example.test/account?id=1",
                    hostname="example.test",
                    path="/account",
                    query_params=["id"],
                    evidence_ids=["EVID-URL-0001"],
                    tags=[],
                ),
                Endpoint(
                    url="http://example.test/account?id=2",
                    hostname="example.test",
                    path="/account",
                    query_params=["id"],
                    evidence_ids=["EVID-URL-0002"],
                    tags=[],
                ),
                Endpoint(
                    url="https://example.test/account?id=1",
                    hostname="example.test",
                    path="/account",
                    query_params=["id"],
                    evidence_ids=["EVID-URL-0003"],
                    tags=[],
                ),
            ]
        )
    )

    assert tuple(item.url for item in summary.items) == (
        "http://example.test/account",
        "https://example.test/account",
    )
    assert _item(summary, "http://example.test/account").evidence_ids == (
        "EVID-URL-0001",
        "EVID-URL-0002",
    )
    assert _item(summary, "https://example.test/account").evidence_ids == (
        "EVID-URL-0003",
    )


def test_rendering_includes_sections_counts_and_safety_wording() -> None:
    summary = build_deep_source_route_coverage_from_project_state(
        _project_state(
            http_artifacts=[_artifact("http://example.test/login.php", "form", "form", "EVID-ART-0001")],
            discovered_paths=[_path("http://example.test/portal.php", "EVID-PATH-0001")],
            endpoints=[
                Endpoint(
                    url="http://example.test/assets/app.js",
                    hostname="example.test",
                    path="/assets/app.js",
                    query_params=[],
                    evidence_ids=["EVID-URL-0001"],
                    tags=[],
                )
            ],
        )
    )

    rendered = render_deep_source_route_coverage_markdown(summary)
    lowered = rendered.lower()

    assert rendered.startswith("## Deep Source/Route Coverage\n")
    assert "- Body/source collected: 1" in rendered
    assert "- Discovered but unfetched: 1" in rendered
    assert "- Static noise: 1" in rendered
    assert "### Reviewable Application Routes" in rendered
    assert "### Discovered But Not Body-Fetched" in rendered
    assert "### Static / Directory Context" in rendered
    assert "does not fetch URLs" in rendered
    assert "does not execute Deep Recon" in rendered
    assert "coverage view, not a finding list" in rendered
    assert "Missing body/source evidence does not imply the route is absent or safe" in rendered
    assert (
        "Do not fetch, submit forms, authenticate, brute force, or test routes "
        "from this summary unless explicitly authorised and in scope."
    ) in rendered
    for forbidden in (
        "vulnerability found",
        "vulnerable",
        "exploit",
        "credentials found",
        "password found",
        "login bypass",
        "report automatically",
    ):
        assert forbidden not in lowered


def test_mode_enablement_remains_unchanged() -> None:
    assert get_recon_mode("quick").internal_profile == QUICK_RECON_PROFILE
    assert get_recon_mode("standard").internal_profile == STANDARD_RECON_PROFILE
    assert get_recon_mode("deep").internal_profile == "deep-bounded"
    assert is_recon_mode_available("deep") is False
    assert STANDARD_BOUNDED_CORE_PROFILE == "standard-bounded-core"


def _item(summary: DeepSourceRouteCoverageSummary, url: str):
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
