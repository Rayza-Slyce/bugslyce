"""Tests for offline Deep collection request planning."""

from __future__ import annotations

from bugslyce.core.models import (
    DiscoveredPath,
    Endpoint,
    HTTPArtifact,
    HTTPService,
    ProjectState,
)
from bugslyce.recon.content_plan import STANDARD_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_collection_request_plan import (
    DeepCollectionRequestPlan,
    DeepCollectionRequestSourceCount,
    build_deep_collection_request_plan_from_project_state,
    render_deep_collection_request_plan_markdown,
)
from bugslyce.recon.deep_metadata_plan import DEEP_METADATA_PATHS
from bugslyce.recon.modes import (
    QUICK_RECON_PROFILE,
    STANDARD_RECON_PROFILE,
    get_recon_mode,
    is_recon_mode_available,
)


def test_empty_project_state_returns_no_requests_or_origins() -> None:
    plan = build_deep_collection_request_plan_from_project_state(_project_state())

    assert isinstance(plan, DeepCollectionRequestPlan)
    assert plan.allowed_origins == ()
    assert plan.proposed_requests == ()
    assert plan.source_counts == ()
    assert plan.policy_summary.allowed_count == 0
    assert plan.policy_summary.blocked_count == 0


def test_origins_are_derived_deduped_and_normalised_from_local_evidence() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[
                _service("HTTP://Example.TEST/app", "EVID-HTTP-0001"),
                _service("https://example.test/", "EVID-HTTP-0002"),
            ],
            endpoints=[
                _endpoint("http://example.test:8080/account", "EVID-URL-0001"),
                _endpoint("http://example.test/app", "EVID-URL-0002"),
            ],
            http_artifacts=[
                _artifact("http://other.test/login", "page_title", "Login", "EVID-ART-0001")
            ],
            discovered_paths=[
                _path("https://example.test/admin", "EVID-PATH-0001")
            ],
        )
    )

    assert plan.allowed_origins == (
        "http://example.test",
        "https://example.test",
    )


def test_external_absolute_references_do_not_become_executable_deep_requests() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[_service("http://target.test/", "EVID-HTTP-0001")],
            http_artifacts=[
                _artifact(
                    "http://httpd.apache.org/docs/2.4/mod/mod_userdir.html",
                    "link",
                    "docs",
                    "EVID-ART-0001",
                ),
                _artifact(
                    "http://manpages.debian.org/cgi-bin/man.cgi",
                    "link",
                    "manual",
                    "EVID-ART-0002",
                ),
                _artifact(
                    "https://bugs.launchpad.net/ubuntu/+source/apache2",
                    "link",
                    "bugs",
                    "EVID-ART-0003",
                ),
            ],
            endpoints=[
                _endpoint(
                    "http://httpd.apache.org/docs/2.4/mod/mod_userdir.html",
                    "EVID-URL-0001",
                ),
                _endpoint("http://target.test/admin", "EVID-URL-0002"),
            ],
            discovered_paths=[
                _path("http://target.test/login", "EVID-PATH-0001"),
            ],
        )
    )

    urls = tuple(request.url for request in plan.proposed_requests)
    assert "http://target.test/login" in urls
    assert "http://target.test/admin" in urls
    assert not any("httpd.apache.org" in url for url in urls)
    assert not any("manpages.debian.org" in url for url in urls)
    assert not any("bugs.launchpad.net" in url for url in urls)
    assert plan.allowed_origins == ("http://target.test",)


def test_origin_normalisation_rejects_different_scheme_port_and_host() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[_service("HTTP://Example.TEST.:80/", "EVID-HTTP-0001")],
            endpoints=[
                _endpoint("http://example.test/admin", "EVID-URL-0001"),
                _endpoint("http://example.test:80/status", "EVID-URL-0002"),
                _endpoint("http://example.test:8080/admin", "EVID-URL-0003"),
                _endpoint("https://example.test/admin", "EVID-URL-0004"),
                _endpoint("http://other.test/admin", "EVID-URL-0005"),
            ],
        )
    )

    urls = tuple(request.url for request in plan.proposed_requests)
    assert "http://example.test/admin" in urls
    assert "http://example.test/status" in urls
    assert "http://example.test:8080/admin" not in urls
    assert "https://example.test/admin" not in urls
    assert "http://other.test/admin" not in urls
    assert plan.allowed_origins == ("http://example.test",)


def test_no_http_services_with_external_endpoint_produces_no_executable_request() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(endpoints=[_endpoint("http://external.test/admin", "EVID-URL-0001")])
    )

    assert plan.allowed_origins == ()
    assert plan.proposed_requests == ()
    assert plan.policy_summary.allowed_count == 0


def test_no_http_services_with_external_discovered_path_produces_no_executable_request() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(discovered_paths=[_path("http://external.test/admin", "EVID-PATH-0001")])
    )

    assert plan.allowed_origins == ()
    assert plan.proposed_requests == ()


def test_no_http_services_with_external_http_artifact_produces_no_executable_request() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_artifacts=[
                _artifact("http://external.test/admin", "link", "admin", "EVID-ART-0001")
            ]
        )
    )

    assert plan.allowed_origins == ()
    assert plan.proposed_requests == ()


def test_no_http_services_with_local_looking_endpoint_still_fails_closed() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(endpoints=[_endpoint("http://example.test/admin", "EVID-URL-0001")])
    )

    assert plan.allowed_origins == ()
    assert plan.proposed_requests == ()


def test_invalid_http_service_does_not_fallback_to_evidence_origin() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[_service("ftp://example.test/", "EVID-HTTP-0001")],
            endpoints=[_endpoint("http://example.test/admin", "EVID-URL-0001")],
            discovered_paths=[_path("http://example.test/login", "EVID-PATH-0001")],
        )
    )

    assert plan.allowed_origins == ()
    assert plan.proposed_requests == ()


def test_multiple_valid_http_services_authorise_only_their_own_origins() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[
                _service("http://example.test/", "EVID-HTTP-0001"),
                _service("https://example.test:8443/", "EVID-HTTP-0002"),
            ],
            endpoints=[
                _endpoint("http://example.test/admin", "EVID-URL-0001"),
                _endpoint("https://example.test:8443/admin", "EVID-URL-0002"),
                _endpoint("https://example.test/admin", "EVID-URL-0003"),
            ],
        )
    )

    assert plan.allowed_origins == ("http://example.test", "https://example.test:8443")
    urls = tuple(request.url for request in plan.proposed_requests)
    assert "http://example.test/admin" in urls
    assert "https://example.test:8443/admin" in urls
    assert "https://example.test/admin" not in urls


def test_planned_uncollected_metadata_creates_get_requests() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(http_services=[_service("https://example.test/app", "EVID-HTTP-0001")])
    )

    metadata_requests = tuple(
        request for request in plan.proposed_requests if request.source == "metadata_coverage"
    )
    assert len(metadata_requests) == len(DEEP_METADATA_PATHS)
    assert metadata_requests[0].url == "https://example.test/robots.txt"
    assert metadata_requests[0].method == "GET"
    assert metadata_requests[0].reason == "planned_uncollected_metadata"
    assert metadata_requests[0].tags == ("metadata", "coverage_gap")
    assert plan.policy_summary.allowed_count == len(DEEP_METADATA_PATHS)


def test_collected_metadata_does_not_create_duplicate_metadata_request() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[_service("http://example.test/", "EVID-HTTP-0001")],
            http_artifacts=[
                _artifact(
                    "http://example.test/robots.txt",
                    "robots_value",
                    "remember-this",
                    "EVID-ART-0001",
                )
            ],
        )
    )

    urls = tuple(request.url for request in plan.proposed_requests)
    assert "http://example.test/robots.txt" not in urls
    assert "http://example.test/sitemap.xml" in urls
    assert len([url for url in urls if url.endswith(".txt") or url.endswith(".xml") or url.endswith(".ico")]) == 7


def test_discovered_unfetched_routes_create_requests_before_metadata() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[_service("http://example.test/", "EVID-HTTP-0001")],
            discovered_paths=[
                _path("http://example.test/about", "EVID-PATH-0004"),
                _path("http://example.test/api/v1/users", "EVID-PATH-0003"),
                _path("http://example.test/admin", "EVID-PATH-0002"),
                _path("http://example.test/login.php", "EVID-PATH-0001"),
            ],
        )
    )

    assert tuple(request.url for request in plan.proposed_requests[:4]) == (
            "http://example.test/login.php",
            "http://example.test/admin",
            "http://example.test/api/v1/users",
            "http://example.test/about",
    )
    assert tuple(request.reason for request in plan.proposed_requests[:4]) == (
        "discovered_unfetched_auth_route",
        "discovered_unfetched_admin_or_status_route",
        "discovered_unfetched_api_route",
        "discovered_unfetched_application_route",
    )
    assert plan.proposed_requests[4].source == "metadata_coverage"


def test_referenced_only_high_signal_routes_create_requests() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[_service("http://example.test/", "EVID-HTTP-0001")],
            endpoints=[
                _endpoint("http://example.test/account", "EVID-URL-0001"),
                _endpoint("http://example.test/server-status", "EVID-URL-0002"),
                _endpoint("http://example.test/api/v1/users", "EVID-URL-0003"),
                _endpoint("http://example.test/manual", "EVID-URL-0004"),
            ]
        )
    )

    route_urls = tuple(
        request.url for request in plan.proposed_requests if request.source == "source_route_coverage"
    )
    assert route_urls == (
        "http://example.test/account",
        "http://example.test/server-status",
        "http://example.test/api/v1/users",
        "http://example.test/manual",
    )
    route_requests = tuple(
        request for request in plan.proposed_requests if request.source == "source_route_coverage"
    )
    assert all("referenced_only" in request.tags for request in route_requests)


def test_body_collected_static_noise_and_metadata_context_do_not_create_route_requests() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_artifacts=[
                _artifact("http://example.test/login.php", "form", "form", "EVID-ART-0001"),
            ],
            endpoints=[
                _endpoint("http://example.test/assets/app.js", "EVID-URL-0001"),
            ],
            discovered_paths=[
                _path("http://example.test/robots.txt", "EVID-PATH-0001"),
            ],
        )
    )

    route_urls = tuple(
        request.url for request in plan.proposed_requests if request.source == "source_route_coverage"
    )
    assert "http://example.test/login.php" not in route_urls
    assert "http://example.test/assets/app.js" not in route_urls
    assert "http://example.test/robots.txt" not in route_urls


def test_query_string_candidates_are_included_but_blocked_by_policy() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[_service("http://example.test/", "EVID-HTTP-0001")],
            endpoints=[
                Endpoint(
                    url="http://example.test/account?id=1",
                    hostname="example.test",
                    path="/account",
                    query_params=["id"],
                    evidence_ids=["EVID-URL-0001"],
                    tags=[],
                )
            ]
        )
    )

    query = _request(plan, "http://example.test/account?id=1")
    decision = _decision(plan, "http://example.test/account?id=1")
    assert query.method == "GET"
    assert decision.allowed is False
    assert decision.reason == "query_string_not_allowed"


def test_url_userinfo_is_not_sanitised_into_proposed_request() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[_service("http://example.test/", "EVID-HTTP-0001")],
            endpoints=[
                Endpoint(
                    url="http://user:pass@example.test/admin",
                    hostname="example.test",
                    path="/admin",
                    query_params=[],
                    evidence_ids=["EVID-URL-0001"],
                    tags=[],
                )
            ],
            discovered_paths=[
                _path("http://user:pass@example.test/admin", "EVID-PATH-0001")
            ],
        )
    )

    route_urls = tuple(
        request.url for request in plan.proposed_requests if request.source == "source_route_coverage"
    )
    assert "http://example.test/admin" not in route_urls
    assert route_urls == ()
    assert plan.allowed_origins == ("http://example.test",)


def test_url_fragments_are_not_sanitised_into_proposed_requests() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[_service("http://example.test/", "EVID-HTTP-0001")],
            endpoints=[
                Endpoint(
                    url="http://example.test/admin#panel",
                    hostname="example.test",
                    path="/admin",
                    query_params=[],
                    evidence_ids=["EVID-URL-0001"],
                    tags=[],
                )
            ],
            discovered_paths=[
                _path("http://example.test/admin#panel", "EVID-PATH-0001")
            ],
        )
    )

    route_urls = tuple(
        request.url for request in plan.proposed_requests if request.source == "source_route_coverage"
    )
    assert "http://example.test/admin" not in route_urls
    assert route_urls == ()
    assert plan.allowed_origins == ("http://example.test",)


def test_all_generated_methods_are_get_and_duplicates_are_deduped() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[_service("http://example.test/", "EVID-HTTP-0001")],
            discovered_paths=[
                _path("http://example.test/login.php", "EVID-PATH-0001"),
                _path("HTTP://Example.TEST/login.php/", "EVID-PATH-0002"),
            ],
            endpoints=[
                _endpoint("http://example.test/login.php", "EVID-URL-0001"),
            ],
        )
    )

    assert all(request.method == "GET" for request in plan.proposed_requests)
    assert tuple(request.url for request in plan.proposed_requests).count("http://example.test/login.php") == 1


def test_source_counts_and_policy_summary_are_deterministic() -> None:
    state = _project_state(
        http_services=[_service("http://example.test/", "EVID-HTTP-0001")],
        discovered_paths=[_path("http://example.test/login.php", "EVID-PATH-0001")],
        endpoints=[
            Endpoint(
                url="http://example.test/account?id=1",
                hostname="example.test",
                path="/account",
                query_params=["id"],
                evidence_ids=["EVID-URL-0001"],
                tags=[],
            )
        ],
    )

    first = build_deep_collection_request_plan_from_project_state(state)
    second = build_deep_collection_request_plan_from_project_state(state)

    assert first == second
    assert first.source_counts == (
        DeepCollectionRequestSourceCount(source="metadata_coverage", count=8),
        DeepCollectionRequestSourceCount(source="source_route_coverage", count=3),
    )
    assert first.policy_summary.allowed_count == 10
    assert first.policy_summary.blocked_count == 1
    assert first.policy_summary.blocked_reasons == (("query_string_not_allowed", 1),)


def test_renderer_includes_sections_and_safety_wording_without_tables() -> None:
    plan = build_deep_collection_request_plan_from_project_state(
        _project_state(
            http_services=[_service("http://example.test/", "EVID-HTTP-0001")],
            discovered_paths=[_path("http://example.test/login.php", "EVID-PATH-0001")],
            endpoints=[
                Endpoint(
                    url="http://example.test/account?id=1",
                    hostname="example.test",
                    path="/account",
                    query_params=["id"],
                    evidence_ids=["EVID-URL-0001"],
                    tags=[],
                )
            ],
        )
    )
    rendered = render_deep_collection_request_plan_markdown(plan)
    lowered = rendered.lower()

    assert rendered.startswith("## Deep Collection Request Plan\n")
    for section in (
        "### Origin Allowlist",
        "### Source Counts",
        "### Summary",
        "### Policy-Allowed Future Requests",
        "### Policy-Blocked Requests",
        "### Safety Notes",
    ):
        assert section in rendered
    assert "does not fetch URLs" in rendered
    assert "does not run live recon" in rendered
    assert "does not execute Deep Recon" in rendered
    assert "request planning view, not a collection result" in rendered
    assert "Policy-allowed means allowed for a future bounded collector, not fetched" in rendered
    assert (
        "Do not submit forms, authenticate, brute force, inject payloads, execute browser JavaScript, "
        "or test routes from this plan."
    ) in rendered
    assert "Deep Recon was not executed" in rendered
    assert "|" not in rendered
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


def _request(plan: DeepCollectionRequestPlan, url: str):
    for request in plan.proposed_requests:
        if request.url == url:
            return request
    raise AssertionError(f"missing proposed request for {url}")


def _decision(plan: DeepCollectionRequestPlan, url: str):
    for decision in plan.policy_summary.decisions:
        if decision.url == url:
            return decision
    raise AssertionError(f"missing policy decision for {url}")


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


def _service(url: str, evidence_id: str) -> HTTPService:
    return HTTPService(
        url=url,
        hostname="example.test",
        status_code=200,
        title=None,
        technologies=[],
        content_length=None,
        evidence_ids=[evidence_id],
        tags=[],
    )


def _endpoint(url: str, evidence_id: str) -> Endpoint:
    return Endpoint(
        url=url,
        hostname="example.test",
        path=urlparse_path(url),
        query_params=[],
        evidence_ids=[evidence_id],
        tags=[],
    )


def _artifact(url: str, artifact_type: str, value: str, evidence_id: str) -> HTTPArtifact:
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


def urlparse_path(url: str) -> str:
    return "/" + url.split("/", 3)[3].split("?", 1)[0] if "/" in url[8:] else "/"
