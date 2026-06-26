"""Offline route/source review tests."""

from __future__ import annotations

from bugslyce.core.models import (
    DiscoveredPath,
    Endpoint,
    HTTPArtifact,
    HTTPService,
    ProjectState,
)
from bugslyce.recon.artefact_analysis import ArtefactSource
from bugslyce.recon.route_source_review import (
    build_route_source_review,
    render_route_source_review_markdown,
)


def test_extracts_and_buckets_route_references_from_local_source_text() -> None:
    state = _project_state(
        http_services=[_service("http://example.test/")],
        endpoints=[
            Endpoint(
                url="http://example.test/tenant/123?tenant_id=456",
                hostname="example.test",
                path="/tenant/123",
                query_params=["tenant_id"],
                evidence_ids=["EVID-ENDPOINT-ACCOUNT"],
                tags=[],
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url="http://example.test/admin",
                status_code=200,
                content_length=100,
                redirect_location=None,
                source="gobuster",
                evidence_ids=["EVID-PATH-ADMIN"],
                tags=[],
            )
        ],
    )
    source = _source(
        (
            '<a href="/login">login</a> <a href="/api/users">api</a> '
            '<form action="/upload"></form> '
            'fetch("http://example.test/graphql") '
            'fetch("http://external.test/debug") '
            '<img src="/static/logo.png"><link href="/assets/app.css">'
        ),
        source_id="EVID-SOURCE-HTML",
    )

    leads = build_route_source_review(state, (source,))

    assert [lead.lead_id for lead in leads] == [
        "ROUTE-0001",
        "ROUTE-0002",
        "ROUTE-0003",
        "ROUTE-0004",
        "ROUTE-0005",
    ]
    assert [lead.category for lead in leads] == [
        "authentication/account/session",
        "admin/debug/status/dev",
        "api/graphql/webhook",
        "file/data transfer",
        "object/reference-looking",
    ]
    all_routes = {route for lead in leads for route in lead.route_references}
    assert "/login" in all_routes
    assert "/admin" in all_routes
    assert "/api/users" in all_routes
    assert "/graphql" in all_routes
    assert "/upload" in all_routes
    assert "/tenant/123?tenant_id=456" in all_routes
    assert "/debug" not in all_routes
    assert "/static/logo.png" not in all_routes
    assert "/assets/app.css" not in all_routes


def test_deduplicates_and_caps_routes_deterministically() -> None:
    routes = " ".join(f"/route-{index}" for index in range(40))
    repeated = f"/login /login {routes}"
    leads = build_route_source_review(_project_state(), (_source(repeated),))
    general = next(lead for lead in leads if lead.category == "general route references")
    auth = next(lead for lead in leads if lead.category == "authentication/account/session")

    assert auth.route_references == ("/login",)
    assert len(general.route_references) == 25
    assert general.route_references[0] == "/route-0"
    assert general.route_references[-1] == "/route-24"


def test_render_empty_and_populated_markdown_safely() -> None:
    empty = render_route_source_review_markdown((), engagement_context="unknown")
    leads = build_route_source_review(_project_state(), (_source("/login /admin"),))
    markdown = render_route_source_review_markdown(leads, engagement_context="bug_bounty")
    lowered = markdown.lower()

    assert "## Offline Route/Source Review" in empty
    assert "No offline route/source review leads were generated from the collected evidence." in empty
    assert "In a bug bounty context, treat this as low-confidence metadata" in markdown
    assert "ROUTE-0001" in markdown
    assert "- Source IDs: `SRC-1`" in markdown
    assert "Review the already-collected source context." in markdown
    assert "Do not submit forms, brute force, attempt authentication" in markdown
    assert "confirmed finding" not in lowered
    assert "vulnerable" not in lowered
    assert "credentials found" not in lowered
    assert "secret found" not in lowered


def test_general_bucket_for_unclassified_route_references() -> None:
    leads = build_route_source_review(_project_state(), (_source("/docs /help"),))

    assert len(leads) == 1
    assert leads[0].lead_id == "ROUTE-0001"
    assert leads[0].category == "general route references"
    assert leads[0].priority == "medium"
    assert leads[0].route_references == ("/docs", "/help")


def _project_state(
    *,
    http_services: list[HTTPService] | None = None,
    endpoints: list[Endpoint] | None = None,
    discovered_paths: list[DiscoveredPath] | None = None,
    http_artifacts: list[HTTPArtifact] | None = None,
    engagement_context: str = "unknown",
) -> ProjectState:
    return ProjectState(
        project_name="route-test",
        input_dir="/tmp/route-test",
        processed_files=[],
        scope_summary="No scope file parsed.",
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
        generated_at="2026-06-26T00:00:00Z",
        engagement_context=engagement_context,
    )


def _service(url: str) -> HTTPService:
    return HTTPService(
        url=url,
        hostname="example.test",
        status_code=200,
        title=None,
        technologies=[],
        content_length=None,
        evidence_ids=["EVID-SVC"],
        tags=[],
    )


def _source(text: str, *, source_id: str = "SRC-1") -> ArtefactSource:
    return ArtefactSource(
        source_id=source_id,
        source_kind="html",
        source_label="source",
        url="http://example.test/",
        path=None,
        port=80,
        service="http",
        field_name="body",
        text=text,
    )
