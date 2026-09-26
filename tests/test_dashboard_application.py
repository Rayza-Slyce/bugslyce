"""D2B: bounded application navigation over saved typed model objects."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
from http.client import HTTPConnection
from threading import Thread

import pytest

from bugslyce.dashboard.application_view import (
    RELATION_PAGE_SIZE,
    ROUTE_PAGE_SIZE,
    build_application_navigation,
    render_application_home,
    render_origin_detail,
)
from bugslyce.dashboard.read_model import (
    DashboardAuthoritySummary,
    DashboardProjectIdentity,
    DashboardReadModel,
)
from bugslyce.dashboard.server import DashboardHTTPServer, create_dashboard_server
from bugslyce.recon.application_service_composition import build_application_service_composition
from bugslyce.recon.application_service_model import build_application_service_model
from bugslyce.recon.deep_html_route_extraction import build_deep_html_route_extraction
from bugslyce.recon.deep_javascript_route_extraction import build_deep_javascript_route_extraction
from bugslyce.recon.deep_metadata_collector import DeepMetadataCollectedItem, DeepMetadataCollectionResult
from bugslyce.recon.deep_source_route_collector import DeepSourceRouteCollectedItem, DeepSourceRouteCollectionResult
from bugslyce.recon.documentation_assertions import DocumentationAssertionExtractionResult, build_documentation_assertions
from bugslyce.recon.http_route_relationships import HttpRouteRelationshipEdge
from bugslyce.recon.native_observation_facts import (
    NativeMobileAssociationDeclaration,
    NativeObservationSemanticEvidence,
    NativeRedirectRelationship,
    NativeStructuredResponseFact,
)
from bugslyce.reports.analysis_coverage import build_analysis_coverage
from bugslyce.reports.investigation_context import InvestigationContextAssembly
from bugslyce.reports.operator_report_view import OperatorReportView


def _source(
    body: bytes, *, url: str = "https://a.example.test/docs", content_type: str = "text/html"
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url, method="GET", status_code=200,
        final_url=url, headers=(("content-type", content_type),),
        body_preview=body.decode()[:120], body_sha256=sha256(body).hexdigest(),
        body_bytes=len(body), elapsed_seconds=0.1,
        source="deep_source_route_collection", reason="selected",
        evidence_ids=("EVID-DOC",), body=body,
    )


def _model(*, routes: int = 72, documentation: bool = True) -> DashboardReadModel:
    native = NativeObservationSemanticEvidence(
        structured_responses=(NativeStructuredResponseFact(
            "https://a.example.test/api", 200, 0, 0, "a" * 64,
        ),),
        redirect_relationships=(NativeRedirectRelationship(
            "https://a.example.test/start", "/next", "https://a.example.test/next", 1, 0,
        ),),
        mobile_association_declarations=(NativeMobileAssociationDeclaration(
            "https://a.example.test/.well-known/assetlinks.json", "android",
            "com.example.app", 2, 0, "b" * 64,
        ),),
    )
    edges = tuple(HttpRouteRelationshipEdge(
        edge_type="redirect", source_url=f"https://a.example.test/path/{number:03d}",
        target_url="https://b.example.test/destination", evidence_ids=(f"EVID-{number}",),
        raw_references=("https://b.example.test/destination",), status_code=302,
    ) for number in range(routes))
    html_source = _source(b'<html><a href="/api">API reference</a></html>')
    html_collection = DeepSourceRouteCollectionResult((html_source,), (), 1, 1, 0)
    js_source = _source(
        b'fetch("/js-api");', url="https://a.example.test/app.js",
        content_type="application/javascript",
    )
    js_collection = DeepSourceRouteCollectionResult((js_source,), (), 1, 1, 0)
    documentation_body = (
        b'<html><h2>API base URL</h2><pre>https://a.example.test/v1</pre>'
        b'<h2>WebSocket endpoint</h2><pre>wss://stream.example.test/v1</pre></html>'
    )
    docs_collection = DeepSourceRouteCollectionResult(
        (_source(documentation_body),), (), 1, 1, 0,
    )
    docs = (
        build_documentation_assertions(docs_collection) if documentation
        else DocumentationAssertionExtractionResult((), (), 0, 0)
    )
    sitemap = DeepMetadataCollectedItem(
        url="https://a.example.test/sitemap.xml", method="GET", status_code=200,
        final_url="https://a.example.test/sitemap.xml",
        headers=(("content-type", "application/xml"),), body_preview="<urlset>",
        body_sha256="c" * 64, body_bytes=128, elapsed_seconds=0.1,
        source="metadata_coverage", reason="selected", evidence_ids=("EVID-SITEMAP",),
        sitemap_route_references=("https://a.example.test/sitemap-route",),
    )
    composition = build_application_service_composition(
        redirect_edges=edges,
        html_extraction=build_deep_html_route_extraction(html_collection),
        javascript_extraction=build_deep_javascript_route_extraction(js_collection),
        metadata_collection=DeepMetadataCollectionResult((sitemap,), (), 1, 1, 0),
        native_observation_evidence=native,
    )
    application = build_application_service_model(
        application_composition=composition,
        documentation_assertions=docs,
        native_observation_evidence=native,
    )
    return DashboardReadModel(
        project=DashboardProjectIdentity("<script>project</script>", "a.example.test", "internal_authorised"),
        investigation_threads=(), primary_investigation_threads=(),
        application_service_model=application,
        operator_report_view=OperatorReportView(
            InvestigationContextAssembly((), (), ()), build_analysis_coverage(())
        ),
        analysis_coverage_evidence=None, confidence_notices=(),
        authority=DashboardAuthoritySummary(None, None, None),
    )


@contextmanager
def _running(model: DashboardReadModel):
    server = DashboardHTTPServer(model)
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def _request(server: DashboardHTTPServer, path: str, *, method: str = "GET") -> tuple[int, str]:
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    connection.request(method, path)
    response = connection.getresponse()
    result = response.status, response.read().decode()
    connection.close()
    return result


def test_persistent_navigation_and_absent_versus_empty_application_model():
    model = _model(routes=2)
    index = build_application_navigation(model.application_service_model)
    with _running(model) as server:
        paths = (
            ("/", "/"),
            ("/limitations", "/limitations"),
            ("/application", "/application"),
            (f"/application/origin/{index.origins[0].origin.entity_id}", "/application"),
        )
        for path, active_path in paths:
            status, body = _request(server, path)
            assert status == 200
            for title in ("Investigations", "Application", "Collection context"):
                assert f">{title}</a>" in body
            navigation = body.split('<nav class="primary-nav"', 1)[1].split('</nav>', 1)[0]
            assert navigation.count('aria-current="page"') == 1
            assert f'href="{active_path}" aria-current="page"' in navigation
            for inactive_path in ({"/", "/application", "/limitations"} - {active_path}):
                assert f'href="{inactive_path}" aria-current' not in navigation
    absent = render_application_home(replace(model, application_service_model=None), build_application_navigation(None)).decode()
    empty_application = build_application_service_model(
        application_composition=build_application_service_composition(),
        documentation_assertions=DocumentationAssertionExtractionResult((), (), 0, 0),
    )
    empty = render_application_home(replace(model, application_service_model=empty_application), build_application_navigation(empty_application)).decode()
    assert "Application model unavailable" in absent
    assert "No HTTP origins recorded" in empty
    assert "Application model unavailable" not in empty


def test_origin_order_counts_and_landing_bounding_are_neutral():
    model = _model()
    index = build_application_navigation(model.application_service_model)
    html = render_application_home(model, index).decode()
    origin_urls = tuple(value.origin.origin.origin_url for value in index.origins)
    assert origin_urls == tuple(sorted(origin_urls))
    assert all(html.index(a) < html.index(b) for a, b in zip(origin_urls, origin_urls[1:]))
    assert "not security priority" in html
    assert f"<strong>{len(model.application_service_model.application_composition.routes)}</strong> routes" in html
    assert html.count('class="route-row"') == 0
    assert "https://a.example.test/path/000" not in html
    assert "&lt;script&gt;project&lt;/script&gt;" in html
    assert "<script>project</script>" not in html


def test_lexical_origin_navigation_is_not_a_route_count_order():
    edges = tuple(
        HttpRouteRelationshipEdge(
            edge_type="redirect", source_url=f"https://z.example.test/{number}",
            target_url="https://a.example.test/landing", evidence_ids=(f"EVID-{number}",),
            status_code=302,
        ) for number in range(4)
    )
    application = build_application_service_model(
        application_composition=build_application_service_composition(redirect_edges=edges),
        documentation_assertions=DocumentationAssertionExtractionResult((), (), 0, 0),
    )
    origins = build_application_navigation(application).origins
    assert tuple(value.origin.origin.origin_url for value in origins) == (
        "https://a.example.test", "https://z.example.test",
    )
    assert len(origins[0].routes) < len(origins[1].routes)


def test_route_and_relationship_pages_are_bounded_and_preserve_canonical_values():
    model = _model()
    index = build_application_navigation(model.application_service_model)
    origin = next(value for value in index.origins if value.origin.origin.hostname == "a.example.test")
    assert len(origin.routes) > ROUTE_PAGE_SIZE
    assert len(origin.relations) > RELATION_PAGE_SIZE
    first = render_origin_detail(model, index, origin).decode()
    second = render_origin_detail(model, index, origin, routes_page=2, relations_page=2).decode()
    assert first.count('class="route-row"') == ROUTE_PAGE_SIZE
    assert first.count('class="relation-row"') == RELATION_PAGE_SIZE
    assert f"Showing 1–{ROUTE_PAGE_SIZE} of {len(origin.routes)}" in first
    assert f"Showing {ROUTE_PAGE_SIZE + 1}–{len(origin.routes)} of {len(origin.routes)}" in second
    first_routes = first.split('<ol class="route-list">', 1)[1].split('</ol>', 1)[0]
    second_routes = second.split('<ol class="route-list">', 1)[1].split('</ol>', 1)[0]
    assert origin.routes[0].canonical_url in first_routes
    assert origin.routes[ROUTE_PAGE_SIZE].canonical_url not in first_routes
    assert origin.routes[ROUTE_PAGE_SIZE].canonical_url in second_routes
    all_relation_pages = "".join(
        render_origin_detail(model, index, origin, relations_page=page).decode()
        for page in range(1, (len(origin.relations) - 1) // RELATION_PAGE_SIZE + 2)
    )
    assert "HTML reference" in all_relation_pages
    assert "JavaScript request call" in all_relation_pages
    assert "Sitemap declaration" in all_relation_pages
    assert "Deterministic derivation / reference" in all_relation_pages
    assert "Direct observation" in all_relation_pages
    assert "Native HTTP redirect" in all_relation_pages
    for row in all_relation_pages.split('<li class="relation-row">'):
        if any(label in row for label in (
            "HTML reference", "JavaScript request call", "Sitemap declaration",
        )):
            assert "Deterministic derivation / reference" in row
            assert "Direct observation" not in row
    assert "destination not shown as fetched" in first
    assert "not a confirmed API" in first
    assert "ownership not confirmed" in first
    assert "Source provenance" in first + all_relation_pages
    assert "EVID-" in first + all_relation_pages


def test_only_loaded_ids_and_canonical_pages_route_without_mutation():
    model = _model()
    index = build_application_navigation(model.application_service_model)
    origin_id = index.origins[0].origin.entity_id
    with _running(model) as server:
        good = f"/application/origin/{origin_id}"
        assert _request(server, good)[0] == 200
        assert _request(server, good + "/routes/2")[0] == 200
        assert _request(server, "/application/documentation")[0] == 200
        for bad in (
            "/application/origin/APP-ORIGIN-" + "0" * 64,
            good + "/routes/0", good + "/routes/02", good + "/routes/9999",
            good + "/relations/-1", good + "/../../etc/passwd",
            "/application/documentation/page/9999", "/application?file=secret",
            "/application/origin/%2e%2e", "/project_state.json",
        ):
            assert _request(server, bad)[0] == 404
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            assert _request(server, good, method=method)[0] == 405


def test_a3_documentation_and_correspondence_are_not_direct_reachability():
    model = _model()
    index = build_application_navigation(model.application_service_model)
    assert model.application_service_model.documented_http_services
    assert model.application_service_model.documented_realtime_endpoints
    with _running(model) as server:
        body = _request(server, "/application/documentation")[1]
    assert "Documented HTTP service" in body
    assert "Documented realtime endpoint" in body
    assert "Direct documentation" in body
    assert "Deterministic correspondence" in body
    assert "https://a.example.test/docs" in body
    assert "not independently proven reachable" in body
    origin = next(value for value in index.origins if value.origin.origin.hostname == "a.example.test")
    detail = render_origin_detail(model, index, origin).decode()
    assert "Documented service correspondence" in detail
    assert "deterministic derivation" in detail


def test_packaged_css_and_csp_remain_local():
    model = _model(routes=1)
    with _running(model) as server:
        assert server.server_address[0] == "127.0.0.1"
        status, body = _request(server, "/assets/dashboard.css")
        assert status == 200 and ".origin-row" in body
        assert "@import" not in body and "url(" not in body
        status, page = _request(server, "/application")
        assert status == 200 and "<script" not in page


def test_model_controlled_native_text_is_escaped():
    model = _model(routes=1)
    original = model.application_service_model
    assert original is not None
    malicious = '<img src=x onerror="alert(1)">'
    native = replace(
        original.native_observation_evidence,
        mobile_association_declarations=(replace(
            original.native_observation_evidence.mobile_association_declarations[0],
            package_name=malicious,
        ),),
    )
    model = replace(model, application_service_model=replace(original, native_observation_evidence=native))
    index = build_application_navigation(model.application_service_model)
    landing = render_application_home(model, index).decode()
    detail = render_origin_detail(model, index, index.origins[0]).decode()
    assert malicious not in landing + detail
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in landing + detail


def test_application_requests_reuse_one_loaded_read_model(monkeypatch, tmp_path):
    model = _model(routes=3)
    calls: list[object] = []

    def load(project):
        calls.append(project)
        return model

    monkeypatch.setattr("bugslyce.dashboard.server.build_dashboard_read_model", load)
    server = create_dashboard_server(tmp_path)
    origin_id = server.application_navigation.origins[0].origin.entity_id
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    worker.start()
    try:
        for path in ("/application", f"/application/origin/{origin_id}", "/application/documentation"):
            assert _request(server, path)[0] == 200
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert calls == [tmp_path]
