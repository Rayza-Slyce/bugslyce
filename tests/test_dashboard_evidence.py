"""D2C: bounded navigation of existing, separate provenance owners."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
from html import unescape
from http.client import HTTPConnection
import re
from threading import Thread

import pytest

from bugslyce.core.models import Evidence
from bugslyce.dashboard.application_view import build_application_navigation, render_origin_detail
from bugslyce.dashboard.evidence_view import (
    CONTEXT_ITEMS_LIMIT,
    GENERIC_PAGE_SIZE,
    LANDING_PREVIEW_SIZE,
    NATIVE_PAGE_SIZE,
    RELATION_PAGE_SIZE,
    SUPPORT_PAGE_SIZE,
    build_evidence_navigation,
    render_evidence_index,
    render_evidence_landing,
    render_generic_detail,
    render_native_detail,
    render_relation_detail,
)
from bugslyce.dashboard.presentation import SUPPORT_PREVIEW_LIMIT, render_thread_detail
from bugslyce.dashboard.read_model import (
    DashboardAuthoritySummary,
    DashboardProjectIdentity,
    DashboardReadModel,
)
from bugslyce.dashboard.server import DashboardHTTPServer
from bugslyce.recon.application_service_composition import build_application_service_composition
from bugslyce.recon.application_service_model import build_application_service_model
from bugslyce.recon.deep_html_route_extraction import build_deep_html_route_extraction
from bugslyce.recon.deep_javascript_route_extraction import build_deep_javascript_route_extraction
from bugslyce.recon.deep_metadata_collector import DeepMetadataCollectedItem, DeepMetadataCollectionResult
from bugslyce.recon.deep_source_route_collector import DeepSourceRouteCollectedItem, DeepSourceRouteCollectionResult
from bugslyce.recon.documentation_assertions import (
    DocumentationAssertionExtractionResult,
    build_documentation_assertions,
)
from bugslyce.recon.http_route_relationships import HttpRouteRelationshipEdge
from bugslyce.recon.investigation_threads import InvestigationThread
from bugslyce.recon.native_observation_facts import (
    NativeMobileAssociationDeclaration,
    NativeObservationSemanticEvidence,
    NativeRedirectRelationship,
    NativeStructuredResponseFact,
)
from bugslyce.reports.analysis_coverage import build_analysis_coverage
from bugslyce.reports.investigation_context import (
    InvestigationContextSources,
    build_primary_investigation_contexts_for_threads,
)
from bugslyce.reports.operator_report_view import OperatorReportView


def _thread(digit: str, **changes: object) -> InvestigationThread:
    return replace(InvestigationThread(
        thread_id="THREAD-" + digit * 64, title="Thread " + digit,
        priority="medium", category="application_interface", summary="Saved fact.",
        why_it_matters="Review retained support.", related_endpoints=(),
        related_evidence_ids=("EVID-ONE",), related_candidate_ids=(), related_lead_ids=(),
        suggested_manual_review_order=("Read support.",), kill_switch_guidance=None,
    ), **changes)


def _application():
    native = NativeObservationSemanticEvidence(
        structured_responses=(NativeStructuredResponseFact(
            "https://example.test/api", 200, 0, 0, "a" * 64,
        ),),
        redirect_relationships=(NativeRedirectRelationship(
            "https://example.test/start", "/next", "https://example.test/next", 0, 0,
        ),),
        mobile_association_declarations=(NativeMobileAssociationDeclaration(
            "https://example.test/.well-known/assetlinks.json", "android",
            "com.example.app", 1, 0, "b" * 64,
        ),),
    )
    html = b'<a href="/referenced">Reference only</a>'
    source = DeepSourceRouteCollectedItem(
        url="https://example.test/home", method="GET", status_code=200,
        final_url="https://example.test/home", headers=(("content-type", "text/html"),),
        body_preview=html.decode(), body_sha256="c" * 64, body_bytes=len(html),
        elapsed_seconds=0.1, source="deep_source_route_collection", reason="selected",
        evidence_ids=("EVID-MISSING",), body=html,
    )
    javascript = b'fetch("/js-api");'
    js_source = replace(
        source, url="https://example.test/app.js", final_url="https://example.test/app.js",
        headers=(("content-type", "application/javascript"),),
        body_preview=javascript.decode(), body_sha256="d" * 64,
        body_bytes=len(javascript), body=javascript,
    )
    sitemap = DeepMetadataCollectedItem(
        url="https://example.test/sitemap.xml", method="GET", status_code=200,
        final_url="https://example.test/sitemap.xml",
        headers=(("content-type", "application/xml"),), body_preview="<urlset>",
        body_sha256="e" * 64, body_bytes=128, elapsed_seconds=0.1,
        source="metadata_coverage", reason="selected", evidence_ids=("EVID-SITEMAP",),
        sitemap_route_references=("https://example.test/from-sitemap",),
    )
    composition = build_application_service_composition(
        redirect_edges=(HttpRouteRelationshipEdge(
            edge_type="redirect", source_url="https://example.test/old",
            target_url="https://example.test/new", evidence_ids=("EVID-ONE",),
            raw_references=("/new",), status_code=302,
        ),),
        html_extraction=build_deep_html_route_extraction(
            DeepSourceRouteCollectionResult((source,), (), 1, 1, 0)
        ),
        javascript_extraction=build_deep_javascript_route_extraction(
            DeepSourceRouteCollectionResult((js_source,), (), 1, 1, 0)
        ),
        metadata_collection=DeepMetadataCollectionResult((sitemap,), (), 1, 1, 0),
        native_observation_evidence=native,
    )
    return build_application_service_model(
        application_composition=composition,
        documentation_assertions=DocumentationAssertionExtractionResult((), (), 0, 0),
        native_observation_evidence=native,
    )


def _documented_application():
    body = (
        b'<html><h2>API base URL</h2><pre>https://example.test/v1</pre></html>'
    )
    source = DeepSourceRouteCollectedItem(
        url="https://example.test/docs", method="GET", status_code=200,
        final_url="https://example.test/docs",
        headers=(("content-type", "text/html"),),
        body_preview=body.decode(), body_sha256=sha256(body).hexdigest(),
        body_bytes=len(body), elapsed_seconds=0.1,
        source="deep_source_route_collection", reason="selected",
        evidence_ids=("EVID-DOC",), body=body,
    )
    assertions = build_documentation_assertions(
        DeepSourceRouteCollectionResult((source,), (), 1, 1, 0)
    )
    assert assertions.assertions
    return build_application_service_model(
        application_composition=build_application_service_composition(),
        documentation_assertions=assertions,
    )


def _model(*, generic: tuple[Evidence, ...] | None = None, threads=None,
           application=None) -> DashboardReadModel:
    if generic is None:
        generic = (Evidence(
            "EVID-ONE", "<script>/saved/path</script>", "http",
            '<img src=x onerror="bad">',
            {"z": {"b": "<script>bad</script>", "a": list(range(30))},
             "a": "x" * 500},
        ),)
    if application is None:
        application = _application()
    if threads is None:
        native_id = "native-observation:0:0"
        relation_ids = tuple(item.relation_id for item in application.application_composition.relations)
        threads = (_thread("a", related_native_observation_ids=(native_id,),
                           related_application_relation_ids=relation_ids),)
    context = build_primary_investigation_contexts_for_threads(
        threads, InvestigationContextSources(evidence=generic),
    )
    return DashboardReadModel(
        project=DashboardProjectIdentity("Example", None, "internal_authorised"),
        investigation_threads=threads, primary_investigation_threads=threads,
        application_service_model=application,
        operator_report_view=OperatorReportView(context, build_analysis_coverage(())),
        analysis_coverage_evidence=None, confidence_notices=(),
        authority=DashboardAuthoritySummary(None, None, None), generic_evidence=generic,
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


def _get(server: DashboardHTTPServer, path: str, *, method: str = "GET") -> tuple[int, str]:
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    connection.request(method, path)
    response = connection.getresponse()
    result = response.status, response.read().decode()
    connection.close()
    return result


def test_landing_has_distinct_domains_counts_and_navigation_order():
    model = _model()
    nav = build_evidence_navigation(model)
    html = render_evidence_landing(model, nav).decode()
    assert "Generic retained Evidence" in html
    assert "Native observation identities" in html
    assert "Application A1 relationships" in html
    assert f"<span class=\"count\">{len(nav.native_sources)}</span>" in html
    assert len(nav.native_sources) == 2  # two facts share one exact source identity
    assert tuple(item.source_id for item in nav.native_sources) == (
        "native-observation:0:0", "native-observation:1:0",
    )
    assert tuple(item.relation_id for item in nav.relations) == tuple(
        sorted(item.relation_id for item in nav.relations)
    )
    assert "evidence-pack closure check" in html


def test_absent_and_empty_snapshots_have_distinct_evidence_states():
    model = _model()
    unavailable = replace(model, generic_evidence=None, application_service_model=None)
    unavailable_html = render_evidence_landing(
        unavailable, build_evidence_navigation(unavailable)
    ).decode()
    assert unavailable_html.count('class="count">Unavailable') == 3
    assert "Snapshot unavailable" in unavailable_html
    empty_application = build_application_service_model(
        application_composition=build_application_service_composition(),
        documentation_assertions=DocumentationAssertionExtractionResult((), (), 0, 0),
    )
    empty = replace(model, generic_evidence=(), application_service_model=empty_application)
    empty_html = render_evidence_landing(empty, build_evidence_navigation(empty)).decode()
    assert empty_html.count('class="count">0') == 3
    assert "No records in this loaded snapshot" in empty_html
    assert "Snapshot unavailable" not in empty_html


@pytest.mark.parametrize("evidence_id", [
    "LEGACY-HTTP-001",
    "Legacy HTTP / <&?> 001",
])
def test_arbitrary_loaded_generic_ids_have_safe_detail_routes(evidence_id):
    evidence = Evidence(evidence_id, "private/source-file.txt", "http", "saved", {})
    thread = _thread("b", related_evidence_ids=(evidence_id,))
    model = _model(generic=(evidence,), threads=(thread,))
    nav = build_evidence_navigation(model)
    path = nav.generic_path(evidence_id)
    assert path is not None
    assert re.fullmatch(r"/evidence/generic/id/[0-9a-f]{64}", path)
    assert evidence_id not in path
    assert "source-file" not in path
    with _running(model) as server:
        status, listing = _get(server, "/evidence/generic/page/1")
        assert status == 200
        assert f'href="{path}"' in listing
        assert evidence_id in unescape(listing)
        status, detail = _get(server, path)
        assert status == 200
        assert evidence_id in unescape(detail)
        assert f'href="/thread/{thread.thread_id}"' in detail
        assert path in _get(server, "/thread/" + thread.thread_id)[1]
        assert _get(server, "/evidence/generic/id/" + "0" * 64)[0] == 404
        assert _get(server, "/evidence/generic/id/not-a-locator")[0] == 404
        assert _get(server, "/evidence/generic/id/../../etc/passwd")[0] == 404


def test_generic_locator_collision_and_duplicate_ids_are_refused(monkeypatch):
    from bugslyce.dashboard import evidence_view

    first = Evidence("LEGACY-ONE", "a.txt", "http", "a", {})
    second = Evidence("LEGACY-TWO", "b.txt", "http", "b", {})
    model = _model(generic=(first, second), threads=())
    monkeypatch.setattr(evidence_view, "_generic_locator", lambda evidence_id: "a" * 64)
    navigation = build_evidence_navigation(model)
    assert navigation.generic_path(first.id) is None
    assert navigation.generic_path(second.id) is None
    assert not navigation.generic_by_locator
    with _running(model) as server:
        assert _get(server, "/evidence/generic/id/" + "a" * 64)[0] == 404
    duplicate = replace(model, generic_evidence=(first, replace(first, value="different")))
    duplicate_navigation = build_evidence_navigation(duplicate)
    assert duplicate_navigation.generic_path(first.id) is None
    assert not duplicate_navigation.generic_by_id


def test_native_route_uses_the_existing_nonnegative_index_contract():
    large_index = 10**12
    native = NativeObservationSemanticEvidence(redirect_relationships=(
        NativeRedirectRelationship(
            "https://example.test/old", "/new", "https://example.test/new",
            large_index, 0,
        ),
    ))
    application = replace(_application(), native_observation_evidence=native)
    model = _model(application=application, threads=())
    source_id = f"native-observation:{large_index}:0"
    path = build_evidence_navigation(model).native_path(source_id)
    assert path == f"/evidence/native/{large_index}/0"
    with _running(model) as server:
        assert _get(server, path)[0] == 200


def test_documentation_provenance_absent_model_is_not_linked():
    model = replace(_model(), application_service_model=None)
    html = render_evidence_landing(model, build_evidence_navigation(model)).decode()
    assert "Documentation provenance unavailable" in html
    assert 'href="/application/documentation"' not in html


def test_documentation_provenance_loaded_empty_is_distinct():
    model = _model()
    assert not model.application_service_model.documented_http_services
    assert not model.application_service_model.documented_realtime_endpoints
    assert not model.application_service_model.relations
    html = render_evidence_landing(model, build_evidence_navigation(model)).decode()
    assert "No documented services, realtime endpoints, or A3 relationships are recorded" in html
    assert "Documentation provenance unavailable" not in html
    assert 'href="/application/documentation"' not in html


def test_documentation_provenance_present_keeps_valid_link():
    model = _model(application=_documented_application(), threads=())
    assert model.application_service_model.documented_http_services
    html = render_evidence_landing(model, build_evidence_navigation(model)).decode()
    assert 'href="/application/documentation"' in html
    with _running(model) as server:
        assert _get(server, "/application/documentation")[0] == 200


def test_generic_detail_escapes_and_bounds_context_and_uses_report_backlink():
    model = _model()
    nav = build_evidence_navigation(model)
    html = render_generic_detail(model, nav, nav.generic[0]).decode()
    assert "<script>/saved/path</script>" not in html
    assert "&lt;script&gt;/saved/path&lt;/script&gt;" in html
    assert '<a href="/saved/path"' not in html
    assert '<img src=x onerror="bad">' not in html
    assert "&lt;img src=x onerror=&quot;bad&quot;&gt;" in html
    assert html.index('<dt>a</dt>') < html.index('<dt>z</dt>')
    assert "Context truncated for display" in html
    assert len(html) < 14000
    assert f'/thread/{model.investigation_threads[0].thread_id}' in html
    empty_context = replace(model.operator_report_view.investigation_context, evidence_backlinks=())
    without_owner = replace(model, operator_report_view=replace(
        model.operator_report_view, investigation_context=empty_context,
    ))
    no_link = render_generic_detail(without_owner, build_evidence_navigation(without_owner),
                                    without_owner.generic_evidence[0]).decode()
    assert "No primary Investigation thread currently references" in no_link
    assert f'/thread/{model.investigation_threads[0].thread_id}' not in no_link


def test_context_rendering_has_stable_bounded_nested_values():
    evidence = Evidence("EVID-ONE", "recorded.txt", "http", "value", {
        f"key-{number:02d}": {"nested": list(range(30))} for number in range(50)
    })
    model = _model(generic=(evidence,))
    nav = build_evidence_navigation(model)
    first = render_generic_detail(model, nav, evidence)
    assert first == render_generic_detail(model, nav, evidence)
    html = first.decode()
    assert "Context truncated for display" in html
    assert html.count('class="context-pair"') == 3 + 20
    assert "key-20" not in html
    assert len(html) < 15000
    assert CONTEXT_ITEMS_LIMIT == 12


def test_native_detail_facts_qualifications_and_only_explicit_backlinks():
    model = _model()
    nav = build_evidence_navigation(model)
    source = nav.native_by_id["native-observation:0:0"]
    html = render_native_detail(model, nav, source).decode()
    assert "HTTP status: 200" in html
    assert "Body SHA-256" in html
    assert "structured response does not confirm API status" in html
    assert "destination fetch not implied" in html
    assert f'/thread/{model.investigation_threads[0].thread_id}' in html
    mobile = render_native_detail(model, nav, nav.native_by_id["native-observation:1:0"]).decode()
    assert "ownership unconfirmed" in mobile
    assert "No Investigation thread explicitly references" in mobile


def test_relationship_support_types_links_and_reference_qualification():
    model = _model()
    nav = build_evidence_navigation(model)
    relations = nav.relations
    direct = next(item for item in relations if any(
        "EVID-ONE" in support.evidence_ids for support in item.supports
    ))
    html = render_relation_detail(model, nav, direct).decode()
    assert "Direct observation" in html
    assert "HTTP redirect" in html
    assert "http_route_relationship_edge" in html
    assert "HTTP status: 302" in html
    assert "Raw references" in html
    assert "artefact references" in html.lower()
    assert nav.generic_path("EVID-ONE") in html
    assert "EVID-ONE</a> · generic Evidence" in html
    assert f'/thread/{model.investigation_threads[0].thread_id}' in html
    no_relation_thread = replace(model.investigation_threads[0], related_application_relation_ids=())
    no_relation_model = replace(
        model, investigation_threads=(no_relation_thread,),
        primary_investigation_threads=(no_relation_thread,),
    )
    no_backlink = render_relation_detail(
        no_relation_model, build_evidence_navigation(no_relation_model), direct,
    ).decode()
    assert "No Investigation thread explicitly references this Application relationship" in no_backlink
    reference = next(item for item in relations if any(
        "EVID-MISSING" in support.evidence_ids for support in item.supports
    ))
    reference_html = render_relation_detail(model, nav, reference).decode()
    assert "HTML reference" in reference_html
    assert "Deterministic derivation / reference" in reference_html
    assert "EVID-MISSING · retained support reference · no matching generic Evidence record in this snapshot" in reference_html
    assert "unresolved" not in reference_html.lower()
    assert "A reference is not proof of a reached or working route" in reference_html
    for semantic in ("HTML reference", "JavaScript request call", "Sitemap declaration"):
        candidate = next(item for item in relations if any(
            semantic.lower().replace(" ", "_") == support.source_semantic.value
            or (semantic == "HTML reference" and support.source_semantic.value == "html_route_reference")
            for support in item.supports
        ))
        candidate_html = render_relation_detail(model, nav, candidate).decode()
        assert semantic in candidate_html
        assert "Deterministic derivation / reference" in candidate_html
        assert "Direct observation</strong>" not in candidate_html
    native = next(item for item in relations if any(
        support.source_reference.source_id == "native-observation:0:0"
        for support in item.supports
    ))
    native_html = render_relation_detail(model, nav, native).decode()
    assert 'href="/evidence/native/0/0"' in native_html
    assert "native-observation:0:0 · retained support reference · no matching generic Evidence record in this snapshot" in native_html
    for forbidden in ("unresolved", "missing artefact", "missing evidence", "pack failure", "pack verified"):
        assert forbidden not in native_html.lower()
    without_native = replace(model, application_service_model=replace(
        model.application_service_model,
        native_observation_evidence=NativeObservationSemanticEvidence(),
    ))
    unresolved = render_relation_detail(without_native, build_evidence_navigation(without_native), native).decode()
    assert 'href="/evidence/native/0/0"' not in unresolved
    assert "native-observation:0:0" in unresolved


def test_thread_support_preview_is_bounded_and_all_domains_navigable():
    model = _model()
    nav = build_evidence_navigation(model)
    detail = render_thread_detail(model, model.investigation_threads[0], nav).decode()
    assert nav.generic_path("EVID-ONE") in detail
    assert '/evidence/native/0/0' in detail
    assert '/evidence/application/APP-RELATION-' in detail
    many = replace(model.investigation_threads[0],
        related_evidence_ids=(),
        related_native_observation_ids=tuple(f"native-observation:{i}:0" for i in range(35)),
        related_application_relation_ids=tuple(f"APP-RELATION-{i}" for i in range(35)),
    )
    html = render_thread_detail(model, many, nav).decode()
    assert "Native observations <strong>35</strong>" in html
    assert "Application relationships <strong>35</strong>" in html
    assert "+30 more retained references" in html
    assert html.count("retained reference unresolved") == SUPPORT_PREVIEW_LIMIT * 2 - 2
    assert "unsupported" not in html.lower()


def test_indices_and_origin_rows_are_bounded():
    model = _model()
    evidence = tuple(Evidence(f"EVID-{i:04d}", "saved.txt", "test", str(i), {})
                     for i in range(GENERIC_PAGE_SIZE + 5))
    large = replace(model, generic_evidence=evidence)
    nav = build_evidence_navigation(large)
    landing = render_evidence_landing(large, nav).decode()
    assert landing.count('class="evidence-row"') <= LANDING_PREVIEW_SIZE * 3
    first = render_evidence_index(large, nav, "generic", 1).decode()
    second = render_evidence_index(large, nav, "generic", 2).decode()
    assert first.count('class="evidence-row"') == GENERIC_PAGE_SIZE
    assert second.count('class="evidence-row"') == 5
    assert NATIVE_PAGE_SIZE == 60 and RELATION_PAGE_SIZE == 32
    application = build_application_navigation(model.application_service_model)
    origin = next(item for item in application.origins if item.relations)
    origin_html = render_origin_detail(model, application, origin).decode()
    assert 'Review provenance</a>' in origin_html
    assert '/evidence/application/APP-RELATION-' in origin_html
    out_of_order = replace(model, generic_evidence=(
        Evidence("EVID-Z", "z.txt", "test", "z", {}),
        Evidence("EVID-A", "a.txt", "test", "a", {}),
    ))
    order_html = render_evidence_index(
        out_of_order, build_evidence_navigation(out_of_order), "generic", 1,
    ).decode()
    assert order_html.index("EVID-Z") < order_html.index("EVID-A")


def test_relation_support_pages_bound_large_support_sets():
    model = _model()
    nav = build_evidence_navigation(model)
    relation = nav.relations[0]
    supports = tuple(replace(
        relation.supports[0], evidence_ids=(f"EVID-OTHER-{number:03d}",),
    ) for number in range(SUPPORT_PAGE_SIZE + 5))
    large = replace(relation, supports=supports)
    first = render_relation_detail(model, nav, large, page=1).decode()
    second = render_relation_detail(model, nav, large, page=2).decode()
    assert first.count('class="evidence-row"') == SUPPORT_PAGE_SIZE
    assert second.count('class="evidence-row"') == 5
    assert "EVID-OTHER-044" not in first
    assert "EVID-OTHER-044" in second


@pytest.mark.parametrize("path", [
    "/evidence/generic/EVID-UNKNOWN", "/evidence/generic/../source.txt",
    "/evidence/generic/%2Fetc%2Fpasswd", "/evidence/native/999/999",
    "/evidence/generic/id/" + "0" * 64, "/evidence/generic/id/" + "A" * 64,
    "/evidence/generic/id/%2e%2e", "/evidence/generic/id/not-a-locator",
    "/evidence/native/00/0", "/evidence/application/APP-RELATION-" + "f" * 64,
    "/evidence/generic/page/999", "/evidence/native/page/999",
    "/evidence/application/page/999", "/evidence/application/../../etc/passwd",
])
def test_evidence_routes_refuse_unknown_and_malformed_ids(path):
    with _running(_model()) as server:
        status, body = _get(server, path)
        assert status == 404 and body == "Not found"


def test_evidence_nav_active_and_fixed_local_read_only_routes():
    model = _model()
    nav = build_evidence_navigation(model)
    paths = ["/evidence", nav.generic_path("EVID-ONE"), "/evidence/native/0/0",
             nav.relation_path(nav.relations[0].relation_id)]
    with _running(model) as server:
        assert server.server_address[0] == "127.0.0.1"
        for path in paths:
            status, html = _get(server, path)
            assert status == 200
            navigation = html.split('<nav class="primary-nav"', 1)[1].split('</nav>', 1)[0]
            assert 'href="/evidence" aria-current="page"' in navigation
            assert navigation.count('aria-current="page"') == 1
        assert _get(server, nav.generic_path("EVID-ONE"), method="POST")[0] == 405
