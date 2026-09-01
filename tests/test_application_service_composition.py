"""WP5A1 deterministic application/service composition RED contract."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import importlib
import inspect

import pytest

from bugslyce.recon.deep_html_route_extraction import (
    build_deep_html_route_extraction,
)
from bugslyce.recon.deep_javascript_route_extraction import (
    build_deep_javascript_route_extraction,
)
from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.http_origin import HttpOrigin
from bugslyce.recon.http_route_relationships import HttpRouteRelationshipEdge


def _api():
    return importlib.import_module(
        "bugslyce.recon.application_service_composition"
    )


def _source_item(
    *,
    url: str = "https://app.example.test/index.html",
    body: bytes,
    content_type: str,
    evidence_ids: tuple[str, ...] = ("EVID-SOURCE-0001",),
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=(("content-type", content_type),),
        body_preview=body.decode("utf-8", errors="replace")[:120],
        body_sha256=sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.125,
        source="deep_source_route_collection",
        reason="selected",
        evidence_ids=evidence_ids,
        body=body,
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


def _metadata_item(
    *,
    url: str = "https://app.example.test/sitemap.xml",
    routes: tuple[str, ...],
    evidence_ids: tuple[str, ...] = ("EVID-SITEMAP-0001",),
) -> DeepMetadataCollectedItem:
    return DeepMetadataCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=(("content-type", "application/xml"),),
        body_preview="<urlset>...</urlset>",
        body_sha256="a" * 64,
        body_bytes=128,
        elapsed_seconds=0.125,
        source="metadata_coverage",
        reason="selected",
        evidence_ids=evidence_ids,
        sitemap_route_references=routes,
    )


def _metadata_collection(
    *items: DeepMetadataCollectedItem,
) -> DeepMetadataCollectionResult:
    return DeepMetadataCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _redirect_edge(
    *,
    source: str = "https://app.example.test/login",
    target: str = "https://app.example.test/account",
    location: str = "/account",
    evidence_ids: tuple[str, ...] = ("EVID-REDIRECT-0001",),
    artefacts: tuple[str, ...] = ("deep_source_route_collection.json",),
) -> HttpRouteRelationshipEdge:
    return HttpRouteRelationshipEdge(
        edge_type="redirect",
        source_url=source,
        target_url=target,
        evidence_ids=evidence_ids,
        artefact_references=artefacts,
        raw_references=(location,),
        status_code=302,
    )


def test_observed_redirect_becomes_one_supported_redirects_to_relation() -> None:
    api = _api()
    edge = _redirect_edge(
        evidence_ids=("EVID-REDIRECT-0002", "EVID-REDIRECT-0001"),
        artefacts=("headers.txt", "deep_source_route_collection.json"),
    )

    composition = api.build_application_service_composition(
        redirect_edges=(edge,),
    )

    assert len(composition.routes) == 2
    assert composition.source_sets == ()
    assert len(composition.relations) == 1
    relation = composition.relations[0]
    assert relation.relation_kind is api.ApplicationServiceRelationKind.REDIRECTS_TO
    assert len(relation.supports) == 1
    support = relation.supports[0]
    assert support.basis is api.ApplicationServiceSupportBasis.DIRECT_OBSERVATION
    assert (
        support.source_semantic
        is api.ApplicationServiceSourceSemantic.HTTP_REDIRECT
    )
    assert (
        support.source_reference.owner_kind
        is api.ApplicationServiceSourceOwnerKind.HTTP_ROUTE_RELATIONSHIP_EDGE
    )
    assert support.source_reference.source_id
    assert support.evidence_ids == (
        "EVID-REDIRECT-0001",
        "EVID-REDIRECT-0002",
    )
    assert support.artefact_references == (
        "deep_source_route_collection.json",
        "headers.txt",
    )
    assert support.http_status_code == 302
    assert support.raw_references == ("/account",)


def test_non_redirect_relationship_edge_is_rejected_by_redirect_adapter() -> None:
    api = _api()
    source_reference = HttpRouteRelationshipEdge(
        edge_type="source_reference",
        source_url="https://app.example.test/docs",
        target_url="https://app.example.test/api",
        evidence_ids=("EVID-SOURCE-REFERENCE",),
        artefact_references=("saved-docs.html",),
        raw_references=("/api",),
    )

    with pytest.raises(ValueError, match="redirect"):
        api.build_application_service_composition(
            redirect_edges=(source_reference,),
        )


def test_sitemap_declares_route_as_deterministic_derivation_only() -> None:
    api = _api()
    metadata = _metadata_collection(
        _metadata_item(
            routes=("https://app.example.test/docs?view=summary",),
        )
    )

    composition = api.build_application_service_composition(
        metadata_collection=metadata,
    )

    assert len(composition.source_sets) == 1
    assert composition.source_sets[0].resource_urls == (
        "https://app.example.test/sitemap.xml",
    )
    assert tuple(route.canonical_url for route in composition.routes) == (
        "https://app.example.test/docs?view=summary",
    )
    relation = composition.relations[0]
    assert relation.relation_kind is api.ApplicationServiceRelationKind.DECLARES_ROUTE
    support = relation.supports[0]
    assert (
        support.basis
        is api.ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION
    )
    assert (
        support.source_semantic
        is api.ApplicationServiceSourceSemantic.SITEMAP_DECLARATION
    )
    assert (
        support.source_reference.owner_kind
        is api.ApplicationServiceSourceOwnerKind.DEEP_METADATA_COLLECTED_ITEM
    )
    assert support.evidence_ids == ("EVID-SITEMAP-0001",)
    assert all(
        item.basis is not api.ApplicationServiceSupportBasis.DIRECT_OBSERVATION
        for item in relation.supports
    )


def test_metadata_without_sitemap_declarations_does_not_build_unused_support() -> None:
    api = _api()

    composition = api.build_application_service_composition(
        metadata_collection=_metadata_collection(
            _metadata_item(routes=(), evidence_ids=()),
        ),
    )

    assert composition.source_sets == ()
    assert composition.routes == ()
    assert composition.relations == ()

    with pytest.raises(ValueError, match="evidence"):
        api.build_application_service_composition(
            metadata_collection=_metadata_collection(
                _metadata_item(
                    routes=("https://app.example.test/declared",),
                    evidence_ids=(),
                ),
            ),
        )


def test_javascript_request_call_references_route_with_exact_semantics() -> None:
    api = _api()
    extraction = build_deep_javascript_route_extraction(
        _source_collection(
            _source_item(
                url="https://app.example.test/assets/app.js",
                body=b'fetch("/api/users");',
                content_type="application/javascript",
                evidence_ids=("EVID-JS-REQUEST",),
            )
        )
    )
    assert extraction.candidates[0].semantic_contexts == ("request_call",)

    composition = api.build_application_service_composition(
        javascript_extraction=extraction,
    )

    relation = composition.relations[0]
    assert relation.relation_kind is api.ApplicationServiceRelationKind.REFERENCES_ROUTE
    assert tuple(route.canonical_url for route in composition.routes) == (
        "https://app.example.test/api/users",
    )
    support = relation.supports[0]
    assert (
        support.basis
        is api.ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION
    )
    assert (
        support.source_semantic
        is api.ApplicationServiceSourceSemantic.JAVASCRIPT_REQUEST_CALL
    )
    assert (
        support.source_reference.owner_kind
        is api.ApplicationServiceSourceOwnerKind.DEEP_JAVASCRIPT_ROUTE_CANDIDATE
    )
    assert support.source_reference.source_id == extraction.candidates[0].candidate_id
    assert support.evidence_ids == ("EVID-JS-REQUEST",)


def test_javascript_route_configuration_references_route_with_exact_semantics() -> None:
    api = _api()
    extraction = build_deep_javascript_route_extraction(
        _source_collection(
            _source_item(
                url="https://app.example.test/assets/routes.js",
                body=b'const routes = { status: "/service/status" };',
                content_type="application/javascript",
                evidence_ids=("EVID-JS-CONFIG",),
            )
        )
    )
    assert extraction.candidates[0].semantic_contexts == (
        "route_configuration",
    )

    composition = api.build_application_service_composition(
        javascript_extraction=extraction,
    )

    relation = composition.relations[0]
    support = relation.supports[0]
    assert relation.relation_kind is api.ApplicationServiceRelationKind.REFERENCES_ROUTE
    assert (
        support.source_semantic
        is api.ApplicationServiceSourceSemantic.JAVASCRIPT_ROUTE_CONFIGURATION
    )
    assert (
        support.basis
        is api.ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION
    )
    assert tuple(route.canonical_url for route in composition.routes) == (
        "https://app.example.test/service/status",
    )


def test_html_reference_references_route_with_truthful_source_provenance() -> None:
    api = _api()
    extraction = build_deep_html_route_extraction(
        _source_collection(
            _source_item(
                url="https://app.example.test/docs/index.html",
                body=b'<html><a href="/api/catalog">API</a></html>',
                content_type="text/html",
                evidence_ids=("EVID-HTML-REFERENCE",),
            )
        )
    )

    composition = api.build_application_service_composition(
        html_extraction=extraction,
    )

    relation = composition.relations[0]
    support = relation.supports[0]
    assert relation.relation_kind is api.ApplicationServiceRelationKind.REFERENCES_ROUTE
    assert (
        support.basis
        is api.ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION
    )
    assert (
        support.source_semantic
        is api.ApplicationServiceSourceSemantic.HTML_ROUTE_REFERENCE
    )
    assert (
        support.source_reference.owner_kind
        is api.ApplicationServiceSourceOwnerKind.DEEP_HTML_ROUTE_REFERENCE
    )
    assert support.source_reference.source_id == extraction.routes[0].route_id
    assert support.evidence_ids == ("EVID-HTML-REFERENCE",)
    assert composition.source_sets[0].resource_urls == (
        "https://app.example.test/docs/index.html",
    )


def test_lexical_and_framework_javascript_noise_produces_no_relation() -> None:
    extraction = build_deep_javascript_route_extraction(
        _source_collection(
            _source_item(
                url="https://app.example.test/assets/noise.js",
                body=b"""
                    const descriptiveText = "/api/not-semantic";
                    self.__next_f.push(["/api/framework-state"]);
                """,
                content_type="application/javascript",
            )
        )
    )
    assert extraction.candidates == ()
    api = _api()

    composition = api.build_application_service_composition(
        javascript_extraction=extraction,
    )

    assert composition.origins == ()
    assert composition.routes == ()
    assert composition.source_sets == ()
    assert composition.relations == ()


def test_duplicate_relation_evidence_coalesces_distinct_supports() -> None:
    api = _api()
    first = _redirect_edge(
        evidence_ids=("EVID-REDIRECT-A",),
        artefacts=("first.txt",),
    )
    second = _redirect_edge(
        evidence_ids=("EVID-REDIRECT-B",),
        artefacts=("second.txt",),
    )

    composition = api.build_application_service_composition(
        redirect_edges=(first, first, second),
    )

    assert len(composition.relations) == 1
    relation = composition.relations[0]
    assert len(relation.supports) == 2
    assert {support.evidence_ids for support in relation.supports} == {
        ("EVID-REDIRECT-A",),
        ("EVID-REDIRECT-B",),
    }
    assert {support.artefact_references for support in relation.supports} == {
        ("first.txt",),
        ("second.txt",),
    }


def test_adding_corroborating_support_does_not_change_relation_identity() -> None:
    api = _api()
    first = _redirect_edge(
        evidence_ids=("EVID-REDIRECT-A",),
        artefacts=("first.txt",),
    )
    corroborating = _redirect_edge(
        evidence_ids=("EVID-REDIRECT-B",),
        artefacts=("second.txt",),
    )

    initial = api.build_application_service_composition(
        redirect_edges=(first,),
    )
    corroborated = api.build_application_service_composition(
        redirect_edges=(first, corroborating),
    )

    assert initial.relations[0].relation_id == corroborated.relations[0].relation_id
    assert initial.relations[0].source_entity_id == corroborated.relations[0].source_entity_id
    assert initial.relations[0].target_entity_id == corroborated.relations[0].target_entity_id
    assert len(initial.relations[0].supports) == 1
    assert len(corroborated.relations[0].supports) == 2


def test_reversed_typed_inputs_produce_equal_ordered_composition() -> None:
    api = _api()
    edges = (
        _redirect_edge(
            source="https://app.example.test/first",
            target="https://app.example.test/second",
            location="/second",
            evidence_ids=("EVID-FIRST",),
        ),
        _redirect_edge(
            source="https://app.example.test/third",
            target="https://app.example.test/fourth",
            location="/fourth",
            evidence_ids=("EVID-SECOND",),
        ),
    )
    metadata_items = (
        _metadata_item(
            url="https://app.example.test/sitemap.xml",
            routes=("https://app.example.test/docs",),
            evidence_ids=("EVID-SITEMAP-A",),
        ),
        _metadata_item(
            url="https://app.example.test/secondary-sitemap.xml",
            routes=("https://app.example.test/help",),
            evidence_ids=("EVID-SITEMAP-B",),
        ),
    )

    forward = api.build_application_service_composition(
        redirect_edges=edges,
        metadata_collection=_metadata_collection(*metadata_items),
    )
    reversed_result = api.build_application_service_composition(
        redirect_edges=tuple(reversed(edges)),
        metadata_collection=_metadata_collection(*reversed(metadata_items)),
    )

    assert forward == reversed_result
    assert tuple(item.entity_id for item in forward.origins) == tuple(
        sorted(item.entity_id for item in forward.origins)
    )
    assert tuple(item.entity_id for item in forward.routes) == tuple(
        sorted(item.entity_id for item in forward.routes)
    )
    assert tuple(item.entity_id for item in forward.source_sets) == tuple(
        sorted(item.entity_id for item in forward.source_sets)
    )
    assert tuple(item.relation_id for item in forward.relations) == tuple(
        sorted(item.relation_id for item in forward.relations)
    )
    assert len({item.entity_id for item in forward.routes}) == len(forward.routes)
    assert len({item.relation_id for item in forward.relations}) == len(
        forward.relations
    )


def test_http_origin_identity_preserves_scheme_hostname_and_effective_port() -> None:
    api = _api()
    composition = api.build_application_service_composition(
        redirect_edges=(
            _redirect_edge(
                source="http://APP.example.test:443/plain",
                target="http://app.example.test:443/next",
                location="/next",
                evidence_ids=("EVID-HTTP-443",),
            ),
            _redirect_edge(
                source="https://APP.example.test/secure",
                target="https://app.example.test/next",
                location="/next",
                evidence_ids=("EVID-HTTPS-443",),
            ),
        ),
    )

    app_origins = {
        item.origin
        for item in composition.origins
        if item.origin.hostname == "app.example.test"
    }
    assert app_origins == {
        HttpOrigin("http", "app.example.test", 443),
        HttpOrigin("https", "app.example.test", 443),
    }


def test_route_identity_delegates_to_sitemap_and_html_owners() -> None:
    html_extraction = build_deep_html_route_extraction(
        _source_collection(
            _source_item(
                body=(
                    b'<html><a href="/search?token=secret&state=value">'
                    b"Search</a></html>"
                ),
                content_type="text/html",
            )
        )
    )
    assert html_extraction.routes[0].safe_resolved_url == (
        "https://app.example.test/search?state&token"
    )
    metadata = _metadata_collection(
        _metadata_item(
            routes=("https://app.example.test/account?view=summary",),
        )
    )
    api = _api()

    composition = api.build_application_service_composition(
        metadata_collection=metadata,
        html_extraction=html_extraction,
    )

    assert {route.canonical_url for route in composition.routes} == {
        "https://app.example.test/account?view=summary",
        "https://app.example.test/search?state&token",
    }


def test_relation_support_rejects_missing_concrete_provenance() -> None:
    api = _api()
    reference = api.ApplicationServiceSourceReference(
        owner_kind=api.ApplicationServiceSourceOwnerKind.DEEP_HTML_ROUTE_REFERENCE,
        source_id="DEEP-HTML-ROUTE-0001",
    )

    with pytest.raises(ValueError, match="evidence"):
        api.ApplicationServiceRelationSupport(
            basis=api.ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION,
            source_semantic=api.ApplicationServiceSourceSemantic.HTML_ROUTE_REFERENCE,
            source_reference=reference,
            evidence_ids=(),
        )

    with pytest.raises(ValueError, match="source|id"):
        api.ApplicationServiceSourceReference(
            owner_kind=(
                api.ApplicationServiceSourceOwnerKind.DEEP_HTML_ROUTE_REFERENCE
            ),
            source_id="   ",
        )

    support = api.ApplicationServiceRelationSupport(
        basis=api.ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION,
        source_semantic=api.ApplicationServiceSourceSemantic.HTML_ROUTE_REFERENCE,
        source_reference=reference,
        evidence_ids=(" EVID-B ", "EVID-A", "EVID-B"),
    )
    assert support.evidence_ids == ("EVID-A", "EVID-B")


def test_relation_support_rejects_contradictory_semantic_mappings() -> None:
    api = _api()

    def reference(owner_kind):
        return api.ApplicationServiceSourceReference(
            owner_kind=owner_kind,
            source_id="SOURCE-0001",
        )

    with pytest.raises(ValueError, match="semantic|basis|owner"):
        api.ApplicationServiceRelationSupport(
            basis=api.ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION,
            source_semantic=api.ApplicationServiceSourceSemantic.HTTP_REDIRECT,
            source_reference=reference(
                api.ApplicationServiceSourceOwnerKind.HTTP_ROUTE_RELATIONSHIP_EDGE
            ),
            evidence_ids=("EVID-REDIRECT",),
        )

    with pytest.raises(ValueError, match="semantic|basis|owner"):
        api.ApplicationServiceRelationSupport(
            basis=api.ApplicationServiceSupportBasis.DIRECT_DOCUMENTATION,
            source_semantic=(
                api.ApplicationServiceSourceSemantic.HTML_ROUTE_REFERENCE
            ),
            source_reference=reference(
                api.ApplicationServiceSourceOwnerKind.DEEP_HTML_ROUTE_REFERENCE
            ),
            evidence_ids=("EVID-HTML",),
        )

    with pytest.raises(ValueError, match="semantic|basis|owner"):
        api.ApplicationServiceRelationSupport(
            basis=api.ApplicationServiceSupportBasis.DETERMINISTIC_DERIVATION,
            source_semantic=(
                api.ApplicationServiceSourceSemantic.HTML_ROUTE_REFERENCE
            ),
            source_reference=reference(
                api.ApplicationServiceSourceOwnerKind.DEEP_JAVASCRIPT_ROUTE_CANDIDATE
            ),
            evidence_ids=("EVID-WRONG-OWNER",),
        )


def test_source_owner_kind_and_initial_vocabularies_are_closed() -> None:
    api = _api()

    assert {item.value for item in api.ApplicationServiceSourceOwnerKind} == {
        "http_route_relationship_edge",
        "deep_metadata_collected_item",
        "deep_html_route_reference",
        "deep_javascript_route_candidate",
    }
    assert {item.value for item in api.ApplicationServiceEntityKind} == {
        "http_origin",
        "http_route",
        "source_set",
    }
    assert {item.value for item in api.ApplicationServiceRelationKind} == {
        "redirects_to",
        "declares_route",
        "references_route",
    }
    assert {item.value for item in api.ApplicationServiceSupportBasis} == {
        "direct_observation",
        "direct_documentation",
        "deterministic_derivation",
    }
    assert {item.value for item in api.ApplicationServiceSourceSemantic} == {
        "http_redirect",
        "sitemap_declaration",
        "html_route_reference",
        "javascript_request_call",
        "javascript_route_configuration",
    }
    with pytest.raises((TypeError, ValueError)):
        api.ApplicationServiceSourceReference(
            owner_kind="deep_html_route_reference",
            source_id="DEEP-HTML-ROUTE-0001",
        )


def test_invalid_relation_entity_shape_and_references_fail_closed() -> None:
    api = _api()
    valid = api.build_application_service_composition(
        metadata_collection=_metadata_collection(
            _metadata_item(
                routes=("https://app.example.test/docs",),
            )
        )
    )
    relation = valid.relations[0]

    with pytest.raises(ValueError, match="source set"):
        api.ApplicationServiceComposition(
            origins=valid.origins,
            routes=valid.routes,
            source_sets=valid.source_sets,
            relations=(
                replace(
                    relation,
                    source_entity_id=valid.origins[0].entity_id,
                ),
            ),
        )

    with pytest.raises(ValueError, match="reference"):
        api.ApplicationServiceComposition(
            origins=valid.origins,
            routes=valid.routes,
            source_sets=valid.source_sets,
            relations=(replace(relation, target_entity_id="APP-ROUTE-MISSING"),),
        )

    wrong_origin = next(
        origin
        for origin in valid.origins
        if origin.entity_id != valid.routes[0].origin_id
    ) if len(valid.origins) > 1 else replace(
        valid.origins[0],
        entity_id="APP-ORIGIN-WRONG",
        origin=HttpOrigin("http", "app.example.test", 80),
    )
    with pytest.raises(ValueError, match="origin"):
        api.ApplicationServiceComposition(
            origins=tuple(sorted((*valid.origins, wrong_origin), key=lambda item: item.entity_id)),
            routes=(replace(valid.routes[0], origin_id=wrong_origin.entity_id),),
            source_sets=valid.source_sets,
            relations=valid.relations,
        )


def test_multi_source_extraction_remains_one_truthful_source_set() -> None:
    first_source = "https://app.example.test/first.html"
    second_source = "https://app.example.test/second.html"
    target = "https://app.example.test/shared"
    extraction = build_deep_html_route_extraction(
        _source_collection(
            _source_item(
                url=first_source,
                body=b'<html><a href="/shared">Shared</a></html>',
                content_type="text/html",
                evidence_ids=("EVID-FIRST-SOURCE",),
            ),
            _source_item(
                url=second_source,
                body=b'<html><a href="/shared">Shared</a></html>',
                content_type="text/html",
                evidence_ids=("EVID-SECOND-SOURCE",),
            ),
        )
    )
    assert len(extraction.routes) == 1
    assert extraction.routes[0].source_request_urls == (
        first_source,
        second_source,
    )
    api = _api()

    composition = api.build_application_service_composition(
        html_extraction=extraction,
    )

    assert len(composition.source_sets) == 1
    source_set = composition.source_sets[0]
    assert source_set.kind is api.ApplicationServiceEntityKind.SOURCE_SET
    assert source_set.resource_urls == (first_source, second_source)
    assert len(composition.relations) == 1
    relation = composition.relations[0]
    assert relation.source_entity_id == source_set.entity_id
    assert len(relation.supports) == 1
    assert relation.supports[0].evidence_ids == (
        "EVID-FIRST-SOURCE",
        "EVID-SECOND-SOURCE",
    )
    assert (
        relation.supports[0].source_reference.owner_kind
        is api.ApplicationServiceSourceOwnerKind.DEEP_HTML_ROUTE_REFERENCE
    )
    assert (
        relation.supports[0].source_reference.source_id
        == extraction.routes[0].route_id
    )
    assert tuple(route.canonical_url for route in composition.routes) == (target,)
    assert not any(
        item.resource_urls in {(first_source,), (second_source,)}
        for item in composition.source_sets
    )


def test_composition_is_immutable_and_builder_preserves_typed_inputs() -> None:
    api = _api()
    edge = _redirect_edge()
    original_edge = replace(edge)
    parameters = inspect.signature(
        api.build_application_service_composition
    ).parameters
    assert tuple(parameters) == (
        "redirect_edges",
        "metadata_collection",
        "html_extraction",
        "javascript_extraction",
    )

    composition = api.build_application_service_composition(
        redirect_edges=(edge,),
    )

    with pytest.raises(FrozenInstanceError):
        composition.relations = ()
    with pytest.raises(FrozenInstanceError):
        composition.relations[0].supports = ()
    assert edge == original_edge
