"""WP5A3 target-independent application/service model RED contract."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from hashlib import sha256
import importlib
import inspect

import pytest

from bugslyce.recon.application_service_composition import (
    ApplicationServiceComposition,
    ApplicationServiceRelationKind,
    ApplicationServiceSupportBasis,
    build_application_service_composition,
)
from bugslyce.recon.deep_html_route_extraction import build_deep_html_route_extraction
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
from bugslyce.recon.documentation_assertions import (
    DocumentationAssertionExtractionResult,
    DocumentationAssertionKind,
    build_documentation_assertions,
)
from bugslyce.recon.http_origin import HttpOrigin
from bugslyce.recon.http_route_relationships import HttpRouteRelationshipEdge


def _api():
    return importlib.import_module("bugslyce.recon.application_service_model")


def _source_item(
    body: bytes,
    *,
    url: str = "https://docs.example.test/guide",
    content_type: str = "text/html",
    evidence_ids: tuple[str, ...] = ("EVID-DOC-0001",),
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
        source="recursive_evidence_feedback",
        reason="bounded_second_pass",
        evidence_ids=evidence_ids,
        body=body,
    )


def _source_collection(*items) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=tuple(items), skipped=(), total_considered=len(items),
        total_collected=len(items), total_skipped=0,
    )


def _documentation(*items) -> DocumentationAssertionExtractionResult:
    return build_documentation_assertions(_source_collection(*items))


def _service_item(
    *, path: str = "/v1", url: str = "https://docs.example.test/guide",
    evidence_ids: tuple[str, ...] = ("EVID-SERVICE",), two_supports: bool = False,
):
    second = (
        f"<dl><dt>Service base URL</dt><dd>https://api.example.test{path}</dd></dl>"
        if two_supports else ""
    )
    body = (
        "<html><main><h2>API base URL</h2>"
        f"<pre>https://api.example.test{path}</pre>{second}</main></html>"
    ).encode()
    return _source_item(body, url=url, evidence_ids=evidence_ids)


def _realtime_item():
    return _source_item(
        b"<html><main><h2>WebSocket endpoint</h2>"
        b"<pre>wss://stream.example.test/v1/public</pre></main></html>",
        evidence_ids=("EVID-REALTIME",),
    )


def _redirect(source: str, target: str, evidence_id: str):
    return HttpRouteRelationshipEdge(
        edge_type="redirect", source_url=source, target_url=target,
        evidence_ids=(evidence_id,), raw_references=(target,), status_code=302,
    )


def _observed_composition(*edges) -> ApplicationServiceComposition:
    return build_application_service_composition(redirect_edges=tuple(edges))


def _empty_composition() -> ApplicationServiceComposition:
    return build_application_service_composition()


def _metadata_composition() -> ApplicationServiceComposition:
    item = DeepMetadataCollectedItem(
        url="https://docs.example.test/sitemap.xml", method="GET", status_code=200,
        final_url="https://docs.example.test/sitemap.xml",
        headers=(("content-type", "application/xml"),), body_preview="<urlset/>",
        body_sha256="a" * 64, body_bytes=9, elapsed_seconds=0.125,
        source="metadata_coverage", reason="selected",
        evidence_ids=("EVID-SITEMAP",),
        sitemap_route_references=("https://api.example.test/v1/status",),
    )
    result = DeepMetadataCollectionResult(
        collected=(item,), skipped=(), total_considered=1,
        total_collected=1, total_skipped=0,
    )
    return build_application_service_composition(metadata_collection=result)


def _derived_composition(source_kind: str) -> ApplicationServiceComposition:
    if source_kind == "sitemap":
        return _metadata_composition()
    if source_kind == "html":
        extraction = build_deep_html_route_extraction(
            _source_collection(_source_item(
                b'<html><a href="https://api.example.test/v1/status">status</a></html>',
                content_type="text/html", evidence_ids=("EVID-HTML",),
            ))
        )
        return build_application_service_composition(html_extraction=extraction)
    extraction = build_deep_javascript_route_extraction(
        _source_collection(_source_item(
            b'fetch("https://api.example.test/v1/status");',
            url="https://docs.example.test/app.js",
            content_type="application/javascript", evidence_ids=("EVID-JS",),
        ))
    )
    return build_application_service_composition(javascript_extraction=extraction)


def _model(api, composition=None, documentation=None):
    return api.build_application_service_model(
        application_composition=composition or _empty_composition(),
        documentation_assertions=documentation or _documentation(_service_item()),
    )


def _relation(model, kind):
    return next(item for item in model.relations if item.relation_kind is kind)


def test_documented_service_creates_resource_service_and_direct_documentation_relation():
    api = _api()
    documentation = _documentation(_service_item())
    model = _model(api, documentation=documentation)
    assert len(model.documentation_resources) == 1
    assert len(model.documented_http_services) == 1
    service = model.documented_http_services[0]
    assert service.value.canonical_url == "https://api.example.test/v1"
    assert service.value.origin == HttpOrigin("https", "api.example.test", 443)
    assertion = documentation.assertions[0]
    resource = model.documentation_resources[0]
    assert resource.entity_id == assertion.supports[0].source_reference.source_id
    assert resource.source_reference is assertion.supports[0].source_reference
    relation = _relation(model, api.ApplicationServiceModelRelationKind.DESCRIBES_SERVICE)
    assert relation.basis is api.ApplicationServiceModelSupportBasis.DIRECT_DOCUMENTATION
    assert relation.source.entity_id == resource.entity_id
    assert relation.target.entity_id == service.entity_id
    assert relation.supports[0].assertion_id == assertion.assertion_id
    assert relation.supports[0].assertion_support is assertion.supports[0]


def test_documented_service_alone_creates_no_observed_origin_correspondence():
    api = _api()
    model = _model(api)
    assert not any(r.relation_kind is api.ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN for r in model.relations)


def test_source_side_directly_observed_redirect_origin_creates_correspondence():
    api = _api()
    composition = _observed_composition(_redirect(
        "https://api.example.test/start",
        "https://elsewhere.example.test/login",
        "EVID-OBS-1",
    ))
    model = _model(api, composition=composition)
    relation = _relation(model, api.ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN)
    target_origin = next(o for o in composition.origins if o.origin == HttpOrigin("https", "api.example.test", 443))
    assert relation.target.entity_id == target_origin.entity_id
    assert relation.target.entity_kind is api.ApplicationServiceModelEntityKind.HTTP_ORIGIN


def test_target_only_redirect_destination_does_not_create_observed_origin_correspondence():
    api = _api()
    composition = _observed_composition(_redirect(
        "https://observed.example.test/start",
        "https://api.example.test/login",
        "EVID-OBS-TARGET",
    ))
    model = _model(api, composition=composition)
    assert not any(
        relation.relation_kind
        is api.ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN
        for relation in model.relations
    )


def test_correspondence_preserves_separate_lower_truth_records():
    api = _api()
    composition = _observed_composition(_redirect(
        "https://api.example.test/start",
        "https://elsewhere.example.test/login",
        "EVID-OBS-1",
    ))
    documentation = _documentation(_service_item())
    model = _model(api, composition, documentation)
    relation = _relation(model, api.ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN)
    support = relation.supports[0]
    assert relation.basis is api.ApplicationServiceModelSupportBasis.DETERMINISTIC_DERIVATION
    assert isinstance(support, api.ApplicationServiceObservedOriginCorrespondenceSupport)
    assert support.basis is api.ApplicationServiceModelSupportBasis.DETERMINISTIC_DERIVATION
    assert support.documentation_assertion_id == documentation.assertions[0].assertion_id
    assert support.documentation_support in documentation.assertions[0].supports
    observed = next(r for r in composition.relations if r.relation_id == support.observed_relation_id)
    assert support.observation_support in observed.supports
    assert support.observation_support.basis is ApplicationServiceSupportBasis.DIRECT_OBSERVATION


@pytest.mark.parametrize("source_kind", ("sitemap", "html", "javascript"))
def test_derived_only_origin_does_not_qualify_as_observed(source_kind):
    api = _api()
    model = _model(api, composition=_derived_composition(source_kind))
    assert not any(r.relation_kind is api.ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN for r in model.relations)


def test_documented_service_base_path_is_distinct_from_http_origin():
    api = _api()
    composition = _observed_composition(_redirect(
        "https://api.example.test/start",
        "https://elsewhere.example.test/login",
        "EVID-OBS-SERVICE-ORIGIN",
    ))
    model = _model(api, composition=composition)
    service = model.documented_http_services[0]
    matching_origin = next(
        origin
        for origin in composition.origins
        if origin.origin == HttpOrigin("https", "api.example.test", 443)
    )
    assert service.value.canonical_url == "https://api.example.test/v1"
    assert service.value.origin == matching_origin.origin
    assert service.entity_id != matching_origin.entity_id


def test_two_service_bases_on_one_origin_remain_distinct():
    api = _api()
    docs = _documentation(
        _service_item(path="/v1", url="https://docs.example.test/v1"),
        _service_item(path="/v2", url="https://docs.example.test/v2"),
    )
    model = _model(api, documentation=docs)
    assert {s.value.canonical_url for s in model.documented_http_services} == {
        "https://api.example.test/v1", "https://api.example.test/v2"
    }
    assert len({s.entity_id for s in model.documented_http_services}) == 2
    assert {s.value.origin for s in model.documented_http_services} == {
        HttpOrigin("https", "api.example.test", 443)
    }


def test_documented_realtime_creates_non_executable_documentation_relation():
    api = _api()
    docs = _documentation(_realtime_item())
    model = _model(api, documentation=docs)
    assert len(model.documentation_resources) == 1
    assert len(model.documented_realtime_endpoints) == 1
    endpoint = model.documented_realtime_endpoints[0]
    assert endpoint.value.canonical_url == "wss://stream.example.test/v1/public"
    relation = _relation(model, api.ApplicationServiceModelRelationKind.DOCUMENTS_REALTIME_ENDPOINT)
    assert relation.basis is api.ApplicationServiceModelSupportBasis.DIRECT_DOCUMENTATION
    assert relation.supports[0].assertion_support is docs.assertions[0].supports[0]


def test_realtime_entity_is_not_http_origin_and_has_no_execution_surface():
    api = _api()
    endpoint = _model(api, documentation=_documentation(_realtime_item())).documented_realtime_endpoints[0]
    assert not isinstance(endpoint.value, HttpOrigin)
    assert tuple(f.name for f in fields(endpoint)) == ("entity_id", "value", "kind")
    assert not hasattr(endpoint, "connect")
    assert not hasattr(endpoint, "execute")


def test_unrelated_same_page_assertions_are_preserved_but_unrelated():
    api = _api()
    body = b"""<html><main>
      <h2>HTTP operation</h2><pre>POST /v1/accounts/{accountId}/token</pre>
      <table><tr><th>Header name</th><th>Required</th></tr><tr><td>X-Client-Token</td><td>Yes</td></tr></table>
      <dl><dt>Required authentication scheme</dt><dd>Bearer</dd></dl>
      <table><tr><th>Required OAuth scope</th></tr><tr><td>account:write</td></tr></table>
    </main></html>"""
    docs = _documentation(_source_item(body))
    model = _model(api, documentation=docs)
    assert model.documentation_assertions is docs
    assert {a.kind for a in docs.assertions} == {
        DocumentationAssertionKind.HTTP_OPERATION,
        DocumentationAssertionKind.REQUIRED_HEADER,
        DocumentationAssertionKind.AUTHENTICATION_SCHEME,
        DocumentationAssertionKind.OAUTH_SCOPE,
    }
    assert model.documentation_resources == ()
    assert model.relations == ()


def test_relation_vocabulary_excludes_deferred_semantics():
    api = _api()
    assert {item.value for item in api.ApplicationServiceModelRelationKind} == {
        "describes_service", "documents_realtime_endpoint", "corresponds_to_observed_origin"
    }


def test_documentation_corroboration_does_not_change_service_or_relation_identity():
    api = _api()
    full_docs = _documentation(_service_item(two_supports=True))
    assertion = full_docs.assertions[0]
    single_docs = replace(full_docs, assertions=(replace(assertion, supports=(assertion.supports[0],)),))
    single = _model(api, documentation=single_docs)
    full = _model(api, documentation=full_docs)
    assert single.documented_http_services[0].entity_id == full.documented_http_services[0].entity_id
    one_relation = _relation(single, api.ApplicationServiceModelRelationKind.DESCRIBES_SERVICE)
    full_relation = _relation(full, api.ApplicationServiceModelRelationKind.DESCRIBES_SERVICE)
    assert one_relation.relation_id == full_relation.relation_id
    assert len(one_relation.supports) == 1 and len(full_relation.supports) == 2


def test_observation_corroboration_does_not_change_correspondence_identity():
    api = _api()
    edges = (
        _redirect("https://api.example.test/a", "https://elsewhere.example.test/b", "EVID-OBS-A"),
        _redirect("https://api.example.test/c", "https://another.example.test/d", "EVID-OBS-B"),
    )
    full_composition = _observed_composition(*edges)
    one_composition = _observed_composition(edges[0])
    one = _model(api, composition=one_composition)
    full = _model(api, composition=full_composition)
    first = _relation(one, api.ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN)
    second = _relation(full, api.ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN)
    assert first.relation_id == second.relation_id
    assert len(second.supports) > len(first.supports)


def test_duplicate_supports_coalesce_and_distinct_supports_remain():
    api = _api()
    model = _model(api, documentation=_documentation(_service_item(two_supports=True)))
    relation = _relation(model, api.ApplicationServiceModelRelationKind.DESCRIBES_SERVICE)
    rebuilt = replace(relation, supports=(relation.supports[0], *relation.supports, relation.supports[0]))
    assert rebuilt.supports == relation.supports
    assert len(rebuilt.supports) == 2


def test_reversed_lower_evidence_produces_equal_immutable_model():
    api = _api()
    docs_forward = _documentation(
        _service_item(url="https://docs.example.test/a"), _realtime_item()
    )
    docs_reverse = _documentation(
        _realtime_item(), _service_item(url="https://docs.example.test/a")
    )
    edge_a = _redirect("https://api.example.test/a", "https://api.example.test/b", "EVID-A")
    edge_b = _redirect("https://api.example.test/c", "https://api.example.test/d", "EVID-B")
    forward = _model(api, _observed_composition(edge_a, edge_b), docs_forward)
    reverse = _model(api, _observed_composition(edge_b, edge_a), docs_reverse)
    assert forward == reverse
    assert tuple(r.relation_id for r in forward.relations) == tuple(sorted(r.relation_id for r in forward.relations))
    with pytest.raises(FrozenInstanceError):
        forward.relations = ()


def test_conflicting_source_reference_for_same_source_id_fails_closed():
    api = _api()
    docs = _documentation(_service_item())
    assertion = docs.assertions[0]
    support = assertion.supports[0]
    conflicting_reference = replace(
        support.source_reference, final_url="https://docs.example.test/contradiction"
    )
    conflicting_support = replace(support, source_reference=conflicting_reference)
    contradictory = replace(
        docs, assertions=(replace(assertion, supports=(support, conflicting_support)),)
    )
    with pytest.raises(ValueError, match="source|conflict|reference"):
        _model(api, documentation=contradictory)


@pytest.mark.parametrize(
    "relation_kind,invalid_source_kind,invalid_target_kind",
    (
        ("describes", "http_origin", "documented_http_service"),
        ("realtime", "documentation_resource", "documented_http_service"),
        ("corresponds", "documentation_resource", "http_origin"),
    ),
)
def test_invalid_relation_entity_shape_fails_closed(relation_kind, invalid_source_kind, invalid_target_kind):
    api = _api()
    composition = _observed_composition(_redirect(
        "https://api.example.test/a", "https://api.example.test/b", "EVID-OBS"
    ))
    docs = _documentation(_service_item(), _realtime_item())
    model = _model(api, composition, docs)
    wanted = {
        "describes": api.ApplicationServiceModelRelationKind.DESCRIBES_SERVICE,
        "realtime": api.ApplicationServiceModelRelationKind.DOCUMENTS_REALTIME_ENDPOINT,
        "corresponds": api.ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN,
    }[relation_kind]
    relation = _relation(model, wanted)
    bad_source = replace(relation.source, entity_kind=api.ApplicationServiceModelEntityKind(invalid_source_kind))
    bad_target = replace(relation.target, entity_kind=api.ApplicationServiceModelEntityKind(invalid_target_kind))
    with pytest.raises(ValueError, match="shape|entity|relation"):
        replace(relation, source=bad_source, target=bad_target)


def test_wrong_documentation_assertion_kind_for_relation_support_fails_closed():
    api = _api()
    body = b"<html><main><h2>API base URL</h2><pre>https://api.example.test/v1</pre><h2>HTTP operation</h2><pre>GET /v1/status</pre></main></html>"
    docs = _documentation(_source_item(body))
    model = _model(api, documentation=docs)
    relation = _relation(model, api.ApplicationServiceModelRelationKind.DESCRIBES_SERVICE)
    operation = next(a for a in docs.assertions if a.kind is DocumentationAssertionKind.HTTP_OPERATION)
    tampered_support = replace(relation.supports[0], assertion_id=operation.assertion_id)
    tampered_relation = replace(relation, supports=(tampered_support,))
    with pytest.raises(ValueError, match="assertion|kind|support"):
        replace(model, relations=(tampered_relation,))


def test_derived_support_cannot_construct_observed_origin_correspondence():
    api = _api()
    observed = _observed_composition(_redirect(
        "https://api.example.test/a", "https://api.example.test/b", "EVID-OBS"
    ))
    model = _model(api, observed)
    correspondence = _relation(model, api.ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN)
    derived_relation = _metadata_composition().relations[0]
    with pytest.raises(ValueError, match="observation|direct"):
        replace(
            correspondence.supports[0],
            observed_relation_id=derived_relation.relation_id,
            observation_support=derived_relation.supports[0],
        )


@pytest.mark.parametrize(
    "observed_source",
    ("http://api.example.test/start", "https://api.example.test:8443/start"),
)
def test_nonmatching_scheme_or_effective_port_does_not_correspond(observed_source):
    api = _api()
    composition = _observed_composition(_redirect(
        observed_source, observed_source.rsplit("/", 1)[0] + "/target", "EVID-MISMATCH"
    ))
    model = _model(api, composition)
    assert not any(r.relation_kind is api.ApplicationServiceModelRelationKind.CORRESPONDS_TO_OBSERVED_ORIGIN for r in model.relations)


def test_model_preserves_exact_lower_inputs_and_builder_does_not_mutate():
    api = _api()
    composition = _observed_composition(_redirect(
        "https://api.example.test/a", "https://api.example.test/b", "EVID-OBS"
    ))
    docs = _documentation(_service_item())
    composition_before, docs_before = replace(composition), replace(docs)
    model = _model(api, composition, docs)
    assert model.application_composition is composition
    assert model.documentation_assertions is docs
    assert composition == composition_before and docs == docs_before


def test_public_api_signature_vocabularies_and_boundary_are_closed():
    api = _api()
    assert {x.value for x in api.ApplicationServiceModelEntityKind} == {
        "documentation_resource", "documented_http_service",
        "documented_realtime_endpoint", "http_origin",
    }
    assert {x.value for x in api.ApplicationServiceModelRelationKind} == {
        "describes_service", "documents_realtime_endpoint", "corresponds_to_observed_origin",
    }
    assert {x.value for x in api.ApplicationServiceModelSupportBasis} == {
        "direct_documentation", "deterministic_derivation",
    }
    signature = inspect.signature(api.build_application_service_model)
    assert tuple(signature.parameters) == ("application_composition", "documentation_assertions")
    assert all(p.kind is inspect.Parameter.KEYWORD_ONLY and p.default is inspect.Parameter.empty for p in signature.parameters.values())
    assert tuple(f.name for f in fields(api.ApplicationServiceModel)) == (
        "application_composition", "documentation_assertions", "documentation_resources",
        "documented_http_services", "documented_realtime_endpoints", "relations",
    )
    assert tuple(f.name for f in fields(api.ApplicationServiceDocumentationResource)) == ("entity_id", "source_reference", "kind")
    assert tuple(f.name for f in fields(api.ApplicationServiceDocumentedHttpService)) == ("entity_id", "value", "kind")
    assert tuple(f.name for f in fields(api.ApplicationServiceDocumentedRealtimeEndpoint)) == ("entity_id", "value", "kind")
    assert tuple(f.name for f in fields(api.ApplicationServiceDocumentationRelationSupport)) == ("basis", "assertion_id", "assertion_support")
    assert tuple(f.name for f in fields(api.ApplicationServiceObservedOriginCorrespondenceSupport)) == (
        "basis", "documentation_assertion_id", "documentation_support",
        "observed_relation_id", "observation_support",
    )
