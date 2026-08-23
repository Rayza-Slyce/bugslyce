"""RED contract for normalized source, robots, and route composition."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from inspect import signature

import pytest

from bugslyce.core.models import (
    DiscoveredPath,
    Evidence,
    HTTPArtifact,
    ProjectState,
)
from bugslyce.recon.artefact_analysis import ArtefactSource
from bugslyce.recon.deep_successful_content import SuccessfulDeepContentReview
from bugslyce.recon.http_route_relationships import (
    HttpRouteRelationshipCluster,
    HttpRouteRelationshipEdge,
    build_http_route_relationship_clusters,
)
from bugslyce.recon.robots_analysis import RobotsAnalysis, analyse_robots_txt
from bugslyce.reports.operator_brief import (
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSubjectKind,
)


def _api():
    from bugslyce.reports.operator_brief_web_context import (
        OperatorBriefRouteObservation,
        OperatorBriefRouteRelationship,
        OperatorBriefSourceClueObservation,
        OperatorBriefWebContextComposition,
        OperatorBriefWebContextCompositionInput,
        OperatorBriefWebContextSubject,
        build_operator_brief_route_observation,
        build_operator_brief_route_relationship,
        build_operator_brief_source_clue_observation,
        build_operator_brief_web_context_inputs_from_project_state,
        combine_operator_brief_web_context_inputs,
        compose_operator_brief_web_context,
    )

    return locals()


def _state(
    *,
    artifacts: tuple[HTTPArtifact, ...] = (),
    paths: tuple[DiscoveredPath, ...] = (),
    evidence: tuple[Evidence, ...] = (),
) -> ProjectState:
    return ProjectState(
        project_name="web-context",
        input_dir="/live/project",
        processed_files=[],
        scope_summary="example.test",
        assets=[],
        http_services=[],
        endpoints=[],
        port_services=[],
        http_artifacts=list(artifacts),
        discovered_paths=list(paths),
        recon_summary=None,
        recon_manifest=None,
        evidence=list(evidence),
        warnings=[],
        generated_at="2026-08-22T12:00:00Z",
    )


def _robots(
    *,
    source_id: str = "ROBOTS-SOURCE",
    url: str = "https://example.test/robots.txt",
    path: str = "robots-example.test-443.txt",
    text: str = "User-agent: *\nDisallow: /review-area\n",
    evidence_ids: tuple[str, ...] = ("EVID-ROBOTS",),
) -> RobotsAnalysis:
    return analyse_robots_txt(
        ArtefactSource(
            source_id=source_id,
            source_kind="robots_txt",
            source_label=path,
            url=url,
            path=path,
            port=443,
            service="https",
            text=text,
            evidence_ids=evidence_ids,
        )
    )


def _edge(
    *,
    edge_type: str = "source_reference",
    source_url: str = "https://example.test/source",
    target_url: str = "https://example.test/review-area",
    status_code: int | None = None,
    evidence_ids: tuple[str, ...] = ("EVID-EDGE",),
    artefact_references: tuple[str, ...] = ("source.html",),
) -> HttpRouteRelationshipEdge:
    return HttpRouteRelationshipEdge(
        edge_type=edge_type,
        source_url=source_url,
        target_url=target_url,
        status_code=status_code,
        evidence_ids=evidence_ids,
        artefact_references=artefact_references,
        raw_references=("/review-area",),
    )


def _cluster(*edges: HttpRouteRelationshipEdge) -> HttpRouteRelationshipCluster:
    nodes = tuple(
        sorted(
            {
                endpoint
                for edge in edges
                for endpoint in (edge.source_url, edge.target_url)
            }
        )
    )
    return HttpRouteRelationshipCluster(
        cluster_id="ROUTE-CLUSTER-0001",
        title="Direct retained route relationships",
        anchor_url=nodes[0],
        route_nodes=nodes,
        edges=tuple(edges),
        retained_responses=(),
        evidence_ids=tuple(
            sorted({value for edge in edges for value in edge.evidence_ids})
        ),
        retained_response_review_ids=(),
        artefact_references=tuple(
            sorted(
                {value for edge in edges for value in edge.artefact_references}
            )
        ),
        summary="Direct relationship evidence.",
        manual_review_order=("Inspect retained evidence.",),
    )


def _clue(
    api,
    *,
    source_kind: str = "robots_txt",
    source_id: str = "ROBOTS-SOURCE:2",
    source_endpoint: str = "https://example.test/robots.txt",
    clue_type: str = "disallow",
    value: str = "/review-area",
    resolved_endpoint: str | None = "https://example.test/review-area",
    evidence_ids: tuple[str, ...] = ("EVID-ROBOTS",),
    artefact_references: tuple[str, ...] = (
        "robots-example.test-443.txt",
    ),
):
    return api["build_operator_brief_source_clue_observation"](
        source_kind=source_kind,
        source_id=source_id,
        source_endpoint=source_endpoint,
        clue_type=clue_type,
        value=value,
        resolved_endpoint=resolved_endpoint,
        evidence_ids=evidence_ids,
        artefact_references=artefact_references,
    )


def _route(
    api,
    *,
    source_kind: str = "project_state_discovered_path",
    source_id: str = "DISCOVERED-PATH-SOURCE",
    endpoint: str = "https://example.test/review-area",
    status_codes: tuple[int, ...] = (404,),
    status_unknown: bool = False,
    redirect_locations: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] = ("EVID-PATH",),
    artefact_references: tuple[str, ...] = ("gobuster.txt",),
):
    return api["build_operator_brief_route_observation"](
        source_kind=source_kind,
        source_id=source_id,
        endpoint=endpoint,
        status_codes=status_codes,
        status_unknown=status_unknown,
        redirect_locations=redirect_locations,
        evidence_ids=evidence_ids,
        artefact_references=artefact_references,
    )


def _relationship(
    api,
    *,
    source_kind: str = "http_route_relationship_edge",
    source_id: str = "ROUTE-EDGE-SOURCE",
    relationship_type: str = "source_reference",
    source_endpoint: str = "https://example.test/source",
    target_endpoint: str = "https://example.test/review-area",
    status_code: int | None = None,
    evidence_ids: tuple[str, ...] = ("EVID-EDGE",),
    artefact_references: tuple[str, ...] = ("source.html",),
):
    return api["build_operator_brief_route_relationship"](
        source_kind=source_kind,
        source_id=source_id,
        relationship_type=relationship_type,
        source_endpoint=source_endpoint,
        target_endpoint=target_endpoint,
        status_code=status_code,
        raw_references=("/review-area",),
        evidence_ids=evidence_ids,
        artefact_references=artefact_references,
    )


def _inputs(api, *, clues=(), routes=(), relationships=()):
    return api["OperatorBriefWebContextCompositionInput"](
        clues=tuple(clues),
        routes=tuple(routes),
        relationships=tuple(relationships),
    )


def _compose(api, *, clues=(), routes=(), relationships=()):
    return api["compose_operator_brief_web_context"](
        _inputs(
            api,
            clues=clues,
            routes=routes,
            relationships=relationships,
        )
    )


def _facts(composition, kind: OperatorBriefFactKind):
    return tuple(fact for fact in composition.facts if fact.kind is kind)


# Current-source authority controls remain green before the future module exists.


def test_current_robots_analysis_preserves_direct_directive_authority() -> None:
    analysis = _robots()
    entry = analysis.entries[1]

    assert entry.field_name == "disallow"
    assert entry.raw_value == "/review-area"
    assert entry.url == "https://example.test/robots.txt"
    assert entry.path == "robots-example.test-443.txt"
    assert entry.evidence_ids == ("EVID-ROBOTS",)


def test_current_discovered_path_keeps_request_status_separate() -> None:
    path = DiscoveredPath(
        url="https://example.test/review-area",
        status_code=404,
        content_length=19,
        redirect_location=None,
        source="gobuster.txt",
        evidence_ids=["EVID-PATH"],
        tags=[],
    )

    assert path.url == "https://example.test/review-area"
    assert path.status_code == 404
    assert path.source == "gobuster.txt"


def test_current_relationship_builder_preserves_directional_exact_edge() -> None:
    source = "https://example.test/source"
    target = "https://example.test/review-area"
    state = _state(
        artifacts=(
            HTTPArtifact(
                url=source,
                artifact_type="link",
                value="/review-area",
                source_file="source.html",
                evidence_ids=["EVID-EDGE"],
                tags=[],
            ),
        )
    )
    review = SuccessfulDeepContentReview(
        review_id="DEEP-CONTENT-0001",
        canonical_url=target,
        requested_urls=(target,),
        status_code=200,
        content_type="text/html",
        body_bytes=7,
        body_sha256="a" * 64,
        body_preview="retained",
        evidence_ids=("EVID-EDGE",),
        artefact_references=("deep_source_route_collection.json",),
    )

    clusters = build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(review,),
    )

    assert len(clusters) == 1
    assert clusters[0].edges[0].source_url == source
    assert clusters[0].edges[0].target_url == target
    assert clusters[0].edges[0].edge_type == "source_reference"


def test_current_relationship_builder_rejects_cross_origin_source_edge() -> None:
    state = _state(
        artifacts=(
            HTTPArtifact(
                url="https://first.example.test/source",
                artifact_type="link",
                value="https://second.example.test/review-area",
                source_file="source.html",
                evidence_ids=["EVID-EDGE"],
                tags=[],
            ),
        )
    )
    review = SuccessfulDeepContentReview(
        review_id="DEEP-CONTENT-0001",
        canonical_url="https://second.example.test/review-area",
        requested_urls=("https://second.example.test/review-area",),
        status_code=200,
        content_type="text/html",
        body_bytes=7,
        body_sha256="b" * 64,
        body_preview="retained",
        evidence_ids=("EVID-EDGE",),
        artefact_references=("deep_source_route_collection.json",),
    )

    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(review,),
    ) == ()


def test_current_operator_brief_schema_supports_web_context_semantics() -> None:
    assert OperatorBriefFactKind.SOURCE_ROBOTS_CLUE.value == "source_robots_clue"
    assert OperatorBriefFactKind.HTTP_ROUTE.value == "http_route"
    assert OperatorBriefFactKind.ROUTE_RELATIONSHIP.value == "route_relationship"
    assert OperatorBriefSubjectKind.CONTENT_SURFACE.value == "content_surface"


# Future normalized API and behavioral contract.


def test_web_context_api_is_one_storage_agnostic_normalized_boundary() -> None:
    api = _api()

    assert set(api) >= {
        "OperatorBriefSourceClueObservation",
        "OperatorBriefRouteObservation",
        "OperatorBriefRouteRelationship",
        "OperatorBriefWebContextCompositionInput",
        "OperatorBriefWebContextSubject",
        "OperatorBriefWebContextComposition",
        "build_operator_brief_source_clue_observation",
        "build_operator_brief_route_observation",
        "build_operator_brief_route_relationship",
        "build_operator_brief_web_context_inputs_from_project_state",
        "combine_operator_brief_web_context_inputs",
        "compose_operator_brief_web_context",
    }


def test_project_state_adapter_uses_explicit_current_source_owners() -> None:
    api = _api()
    parameters = signature(
        api["build_operator_brief_web_context_inputs_from_project_state"]
    ).parameters

    assert tuple(parameters) == (
        "project_state",
        "robots_analyses",
        "relationship_clusters",
    )


def test_one_robots_clue_becomes_observed_direct_fact() -> None:
    api = _api()
    clue = _clue(api)
    composition = _compose(api, clues=(clue,))
    fact = _facts(composition, OperatorBriefFactKind.SOURCE_ROBOTS_CLUE)[0]

    assert clue.origin == "https://example.test"
    assert clue.clue_type == "disallow"
    assert clue.value == "/review-area"
    assert fact.semantic_class is OperatorBriefSemanticClass.OBSERVED
    assert fact.role is OperatorBriefFactRole.DIRECT_EVIDENCE
    assert fact.evidence_ids == ("EVID-ROBOTS",)
    assert fact.artefact_references == ("robots-example.test-443.txt",)


def test_same_clue_text_on_different_origins_remains_distinct() -> None:
    api = _api()
    first = _clue(api)
    second = _clue(
        api,
        source_id="OTHER-ROBOTS:2",
        source_endpoint="https://other.example.test/robots.txt",
        resolved_endpoint="https://other.example.test/review-area",
    )
    composition = _compose(api, clues=(first, second))

    assert len(composition.clues) == 2
    assert len({item.observation_id for item in composition.clues}) == 2
    assert len(composition.subjects) == 2


def test_clue_order_is_deterministic() -> None:
    api = _api()
    clues = (
        _clue(api),
        _clue(
            api,
            clue_type="allow",
            value="/public",
            resolved_endpoint="https://example.test/public",
        ),
    )

    assert _compose(api, clues=clues) == _compose(
        api,
        clues=tuple(reversed(clues)),
    )


def test_clue_identity_ignores_provenance_enrichment() -> None:
    api = _api()
    first = _clue(api)
    enriched = _clue(
        api,
        source_id="ROBOTS-SOURCE-COPY:2",
        evidence_ids=("EVID-ROBOTS-COPY",),
        artefact_references=("robots-copy.txt",),
    )

    assert first.observation_id == enriched.observation_id


def test_duplicate_clue_semantics_union_provenance() -> None:
    api = _api()
    combined = api["combine_operator_brief_web_context_inputs"](
        _inputs(api, clues=(_clue(api),)),
        _inputs(
            api,
            clues=(
                _clue(
                    api,
                    source_id="ROBOTS-SOURCE-COPY:2",
                    evidence_ids=("EVID-ROBOTS-COPY",),
                    artefact_references=("robots-copy.txt",),
                ),
            ),
        ),
    )

    assert len(combined.clues) == 1
    assert combined.clues[0].evidence_ids == (
        "EVID-ROBOTS",
        "EVID-ROBOTS-COPY",
    )
    assert combined.clues[0].artefact_references == (
        "robots-copy.txt",
        "robots-example.test-443.txt",
    )


def test_robots_clue_does_not_claim_access_or_vulnerability() -> None:
    api = _api()
    fact = _facts(
        _compose(api, clues=(_clue(api),)),
        OperatorBriefFactKind.SOURCE_ROBOTS_CLUE,
    )[0]
    rendered = f"{fact.label} {fact.summary}".casefold()

    assert "accessible" not in rendered
    assert "vulnerab" not in rendered
    assert "access control" not in rendered


def test_source_extracted_clue_remains_distinct_from_robots_directive() -> None:
    api = _api()
    robots = _clue(api)
    source = _clue(
        api,
        source_kind="retained_source_reference",
        source_id="SOURCE-HTML-LINK",
        source_endpoint="https://example.test/source",
        clue_type="link",
        artefact_references=("source.html",),
    )
    composition = _compose(api, clues=(robots, source))

    assert len(composition.clues) == 2
    assert {item.source_kind for item in composition.clues} == {
        "robots_txt",
        "retained_source_reference",
    }


def test_empty_clue_input_is_empty_and_invalid_clue_fails_closed() -> None:
    api = _api()

    assert not _compose(api).clues
    with pytest.raises(ValueError):
        _clue(api, source_endpoint="")
    with pytest.raises(ValueError):
        _clue(api, value="")


def test_clue_logical_artefact_reference_is_not_pack_rewritten() -> None:
    api = _api()
    clue = _clue(api, artefact_references=("nested/robots.txt",))

    assert clue.artefact_references == ("nested/robots.txt",)
    assert not clue.artefact_references[0].startswith("raw/")


def test_project_adapter_normalizes_local_paths_without_filesystem_reads() -> None:
    api = _api()
    path = DiscoveredPath(
        url="https://example.test/review-area",
        status_code=404,
        content_length=19,
        redirect_location=None,
        source="/live/project/nested/gobuster.txt",
        evidence_ids=["EVID-PATH"],
        tags=[],
    )
    inputs = api["build_operator_brief_web_context_inputs_from_project_state"](
        _state(paths=(path,)),
        robots_analyses=(),
        relationship_clusters=(),
    )

    assert inputs.routes[0].artefact_references == ("nested/gobuster.txt",)


def test_clue_result_is_semantically_self_contained() -> None:
    api = _api()
    composition = _compose(api, clues=(_clue(api),))
    subject = composition.subjects[0]
    lookup = {item.observation_id: item for item in composition.clues}

    observation = lookup[subject.clue_observation_ids[0]]
    assert observation.value == "/review-area"
    assert observation.clue_type == "disallow"


def test_one_route_becomes_observed_direct_http_route_fact() -> None:
    api = _api()
    route = _route(api)
    composition = _compose(api, routes=(route,))
    fact = _facts(composition, OperatorBriefFactKind.HTTP_ROUTE)[0]

    assert route.origin == "https://example.test"
    assert route.endpoint == "https://example.test/review-area"
    assert route.status_codes == (404,)
    assert fact.semantic_class is OperatorBriefSemanticClass.OBSERVED
    assert fact.role is OperatorBriefFactRole.DIRECT_EVIDENCE
    assert fact.route == "https://example.test/review-area"


def test_same_route_path_on_different_origins_remains_distinct() -> None:
    api = _api()
    routes = (
        _route(api),
        _route(
            api,
            source_id="OTHER-PATH",
            endpoint="https://other.example.test/review-area",
        ),
    )
    composition = _compose(api, routes=routes)

    assert len(composition.routes) == 2
    assert len(composition.subjects) == 2


def test_route_order_and_identity_ignore_provenance() -> None:
    api = _api()
    first = _route(api)
    enriched = _route(
        api,
        source_id="PATH-COPY",
        evidence_ids=("EVID-PATH-COPY",),
        artefact_references=("gobuster-copy.txt",),
    )
    other = _route(
        api,
        source_id="PATH-OTHER",
        endpoint="https://example.test/other",
    )

    assert first.observation_id == enriched.observation_id
    assert _compose(api, routes=(first, other)) == _compose(
        api,
        routes=(other, first),
    )


def test_duplicate_route_semantics_preserve_statuses_and_union_provenance() -> None:
    api = _api()
    first = _route(api, status_codes=(404,))
    second = _route(
        api,
        source_id="PATH-SECOND",
        status_codes=(200,),
        evidence_ids=("EVID-PATH-SECOND",),
        artefact_references=("followup.txt",),
    )
    combined = api["combine_operator_brief_web_context_inputs"](
        _inputs(api, routes=(first,)),
        _inputs(api, routes=(second,)),
    )

    assert len(combined.routes) == 1
    assert combined.routes[0].status_codes == (200, 404)
    assert combined.routes[0].evidence_ids == (
        "EVID-PATH",
        "EVID-PATH-SECOND",
    )


@pytest.mark.parametrize(
    ("status_codes", "status_unknown"),
    (((404,), False), ((), True)),
)
def test_unsuccessful_or_unknown_route_is_not_upgraded_to_success(
    status_codes: tuple[int, ...],
    status_unknown: bool,
) -> None:
    api = _api()
    route = _route(
        api,
        status_codes=status_codes,
        status_unknown=status_unknown,
    )
    fact = _facts(
        _compose(api, routes=(route,)),
        OperatorBriefFactKind.HTTP_ROUTE,
    )[0]
    rendered = f"{fact.label} {fact.summary}".casefold()

    assert route.status_codes == status_codes
    assert route.status_unknown is status_unknown
    assert "successful" not in rendered
    assert "accessible" not in rendered


def test_source_clue_is_not_silently_converted_to_route() -> None:
    api = _api()
    composition = _compose(api, clues=(_clue(api),))

    assert not composition.routes
    assert not _facts(composition, OperatorBriefFactKind.HTTP_ROUTE)


def test_route_fact_does_not_duplicate_closed_http_response_authority() -> None:
    api = _api()
    composition = _compose(api, routes=(_route(api, status_codes=(200,)),))

    assert {fact.kind for fact in composition.facts} == {
        OperatorBriefFactKind.HTTP_ROUTE
    }
    assert not _facts(composition, OperatorBriefFactKind.HTTP_RESPONSE)


def test_empty_route_input_is_empty_and_invalid_route_fails_closed() -> None:
    api = _api()

    assert not _compose(api).routes
    with pytest.raises(ValueError):
        _route(api, endpoint="ftp://example.test/review-area")


def test_route_result_is_semantically_self_contained() -> None:
    api = _api()
    composition = _compose(api, routes=(_route(api),))
    subject = composition.subjects[0]
    lookup = {item.observation_id: item for item in composition.routes}

    observation = lookup[subject.route_observation_ids[0]]
    assert observation.status_codes == (404,)
    assert observation.artefact_references == ("gobuster.txt",)


def test_web_context_models_have_no_rank_disposition_or_storage_fields() -> None:
    api = _api()
    models = (
        api["OperatorBriefSourceClueObservation"],
        api["OperatorBriefRouteObservation"],
        api["OperatorBriefRouteRelationship"],
        api["OperatorBriefWebContextSubject"],
        api["OperatorBriefWebContextComposition"],
    )

    for model in models:
        names = {item.name for item in fields(model)}
        assert not names & {
            "rank",
            "signal",
            "score",
            "disposition",
            "why_review",
            "next_review_step",
            "project_root",
            "body",
        }


def test_one_route_relationship_becomes_derived_context_fact() -> None:
    api = _api()
    relationship = _relationship(api)
    composition = _compose(api, relationships=(relationship,))
    fact = _facts(composition, OperatorBriefFactKind.ROUTE_RELATIONSHIP)[0]

    assert fact.semantic_class is OperatorBriefSemanticClass.DERIVED
    assert fact.role is OperatorBriefFactRole.RELATIONSHIP_CONTEXT
    assert fact.endpoints == (
        "https://example.test/source",
        "https://example.test/review-area",
    )


def test_relationship_retains_direction_and_member_endpoints() -> None:
    api = _api()
    relationship = _relationship(api)

    assert relationship.source_endpoint == "https://example.test/source"
    assert relationship.target_endpoint == "https://example.test/review-area"
    assert relationship.relationship_type == "source_reference"


def test_relationship_member_order_is_semantic_but_input_order_is_not() -> None:
    api = _api()
    forward = _relationship(api)
    reverse = _relationship(
        api,
        source_id="REVERSE-EDGE",
        source_endpoint=forward.target_endpoint,
        target_endpoint=forward.source_endpoint,
    )

    assert forward.relationship_id != reverse.relationship_id
    assert _compose(api, relationships=(forward, reverse)) == _compose(
        api,
        relationships=(reverse, forward),
    )


def test_duplicate_relationship_semantics_union_provenance() -> None:
    api = _api()
    first = _relationship(api)
    second = _relationship(
        api,
        source_id="EDGE-COPY",
        evidence_ids=("EVID-EDGE-COPY",),
        artefact_references=("source-copy.html",),
    )
    combined = api["combine_operator_brief_web_context_inputs"](
        _inputs(api, relationships=(first,)),
        _inputs(api, relationships=(second,)),
    )

    assert len(combined.relationships) == 1
    assert combined.relationships[0].evidence_ids == (
        "EVID-EDGE",
        "EVID-EDGE-COPY",
    )


def test_same_path_cross_origin_coincidence_does_not_create_relationship() -> None:
    api = _api()
    composition = _compose(
        api,
        routes=(
            _route(api),
            _route(
                api,
                source_id="OTHER-PATH",
                endpoint="https://other.example.test/review-area",
            ),
        ),
    )

    assert not composition.relationships
    assert not _facts(composition, OperatorBriefFactKind.ROUTE_RELATIONSHIP)


def test_relationship_does_not_merge_route_subjects() -> None:
    api = _api()
    relationship = _relationship(api)
    routes = (
        _route(api, endpoint=relationship.source_endpoint),
        _route(
            api,
            source_id="TARGET-PATH",
            endpoint=relationship.target_endpoint,
        ),
    )
    composition = _compose(
        api,
        routes=routes,
        relationships=(relationship,),
    )

    assert len(composition.subjects) == 2
    assert {subject.endpoint for subject in composition.subjects} == {
        relationship.source_endpoint,
        relationship.target_endpoint,
    }


def test_relationship_result_is_semantically_self_contained() -> None:
    api = _api()
    relationship = _relationship(api)
    composition = _compose(api, relationships=(relationship,))
    lookup = {
        item.relationship_id: item for item in composition.relationships
    }

    assert lookup[relationship.relationship_id].evidence_ids == ("EVID-EDGE",)
    assert lookup[relationship.relationship_id].raw_references == (
        "/review-area",
    )


def test_empty_relationship_input_is_empty() -> None:
    api = _api()
    composition = _compose(api)

    assert not composition.relationships
    assert not _facts(composition, OperatorBriefFactKind.ROUTE_RELATIONSHIP)


def test_project_adapter_preserves_all_three_authority_families() -> None:
    api = _api()
    path = DiscoveredPath(
        url="https://example.test/review-area",
        status_code=404,
        content_length=19,
        redirect_location=None,
        source="gobuster.txt",
        evidence_ids=["EVID-PATH"],
        tags=[],
    )
    inputs = api["build_operator_brief_web_context_inputs_from_project_state"](
        _state(paths=(path,)),
        robots_analyses=(_robots(),),
        relationship_clusters=(_cluster(_edge()),),
    )

    assert len(inputs.clues) == 1
    assert len(inputs.routes) == 1
    assert len(inputs.relationships) == 1


def test_clue_and_observed_route_coexist_without_authority_duplication() -> None:
    api = _api()
    composition = _compose(
        api,
        clues=(_clue(api),),
        routes=(_route(api),),
    )

    assert len(composition.subjects) == 1
    assert len(composition.clues) == 1
    assert len(composition.routes) == 1
    assert {fact.kind for fact in composition.facts} == {
        OperatorBriefFactKind.SOURCE_ROBOTS_CLUE,
        OperatorBriefFactKind.HTTP_ROUTE,
    }


def test_clue_context_does_not_change_route_status_directness() -> None:
    api = _api()
    composition = _compose(
        api,
        clues=(_clue(api),),
        routes=(_route(api, status_codes=(404,)),),
    )
    route = composition.routes[0]
    route_fact = _facts(composition, OperatorBriefFactKind.HTTP_ROUTE)[0]

    assert route.status_codes == (404,)
    assert route_fact.semantic_class is OperatorBriefSemanticClass.OBSERVED
    assert route_fact.role is OperatorBriefFactRole.DIRECT_EVIDENCE


def test_clue_on_origin_a_does_not_attach_to_same_path_on_origin_b() -> None:
    api = _api()
    composition = _compose(
        api,
        clues=(_clue(api),),
        routes=(
            _route(
                api,
                source_id="OTHER-PATH",
                endpoint="https://other.example.test/review-area",
            ),
        ),
    )

    assert len(composition.subjects) == 2
    assert all(
        not (subject.clue_observation_ids and subject.route_observation_ids)
        for subject in composition.subjects
    )


def test_relationship_between_clue_and_route_does_not_upgrade_clue() -> None:
    api = _api()
    clue = _clue(
        api,
        source_endpoint="https://example.test/source",
    )
    route = _route(api)
    relationship = _relationship(api)
    composition = _compose(
        api,
        clues=(clue,),
        routes=(route,),
        relationships=(relationship,),
    )
    clue_fact = _facts(
        composition,
        OperatorBriefFactKind.SOURCE_ROBOTS_CLUE,
    )[0]
    relationship_fact = _facts(
        composition,
        OperatorBriefFactKind.ROUTE_RELATIONSHIP,
    )[0]

    assert clue_fact.semantic_class is OperatorBriefSemanticClass.OBSERVED
    assert relationship_fact.semantic_class is OperatorBriefSemanticClass.DERIVED


def test_shared_cross_family_provenance_is_deduped_at_subject() -> None:
    api = _api()
    clue = _clue(api, evidence_ids=("EVID-SHARED",))
    route = _route(api, evidence_ids=("EVID-SHARED",))
    composition = _compose(api, clues=(clue,), routes=(route,))

    assert composition.subjects[0].evidence_ids == ("EVID-SHARED",)


def test_watcher_shaped_specific_clue_remains_visible_with_route_context() -> None:
    api = _api()
    clue = _clue(
        api,
        clue_type="unknown",
        value="/specific-review-candidate",
        resolved_endpoint="https://example.test/specific-review-candidate",
    )
    route = _route(
        api,
        endpoint="https://example.test/generic",
        status_codes=(),
        status_unknown=True,
    )
    composition = _compose(api, clues=(clue,), routes=(route,))
    clue_fact = _facts(
        composition,
        OperatorBriefFactKind.SOURCE_ROBOTS_CLUE,
    )[0]

    assert composition.clues[0].value == "/specific-review-candidate"
    assert "/specific-review-candidate" in clue_fact.summary
    assert len(composition.subjects) == 2


def test_non_file_discovered_path_source_label_is_not_an_artefact() -> None:
    api = _api()
    path = DiscoveredPath(
        url="https://example.test/review-area",
        status_code=404,
        content_length=19,
        redirect_location=None,
        source="gobuster",
        evidence_ids=["EVID-PATH"],
        tags=[],
    )

    inputs = api["build_operator_brief_web_context_inputs_from_project_state"](
        _state(paths=(path,)),
        robots_analyses=(),
        relationship_clusters=(),
    )

    assert len(inputs.routes) == 1
    assert inputs.routes[0].status_codes == (404,)
    assert inputs.routes[0].evidence_ids == ("EVID-PATH",)
    assert "gobuster" not in inputs.routes[0].artefact_references


def test_non_file_source_label_does_not_reach_fact_or_subject_artefacts() -> None:
    api = _api()
    path = DiscoveredPath(
        url="https://example.test/review-area",
        status_code=404,
        content_length=19,
        redirect_location=None,
        source="gobuster",
        evidence_ids=["EVID-PATH"],
        tags=[],
    )
    inputs = api["build_operator_brief_web_context_inputs_from_project_state"](
        _state(paths=(path,)),
        robots_analyses=(),
        relationship_clusters=(),
    )
    composition = api["compose_operator_brief_web_context"](inputs)
    route_fact = _facts(composition, OperatorBriefFactKind.HTTP_ROUTE)[0]

    assert composition.routes[0].evidence_ids == ("EVID-PATH",)
    assert composition.subjects[0].evidence_ids == ("EVID-PATH",)
    propagated = {
        owner
        for owner, references in (
            ("route", composition.routes[0].artefact_references),
            ("fact", route_fact.artefact_references),
            ("subject", composition.subjects[0].artefact_references),
        )
        if "gobuster" in references
    }
    assert propagated == set()


def test_route_source_reference_is_stable_across_logical_path_spelling() -> None:
    api = _api()
    url = "https://example.test/review-area"

    def adapted(source_file: str):
        path = DiscoveredPath(
            url=url,
            status_code=404,
            content_length=19,
            redirect_location=None,
            source=source_file,
            evidence_ids=["EVID-PATH"],
            tags=[],
        )
        evidence = Evidence(
            id="EVID-PATH",
            source_file=source_file,
            evidence_type="discovered_path",
            value=url,
            context={"status_code": 404, "content_length": 19},
        )
        return api["build_operator_brief_web_context_inputs_from_project_state"](
            _state(paths=(path,), evidence=(evidence,)),
            robots_analyses=(),
            relationship_clusters=(),
        ).routes[0]

    first = adapted("nested/gobuster.txt")
    second = adapted("/live/project/nested/gobuster.txt")

    assert first.observation_id == second.observation_id
    assert first.artefact_references == second.artefact_references == (
        "nested/gobuster.txt",
    )
    assert first.source_references == second.source_references


def test_unowned_file_like_discovered_path_source_is_not_an_artefact() -> None:
    api = _api()
    path = DiscoveredPath(
        url="https://example.test/review-area",
        status_code=404,
        content_length=19,
        redirect_location=None,
        source="nested/gobuster.txt",
        evidence_ids=["EVID-PATH"],
        tags=[],
    )

    inputs = api["build_operator_brief_web_context_inputs_from_project_state"](
        _state(paths=(path,)),
        robots_analyses=(),
        relationship_clusters=(),
    )

    assert inputs.routes[0].evidence_ids == ("EVID-PATH",)
    assert inputs.routes[0].artefact_references == ()


def test_source_clue_reference_is_stable_across_logical_path_spelling() -> None:
    api = _api()

    def adapted(source_file: str):
        artefact = HTTPArtifact(
            url="https://example.test/source",
            artifact_type="link",
            value="/review-area",
            source_file=source_file,
            evidence_ids=["EVID-SOURCE"],
            tags=[],
        )
        return api["build_operator_brief_web_context_inputs_from_project_state"](
            _state(artifacts=(artefact,)),
            robots_analyses=(),
            relationship_clusters=(),
        ).clues[0]

    first = adapted("nested/source.html")
    second = adapted("/live/project/nested/source.html")

    assert first.observation_id == second.observation_id
    assert first.artefact_references == second.artefact_references == (
        "nested/source.html",
    )
    assert first.source_references == second.source_references


def _atomic_route_provenance(composition) -> set[tuple[object, ...]]:
    records: set[tuple[object, ...]] = set()
    visited: set[int] = set()

    def visit(value) -> None:
        if isinstance(value, (tuple, list)):
            for item in value:
                visit(item)
            return
        if not is_dataclass(value) or id(value) in visited:
            return
        visited.add(id(value))
        names = {item.name for item in fields(value)}
        required = {
            "status_codes",
            "status_unknown",
            "evidence_ids",
            "artefact_references",
        }
        if required <= names:
            statuses = tuple(value.status_codes)
            unknown = value.status_unknown
            if (len(statuses) == 1 and not unknown) or (not statuses and unknown):
                records.add(
                    (
                        statuses,
                        unknown,
                        tuple(value.evidence_ids),
                        tuple(value.artefact_references),
                    )
                )
        for item in fields(value):
            visit(getattr(value, item.name))

    visit(composition)
    return records


def test_differing_route_statuses_retain_atomic_provenance() -> None:
    api = _api()
    first = _route(
        api,
        source_id="PATH-404",
        status_codes=(404,),
        evidence_ids=("EVID-404",),
        artefact_references=("gobuster.txt",),
    )
    second = _route(
        api,
        source_id="PATH-200",
        status_codes=(200,),
        evidence_ids=("EVID-200",),
        artefact_references=("followup.txt",),
    )

    composition = _compose(api, routes=(first, second))
    associations = _atomic_route_provenance(composition)

    assert len(composition.routes) == 1
    assert composition.routes[0].status_codes == (200, 404)
    assert ((404,), False, ("EVID-404",), ("gobuster.txt",)) in associations
    assert ((200,), False, ("EVID-200",), ("followup.txt",)) in associations


def test_known_and_unknown_route_statuses_retain_atomic_provenance() -> None:
    api = _api()
    known = _route(
        api,
        source_id="PATH-KNOWN",
        status_codes=(404,),
        status_unknown=False,
        evidence_ids=("EVID-KNOWN",),
        artefact_references=("known.txt",),
    )
    unknown = _route(
        api,
        source_id="PATH-UNKNOWN",
        status_codes=(),
        status_unknown=True,
        evidence_ids=("EVID-UNKNOWN",),
        artefact_references=("unknown.txt",),
    )

    composition = _compose(api, routes=(known, unknown))
    associations = _atomic_route_provenance(composition)

    assert len(composition.routes) == 1
    assert composition.routes[0].status_codes == (404,)
    assert composition.routes[0].status_unknown is True
    assert ((404,), False, ("EVID-KNOWN",), ("known.txt",)) in associations
    assert ((), True, ("EVID-UNKNOWN",), ("unknown.txt",)) in associations


def test_same_route_status_duplicate_remains_mergeable() -> None:
    api = _api()
    first = _route(
        api,
        source_id="PATH-404-A",
        status_codes=(404,),
        evidence_ids=("EVID-404-A",),
        artefact_references=("gobuster-a.txt",),
    )
    second = _route(
        api,
        source_id="PATH-404-B",
        status_codes=(404,),
        evidence_ids=("EVID-404-B",),
        artefact_references=("gobuster-b.txt",),
    )

    composition = _compose(api, routes=(first, second))

    assert len(composition.routes) == 1
    assert composition.routes[0].status_codes == (404,)
    assert composition.routes[0].evidence_ids == (
        "EVID-404-A",
        "EVID-404-B",
    )
    assert composition.routes[0].artefact_references == (
        "gobuster-a.txt",
        "gobuster-b.txt",
    )
