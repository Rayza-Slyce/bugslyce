"""Contracts for immutable report-only investigation-context assembly."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from bugslyce.core.models import Candidate, Evidence
from bugslyce.recon.deep_initial_retained_javascript_route_extraction import (
    DeepInitialRetainedJavaScriptRouteCandidate,
    DeepInitialRetainedJavaScriptRouteSourceObservation,
)
from bugslyce.recon.deep_parameter_inventory import (
    DeepParameterInventoryItem,
    DeepParameterInventoryObservation,
)
from bugslyce.recon.deep_post_followup_javascript_route_extraction import (
    DeepPostFollowupJavaScriptRouteSourceObservation,
)
from bugslyce.recon.deep_successful_content import SuccessfulDeepContentReview
from bugslyce.recon.http_route_relationships import (
    HttpRouteRelationshipCluster,
    HttpRouteRelationshipEdge,
)
from bugslyce.recon.interpretation import ReviewLead
from bugslyce.recon.reasoning_relationships import (
    MAPPING_AMBIGUOUS,
    MAPPING_MAPPED,
    RouteReasoningContext,
    RouteReasoningReview,
    RouteRelationshipMapping,
    RouteSourceReference,
    RouteWeakeningGroup,
)
from bugslyce.reports.investigation_context import (
    DERIVED,
    OBSERVED,
    RELATED,
    InvestigationContextSources,
    ReportReferenceTarget,
    build_context_for_route,
    build_primary_investigation_contexts,
    build_report_navigation_references,
)
from bugslyce.reports.operator_summary import OperatorSummaryLead
from bugslyce.triage.workflow_leads import WorkflowLead


ROUTE = "https://example.test/service/status"
SEARCH_ALPHA = "https://example.test/search?tenant=alpha"
SEARCH_BETA = "https://example.test/search?tenant=beta"


def _lead(
    lead_id: str,
    rank: int,
    *,
    route: str = "",
    evidence_ids: tuple[str, ...] = (),
) -> OperatorSummaryLead:
    return OperatorSummaryLead(
        title=f"Review {lead_id}",
        why="Existing deterministic evidence warrants review.",
        endpoints=[route] if route else [],
        evidence_ids=list(evidence_ids),
        next_action="Review retained evidence offline.",
        signal="direct retained evidence",
        score=90 - rank,
        lead_type="controlled_review",
        lead_id=lead_id,
        rank=rank,
    )


def _reasoning() -> RouteReasoningReview:
    return RouteReasoningReview(
        contexts=(
            RouteReasoningContext(
                context_id="ROUTE-CONTEXT-EXACT",
                mapping=RouteRelationshipMapping(
                    page_key=ROUTE,
                    relationship_node_keys=(ROUTE,),
                    status=MAPPING_MAPPED,
                    reason="One relationship node maps to the canonical page key.",
                ),
                request_evidence_ids=("EVID-REQUEST",),
                independent_reference_evidence_ids=("EVID-SOURCE",),
                retained_response_review_ids=("DEEP-CONTENT-0001",),
                retained_response_evidence_ids=("EVID-RESPONSE",),
                source_references=(
                    RouteSourceReference(
                        cluster_id="ROUTE-CLUSTER-0001",
                        source_url="https://example.test/loader",
                        target_url=ROUTE,
                        evidence_ids=("EVID-SOURCE",),
                        artefact_references=("deep_source_route_collection.json",),
                    ),
                ),
                weakening_groups=(
                    RouteWeakeningGroup(
                        group_id="DEEP-SIMILARITY-0001",
                        category="repeated_generic_content",
                        evidence_ids=("EVID-WEAKENING",),
                        policy_relevant=True,
                    ),
                ),
            ),
        )
    )


def _sources() -> InvestigationContextSources:
    return InvestigationContextSources(
        evidence=(
            Evidence("EVID-ANCHOR", "source.html", "link", ROUTE, {}),
            Evidence("EVID-UNRELATED", "source.html", "text", "nearby", {}),
        ),
        route_reasoning=_reasoning(),
        successful_content=(
            SuccessfulDeepContentReview(
                review_id="DEEP-CONTENT-0001",
                canonical_url=ROUTE,
                requested_urls=(ROUTE,),
                status_code=200,
                content_type="application/json",
                body_bytes=2,
                body_sha256="a" * 64,
                body_preview="{}",
                evidence_ids=("EVID-RESPONSE",),
                artefact_references=("deep_source_route_collection.json",),
            ),
        ),
        route_relationships=(
            HttpRouteRelationshipCluster(
                cluster_id="ROUTE-CLUSTER-REDIRECT",
                title="Controlled redirect",
                anchor_url="https://example.test/login",
                route_nodes=("https://example.test/login", ROUTE),
                edges=(
                    HttpRouteRelationshipEdge(
                        edge_type="redirect",
                        source_url="https://example.test/login",
                        target_url=ROUTE,
                        evidence_ids=("EVID-REDIRECT",),
                        status_code=302,
                    ),
                ),
                retained_responses=(),
                evidence_ids=("EVID-REDIRECT",),
                retained_response_review_ids=(),
                artefact_references=(),
                summary="One represented redirect.",
                manual_review_order=(),
            ),
        ),
        forms=(
            SimpleNamespace(
                form_id="DEEP-FORM-0001",
                safe_resolved_action_url=ROUTE,
                evidence_ids=("EVID-FORM",),
                source_ids=("SOURCE-FORM",),
                safe_document_urls=("https://example.test/form.html",),
                methods=("post",),
            ),
        ),
        parameters=(
            DeepParameterInventoryItem(
                parameter_id="DEEP-PARAM-0001",
                observations=(
                    DeepParameterInventoryObservation(
                        name="tenant",
                        context="javascript_route_query",
                        occurrence_count=1,
                        safe_route_url=ROUTE,
                        source_kind="javascript_route",
                        source_id="SOURCE-PARAM",
                        safe_source_urls=("https://example.test/app.js",),
                        evidence_ids=("EVID-PARAM",),
                    ),
                ),
                interpretation="Existing parameter observation.",
            ),
        ),
        workflow_leads=(
            WorkflowLead(
                title="Account workflow",
                priority="medium",
                category="account_workflow",
                summary="Existing grouped workflow.",
                why_it_matters="Review only.",
                suggested_manual_action="Review retained evidence.",
                representative_urls=(ROUTE,),
                covered_urls=(ROUTE,),
                evidence_ids=("EVID-WORKFLOW",),
                signal="direct evidence",
            ),
        ),
    )


def _initial_route(*observations) -> DeepInitialRetainedJavaScriptRouteCandidate:
    return DeepInitialRetainedJavaScriptRouteCandidate(
        candidate_id="DEEP-JS-INITIAL-ROUTE-0001",
        safe_candidate="/service/status",
        safe_resolved_url=ROUTE,
        path="/service/status",
        query_parameter_names=(),
        source_observations=tuple(observations),
        occurrence_count=sum(item.occurrence_count for item in observations),
        interpretation="Static route candidate from retained initial HTML.",
    )


def _observation(source_id: str, url: str, digest: str = "b" * 64):
    return DeepInitialRetainedJavaScriptRouteSourceObservation(
        source_role="initial_retained_html",
        source_id=source_id,
        manifest_file=f"raw/{source_id}.html",
        safe_document_url=url,
        source_body_sha256=digest,
        evidence_ids=(f"EVID-{source_id}",),
        source_selection_reasons=("manifest_retained_initial_html",),
        script_types=("inline",),
        candidate_forms=("root_relative",),
        resolution_contexts=(url,),
        occurrence_count=1,
    )


def test_primary_contexts_preserve_canonical_authority_and_exact_relationships() -> None:
    leads = (
        _lead("LEAD-B", 1, route=ROUTE, evidence_ids=("EVID-ANCHOR",)),
        _lead("LEAD-A", 2),
    )
    candidates = (Candidate("CAND-1", "test", "Test", "low", "Review.", [], [], [], [], None),)
    reviews = (
        ReviewLead(
            "REVIEW-1", "test", "test", "low", "Review", "Review.",
            "SOURCE-1", "fixture", None, None, None, None, None, None, None,
            "value", None, (), (), ("Review.",), ("EVID-ANCHOR",),
        ),
    )

    assembly = build_primary_investigation_contexts(leads, _sources())

    assert len(assembly.primary_contexts) == len(leads)
    assert [item.anchor_id for item in assembly.primary_contexts] == [
        lead.lead_id for lead in leads
    ]
    assert assembly.primary_contexts[1].context_items == ()
    kinds = {item.context_kind for item in assembly.primary_contexts[0].context_items}
    assert kinds == {
        "direct_response",
        "evidence",
        "form_action",
        "redirect_relationship",
        "response_family",
        "route_parameter",
        "route_reasoning",
        "route_source_reference",
        "workflow",
    }
    assert {item.relationship_kind for item in assembly.primary_contexts[0].context_items} == {
        OBSERVED,
        DERIVED,
        RELATED,
    }
    assert "EVID-UNRELATED" not in assembly.primary_contexts[0].evidence_ids
    assert assembly.primary_contexts[0].evidence_ids.count("EVID-RESPONSE") == 1
    assert tuple(candidates) == candidates
    assert tuple(reviews) == reviews


def test_unrelated_page_and_lexical_similarity_do_not_attach() -> None:
    sources = _sources()
    unrelated = replace(
        sources,
        forms=(
            SimpleNamespace(
                form_id="DEEP-FORM-OTHER",
                safe_resolved_action_url="https://example.test/service/status-like",
                evidence_ids=("EVID-OTHER",),
                source_ids=("SOURCE-OTHER",),
                safe_document_urls=("https://example.test/other.html",),
                methods=("get",),
            ),
        ),
        parameters=(),
        workflow_leads=(),
    )
    context = build_primary_investigation_contexts(
        (_lead("LEAD-EXACT", 1, route=ROUTE),),
        unrelated,
    ).primary_contexts[0]

    assert "DEEP-FORM-OTHER" not in {item.target_id for item in context.context_items}
    assert "EVID-UNRELATED" not in context.evidence_ids
    assert "EVID-OTHER" not in context.evidence_ids


def test_explicit_o4d_route_context_preserves_source_independence_without_promotion() -> None:
    first = _observation("SOURCE-A", "https://example.test/index.html")
    duplicate = _observation("SOURCE-A", "https://example.test/index.html")
    independent = _observation(
        "SOURCE-B",
        "https://example.test/other.html",
        digest=first.source_body_sha256,
    )
    route = _initial_route(first, duplicate, independent)
    assembly = build_primary_investigation_contexts((_lead("LEAD-ONLY", 1),), _sources())

    context = build_context_for_route(route, _sources())

    typed_sources = [
        item for item in context.context_items if item.context_kind == "typed_route_source"
    ]
    assert context.anchor_id == route.candidate_id
    assert len(typed_sources) == 2
    assert {item.source_ids for item in typed_sources} == {
        ("SOURCE-A",),
        ("SOURCE-B",),
    }
    assert all(
        item.body_sha256s == (first.source_body_sha256,)
        for item in typed_sources
    )
    assert [item.anchor_id for item in assembly.primary_contexts] == ["LEAD-ONLY"]
    assert route.candidate_id not in [
        item.anchor_id for item in assembly.primary_contexts
    ]


def test_equal_body_at_independent_source_urls_remains_distinct() -> None:
    digest = "c" * 64
    route = _initial_route(
        _observation("SOURCE-A", "https://one.example.test/index.html", digest),
        _observation("SOURCE-B", "https://two.example.test/index.html", digest),
    )

    context = build_context_for_route(route)

    source_items = [
        item for item in context.context_items if item.context_kind == "typed_route_source"
    ]
    assert len(source_items) == 2
    assert {item.source_ids for item in source_items} == {
        ("SOURCE-A",),
        ("SOURCE-B",),
    }


def test_navigation_and_reverse_references_are_permutation_stable() -> None:
    leads = (
        _lead("LEAD-ONE", 1, route=ROUTE, evidence_ids=("EVID-ANCHOR",)),
        _lead("LEAD-TWO", 2, route=ROUTE, evidence_ids=("EVID-ANCHOR",)),
    )
    forward = build_primary_investigation_contexts(leads, _sources())
    reversed_sources = replace(
        _sources(),
        evidence=tuple(reversed(_sources().evidence)),
        successful_content=tuple(reversed(_sources().successful_content)),
        route_relationships=tuple(reversed(_sources().route_relationships)),
        forms=tuple(reversed(_sources().forms)),
        parameters=tuple(reversed(_sources().parameters)),
        workflow_leads=tuple(reversed(_sources().workflow_leads)),
    )
    backward = build_primary_investigation_contexts(leads, reversed_sources)

    assert backward == forward
    evidence_backlink = next(
        item for item in forward.evidence_backlinks if item.target_identity == "EVID-ANCHOR"
    )
    assert tuple(ref.target_id for ref in evidence_backlink.primary_anchor_references) == (
        "LEAD-ONE",
        "LEAD-TWO",
    )
    assert any(item.target_identity == ROUTE for item in forward.route_backlinks)


def test_navigation_collision_expands_every_colliding_member(monkeypatch) -> None:
    import bugslyce.reports.investigation_context as module

    digests = {
        ("A B",): "1" * 16 + "a" * 48,
        ("a-b",): "1" * 16 + "b" * 48,
    }
    monkeypatch.setattr(module, "_identity_digest", lambda target: digests[target.identity_parts])

    references = build_report_navigation_references(
        (
            ReportReferenceTarget("route", "A B", ("A B",)),
            ReportReferenceTarget("route", "a-b", ("a-b",)),
        )
    )

    assert len({item.anchor_token for item in references}) == 2
    assert all(len(item.anchor_token.rsplit("-", 1)[-1]) == 64 for item in references)
    safe_characters = set("abcdefghijklmnopqrstuvwxyz0123456789-._")
    assert all(set(item.anchor_token) <= safe_characters for item in references)


def test_missing_evidence_target_fails_closed_and_empty_evidence_is_truthful() -> None:
    context = build_primary_investigation_contexts(
        (_lead("LEAD-MISSING", 1, evidence_ids=("EVID-NOT-AVAILABLE",)),)
    ).primary_contexts[0]

    assert context.context_items == ()
    assert context.evidence_ids == ()
    assert context.navigation_references == (context.anchor_reference,)


def test_high_cardinality_assembly_is_deterministic_and_complete() -> None:
    count = 300
    evidence = tuple(
        Evidence(f"EVID-{index:04d}", f"source-{index}.txt", "fixture", str(index), {})
        for index in range(count)
    )
    leads = tuple(
        _lead(f"LEAD-{index:04d}", index + 1, evidence_ids=(f"EVID-{index:04d}",))
        for index in range(count)
    )

    forward = build_primary_investigation_contexts(
        leads,
        InvestigationContextSources(evidence=evidence),
    )
    backward = build_primary_investigation_contexts(
        leads,
        InvestigationContextSources(evidence=tuple(reversed(evidence))),
    )

    assert forward == backward
    assert len(forward.primary_contexts) == count
    assert len(forward.evidence_backlinks) == count
    assert all(len(context.context_items) == 1 for context in forward.primary_contexts)


def _query_reasoning(route: str) -> RouteReasoningReview:
    return RouteReasoningReview(
        contexts=(
            RouteReasoningContext(
                context_id="ROUTE-CONTEXT-QUERY",
                mapping=RouteRelationshipMapping(
                    page_key="https://example.test/search",
                    relationship_node_keys=(route,),
                    status=MAPPING_MAPPED,
                    reason="One exact query-bearing relationship node is represented.",
                ),
                request_evidence_ids=(),
                independent_reference_evidence_ids=("EVID-QUERY-SOURCE",),
                retained_response_review_ids=(),
                retained_response_evidence_ids=(),
                source_references=(
                    RouteSourceReference(
                        cluster_id="ROUTE-CLUSTER-QUERY",
                        source_url="https://example.test/loader",
                        target_url=route,
                        evidence_ids=("EVID-QUERY-SOURCE",),
                        artefact_references=("deep_source_route_collection.json",),
                    ),
                ),
                weakening_groups=(
                    RouteWeakeningGroup(
                        group_id="DEEP-SIMILARITY-QUERY",
                        category="repeated_generic_content",
                        evidence_ids=("EVID-QUERY-WEAKENING",),
                        policy_relevant=True,
                    ),
                ),
            ),
        )
    )


def test_query_bearing_route_reasoning_does_not_overjoin_by_page_key() -> None:
    context = build_primary_investigation_contexts(
        (_lead("LEAD-ALPHA", 1, route=SEARCH_ALPHA),),
        InvestigationContextSources(route_reasoning=_query_reasoning(SEARCH_BETA)),
    ).primary_contexts[0]

    assert context.context_items == ()


def test_query_bearing_route_reasoning_attaches_for_exact_existing_node() -> None:
    context = build_primary_investigation_contexts(
        (_lead("LEAD-ALPHA", 1, route=SEARCH_ALPHA),),
        InvestigationContextSources(route_reasoning=_query_reasoning(SEARCH_ALPHA)),
    ).primary_contexts[0]

    assert {item.context_kind for item in context.context_items} == {
        "response_family",
        "route_reasoning",
        "route_source_reference",
    }
    assert all(
        item.route_url in {"https://example.test/search", SEARCH_ALPHA}
        for item in context.context_items
    )


def test_ambiguous_query_bearing_route_reasoning_fails_closed() -> None:
    reasoning = _query_reasoning(SEARCH_ALPHA)
    ambiguous = replace(
        reasoning.contexts[0],
        mapping=replace(
            reasoning.contexts[0].mapping,
            relationship_node_keys=(SEARCH_ALPHA, SEARCH_BETA),
            status=MAPPING_AMBIGUOUS,
        ),
    )

    context = build_primary_investigation_contexts(
        (_lead("LEAD-ALPHA", 1, route=SEARCH_ALPHA),),
        InvestigationContextSources(route_reasoning=RouteReasoningReview((ambiguous,))),
    ).primary_contexts[0]

    assert context.context_items == ()


def test_stable_parameter_navigation_is_one_target_across_exact_route_contexts() -> None:
    parameter = DeepParameterInventoryItem(
        parameter_id="DEEP-PARAM-0001",
        observations=(
            DeepParameterInventoryObservation(
                name="tenant",
                context="javascript_route_query",
                occurrence_count=1,
                safe_route_url=SEARCH_ALPHA,
                source_kind="javascript_route",
                source_id="SOURCE-PARAM",
                safe_source_urls=("https://example.test/app.js",),
                evidence_ids=("EVID-PARAM-ALPHA",),
            ),
            DeepParameterInventoryObservation(
                name="tenant",
                context="javascript_route_query",
                occurrence_count=1,
                safe_route_url=SEARCH_BETA,
                source_kind="javascript_route",
                source_id="SOURCE-PARAM",
                safe_source_urls=("https://example.test/app.js",),
                evidence_ids=("EVID-PARAM-BETA",),
            ),
        ),
        interpretation="Existing parameter observations.",
    )
    lead = OperatorSummaryLead(
        title="Two exact tenant routes",
        why="Existing routes refer to the same parameter object.",
        endpoints=[SEARCH_ALPHA, SEARCH_BETA],
        evidence_ids=[],
        next_action="Review existing parameter provenance.",
        signal="direct evidence",
        score=90,
        lead_type="controlled_review",
        lead_id="LEAD-PARAMETER",
        rank=1,
    )

    forward = build_primary_investigation_contexts(
        (lead,),
        InvestigationContextSources(parameters=(parameter,)),
    ).primary_contexts[0]
    backward = build_primary_investigation_contexts(
        (lead,),
        InvestigationContextSources(parameters=(parameter,)),
    ).primary_contexts[0]
    parameter_items = [
        item for item in forward.context_items if item.context_kind == "route_parameter"
    ]
    parameter_refs = [
        reference
        for reference in forward.navigation_references
        if reference.target_kind == "deep_parameter"
    ]

    assert len(parameter_items) == 2
    assert {item.route_url for item in parameter_items} == {SEARCH_ALPHA, SEARCH_BETA}
    assert len(parameter_refs) == 1
    assert parameter_refs[0].target_id == "DEEP-PARAM-0001"
    assert forward == backward


def _post_parameter_item() -> DeepParameterInventoryItem:
    alpha_source = DeepPostFollowupJavaScriptRouteSourceObservation(
        shallow_request_id="DEEP-SHALLOW-REQ-ALPHA",
        upstream_route_candidate_ids=("DEEP-JS-ROUTE-ALPHA",),
        safe_requested_url="https://example.test/js/alpha.js",
        safe_final_url="https://example.test/assets/alpha-v2.js",
        source_body_sha256="a" * 64,
        evidence_ids=("EVID-PARAM-ALPHA",),
        source_model_kinds=("javascript_route",),
        source_selection_reasons=("javascript_content_type",),
        script_types=("classic",),
        candidate_forms=("root_relative",),
        resolution_contexts=("javascript_response_url",),
        occurrence_count=1,
    )
    beta_source = DeepPostFollowupJavaScriptRouteSourceObservation(
        shallow_request_id="DEEP-SHALLOW-REQ-BETA",
        upstream_route_candidate_ids=("DEEP-JS-ROUTE-BETA",),
        safe_requested_url="https://example.test/js/beta.js",
        safe_final_url="https://example.test/assets/beta-v2.js",
        source_body_sha256="b" * 64,
        evidence_ids=("EVID-PARAM-BETA",),
        source_model_kinds=("javascript_route",),
        source_selection_reasons=("javascript_content_type",),
        script_types=("classic",),
        candidate_forms=("root_relative",),
        resolution_contexts=("javascript_response_url",),
        occurrence_count=1,
    )
    return DeepParameterInventoryItem(
        parameter_id="DEEP-PARAM-0001",
        observations=(
            DeepParameterInventoryObservation(
                name="tenant",
                context="post_followup_javascript_route_query",
                occurrence_count=1,
                safe_route_url=SEARCH_ALPHA,
                source_kind="post_followup_javascript_route",
                post_followup_candidate_id="DEEP-JS-POST-ROUTE-ALPHA",
                post_followup_source_observation=alpha_source,
            ),
            DeepParameterInventoryObservation(
                name="tenant",
                context="post_followup_javascript_route_query",
                occurrence_count=1,
                safe_route_url=SEARCH_BETA,
                source_kind="post_followup_javascript_route",
                post_followup_candidate_id="DEEP-JS-POST-ROUTE-BETA",
                post_followup_source_observation=beta_source,
            ),
        ),
        interpretation="Existing parameter observations only.",
    )


def _parameter_assembly(route: str):
    return build_primary_investigation_contexts(
        (_lead("LEAD-PARAMETER", 1, route=route),),
        InvestigationContextSources(parameters=(_post_parameter_item(),)),
    )


def test_route_specific_parameter_context_preserves_relational_post_provenance() -> None:
    alpha_assembly = _parameter_assembly(SEARCH_ALPHA)
    beta_assembly = _parameter_assembly(SEARCH_BETA)
    alpha = alpha_assembly.primary_contexts[0]
    beta = beta_assembly.primary_contexts[0]
    both_lead = _lead("LEAD-PARAMETER-BOTH", 1, route=SEARCH_ALPHA)
    both_lead = replace(both_lead, endpoints=[SEARCH_ALPHA, SEARCH_BETA])
    both = build_primary_investigation_contexts(
        (both_lead,),
        InvestigationContextSources(parameters=(_post_parameter_item(),)),
    )

    alpha_item = next(item for item in alpha.context_items if item.context_kind == "route_parameter")
    beta_item = next(item for item in beta.context_items if item.context_kind == "route_parameter")

    assert alpha_item.evidence_ids == ("EVID-PARAM-ALPHA",)
    assert alpha_item.source_ids == ("DEEP-JS-POST-ROUTE-ALPHA",)
    assert alpha_item.source_urls == (
        "https://example.test/assets/alpha-v2.js",
        "https://example.test/js/alpha.js",
    )
    assert alpha_item.body_sha256s == ("a" * 64,)
    assert beta_item.evidence_ids == ("EVID-PARAM-BETA",)
    assert beta_item.source_ids == ("DEEP-JS-POST-ROUTE-BETA",)
    assert beta_item.source_urls == (
        "https://example.test/assets/beta-v2.js",
        "https://example.test/js/beta.js",
    )
    assert beta_item.body_sha256s == ("b" * 64,)
    assert {item.target_identity for item in alpha_assembly.evidence_backlinks} == {
        "EVID-PARAM-ALPHA",
    }
    assert {item.target_identity for item in beta_assembly.evidence_backlinks} == {
        "EVID-PARAM-BETA",
    }
    assert both.primary_contexts[0].anchor_id == "LEAD-PARAMETER-BOTH"
    both_items = [
        item
        for item in both.primary_contexts[0].context_items
        if item.context_kind == "route_parameter"
    ]
    assert {item.route_url for item in both_items} == {SEARCH_ALPHA, SEARCH_BETA}
    assert len(
        [
            reference
            for reference in both.primary_contexts[0].navigation_references
            if reference.target_kind == "deep_parameter"
        ]
    ) == 1
