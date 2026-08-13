"""Focused production contracts for derived route reasoning composition."""

from __future__ import annotations

from types import SimpleNamespace

from dataclasses import replace
from hashlib import sha256
import json

import pytest

from bugslyce.core.models import (
    Asset,
    DiscoveredPath,
    Endpoint,
    Evidence,
    HTTPArtifact,
    ProjectState,
)
from bugslyce.recon.deep_http_fingerprint_summary import (
    build_deep_http_fingerprint_summary,
)
from bugslyce.recon.deep_metadata_collector import DeepMetadataCollectionResult
from bugslyce.recon.deep_redirect_auth_flow_review import (
    build_deep_redirect_auth_flow_review,
)
from bugslyce.recon.deep_response_similarity_review import (
    build_deep_response_similarity_review,
)
from bugslyce.recon.deep_source_route_collection_export import (
    deep_source_route_collection_result_to_dict,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.deep_successful_content import (
    SuccessfulDeepContentReview,
    build_successful_deep_content_reviews,
)
from bugslyce.recon.http_route_relationships import (
    build_http_route_relationship_clusters,
)
from bugslyce.recon.reasoning_relationships import (
    MAPPING_AMBIGUOUS,
    MAPPING_MAPPED,
    MAPPING_UNMAPPED,
    build_route_reasoning_review,
    map_relationship_nodes,
)
from bugslyce.recon.route_provenance import canonical_route_url
from bugslyce.reports.html import build_html_report_model, render_html_report
from bugslyce.reports.markdown import (
    export_project_state_json,
    render_markdown_report,
)
from bugslyce.reports.operator_summary import (
    build_deep_operator_summary_leads,
    build_operator_summary,
)
from bugslyce.triage.candidates import generate_candidates


TARGET = "http://example.test/admin/console"
PARENT = "http://example.test/"


def _state(
    tmp_path,
    *,
    name: str,
    artifacts=(),
    endpoints=(),
    paths=(),
    evidence=(),
) -> ProjectState:
    root = tmp_path / name
    root.mkdir()
    return ProjectState(
        project_name=name,
        input_dir=str(root),
        processed_files=[],
        scope_summary="Synthetic offline fixture.",
        assets=[Asset("example.test", True, ["fixture"], ["EVID-ASSET"], [])],
        http_services=[],
        endpoints=list(endpoints),
        port_services=[],
        http_artifacts=list(artifacts),
        discovered_paths=list(paths),
        recon_summary=None,
        recon_manifest=None,
        evidence=list(evidence),
        warnings=[],
        generated_at="2026-08-13T00:00:00Z",
        engagement_context="authorised-lab",
    )


def _artifact(url, kind, value, source, evidence_id):
    return HTTPArtifact(url, kind, value, source, [evidence_id], [])


def _collected(url, body, evidence_ids):
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=(("Content-Type", "text/html"),),
        body_preview=body.decode(),
        body_sha256=sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="controlled offline fixture",
        evidence_ids=evidence_ids,
        body=body,
    )


def _source_result(*items):
    return DeepSourceRouteCollectionResult(tuple(items), (), len(items), len(items), 0)


def _deep_models(state, source_result):
    if source_result is None:
        return (), None, (), ()
    fingerprints = build_deep_http_fingerprint_summary(
        DeepMetadataCollectionResult((), (), 0, 0, 0),
        source_result,
    )
    similarity = build_deep_response_similarity_review(
        fingerprints,
        build_deep_redirect_auth_flow_review(fingerprints),
    )
    successful = build_successful_deep_content_reviews(source_result)
    clusters = build_http_route_relationship_clusters(
        state,
        source_collection=source_result,
        successful_reviews=successful,
    )
    deep_leads = build_deep_operator_summary_leads(
        (),
        successful,
        http_fingerprint_summary=fingerprints,
        response_similarity_review=similarity,
    )
    return successful, similarity, clusters, deep_leads


def _arm(tmp_path, name):
    link_evidence = Evidence("EVID-LINK", "parent.html", "link", TARGET, {"url": PARENT})
    response_evidence = Evidence(
        "EVID-RESP", "headers-admin.txt", "http_headers", TARGET, {"status_code": 200}
    )
    header_evidence = Evidence(
        "EVID-HEAD", "headers-admin.txt", "http_headers", TARGET, {"status_code": 200}
    )
    link = _artifact(PARENT, "link", "/admin/console", "parent.html", "EVID-LINK")
    title = _artifact(
        TARGET, "page_title", "Application Console", "body-fetch-admin.html", "EVID-RESP"
    )
    path = DiscoveredPath(TARGET, 200, 96, None, "headers-admin.txt", ["EVID-RESP"], [])
    body = b"<html><head><title>Application Console</title></head><body>Distinct console.</body></html>"
    source_result = None
    if name == "A":
        state = _state(
            tmp_path,
            name=name,
            artifacts=(link,),
            endpoints=(Endpoint(TARGET, "example.test", "/admin/console", [], ["EVID-LINK"], []),),
            evidence=(link_evidence,),
        )
    elif name == "B":
        source_result = _source_result(_collected(TARGET, body, ("EVID-RESP",)))
        state = _state(
            tmp_path,
            name=name,
            artifacts=(title,),
            endpoints=(Endpoint(TARGET, "example.test", "/admin/console", [], ["EVID-RESP"], []),),
            paths=(path,),
            evidence=(response_evidence,),
        )
    elif name == "C":
        source_result = _source_result(_collected(TARGET, body, ("EVID-LINK", "EVID-RESP")))
        state = _state(
            tmp_path,
            name=name,
            artifacts=(link, title),
            endpoints=(Endpoint(TARGET, "example.test", "/admin/console", [], ["EVID-LINK", "EVID-RESP"], []),),
            paths=(path,),
            evidence=(link_evidence, response_evidence),
        )
    elif name == "D":
        repeated = b"<html><head><title>Application Shell</title></head><body>Shell.</body></html>"
        source_result = _source_result(
            _collected(TARGET, repeated, ("EVID-LINK", "EVID-RESP")),
            _collected("http://example.test/missing-control", repeated, ("EVID-GENERIC",)),
        )
        state = _state(
            tmp_path,
            name=name,
            artifacts=(link, _artifact(TARGET, "page_title", "Application Shell", "body-fetch-admin.html", "EVID-RESP")),
            endpoints=(Endpoint(TARGET, "example.test", "/admin/console", [], ["EVID-LINK", "EVID-RESP"], []),),
            paths=(path,),
            evidence=(link_evidence, response_evidence),
        )
    elif name == "E":
        source_result = _source_result(_collected(TARGET, body, ("EVID-HEAD",)))
        state = _state(
            tmp_path,
            name=name,
            artifacts=(_artifact(TARGET, "page_title", "Application Console", "body-fetch-admin.html", "EVID-HEAD"),),
            endpoints=(Endpoint(TARGET, "example.test", "/admin/console", [], ["EVID-HEAD"], []),),
            paths=(DiscoveredPath(TARGET, 200, 96, None, "headers-admin.txt", ["EVID-HEAD"], []),),
            evidence=(header_evidence,),
        )
    else:
        raise AssertionError(name)
    successful, similarity, clusters, deep_leads = _deep_models(state, source_result)
    reasoning = build_route_reasoning_review(
        state,
        successful_reviews=successful,
        relationship_clusters=clusters,
        response_similarity_review=similarity,
    )
    context = reasoning.by_page_key()[canonical_route_url(TARGET)]
    summary = build_operator_summary(
        state,
        generate_candidates(state),
        additional_leads=deep_leads,
        response_similarity_review=similarity,
        route_reasoning_review=reasoning,
    )
    page_lead = next(
        (lead for lead in summary.ranked_leads if lead.lead_type == "fetched_application_page"),
        None,
    )
    return state, source_result, successful, similarity, clusters, reasoning, context, page_lead


@pytest.mark.parametrize(
    ("page_input", "nodes", "expected"),
    (
        (TARGET, (TARGET,), MAPPING_MAPPED),
        ("http://example.test:80/admin/console", (TARGET,), MAPPING_MAPPED),
        ("http://example.test:8080/admin/console", ("http://example.test:8080/admin/console",), MAPPING_MAPPED),
        (TARGET + "/", (TARGET + "/",), MAPPING_MAPPED),
        (TARGET + "?view=one", (TARGET + "?view=one",), MAPPING_MAPPED),
        (TARGET, (TARGET + "?view=one", TARGET + "?view=two"), MAPPING_AMBIGUOUS),
        ("mailto:operator@example.test", ("mailto:operator@example.test",), MAPPING_UNMAPPED),
        ("http://[broken/admin", ("http://[broken/admin",), MAPPING_UNMAPPED),
    ),
)
def test_route_relationship_mapping_is_explicit_and_fail_closed(
    page_input, nodes, expected
) -> None:
    page_key = canonical_route_url(page_input)

    forward = map_relationship_nodes(page_key, nodes)
    reverse = map_relationship_nodes(page_key, tuple(reversed(nodes)))

    assert forward == reverse
    assert forward.status == expected
    if expected == MAPPING_AMBIGUOUS:
        assert forward.relationship_node_keys == tuple(sorted(nodes))


@pytest.mark.parametrize(
    ("name", "response", "independent", "weakening", "distinct", "page"),
    (
        ("A", False, False, False, False, False),
        ("B", True, False, False, False, True),
        ("C", True, True, False, True, True),
        ("D", True, True, True, False, True),
        ("E", True, False, False, False, True),
    ),
)
def test_route_reasoning_arms_are_composed_without_inference_leaks(
    tmp_path, name, response, independent, weakening, distinct, page
) -> None:
    *_unused, context, page_lead = _arm(tmp_path, name)

    assert context.response_observed is response
    assert context.independent_confirmation is independent
    assert context.weakening_family is weakening
    assert context.distinct_response_corroboration_allowed is distinct
    assert (page_lead is not None) is page
    if name == "A":
        assert context.independent_reference_evidence_ids == ("EVID-LINK",)
    if name == "E":
        assert context.request_evidence_ids == ("EVID-HEAD",)
        assert context.source_references == ()


def test_corroboration_changes_explanation_and_provenance_not_score(tmp_path) -> None:
    *_, b_context, b_lead = _arm(tmp_path, "B")
    *_, c_context, c_lead = _arm(tmp_path, "C")

    assert b_lead.score == c_lead.score == 82
    assert b_lead.lead_type == c_lead.lead_type == "fetched_application_page"
    assert "independently references" not in b_lead.why
    assert "independently references the same route" in c_lead.why
    assert b_lead.evidence_ids == ["EVID-RESP"]
    assert c_lead.evidence_ids == ["EVID-LINK", "EVID-RESP"]
    assert c_context.corroborating_evidence_ids == ("EVID-LINK",)


def test_weakening_preserves_source_provenance_and_existing_page_policy(tmp_path) -> None:
    *_, context, lead = _arm(tmp_path, "D")

    assert lead.score == 52
    assert lead.signal == "response-family context"
    assert "independently references the same route" in lead.why
    assert "repeated-response family" in lead.why
    assert "standalone application evidence" in lead.why
    assert set(lead.evidence_ids) == {"EVID-LINK", "EVID-RESP"}
    assert context.independent_confirmation
    assert not context.distinct_response_corroboration_allowed


def test_query_variant_family_does_not_weaken_query_free_corroborated_page(
    tmp_path,
) -> None:
    state, _source, successful, _similarity, clusters, *_ = _arm(tmp_path, "C")
    similarity = SimpleNamespace(
        groups=(
            SimpleNamespace(
                group_id="DEEP-SIM-GRP-QUERY-SIBLINGS",
                category="candidate_default_template_group",
                requested_urls=(
                    TARGET + "?view=one",
                    TARGET + "?view=two",
                ),
                evidence_ids=("EVID-QUERY-ONE", "EVID-QUERY-TWO"),
            ),
        )
    )

    reasoning = build_route_reasoning_review(
        state,
        successful_reviews=successful,
        relationship_clusters=clusters,
        response_similarity_review=similarity,
    )
    context = reasoning.by_page_key()[canonical_route_url(TARGET)]
    lead = next(
        lead
        for lead in build_operator_summary(
            state,
            generate_candidates(state),
            response_similarity_review=similarity,
            route_reasoning_review=reasoning,
        ).ranked_leads
        if lead.lead_type == "fetched_application_page"
    )

    assert context.independent_confirmation
    assert not context.weakening_family
    assert context.distinct_response_corroboration_allowed
    assert lead.score == 82
    assert lead.signal == "medium"
    assert "independently references the same route" in lead.why
    assert "does not establish distinct application behaviour" not in lead.why


def test_unrelated_cluster_evidence_does_not_leak_into_page_lead(tmp_path) -> None:
    state, source_result, successful, similarity, clusters, *_ = _arm(tmp_path, "C")
    unrelated = replace(
        clusters[0],
        cluster_id="ROUTE-CLUSTER-UNRELATED",
        evidence_ids=("EVID-UNRELATED",),
        retained_response_review_ids=(),
        edges=tuple(replace(edge, target_url="http://example.test/elsewhere", evidence_ids=("EVID-UNRELATED",)) for edge in clusters[0].edges),
    )
    reasoning = build_route_reasoning_review(
        state,
        successful_reviews=successful,
        relationship_clusters=(*clusters, unrelated),
        response_similarity_review=similarity,
    )
    lead = next(
        lead
        for lead in build_operator_summary(
            state,
            generate_candidates(state),
            response_similarity_review=similarity,
            route_reasoning_review=reasoning,
        ).ranked_leads
        if lead.lead_type == "fetched_application_page"
    )
    assert "EVID-UNRELATED" not in lead.evidence_ids


def test_reversed_inputs_produce_identical_contexts_and_ids(tmp_path) -> None:
    state, _source, successful, similarity, clusters, reasoning, *_ = _arm(tmp_path, "D")
    reversed_state = replace(
        state,
        endpoints=list(reversed(state.endpoints)),
        discovered_paths=list(reversed(state.discovered_paths)),
        evidence=list(reversed(state.evidence)),
    )
    reversed_similarity = replace(similarity, groups=tuple(reversed(similarity.groups)))

    reversed_reasoning = build_route_reasoning_review(
        reversed_state,
        successful_reviews=tuple(reversed(successful)),
        relationship_clusters=tuple(reversed(clusters)),
        response_similarity_review=reversed_similarity,
    )

    assert reasoning == reversed_reasoning


def test_route_reasoning_does_not_change_canonical_membership_order_or_scores(
    tmp_path,
) -> None:
    corroborated = TARGET
    response_only = "http://example.test/admin/status"
    source = _source_result(
        _collected(
            corroborated,
            b"<html><head><title>Console</title></head><body>Console.</body></html>",
            ("EVID-LINK", "EVID-C"),
        ),
        _collected(
            response_only,
            b"<html><head><title>Status</title></head><body>Status.</body></html>",
            ("EVID-B",),
        ),
    )
    state = _state(
        tmp_path,
        name="ordering-freeze",
        artifacts=(
            _artifact(PARENT, "link", "/admin/console", "parent.html", "EVID-LINK"),
            _artifact(corroborated, "page_title", "Console", "body-fetch-console.html", "EVID-C"),
            _artifact(response_only, "page_title", "Status", "body-fetch-status.html", "EVID-B"),
        ),
        endpoints=(
            Endpoint(corroborated, "example.test", "/admin/console", [], ["EVID-LINK", "EVID-C"], []),
            Endpoint(response_only, "example.test", "/admin/status", [], ["EVID-B"], []),
        ),
        paths=(
            DiscoveredPath(corroborated, 200, 10, None, "headers.txt", ["EVID-C"], []),
            DiscoveredPath(response_only, 200, 10, None, "headers.txt", ["EVID-B"], []),
        ),
        evidence=(
            Evidence("EVID-LINK", "parent.html", "link", corroborated, {"url": PARENT}),
            Evidence("EVID-C", "headers.txt", "http_headers", corroborated, {"status_code": 200}),
            Evidence("EVID-B", "headers.txt", "http_headers", response_only, {"status_code": 200}),
        ),
    )
    successful, similarity, clusters, _deep_leads = _deep_models(state, source)
    reasoning = build_route_reasoning_review(
        state,
        successful_reviews=successful,
        relationship_clusters=clusters,
        response_similarity_review=similarity,
    )
    baseline = build_operator_summary(
        state,
        generate_candidates(state),
        response_similarity_review=similarity,
    )
    composed = build_operator_summary(
        state,
        generate_candidates(state),
        response_similarity_review=similarity,
        route_reasoning_review=reasoning,
    )

    def frozen_policy(summary):
        return [
            (
                lead.lead_id,
                lead.rank,
                lead.score,
                lead.lead_type,
                lead.title,
                tuple(lead.endpoints),
                lead.signal,
                lead.next_action,
            )
            for lead in summary.ranked_leads
        ]

    assert frozen_policy(composed) == frozen_policy(baseline)
    assert [lead.score for lead in composed.ranked_leads if lead.lead_type == "fetched_application_page"] == [82, 82]
    corroborated_lead = next(lead for lead in composed.ranked_leads if lead.endpoints == [corroborated])
    assert "independently references the same route" in corroborated_lead.why


def test_offline_html_reconstruction_builds_same_route_reasoning(tmp_path) -> None:
    state, source_result, successful, similarity, clusters, reasoning, *_ = _arm(tmp_path, "C")
    pack = tmp_path / "offline-pack"
    pack.mkdir()
    (pack / "project_state.json").write_text(
        export_project_state_json(state, generate_candidates(state)), encoding="utf-8"
    )
    (pack / "deep_source_route_collection.json").write_text(
        json.dumps(deep_source_route_collection_result_to_dict(source_result)),
        encoding="utf-8",
    )

    model = build_html_report_model(pack)
    reconstructed = build_route_reasoning_review(
        model.project_state,
        successful_reviews=model.successful_content,
        relationship_clusters=model.relationship_clusters,
        response_similarity_review=model.similarity_review,
    )

    assert reconstructed == reasoning
    lead = next(
        lead
        for lead in model.operator_summary.ranked_leads
        if lead.lead_type == "fetched_application_page"
    )
    assert "independently references the same route" in lead.why
    assert set(lead.evidence_ids) == {"EVID-LINK", "EVID-RESP"}
    markdown = render_markdown_report(
        model.project_state,
        list(model.candidates),
        operator_summary=model.operator_summary,
    )
    html = render_html_report(model)
    for expected in (
        "independently references the same route",
        "EVID-LINK",
        "EVID-RESP",
    ):
        assert expected in markdown
        assert expected in html


def test_indexed_builder_handles_five_thousand_routes_deterministically(tmp_path) -> None:
    count = 5_000
    evidence = []
    endpoints = []
    paths = []
    reviews = []
    for index in range(count):
        url = f"http://example.test/item/{index:05d}"
        request_id = f"EVID-REQ-{index:05d}"
        reference_id = f"EVID-REF-{index:05d}"
        evidence.extend(
            (
                Evidence(request_id, "headers.txt", "http_headers", url, {"status_code": 200}),
                Evidence(reference_id, "source.html", "link", url, {"url": PARENT}),
            )
        )
        endpoints.append(Endpoint(url, "example.test", f"/item/{index:05d}", [], [request_id, reference_id], []))
        paths.append(DiscoveredPath(url, 200, 10, None, "headers.txt", [request_id], []))
        reviews.append(
            SuccessfulDeepContentReview(
                review_id=f"DEEP-{index:05d}",
                canonical_url=url,
                requested_urls=(url,),
                status_code=200,
                content_type="text/html",
                body_bytes=10,
                body_sha256=f"{index:064x}"[-64:],
                body_preview="preview",
                evidence_ids=(request_id,),
                artefact_references=("deep_source_route_collection.json",),
            )
        )
    state = _state(
        tmp_path,
        name="scale",
        endpoints=endpoints,
        paths=paths,
        evidence=evidence,
    )

    forward = build_route_reasoning_review(state, successful_reviews=reviews)
    reverse = build_route_reasoning_review(
        replace(
            state,
            endpoints=list(reversed(endpoints)),
            discovered_paths=list(reversed(paths)),
            evidence=list(reversed(evidence)),
        ),
        successful_reviews=tuple(reversed(reviews)),
    )

    assert len(forward.contexts) == count
    assert forward == reverse
