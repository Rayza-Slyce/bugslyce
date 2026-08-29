"""Corrective trust-boundary regression for programme graph materialisation."""

from __future__ import annotations

from dataclasses import replace

import pytest

from bugslyce.core.programme_graph import (
    RELATIONSHIP_CONFIGURED_SEED,
    RELATIONSHIP_DOCUMENTED_SERVICE,
    build_programme_graph,
    build_programme_http_work_items,
    build_programme_relationship_evidence,
)
from bugslyce.core.programme_scope import (
    ACTION_INCLUDE,
    OUTCOME_ALLOWED,
    OUTCOME_UNKNOWN,
    RULE_WILDCARD_SUBDOMAIN,
    build_programme_scope_policy,
    build_programme_scope_rule,
)


def test_http_work_item_planner_rejects_scope_decision_borrowed_from_another_origin(
) -> None:
    policy = build_programme_scope_policy(
        (
            build_programme_scope_rule(
                rule_id="qualified-wildcard",
                action=ACTION_INCLUDE,
                kind=RULE_WILDCARD_SUBDOMAIN,
                value="*.example.test",
                scheme="https",
                port=443,
            ),
        ),
        updated_at="2026-08-29T12:00:00Z",
    )
    graph = build_programme_graph(
        policy,
        relationship_evidence=(
            build_programme_relationship_evidence(
                relationship_type=RELATIONSHIP_CONFIGURED_SEED,
                source_origin=None,
                destination_origin="https://app.example.test/",
                evidence_ids=(),
                provenance_sources=("bugslyce_project.target",),
            ),
            build_programme_relationship_evidence(
                relationship_type=RELATIONSHIP_DOCUMENTED_SERVICE,
                source_origin="https://app.example.test/",
                destination_origin="https://service.other.test/",
                evidence_ids=("EVID-DOCUMENTED-OTHER",),
                provenance_sources=("raw/programme-documentation.html",),
            ),
        ),
    )
    allowed = next(
        node
        for node in graph.nodes
        if node.canonical_origin == "https://app.example.test"
    )
    unknown = next(
        node
        for node in graph.nodes
        if node.canonical_origin == "https://service.other.test"
    )
    forged_unknown = replace(
        unknown,
        scope_decision=allowed.scope_decision,
        materialisation_eligible=True,
    )
    forged_graph = replace(
        graph,
        nodes=tuple(
            forged_unknown if node.node_id == unknown.node_id else node
            for node in graph.nodes
        ),
    )

    assert allowed.scope_decision.outcome == OUTCOME_ALLOWED
    assert unknown.scope_decision.outcome == OUTCOME_UNKNOWN
    assert forged_unknown.canonical_origin == unknown.canonical_origin
    assert forged_unknown.origin == unknown.origin
    assert forged_unknown.node_id == unknown.node_id
    assert forged_unknown.relationship_ids == unknown.relationship_ids
    with pytest.raises(ValueError, match="canonical"):
        build_programme_http_work_items(forged_graph)
