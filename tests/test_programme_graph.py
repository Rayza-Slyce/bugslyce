"""WP3B RED contracts for offline programme graph and authorised fanout."""

from __future__ import annotations

import importlib

from bugslyce.core.programme_scope import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    OUTCOME_ALLOWED,
    OUTCOME_BLOCKED,
    OUTCOME_UNKNOWN,
    RULE_EXACT_HOSTNAME,
    RULE_WILDCARD_SUBDOMAIN,
    build_programme_scope_policy,
    build_programme_scope_rule,
)


FIXED_TIME = "2026-08-29T09:00:00Z"


def _programme_graph_module():
    return importlib.import_module("bugslyce.core.programme_graph")


def _policy(*, excluded_hosts: tuple[str, ...] = ()):
    rules = [
        build_programme_scope_rule(
            rule_id="include-qualified-wildcard",
            action=ACTION_INCLUDE,
            kind=RULE_WILDCARD_SUBDOMAIN,
            value="*.example.test",
            scheme="https",
            port=443,
        )
    ]
    rules.extend(
        build_programme_scope_rule(
            rule_id=f"exclude-{index}",
            action=ACTION_EXCLUDE,
            kind=RULE_EXACT_HOSTNAME,
            value=hostname,
            scheme="https",
            port=443,
        )
        for index, hostname in enumerate(excluded_hosts, start=1)
    )
    return build_programme_scope_policy(tuple(rules), updated_at=FIXED_TIME)


def _seed(module, destination: str):
    return module.build_programme_relationship_evidence(
        relationship_type=module.RELATIONSHIP_CONFIGURED_SEED,
        source_origin=None,
        destination_origin=destination,
        evidence_ids=(),
        provenance_sources=("bugslyce_project.target",),
    )


def _relationship(
    module,
    relationship_type: str,
    source: str,
    destination: str,
    *,
    evidence_id: str,
    provenance_source: str,
):
    return module.build_programme_relationship_evidence(
        relationship_type=relationship_type,
        source_origin=source,
        destination_origin=destination,
        evidence_ids=(evidence_id,),
        provenance_sources=(provenance_source,),
    )


def _node(graph, canonical_origin: str):
    return next(
        node for node in graph.nodes if node.canonical_origin == canonical_origin
    )


def test_authorised_related_origin_materialises_exact_programme_child() -> None:
    module = _programme_graph_module()
    policy = _policy()
    policy_before = policy.to_dict()
    redirect = _relationship(
        module,
        module.RELATIONSHIP_OBSERVED_REDIRECT,
        "https://app.example.test/",
        "https://child.example.test/",
        evidence_id="EVID-REDIRECT-CHILD",
        provenance_source="raw/root-headers.txt",
    )

    graph = module.build_programme_graph(
        policy,
        relationship_evidence=(
            _seed(module, "https://app.example.test/"),
            redirect,
        ),
    )
    child = _node(graph, "https://child.example.test")
    child_relationship = next(
        item
        for item in graph.relationships
        if item.relationship_type == module.RELATIONSHIP_OBSERVED_REDIRECT
    )
    work_item = next(
        item
        for item in module.build_programme_http_work_items(graph)
        if item.canonical_origin == "https://child.example.test"
    )

    assert child.origin.scheme == "https"
    assert child.origin.hostname == "child.example.test"
    assert child.origin.effective_port == 443
    assert child.scope_decision.outcome == OUTCOME_ALLOWED
    assert child.scope_decision.matched_inclusion_rule_ids == (
        "include-qualified-wildcard",
    )
    assert child.materialisation_eligible is True
    assert child_relationship.destination_scope_decision.outcome == OUTCOME_ALLOWED
    assert child_relationship.destination_materialisation_eligible is True
    assert child_relationship.evidence_ids == ("EVID-REDIRECT-CHILD",)
    assert work_item.node_id == child.node_id
    assert work_item.inclusion_rule_ids == ("include-qualified-wildcard",)
    assert work_item.configured_seed is False
    assert work_item.dynamically_materialised is True
    assert policy.to_dict() == policy_before


def test_wildcard_relationship_does_not_authorise_apex_child() -> None:
    module = _programme_graph_module()
    relationship = _relationship(
        module,
        module.RELATIONSHIP_OBSERVED_REDIRECT,
        "https://app.example.test/",
        "https://example.test/",
        evidence_id="EVID-REDIRECT-APEX",
        provenance_source="raw/apex-headers.txt",
    )

    graph = module.build_programme_graph(
        _policy(),
        relationship_evidence=(
            _seed(module, "https://app.example.test/"),
            relationship,
        ),
    )
    apex = _node(graph, "https://example.test")
    retained = next(
        item
        for item in graph.relationships
        if item.relationship_type == module.RELATIONSHIP_OBSERVED_REDIRECT
    )

    assert retained.destination_origin == "https://example.test"
    assert retained.evidence_ids == ("EVID-REDIRECT-APEX",)
    assert retained.destination_scope_decision.outcome == OUTCOME_UNKNOWN
    assert apex.scope_decision.outcome == OUTCOME_UNKNOWN
    assert apex.materialisation_eligible is False
    assert "https://example.test" not in {
        item.canonical_origin
        for item in module.build_programme_http_work_items(graph)
    }


def test_explicit_exclusion_blocks_related_child_materialisation() -> None:
    module = _programme_graph_module()
    graph = module.build_programme_graph(
        _policy(excluded_hosts=("blocked.example.test",)),
        relationship_evidence=(
            _seed(module, "https://app.example.test/"),
            _relationship(
                module,
                module.RELATIONSHIP_DOCUMENTED_SERVICE,
                "https://app.example.test/",
                "https://blocked.example.test/",
                evidence_id="EVID-DOC-BLOCKED",
                provenance_source="raw/programme-documentation.html",
            ),
        ),
    )
    blocked = _node(graph, "https://blocked.example.test")
    relationship = next(
        item
        for item in graph.relationships
        if item.relationship_type == module.RELATIONSHIP_DOCUMENTED_SERVICE
    )

    assert blocked.scope_decision.outcome == OUTCOME_BLOCKED
    assert blocked.scope_decision.matched_exclusion_rule_ids == ("exclude-1",)
    assert blocked.materialisation_eligible is False
    assert relationship.destination_scope_decision.outcome == OUTCOME_BLOCKED
    assert relationship.destination_materialisation_eligible is False
    assert "https://blocked.example.test" not in {
        item.canonical_origin
        for item in module.build_programme_http_work_items(graph)
    }


def test_scheme_and_port_mismatch_remain_non_materialisable() -> None:
    module = _programme_graph_module()
    graph = module.build_programme_graph(
        _policy(),
        relationship_evidence=(
            _seed(module, "https://app.example.test/"),
            _relationship(
                module,
                module.RELATIONSHIP_OBSERVED_REFERENCE,
                "https://app.example.test/",
                "http://child.example.test/",
                evidence_id="EVID-WRONG-SCHEME",
                provenance_source="raw/source-reference.html",
            ),
            _relationship(
                module,
                module.RELATIONSHIP_OBSERVED_REFERENCE,
                "https://app.example.test/",
                "https://child.example.test:8443/",
                evidence_id="EVID-WRONG-PORT",
                provenance_source="raw/source-reference.js",
            ),
        ),
    )

    wrong_scheme = _node(graph, "http://child.example.test")
    wrong_port = _node(graph, "https://child.example.test:8443")
    relationships = tuple(
        item
        for item in graph.relationships
        if item.relationship_type == module.RELATIONSHIP_OBSERVED_REFERENCE
    )

    assert len(relationships) == 2
    assert wrong_scheme.scope_decision.outcome == OUTCOME_UNKNOWN
    assert wrong_port.scope_decision.outcome == OUTCOME_UNKNOWN
    assert wrong_scheme.materialisation_eligible is False
    assert wrong_port.materialisation_eligible is False
    assert {
        item.canonical_origin
        for item in module.build_programme_http_work_items(graph)
    } == {"https://app.example.test"}


def test_programme_graph_is_deterministic_and_preserves_relationship_provenance() -> None:
    module = _programme_graph_module()
    seed = _seed(module, "https://app.example.test/")
    first_redirect = _relationship(
        module,
        module.RELATIONSHIP_OBSERVED_REDIRECT,
        "https://app.example.test/",
        "https://child.example.test/",
        evidence_id="EVID-REDIRECT-A",
        provenance_source="raw/first-headers.txt",
    )
    second_redirect = _relationship(
        module,
        module.RELATIONSHIP_OBSERVED_REDIRECT,
        "https://app.example.test/",
        "https://child.example.test/",
        evidence_id="EVID-REDIRECT-B",
        provenance_source="raw/second-headers.txt",
    )
    documented = _relationship(
        module,
        module.RELATIONSHIP_DOCUMENTED_SERVICE,
        "https://app.example.test/",
        "https://child.example.test/",
        evidence_id="EVID-DOCUMENTED-CHILD",
        provenance_source="raw/service-documentation.html",
    )
    evidence = (seed, first_redirect, second_redirect, documented)

    first = module.build_programme_graph(
        _policy(),
        relationship_evidence=evidence,
    )
    reversed_result = module.build_programme_graph(
        _policy(),
        relationship_evidence=tuple(reversed(evidence)),
    )
    child = _node(first, "https://child.example.test")
    child_relationships = tuple(
        item
        for item in first.relationships
        if item.destination_origin == "https://child.example.test"
    )
    redirect = next(
        item
        for item in child_relationships
        if item.relationship_type == module.RELATIONSHIP_OBSERVED_REDIRECT
    )

    assert first == reversed_result
    assert tuple(node.canonical_origin for node in first.nodes).count(
        "https://child.example.test"
    ) == 1
    assert len(child_relationships) == 2
    assert redirect.evidence_ids == ("EVID-REDIRECT-A", "EVID-REDIRECT-B")
    assert redirect.provenance_sources == (
        "raw/first-headers.txt",
        "raw/second-headers.txt",
    )
    assert set(child.relationship_ids) == {
        item.relationship_id for item in child_relationships
    }


def test_documented_relationship_does_not_confer_authority() -> None:
    module = _programme_graph_module()
    graph = module.build_programme_graph(
        _policy(),
        relationship_evidence=(
            _seed(module, "https://app.example.test/"),
            _relationship(
                module,
                module.RELATIONSHIP_DOCUMENTED_SERVICE,
                "https://app.example.test/",
                "https://service.other.test/",
                evidence_id="EVID-DOCUMENTED-OTHER",
                provenance_source="raw/programme-documentation.html",
            ),
        ),
    )
    candidate = _node(graph, "https://service.other.test")
    documented = next(
        item
        for item in graph.relationships
        if item.relationship_type == module.RELATIONSHIP_DOCUMENTED_SERVICE
    )

    assert documented.evidence_ids == ("EVID-DOCUMENTED-OTHER",)
    assert documented.destination_scope_decision.outcome == OUTCOME_UNKNOWN
    assert documented.destination_materialisation_eligible is False
    assert candidate.scope_decision.outcome == OUTCOME_UNKNOWN
    assert candidate.materialisation_eligible is False
    assert "https://service.other.test" not in {
        item.canonical_origin
        for item in module.build_programme_http_work_items(graph)
    }


def test_programme_fanout_builds_multiple_exact_authorised_work_items() -> None:
    module = _programme_graph_module()
    evidence = (
        _seed(module, "https://app.example.test/"),
        _relationship(
            module,
            module.RELATIONSHIP_OBSERVED_REDIRECT,
            "https://app.example.test/",
            "https://child.example.test/",
            evidence_id="EVID-CHILD",
            provenance_source="raw/child-headers.txt",
        ),
        _relationship(
            module,
            module.RELATIONSHIP_OBSERVED_REFERENCE,
            "https://app.example.test/",
            "https://developers.example.test/",
            evidence_id="EVID-DEVELOPERS",
            provenance_source="raw/app-source.html",
        ),
        _relationship(
            module,
            module.RELATIONSHIP_DOCUMENTED_SERVICE,
            "https://app.example.test/",
            "https://api.example.test/",
            evidence_id="EVID-API-DOCUMENTATION",
            provenance_source="raw/api-documentation.html",
        ),
    )
    graph = module.build_programme_graph(
        _policy(),
        relationship_evidence=evidence,
    )

    work_items = module.build_programme_http_work_items(graph)
    by_origin = {item.canonical_origin: item for item in work_items}

    assert tuple(sorted(by_origin)) == (
        "https://api.example.test",
        "https://app.example.test",
        "https://child.example.test",
        "https://developers.example.test",
    )
    assert all(
        item.scope_decision.outcome == OUTCOME_ALLOWED for item in work_items
    )
    assert all(
        item.inclusion_rule_ids == ("include-qualified-wildcard",)
        for item in work_items
    )
    assert by_origin["https://app.example.test"].configured_seed is True
    assert by_origin["https://app.example.test"].dynamically_materialised is False
    assert all(
        by_origin[origin].configured_seed is False
        and by_origin[origin].dynamically_materialised is True
        and by_origin[origin].relationship_ids
        for origin in (
            "https://api.example.test",
            "https://child.example.test",
            "https://developers.example.test",
        )
    )
