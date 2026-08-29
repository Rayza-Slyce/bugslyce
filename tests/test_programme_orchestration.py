"""WP3B Stage 2 RED contracts for offline programme-level planning."""

from __future__ import annotations

from dataclasses import replace
import importlib
from pathlib import Path

import pytest

from bugslyce.core.engagement_policy import (
    AUTOMATION_PERMITTED,
    CONFIRMED,
    IDENTIFICATION_NONE,
    build_bug_bounty_policy,
)
from bugslyce.core.models import DiscoveredPath, HTTPArtifact, ProjectState
from bugslyce.core.programme_graph import (
    RELATIONSHIP_CONFIGURED_SEED,
    RELATIONSHIP_OBSERVED_REDIRECT,
    RELATIONSHIP_OBSERVED_REFERENCE,
    build_programme_graph,
    build_programme_http_work_items,
    build_programme_relationship_evidence,
)
from bugslyce.core.programme_scope import (
    ACTION_INCLUDE,
    OUTCOME_ALLOWED,
    OUTCOME_UNKNOWN,
    RULE_EXACT_HOSTNAME,
    RULE_WILDCARD_SUBDOMAIN,
    build_programme_scope_policy,
    build_programme_scope_rule,
)
from bugslyce.project_session import (
    initialize_project,
    load_project,
    save_project_engagement_policy,
    save_project_programme_scope_policy,
)
from bugslyce.recon.external_enforcement import assess_tool_capabilities
from bugslyce.recon.modes import STANDARD_RECON_PROFILE
from bugslyce.recon.project_runtime import build_bug_bounty_project_runtime


FIXED_TIME = "2026-08-29T15:00:00Z"


def _programme_orchestration_module():
    return importlib.import_module("bugslyce.recon.programme_orchestration")


def _capabilities():
    return {
        "curl": assess_tool_capabilities(
            "curl",
            "--disable --connect-timeout --dump-header --globoff --header --head "
            "--max-redirs --max-time --noproxy --output --proto --resolve --silent "
            "--show-error --user-agent --write-out",
        ),
        "gobuster": assess_tool_capabilities(
            "gobuster",
            "dir --url --wordlist --threads --delay --useragent --headers value "
            "-H value --timeout --output --follow-redirect (default false) "
            "--no-tls-validation",
        ),
        "nmap": assess_tool_capabilities(
            "nmap", "-sT -sV -Pn -n -p --max-rate --max-retries -oN"
        ),
    }


def _runtime(tmp_path: Path, *, bind_origin: bool = True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    scope = tmp_path / "scope.md"
    scope.write_text("# Authorised synthetic scope\n", encoding="utf-8")
    _project, project_file = initialize_project(
        "programme-orchestration",
        "app.example.test",
        scope,
        tmp_path / "project",
        engagement_context="bug_bounty",
    )
    save_project_engagement_policy(
        project_file,
        build_bug_bounty_policy(
            programme_rules_reviewed=CONFIRMED,
            automated_reconnaissance=AUTOMATION_PERMITTED,
            identification_requirement=IDENTIFICATION_NONE,
            updated_at=FIXED_TIME,
        ),
    )
    save_project_programme_scope_policy(
        project_file,
        build_programme_scope_policy(
            (
                build_programme_scope_rule(
                    rule_id="include-project-target",
                    action=ACTION_INCLUDE,
                    kind=RULE_EXACT_HOSTNAME,
                    value="app.example.test",
                ),
                build_programme_scope_rule(
                    rule_id="include-qualified-wildcard",
                    action=ACTION_INCLUDE,
                    kind=RULE_WILDCARD_SUBDOMAIN,
                    value="*.example.test",
                    scheme="https",
                    port=443,
                ),
            ),
            updated_at=FIXED_TIME,
        ),
    )
    runtime = build_bug_bounty_project_runtime(
        load_project(project_file),
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
    )
    if bind_origin:
        runtime.bind_http_origins(("https://app.example.test/",))
    return runtime


def _state(
    runtime,
    *,
    discovered_paths: tuple[DiscoveredPath, ...] = (),
    http_artifacts: tuple[HTTPArtifact, ...] = (),
) -> ProjectState:
    return ProjectState(
        project_name=runtime.project.name,
        input_dir=runtime.project.output_dir,
        processed_files=[],
        scope_summary="Synthetic retained programme evidence",
        assets=[],
        http_services=[],
        endpoints=[],
        port_services=[],
        http_artifacts=list(http_artifacts),
        discovered_paths=list(discovered_paths),
        recon_summary=None,
        recon_manifest=None,
        evidence=[],
        warnings=[],
        generated_at=FIXED_TIME,
        engagement_context="bug_bounty",
    )


def test_programme_plan_is_anchored_to_runtime_policy_and_rejects_broader_graph(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    broader_policy = build_programme_scope_policy(
        (
            *runtime.programme_scope_policy.rules,
            build_programme_scope_rule(
                rule_id="broader-other-service",
                action=ACTION_INCLUDE,
                kind=RULE_EXACT_HOSTNAME,
                value="service.other.test",
            ),
        ),
        updated_at=runtime.programme_scope_policy.updated_at,
    )
    broader_graph = build_programme_graph(
        broader_policy,
        relationship_evidence=(
            build_programme_relationship_evidence(
                relationship_type=RELATIONSHIP_CONFIGURED_SEED,
                source_origin=None,
                destination_origin="https://app.example.test/",
                evidence_ids=(),
                provenance_sources=(
                    "bug_bounty_project_runtime.approved_http_origins",
                ),
            ),
        ),
    )
    module = _programme_orchestration_module()
    plan = module.build_programme_orchestration_plan(runtime, _state(runtime))
    forged_plan = replace(
        plan,
        programme_graph=broader_graph,
        http_work_items=build_programme_http_work_items(broader_graph),
    )

    assert plan.programme_graph.programme_scope_policy == (
        runtime.programme_scope_policy
    )
    assert plan.programme_graph.programme_scope_policy is not (
        runtime.programme_scope_policy
    )
    with pytest.raises(ValueError, match="policy|runtime|canonical"):
        module.require_programme_orchestration_plan_binding(runtime, forged_plan)


def test_programme_plan_uses_only_runtime_approved_origins_as_configured_seeds(
    tmp_path: Path,
) -> None:
    unbound_runtime = _runtime(tmp_path / "unbound", bind_origin=False)
    bound_runtime = _runtime(tmp_path / "bound")
    unbound_state = _state(unbound_runtime)
    bound_state = _state(bound_runtime)
    module = _programme_orchestration_module()
    unbound_plan = module.build_programme_orchestration_plan(
        unbound_runtime,
        unbound_state,
    )
    bound_plan = module.build_programme_orchestration_plan(
        bound_runtime,
        bound_state,
    )
    seed = next(
        relationship
        for relationship in bound_plan.programme_graph.relationships
        if relationship.relationship_type == RELATIONSHIP_CONFIGURED_SEED
    )
    seed_item = next(
        item
        for item in bound_plan.http_work_items
        if item.canonical_origin == "https://app.example.test"
    )

    assert unbound_runtime.project.target == "app.example.test"
    assert unbound_runtime.approved_http_origins == ()
    assert unbound_plan.programme_graph.nodes == ()
    assert unbound_plan.http_work_items == ()
    assert seed.destination_origin == "https://app.example.test"
    assert seed.provenance_sources == (
        "bug_bounty_project_runtime.approved_http_origins",
    )
    assert seed_item.configured_seed is True
    assert seed_item.dynamically_materialised is False


def test_retained_redirect_to_authorised_child_becomes_exact_programme_work_item(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state(
        runtime,
        discovered_paths=(
            DiscoveredPath(
                url="https://app.example.test/start",
                status_code=301,
                content_length=0,
                redirect_location="https://child.example.test/login",
                source="raw/child-headers.txt",
                evidence_ids=["EVID-REDIRECT-CHILD"],
                tags=[],
            ),
        ),
    )
    module = _programme_orchestration_module()

    plan = module.build_programme_orchestration_plan(runtime, state)
    redirect = next(
        relationship
        for relationship in plan.programme_graph.relationships
        if relationship.relationship_type == RELATIONSHIP_OBSERVED_REDIRECT
    )
    child = next(
        item
        for item in plan.http_work_items
        if item.canonical_origin == "https://child.example.test"
    )

    assert redirect.source_origin == "https://app.example.test"
    assert redirect.destination_origin == "https://child.example.test"
    assert redirect.evidence_ids == ("EVID-REDIRECT-CHILD",)
    assert redirect.provenance_sources == ("raw/child-headers.txt",)
    assert redirect.destination_scope_decision.outcome == OUTCOME_ALLOWED
    assert child.inclusion_rule_ids == ("include-qualified-wildcard",)
    assert child.configured_seed is False
    assert child.dynamically_materialised is True


def test_retained_redirect_to_unauthorised_apex_remains_evidence_only(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state(
        runtime,
        discovered_paths=(
            DiscoveredPath(
                url="https://app.example.test/authorised",
                status_code=301,
                content_length=0,
                redirect_location="https://child.example.test/",
                source="raw/authorised-headers.txt",
                evidence_ids=["EVID-REDIRECT-AUTHORISED"],
                tags=[],
            ),
            DiscoveredPath(
                url="https://app.example.test/",
                status_code=302,
                content_length=0,
                redirect_location="https://example.test/",
                source="raw/apex-headers.txt",
                evidence_ids=["EVID-REDIRECT-APEX"],
                tags=[],
            ),
        ),
    )
    module = _programme_orchestration_module()

    plan = module.build_programme_orchestration_plan(runtime, state)
    redirect = next(
        relationship
        for relationship in plan.programme_graph.relationships
        if relationship.relationship_type == RELATIONSHIP_OBSERVED_REDIRECT
        and relationship.destination_origin == "https://example.test"
    )
    apex = next(
        node
        for node in plan.programme_graph.nodes
        if node.canonical_origin == "https://example.test"
    )

    assert redirect.evidence_ids == ("EVID-REDIRECT-APEX",)
    assert redirect.destination_scope_decision.outcome == OUTCOME_UNKNOWN
    assert redirect.destination_materialisation_eligible is False
    assert apex.scope_decision.outcome == OUTCOME_UNKNOWN
    assert "https://child.example.test" in {
        item.canonical_origin for item in plan.http_work_items
    }
    assert "https://example.test" not in {
        item.canonical_origin for item in plan.http_work_items
    }


def test_retained_cross_origin_html_reference_preserves_real_provenance(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state(
        runtime,
        http_artifacts=(
            HTTPArtifact(
                url="https://app.example.test/dashboard",
                artifact_type="link",
                value="https://reference.example.test/documentation",
                source_file="raw/app-source.html",
                evidence_ids=["EVID-REFERENCE-CHILD"],
                tags=[],
            ),
        ),
    )
    module = _programme_orchestration_module()

    plan = module.build_programme_orchestration_plan(runtime, state)
    reference = next(
        relationship
        for relationship in plan.programme_graph.relationships
        if relationship.relationship_type == RELATIONSHIP_OBSERVED_REFERENCE
    )

    assert reference.source_origin == "https://app.example.test"
    assert reference.destination_origin == "https://reference.example.test"
    assert reference.evidence_ids == ("EVID-REFERENCE-CHILD",)
    assert reference.provenance_sources == ("raw/app-source.html",)
    assert reference.destination_scope_decision.outcome == OUTCOME_ALLOWED
    assert "https://reference.example.test" in {
        item.canonical_origin for item in plan.http_work_items
    }


def test_programme_planning_does_not_mutate_strict_project_runtime(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    project_target_before = runtime.project.target
    policy_before = runtime.programme_scope_policy
    policy_payload_before = policy_before.to_dict()
    decision_before = runtime.target_decision
    initial_origins_before = runtime.initial_http_origins
    approved_origins_before = runtime.approved_http_origins
    state = _state(
        runtime,
        discovered_paths=(
            DiscoveredPath(
                url="https://app.example.test/",
                status_code=301,
                content_length=0,
                redirect_location="https://child.example.test/",
                source="raw/non-mutation-headers.txt",
                evidence_ids=["EVID-NON-MUTATION"],
                tags=[],
            ),
        ),
    )
    module = _programme_orchestration_module()

    plan = module.build_programme_orchestration_plan(runtime, state)

    assert plan.http_work_items
    assert runtime.project.target == project_target_before
    assert runtime.programme_scope_policy is policy_before
    assert runtime.programme_scope_policy.to_dict() == policy_payload_before
    assert runtime.target_decision is decision_before
    assert runtime.initial_http_origins == initial_origins_before
    assert runtime.approved_http_origins == approved_origins_before
    with pytest.raises(ValueError, match="target"):
        runtime.require_workflow(
            Path(runtime.project.output_dir),
            Path(runtime.project.scope_file),
            "child.example.test",
        )


def test_programme_plan_binding_rejects_work_items_not_derived_from_graph(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    module = _programme_orchestration_module()
    plan = module.build_programme_orchestration_plan(runtime, _state(runtime))
    legitimate_item = next(
        item
        for item in plan.http_work_items
        if item.canonical_origin == "https://app.example.test"
    )
    forged_item = replace(
        legitimate_item,
        canonical_origin="https://service.other.test",
    )
    forged_plan = replace(
        plan,
        http_work_items=(
            *plan.http_work_items,
            forged_item,
        ),
    )

    assert plan.programme_graph.programme_scope_policy == (
        runtime.programme_scope_policy
    )
    assert build_programme_http_work_items(plan.programme_graph) == (
        plan.http_work_items
    )
    assert forged_plan.programme_graph == plan.programme_graph
    assert forged_plan.http_work_items != build_programme_http_work_items(
        forged_plan.programme_graph
    )
    with pytest.raises(ValueError, match="plan|canonical|runtime|binding"):
        module.require_programme_orchestration_plan_binding(
            runtime,
            forged_plan,
        )


def test_programme_plan_binding_rejects_different_runtime_with_same_policy(
    tmp_path: Path,
) -> None:
    runtime_a = _runtime(tmp_path / "runtime-a")
    runtime_b = _runtime(
        tmp_path / "runtime-b",
        bind_origin=False,
    )
    runtime_b.bind_http_origins(("https://child.example.test/",))
    module = _programme_orchestration_module()
    plan_a = module.build_programme_orchestration_plan(
        runtime_a,
        _state(runtime_a),
    )

    assert runtime_a.programme_scope_policy == runtime_b.programme_scope_policy
    assert runtime_a.approved_http_origins == (
        "https://app.example.test/",
    )
    assert runtime_b.approved_http_origins == (
        "https://child.example.test/",
    )
    with pytest.raises(ValueError, match="runtime|binding|canonical|origin"):
        module.require_programme_orchestration_plan_binding(
            runtime_b,
            plan_a,
        )


def test_reference_adapter_resolves_raw_urls_and_ignores_non_programme_origin_noise(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state(
        runtime,
        http_artifacts=(
            HTTPArtifact(
                url="https://app.example.test/dashboard",
                artifact_type="link",
                value="/account",
                source_file="raw/app-source.html",
                evidence_ids=["EVID-SAME-ORIGIN"],
                tags=[],
            ),
            HTTPArtifact(
                url="https://app.example.test/dashboard",
                artifact_type="link",
                value="//reference.example.test/documentation",
                source_file="raw/app-source.html",
                evidence_ids=["EVID-CROSS-ORIGIN"],
                tags=[],
            ),
            HTTPArtifact(
                url="https://app.example.test/dashboard",
                artifact_type="link",
                value="mailto:security@example.test",
                source_file="raw/app-source.html",
                evidence_ids=["EVID-MAILTO"],
                tags=[],
            ),
        ),
    )
    module = _programme_orchestration_module()

    plan = module.build_programme_orchestration_plan(runtime, state)
    references = tuple(
        relationship
        for relationship in plan.programme_graph.relationships
        if relationship.relationship_type == RELATIONSHIP_OBSERVED_REFERENCE
    )

    assert tuple(
        relationship.destination_origin
        for relationship in references
    ) == ("https://reference.example.test",)
    assert references[0].source_origin == "https://app.example.test"
    assert references[0].evidence_ids == ("EVID-CROSS-ORIGIN",)
    assert references[0].provenance_sources == ("raw/app-source.html",)
    assert references[0].destination_scope_decision.outcome == OUTCOME_ALLOWED
    assert "https://reference.example.test" in {
        item.canonical_origin
        for item in plan.http_work_items
    }


def test_redirect_adapter_resolves_scheme_relative_location_against_source_url(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state(
        runtime,
        discovered_paths=(
            DiscoveredPath(
                url="https://app.example.test/start",
                status_code=302,
                content_length=0,
                redirect_location="//child.example.test/login",
                source="raw/scheme-relative-headers.txt",
                evidence_ids=["EVID-SCHEME-RELATIVE-REDIRECT"],
                tags=[],
            ),
        ),
    )
    module = _programme_orchestration_module()

    plan = module.build_programme_orchestration_plan(runtime, state)
    redirect = next(
        relationship
        for relationship in plan.programme_graph.relationships
        if relationship.relationship_type == RELATIONSHIP_OBSERVED_REDIRECT
    )

    assert redirect.source_origin == "https://app.example.test"
    assert redirect.destination_origin == "https://child.example.test"
    assert redirect.evidence_ids == ("EVID-SCHEME-RELATIVE-REDIRECT",)
    assert redirect.provenance_sources == (
        "raw/scheme-relative-headers.txt",
    )
    assert redirect.destination_scope_decision.outcome == OUTCOME_ALLOWED
    assert "https://child.example.test" in {
        item.canonical_origin
        for item in plan.http_work_items
    }


def test_programme_plan_binding_requires_state_for_non_seed_relationships(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state(
        runtime,
        http_artifacts=(
            HTTPArtifact(
                url="https://app.example.test/dashboard",
                artifact_type="link",
                value="https://reference.example.test/documentation",
                source_file="raw/state-backed-reference.html",
                evidence_ids=["EVID-STATE-BACKED-REFERENCE"],
                tags=[],
            ),
        ),
    )
    module = _programme_orchestration_module()
    plan = module.build_programme_orchestration_plan(runtime, state)

    assert any(
        relationship.relationship_type == RELATIONSHIP_OBSERVED_REFERENCE
        for relationship in plan.programme_graph.relationships
    )
    with pytest.raises(ValueError, match="evidence|state|relationship|binding"):
        module.require_programme_orchestration_plan_binding(runtime, plan)


def test_programme_plan_binding_accepts_non_seed_relationships_backed_by_supplied_state(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state(
        runtime,
        discovered_paths=(
            DiscoveredPath(
                url="https://app.example.test/start",
                status_code=302,
                content_length=0,
                redirect_location="https://child.example.test/login",
                source="raw/state-backed-redirect.txt",
                evidence_ids=["EVID-STATE-BACKED-REDIRECT"],
                tags=[],
            ),
        ),
    )
    module = _programme_orchestration_module()
    plan = module.build_programme_orchestration_plan(runtime, state)

    validated = module.require_programme_orchestration_plan_binding(
        runtime,
        plan,
        project_state=state,
    )

    assert validated == plan


def test_programme_plan_binding_rejects_relationship_not_backed_by_supplied_state(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state(runtime)
    module = _programme_orchestration_module()
    legitimate = module.build_programme_orchestration_plan(runtime, state)

    fabricated_graph = build_programme_graph(
        runtime.programme_scope_policy,
        relationship_evidence=(
            build_programme_relationship_evidence(
                relationship_type=RELATIONSHIP_CONFIGURED_SEED,
                source_origin=None,
                destination_origin="https://app.example.test/",
                evidence_ids=(),
                provenance_sources=(
                    "bug_bounty_project_runtime.approved_http_origins",
                ),
            ),
            build_programme_relationship_evidence(
                relationship_type=RELATIONSHIP_OBSERVED_REFERENCE,
                source_origin="https://app.example.test/",
                destination_origin="https://ghost.example.test/",
                evidence_ids=("EVID-FABRICATED-NOT-IN-STATE",),
                provenance_sources=("raw/nonexistent-source.html",),
            ),
        ),
    )
    forged_plan = replace(
        legitimate,
        programme_graph=fabricated_graph,
        http_work_items=build_programme_http_work_items(fabricated_graph),
    )

    assert state.discovered_paths == []
    assert state.http_artifacts == []
    assert "https://ghost.example.test" in {
        item.canonical_origin
        for item in forged_plan.http_work_items
    }
    with pytest.raises(ValueError, match="evidence|state|relationship|canonical"):
        module.require_programme_orchestration_plan_binding(
            runtime,
            forged_plan,
            project_state=state,
        )


def test_programme_plan_binding_rejects_state_backed_relationship_omitted_from_plan(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state(
        runtime,
        http_artifacts=(
            HTTPArtifact(
                url="https://app.example.test/dashboard",
                artifact_type="link",
                value="https://reference.example.test/documentation",
                source_file="raw/omitted-reference.html",
                evidence_ids=["EVID-OMITTED-REFERENCE"],
                tags=[],
            ),
        ),
    )
    module = _programme_orchestration_module()
    legitimate = module.build_programme_orchestration_plan(runtime, state)

    seed_only_graph = build_programme_graph(
        runtime.programme_scope_policy,
        relationship_evidence=(
            build_programme_relationship_evidence(
                relationship_type=RELATIONSHIP_CONFIGURED_SEED,
                source_origin=None,
                destination_origin="https://app.example.test/",
                evidence_ids=(),
                provenance_sources=(
                    "bug_bounty_project_runtime.approved_http_origins",
                ),
            ),
        ),
    )
    stripped_plan = replace(
        legitimate,
        programme_graph=seed_only_graph,
        http_work_items=build_programme_http_work_items(seed_only_graph),
    )

    assert any(
        relationship.relationship_type == RELATIONSHIP_OBSERVED_REFERENCE
        for relationship in legitimate.programme_graph.relationships
    )
    assert all(
        relationship.relationship_type == RELATIONSHIP_CONFIGURED_SEED
        for relationship in stripped_plan.programme_graph.relationships
    )
    with pytest.raises(ValueError, match="evidence|state|relationship|canonical"):
        module.require_programme_orchestration_plan_binding(
            runtime,
            stripped_plan,
            project_state=state,
        )


def test_seed_only_programme_plan_can_be_validated_without_project_state(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    state = _state(runtime)
    module = _programme_orchestration_module()
    plan = module.build_programme_orchestration_plan(runtime, state)

    assert all(
        relationship.relationship_type == RELATIONSHIP_CONFIGURED_SEED
        for relationship in plan.programme_graph.relationships
    )
    assert module.require_programme_orchestration_plan_binding(
        runtime,
        plan,
    ) == plan
