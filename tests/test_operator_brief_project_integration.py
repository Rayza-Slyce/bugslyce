"""RED contract for project-source Operator Brief creation and Stage 010 wiring."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import importlib
from inspect import Parameter, signature
import json
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace
from typing import get_type_hints

import pytest

import bugslyce.project_pipeline as project_pipeline
from bugslyce.core.models import (
    DiscoveredPath,
    HTTPArtifact,
    PortService,
    ProjectState,
    ReconManifest,
    ReconManifestArtifact,
)
from bugslyce.project_pipeline import (
    DEEP_PIPELINE_PROFILE,
    PIPELINE_PROFILE,
    STANDARD_PIPELINE_PROFILE,
    DeepPipelineOutputs,
    ProjectPipelineFailed,
    _step_runners,
    run_project_pipeline,
)
from bugslyce.project_session import scaffold_project
from bugslyce.recon.deep_http_fingerprint_summary import (
    DeepHttpFingerprintSummary,
    DeepHttpFingerprintSummaryCounts,
)
from bugslyce.recon.deep_orchestration import (
    DeepReconOrchestrationResult,
    build_deep_recon_orchestration,
)
from bugslyce.recon.deep_response_similarity_review import (
    DeepResponseSimilarityReview,
    DeepResponseSimilaritySummaryCounts,
)
from bugslyce.recon.deep_shallow_route_followup import (
    DeepShallowRouteFollowupResult,
    DeepShallowRouteFollowupResultSummaryCounts,
)
from bugslyce.recon.deep_source_route_collection_review import (
    DeepSourceRouteCollectionReviewSummary,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.http_route_relationships import (
    build_http_route_relationship_clusters,
)
from bugslyce.recon.standard_interpretation import (
    assemble_standard_interpretation_from_project_state,
)
from bugslyce.reports.artifact_classifier import LIKELY_SIGNAL, classify_encoded_artifact
from bugslyce.reports.operator_brief_assembly import (
    OperatorBriefComposition,
    assemble_operator_brief,
)
from bugslyce.reports.operator_brief_composition_persistence import (
    OPERATOR_BRIEF_COMPOSITION_FILENAME,
)
from bugslyce.reports.operator_brief_http import (
    build_operator_brief_http_inputs_from_deep,
    combine_operator_brief_http_inputs,
    compose_operator_brief_http,
)
from bugslyce.reports.operator_brief_http_retained_manifest import (
    OperatorBriefHttpRetainedManifestRejectionReason,
    build_operator_brief_http_inputs_from_retained_manifest_html,
)
from bugslyce.reports.operator_brief_multi_family_assembly import (
    assemble_operator_brief_policy_subjects,
)
from bugslyce.reports.operator_brief_network import (
    build_operator_brief_network_inputs_from_project_state,
    compose_operator_brief_network,
)
from bugslyce.reports.operator_brief_source_native import (
    OperatorBriefSourceNativeFamily,
    compose_operator_brief_source_native,
)
from bugslyce.reports.operator_brief_web_context import (
    build_operator_brief_web_context_inputs_from_project_state,
    compose_operator_brief_web_context,
)
from bugslyce.triage.workflow_leads import build_grouped_workflow_leads


_FUTURE_MODULE = "bugslyce.reports.operator_brief_project"
_MAXIMUM_RETAINED_BODY_BYTES = 1_000_000
_ORIGIN = "https://stage6c.example.test"
_ENCODED_VALUE = "9fdafbd64c47471a8f54cd3fc64cd312"


def _future_api() -> SimpleNamespace:
    module = importlib.import_module(_FUTURE_MODULE)
    return SimpleNamespace(
        module=module,
        build_project_operator_brief_composition=getattr(
            module,
            "build_project_operator_brief_composition",
        ),
    )


def _empty_source_review() -> DeepSourceRouteCollectionReviewSummary:
    return DeepSourceRouteCollectionReviewSummary(
        total_collected=0,
        total_skipped=0,
        status_buckets=(),
        body_signatures=(),
        skip_reasons=(),
        review_leads=(),
        safety_notes=(),
    )


def _empty_fingerprints() -> DeepHttpFingerprintSummary:
    counts = DeepHttpFingerprintSummaryCounts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return DeepHttpFingerprintSummary((), (), counts, ())


def _empty_similarity() -> DeepResponseSimilarityReview:
    counts = DeepResponseSimilaritySummaryCounts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return DeepResponseSimilarityReview((), (), counts, ())


def _empty_source_collection() -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=(),
        skipped=(),
        total_considered=0,
        total_collected=0,
        total_skipped=0,
    )


def _empty_shallow_followups() -> DeepShallowRouteFollowupResult:
    return DeepShallowRouteFollowupResult(
        collected=(),
        skipped=(),
        summary_counts=DeepShallowRouteFollowupResultSummaryCounts(
            requests_planned=0,
            responses_collected=0,
            requests_skipped_or_failed=0,
            fetch_errors=0,
            invalid_fetch_responses=0,
            responses_too_large=0,
        ),
        safety_notes=(),
    )


def _deep_authority() -> tuple[DeepSourceRouteCollectionResult, DeepReconOrchestrationResult]:
    body = b'{"routes":["/admin","/api/v1"]}'
    item = DeepSourceRouteCollectedItem(
        url=f"{_ORIGIN}/routes.json",
        method="GET",
        status_code=200,
        final_url=f"{_ORIGIN}/routes.json",
        headers=(("Content-Type", "application/json"),),
        body_preview=body.decode("ascii"),
        body_sha256=sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.1,
        source="source_route_coverage",
        reason="source-valid Stage 6C fixture",
        evidence_ids=("EVID-DEEP-ROUTES",),
        body=body,
    )
    source = DeepSourceRouteCollectionResult(
        collected=(item,),
        skipped=(),
        total_considered=1,
        total_collected=1,
        total_skipped=0,
    )
    orchestration = build_deep_recon_orchestration(
        source,
        _empty_shallow_followups(),
        deep_profile_selected=True,
        deep_collection_completed=True,
    )
    return source, orchestration


def _project_state(
    root: Path,
    *,
    retained_body_bytes: int = 128,
    encoded_source_file: str = "assets/data.js",
) -> ProjectState:
    retained = root / "retained" / "application.html"
    retained.parent.mkdir(parents=True, exist_ok=True)
    retained.write_bytes(b"A" * retained_body_bytes)

    return ProjectState(
        project_name="stage6c-project",
        input_dir=str(root),
        processed_files=["recon_manifest.json"],
        scope_summary="stage6c.example.test",
        assets=[],
        http_services=[],
        endpoints=[],
        port_services=[
            PortService(
                host="stage6c.example.test",
                port=445,
                protocol="tcp",
                state="open",
                service="microsoft-ds",
                product="Samba",
                version="4.18",
                source_file="network/services.json",
                evidence_ids=["EVID-SERVICE"],
                tags=[],
            )
        ],
        http_artifacts=[
            HTTPArtifact(
                url=f"{_ORIGIN}/application",
                artifact_type="href",
                value="/admin",
                source_file="retained/application.html",
                evidence_ids=["EVID-HREF"],
                tags=[],
            ),
            HTTPArtifact(
                url=f"{_ORIGIN}/application",
                artifact_type="encoded_like_artifact",
                value=_ENCODED_VALUE,
                source_file=encoded_source_file,
                evidence_ids=["EVID-ENCODED"],
                tags=["encoded_or_hidden_artifact"],
            ),
        ],
        discovered_paths=[
            DiscoveredPath(
                url=f"{_ORIGIN}/admin",
                status_code=403,
                content_length=64,
                redirect_location=None,
                source="routes/gobuster.txt",
                evidence_ids=["EVID-ROUTE"],
                tags=[],
            )
        ],
        recon_summary=None,
        recon_manifest=ReconManifest(
            schema_version="1.0",
            target="stage6c.example.test",
            artifacts=[
                ReconManifestArtifact(
                    type="html",
                    file="retained/application.html",
                    url=f"{_ORIGIN}/application",
                )
            ],
            source_file="recon_manifest.json",
        ),
        evidence=[],
        warnings=[],
        generated_at="2026-08-24T12:00:00Z",
    )


def _closed_composition(
    root: Path,
    state: ProjectState,
    *,
    source_collection: DeepSourceRouteCollectionResult | None = None,
    orchestration: DeepReconOrchestrationResult | None = None,
) -> OperatorBriefComposition:
    retained = build_operator_brief_http_inputs_from_retained_manifest_html(
        state.recon_manifest,
        root,
        maximum_body_bytes=_MAXIMUM_RETAINED_BODY_BYTES,
    )
    http_inputs = retained.inputs
    if orchestration is not None:
        http_inputs = combine_operator_brief_http_inputs(
            http_inputs,
            build_operator_brief_http_inputs_from_deep(
                orchestration.http_fingerprint_summary
            ),
        )
    http = compose_operator_brief_http(http_inputs)
    network = compose_operator_brief_network(
        build_operator_brief_network_inputs_from_project_state(state)
    )
    standard = assemble_standard_interpretation_from_project_state(
        state,
        render_markdown=False,
    )
    successful = () if orchestration is None else orchestration.successful_content_reviews
    relationships = build_http_route_relationship_clusters(
        state,
        source_collection=source_collection,
        successful_reviews=successful,
    )
    web_context = compose_operator_brief_web_context(
        build_operator_brief_web_context_inputs_from_project_state(
            state,
            robots_analyses=standard.collection.robots_analyses,
            relationship_clusters=relationships,
        )
    )
    normalized = assemble_operator_brief_policy_subjects(
        http=http,
        network=network,
        web_context=web_context,
    )
    source_native = compose_operator_brief_source_native(
        deep_source_route_review=(
            _empty_source_review()
            if orchestration is None
            else orchestration.source_route_collection_review
        ),
        successful_content_reviews=successful,
        deep_http_fingerprints=(
            _empty_fingerprints()
            if orchestration is None
            else orchestration.http_fingerprint_summary
        ),
        deep_response_similarity=(
            _empty_similarity()
            if orchestration is None
            else orchestration.response_similarity_review
        ),
        http_artifacts=tuple(state.http_artifacts),
        workflow_leads=build_grouped_workflow_leads(state, orchestration),
        normalized_policy_subjects=normalized,
    )
    return assemble_operator_brief(
        http=http,
        network=network,
        web_context=web_context,
        source_native=source_native,
    )


def _build_future(
    api: SimpleNamespace,
    root: Path,
    state: ProjectState,
    *,
    profile: str = STANDARD_PIPELINE_PROFILE,
    source_collection: DeepSourceRouteCollectionResult | None = None,
    orchestration: DeepReconOrchestrationResult | None = None,
) -> OperatorBriefComposition:
    return api.build_project_operator_brief_composition(
        project_root=root,
        project_state=state,
        profile=profile,
        deep_source_collection=source_collection,
        deep_orchestration=orchestration,
    )


def _status_context(
    root: Path,
    profile: str,
    *,
    deep_outputs: DeepPipelineOutputs | None = None,
) -> dict[str, object]:
    return {
        "project_file": root / "project.json",
        "scope_file": root / "scope.md",
        "output_dir": root,
        "plan_dir": root / "plan",
        "plan_path": root / "plan" / "content_discovery_plan.json",
        "export_path": root.parent / "stage6c-evidence-pack.zip",
        "published_export_path": None,
        "target": "stage6c.example.test",
        "resume": False,
        "profile": profile,
        "deep_outputs": deep_outputs or DeepPipelineOutputs(),
        "project_runtime": None,
        "completion_summary": object(),
    }


def _stage010_consumer_context(
    tmp_path: Path,
) -> tuple[Path, ProjectState, dict[str, object]]:
    scaffold = scaffold_project(
        "stage6c-consumers",
        "stage6c.example.test",
        tmp_path / "projects",
    )
    output_dir = Path(scaffold.project.output_dir)
    state = _project_state(output_dir)
    (output_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "stage6c.example.test",
                "scope_file": "scope.md",
                "created_by": "stage6c-test",
                "profile": STANDARD_PIPELINE_PROFILE,
                "artifacts": [
                    {
                        "type": "html",
                        "file": "retained/application.html",
                        "url": f"{_ORIGIN}/application",
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    context = _status_context(output_dir, STANDARD_PIPELINE_PROFILE)
    context["project_file"] = Path(scaffold.project_file)
    context["scope_file"] = Path(scaffold.scope_file)
    return output_dir, state, context


# Existing-source controls. These never import the absent Stage 6C module.


def test_source_control_representative_project_reaches_all_closed_owners(
    tmp_path: Path,
) -> None:
    state = _project_state(tmp_path)
    composition = _closed_composition(tmp_path, state)

    assert isinstance(composition, OperatorBriefComposition)
    assert composition.http.subjects and composition.http.facts
    assert composition.network.subjects and composition.network.services
    assert composition.web_context.subjects and composition.web_context.routes
    assert composition.source_native.subjects
    assert any(
        item.family is OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT
        for item in composition.source_native.subjects
    )
    assert len(composition.thread_policy_result.decisions) == len(
        composition.policy_subjects
    )


def test_source_control_retained_manifest_owner_freezes_one_million_byte_bound(
    tmp_path: Path,
) -> None:
    accepted_root = tmp_path / "accepted"
    accepted_root.mkdir()
    accepted = _project_state(
        accepted_root,
        retained_body_bytes=_MAXIMUM_RETAINED_BODY_BYTES,
    )
    rejected_root = tmp_path / "rejected"
    rejected_root.mkdir()
    rejected = _project_state(
        rejected_root,
        retained_body_bytes=_MAXIMUM_RETAINED_BODY_BYTES + 1,
    )

    accepted_result = build_operator_brief_http_inputs_from_retained_manifest_html(
        accepted.recon_manifest,
        accepted_root,
        maximum_body_bytes=_MAXIMUM_RETAINED_BODY_BYTES,
    )
    rejected_result = build_operator_brief_http_inputs_from_retained_manifest_html(
        rejected.recon_manifest,
        rejected_root,
        maximum_body_bytes=_MAXIMUM_RETAINED_BODY_BYTES,
    )

    assert len(accepted_result.inputs.retained_content) == 1
    assert rejected_result.inputs.retained_content == ()
    assert rejected_result.rejections[0].reason is (
        OperatorBriefHttpRetainedManifestRejectionReason.OVERSIZED_FILE
    )


def test_source_control_deep_and_encoded_fixtures_are_current_typed_authorities(
    tmp_path: Path,
) -> None:
    source_collection, orchestration = _deep_authority()
    state = _project_state(tmp_path)

    assert orchestration.deep_profile_selected is True
    assert orchestration.deep_collection_completed is True
    assert orchestration.source_route_collection_review.total_collected == 1
    assert orchestration.successful_content_reviews
    assert source_collection.collected[0].body
    assert classify_encoded_artifact(state.http_artifacts[1]).category == LIKELY_SIGNAL


def test_source_control_standard_consumers_accept_stage010_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir, state, context = _stage010_consumer_context(tmp_path)

    def forbidden_assembly(*args: object, **kwargs: object) -> object:
        raise AssertionError("presentation consumers must not assemble semantics")

    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_assembly.assemble_operator_brief",
        forbidden_assembly,
    )
    monkeypatch.setattr(project_pipeline, "build_project_state", lambda _root: state)
    monkeypatch.setattr(
        "bugslyce.recon.status.build_project_state",
        lambda _root: state,
    )
    runners = _step_runners(context, None)

    _message, status_outputs, _updates = runners["PIPELINE-STEP-010"]()
    _message, runbook_outputs, _updates = runners["PIPELINE-STEP-011"]()

    assert str(output_dir / "report.md") in status_outputs
    assert str(output_dir / "project_state.json") in status_outputs
    assert str(output_dir / "recon_status.json") in status_outputs
    assert str(output_dir / "recon_status.md") in status_outputs
    assert runbook_outputs == [str(output_dir / "runbook.md")]
    assert "# BugSlyce Recon Status" in (output_dir / "recon_status.md").read_text(
        encoding="utf-8"
    )
    assert "# BugSlyce Project Runbook" in (output_dir / "runbook.md").read_text(
        encoding="utf-8"
    )


# Future neutral project adapter contract.


def test_future_adapter_public_api_is_narrow_keyword_only_project_seam() -> None:
    api = _future_api()
    function = api.build_project_operator_brief_composition
    parameters = signature(function).parameters

    assert tuple(parameters) == (
        "project_root",
        "project_state",
        "profile",
        "deep_source_collection",
        "deep_orchestration",
    )
    assert all(item.kind is Parameter.KEYWORD_ONLY for item in parameters.values())
    assert get_type_hints(function) == {
        "project_root": Path,
        "project_state": ProjectState,
        "profile": str,
        "deep_source_collection": DeepSourceRouteCollectionResult | None,
        "deep_orchestration": DeepReconOrchestrationResult | None,
        "return": OperatorBriefComposition,
    }


def test_future_adapter_representative_project_retains_meaningful_four_owner_data(
    tmp_path: Path,
) -> None:
    api = _future_api()
    composition = _build_future(api, tmp_path, _project_state(tmp_path))

    assert composition.http.subjects and composition.http.facts
    assert composition.network.subjects and composition.network.services
    assert composition.web_context.subjects and composition.web_context.routes
    assert composition.source_native.subjects
    assert composition.thread_policy_result.subjects is composition.policy_subjects
    assert len(composition.thread_policy_result.decisions) == len(
        composition.policy_subjects
    )


def test_future_adapter_calls_final_assembler_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _project_state(tmp_path)
    calls: list[tuple[object, object, object, object]] = []
    original = assemble_operator_brief
    monkeypatch.delitem(sys.modules, _FUTURE_MODULE, raising=False)

    def counted(*, http, network, web_context, source_native):
        calls.append((http, network, web_context, source_native))
        return original(
            http=http,
            network=network,
            web_context=web_context,
            source_native=source_native,
        )

    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_assembly.assemble_operator_brief",
        counted,
    )
    api = _future_api()

    composition = _build_future(api, tmp_path, state)

    assert len(calls) == 1
    assert calls[0] == (
        composition.http,
        composition.network,
        composition.web_context,
        composition.source_native,
    )


def test_future_adapter_does_not_consult_legacy_presentation_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _project_state(tmp_path)
    monkeypatch.delitem(sys.modules, _FUTURE_MODULE, raising=False)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("legacy presentation authority is forbidden")

    for target in (
        "bugslyce.reports.operator_brief.build_operator_brief_view",
        "bugslyce.reports.operator_brief.load_operator_brief_artifact",
        "bugslyce.reports.operator_summary.build_operator_summary",
        "bugslyce.triage.candidates.generate_candidates",
        "bugslyce.reports.human_triage.build_human_triage_brief",
        "bugslyce.recon.investigation_threads.build_investigation_threads",
    ):
        monkeypatch.setattr(target, forbidden)
    api = _future_api()

    assert isinstance(_build_future(api, tmp_path, state), OperatorBriefComposition)


@pytest.mark.parametrize("profile", (PIPELINE_PROFILE, STANDARD_PIPELINE_PROFILE))
def test_future_adapter_non_deep_profiles_supply_typed_empty_deep_authorities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
) -> None:
    state = _project_state(tmp_path)
    observed: list[dict[str, object]] = []
    original = compose_operator_brief_source_native
    monkeypatch.delitem(sys.modules, _FUTURE_MODULE, raising=False)

    def captured(**kwargs):
        observed.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_source_native.compose_operator_brief_source_native",
        captured,
    )
    api = _future_api()

    composition = _build_future(api, tmp_path, state, profile=profile)

    assert isinstance(composition, OperatorBriefComposition)
    assert len(observed) == 1
    supplied = observed[0]
    assert isinstance(
        supplied["deep_source_route_review"],
        DeepSourceRouteCollectionReviewSummary,
    )
    assert isinstance(supplied["deep_http_fingerprints"], DeepHttpFingerprintSummary)
    assert isinstance(
        supplied["deep_response_similarity"],
        DeepResponseSimilarityReview,
    )
    assert supplied["deep_source_route_review"].total_collected == 0
    assert supplied["deep_http_fingerprints"].fingerprints == ()
    assert supplied["deep_response_similarity"].groups == ()


def test_future_adapter_deep_profile_consumes_supplied_in_memory_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_collection, orchestration = _deep_authority()
    state = _project_state(tmp_path)
    observed: list[dict[str, object]] = []
    original = compose_operator_brief_source_native
    monkeypatch.delitem(sys.modules, _FUTURE_MODULE, raising=False)

    def captured(**kwargs):
        observed.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_source_native.compose_operator_brief_source_native",
        captured,
    )
    api = _future_api()

    composition = _build_future(
        api,
        tmp_path,
        state,
        profile=DEEP_PIPELINE_PROFILE,
        source_collection=source_collection,
        orchestration=orchestration,
    )

    assert isinstance(composition, OperatorBriefComposition)
    assert len(observed) == 1
    supplied = observed[0]
    assert supplied["deep_source_route_review"] is (
        orchestration.source_route_collection_review
    )
    assert supplied["successful_content_reviews"] is (
        orchestration.successful_content_reviews
    )
    assert supplied["deep_http_fingerprints"] is orchestration.http_fingerprint_summary
    assert supplied["deep_response_similarity"] is orchestration.response_similarity_review


@pytest.mark.parametrize(
    ("body_bytes", "expected_http_subjects"),
    ((_MAXIMUM_RETAINED_BODY_BYTES, True), (_MAXIMUM_RETAINED_BODY_BYTES + 1, False)),
)
def test_future_adapter_preserves_retained_body_bound(
    tmp_path: Path,
    body_bytes: int,
    expected_http_subjects: bool,
) -> None:
    api = _future_api()
    state = _project_state(tmp_path, retained_body_bytes=body_bytes)

    composition = _build_future(api, tmp_path, state)

    assert bool(composition.http.subjects) is expected_http_subjects


@pytest.mark.parametrize(
    ("source_file", "expected_reference"),
    (
        ("assets/data.js", "assets/data.js"),
        ("nested/assets/data.js", "nested/assets/data.js"),
    ),
)
def test_future_adapter_canonicalises_project_local_source_paths(
    tmp_path: Path,
    source_file: str,
    expected_reference: str,
) -> None:
    api = _future_api()
    absolute = tmp_path / source_file
    absolute.parent.mkdir(parents=True, exist_ok=True)
    absolute.write_text("retained", encoding="utf-8")
    state = _project_state(tmp_path, encoded_source_file=str(absolute))

    composition = _build_future(api, tmp_path, state)
    encoded = next(
        item
        for item in composition.source_native.subjects
        if item.family is OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT
    )

    assert encoded.artefact_references == (expected_reference,)
    assert all(not Path(value).is_absolute() for value in encoded.artefact_references)


def test_future_adapter_rejects_backslash_source_file_without_requiring_file(
    tmp_path: Path,
) -> None:
    source_file = "assets\\data.js"
    assert not (tmp_path / source_file).exists()
    state = _project_state(tmp_path, encoded_source_file=source_file)
    api = _future_api()

    with pytest.raises(ValueError, match="unsafe|path|source_file"):
        _build_future(api, tmp_path, state)


@pytest.mark.parametrize("case", ("outside", "traversal", "symlink_escape"))
def test_future_adapter_rejects_source_paths_outside_project(
    tmp_path: Path,
    case: str,
) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.js"
    outside.write_text("outside", encoding="utf-8")
    if case == "outside":
        source_file = str(outside)
    elif case == "traversal":
        source_file = f"../{outside.name}"
        traversal_target = (tmp_path / source_file).resolve()
        assert outside.is_file()
        assert traversal_target == outside.resolve()
        assert not traversal_target.is_relative_to(tmp_path.resolve())
    else:
        link = tmp_path / "escape.js"
        link.symlink_to(outside)
        source_file = str(link)
    state = _project_state(tmp_path, encoded_source_file=source_file)
    api = _future_api()

    with pytest.raises(ValueError, match="path|project|outside|unsafe|symlink"):
        _build_future(api, tmp_path, state)


def test_future_adapter_is_offline_and_does_not_mutate_project_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _future_api()
    state = _project_state(tmp_path)
    before = deepcopy(state)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("project composition must remain offline")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)

    assert isinstance(_build_future(api, tmp_path, state), OperatorBriefComposition)
    assert state == before


# Future fresh Stage-010 integration contract.


@pytest.mark.parametrize(
    "profile",
    (PIPELINE_PROFILE, STANDARD_PIPELINE_PROFILE, DEEP_PIPELINE_PROFILE),
)
def test_future_pipeline_status_builds_and_persists_same_composition_once_before_presentation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
) -> None:
    _future_api()
    state = _project_state(tmp_path)
    composition = _closed_composition(tmp_path, state)
    source_collection, orchestration = _deep_authority()
    deep_outputs = (
        DeepPipelineOutputs(
            source_collection=source_collection,
            orchestration=orchestration,
        )
        if profile == DEEP_PIPELINE_PROFILE
        else DeepPipelineOutputs()
    )
    calls: list[tuple[str, object]] = []

    def build(**kwargs):
        calls.append(("build", kwargs))
        return composition

    def write(root: Path, supplied: OperatorBriefComposition) -> Path:
        calls.append(("write", supplied))
        assert root == tmp_path
        return root / OPERATOR_BRIEF_COMPOSITION_FILENAME

    def presentation(*args, **kwargs):
        calls.append(("presentation", None))
        assert [name for name, _value in calls].count("build") == 1
        assert [name for name, _value in calls].count("write") == 1
        return []

    monkeypatch.setattr(project_pipeline, "build_project_operator_brief_composition", build)
    monkeypatch.setattr(project_pipeline, "write_operator_brief_composition_artifact", write)
    monkeypatch.setattr(project_pipeline, "build_project_state", lambda _root: state)
    monkeypatch.setattr(project_pipeline, "_write_interpretation_report_if_needed", presentation)
    monkeypatch.setattr(project_pipeline, "build_recon_status", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        project_pipeline,
        "write_recon_status",
        lambda *_args, **_kwargs: (
            tmp_path / "recon_status.json",
            tmp_path / "recon_status.md",
        ),
    )

    _message, output_paths, _updates = _step_runners(
        _status_context(tmp_path, profile, deep_outputs=deep_outputs),
        None,
    )["PIPELINE-STEP-010"]()

    names = [name for name, _value in calls]
    assert names == ["build", "write", "presentation"]
    assert calls[1][1] is composition
    assert str(tmp_path / OPERATOR_BRIEF_COMPOSITION_FILENAME) in output_paths
    build_arguments = calls[0][1]
    assert build_arguments["project_state"] is state
    assert build_arguments["profile"] == profile
    if profile == DEEP_PIPELINE_PROFILE:
        assert build_arguments["deep_source_collection"] is source_collection
        assert build_arguments["deep_orchestration"] is orchestration
    else:
        assert build_arguments["deep_source_collection"] is None
        assert build_arguments["deep_orchestration"] is None


def test_future_pipeline_real_presentation_and_runbook_do_not_recreate_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir, state, context = _stage010_consumer_context(tmp_path)
    composition = _closed_composition(output_dir, state)
    monkeypatch.delitem(sys.modules, _FUTURE_MODULE, raising=False)
    assembly_calls: list[str] = []

    def forbidden_assembly(*args: object, **kwargs: object) -> object:
        assembly_calls.append("assemble")
        raise AssertionError("presentation must not assemble canonical semantics")

    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_assembly.assemble_operator_brief",
        forbidden_assembly,
    )
    api = _future_api()
    monkeypatch.setattr(
        api.module,
        "assemble_operator_brief",
        forbidden_assembly,
        raising=False,
    )
    monkeypatch.setattr(
        project_pipeline,
        "assemble_operator_brief",
        forbidden_assembly,
        raising=False,
    )
    calls: list[tuple[str, object]] = []
    consumers: list[str] = []

    def build(**kwargs):
        calls.append(("build", kwargs))
        return composition

    def write(root: Path, supplied: OperatorBriefComposition) -> Path:
        calls.append(("write", supplied))
        assert supplied is composition
        return root / OPERATOR_BRIEF_COMPOSITION_FILENAME

    real_write_project_outputs = project_pipeline.write_project_outputs
    real_build_recon_status = project_pipeline.build_recon_status
    real_build_project_runbook = project_pipeline.build_project_runbook

    def write_presentation(*args, **kwargs):
        consumers.append("markdown")
        return real_write_project_outputs(*args, **kwargs)

    def build_status(*args, **kwargs):
        consumers.append("status")
        return real_build_recon_status(*args, **kwargs)

    def build_runbook(*args, **kwargs):
        consumers.append("runbook")
        return real_build_project_runbook(*args, **kwargs)

    monkeypatch.setattr(project_pipeline, "build_project_operator_brief_composition", build)
    monkeypatch.setattr(project_pipeline, "write_operator_brief_composition_artifact", write)
    monkeypatch.setattr(project_pipeline, "build_project_state", lambda _root: state)
    monkeypatch.setattr(
        "bugslyce.recon.status.build_project_state",
        lambda _root: state,
    )
    monkeypatch.setattr(project_pipeline, "write_project_outputs", write_presentation)
    monkeypatch.setattr(project_pipeline, "build_recon_status", build_status)
    monkeypatch.setattr(project_pipeline, "build_project_runbook", build_runbook)
    runners = _step_runners(context, None)

    _message, output_paths, _updates = runners["PIPELINE-STEP-010"]()
    runners["PIPELINE-STEP-011"]()

    assert [name for name, _value in calls] == ["build", "write"]
    assert calls[1][1] is composition
    assert consumers == ["markdown", "status", "runbook"]
    assert assembly_calls == []
    assert str(output_dir / OPERATOR_BRIEF_COMPOSITION_FILENAME) in output_paths


def test_future_pipeline_stage010_composition_failure_uses_existing_failed_step_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _future_api()
    scaffold = scaffold_project("stage6c-failure", "10.10.10.10", tmp_path / "projects")
    project_file = Path(scaffold.project_file)

    def fail_build(**kwargs):
        raise ValueError("canonical Operator Brief composition failed")

    monkeypatch.setattr(project_pipeline, "build_project_operator_brief_composition", fail_build)
    monkeypatch.setattr(
        project_pipeline,
        "write_operator_brief_composition_artifact",
        lambda *args, **kwargs: pytest.fail("writer must not run after composition failure"),
    )
    monkeypatch.setattr(project_pipeline, "enforce_project_execution_policy", lambda *args: None)
    monkeypatch.setattr(project_pipeline, "build_doctor_report", lambda: object())
    monkeypatch.setattr(
        project_pipeline,
        "_validate_pipeline",
        lambda *args, **kwargs: SimpleNamespace(
            skipped_step_ids=frozenset(),
            preserve_canonical_pipeline_metadata=False,
            prior_pipeline=None,
        ),
    )
    monkeypatch.setattr(project_pipeline, "_write_project_pipeline_checkpoint", lambda *args: None)
    monkeypatch.setattr(
        project_pipeline,
        "_reconcile_failed_pipeline_outputs",
        lambda result, *args, **kwargs: result,
    )
    monkeypatch.setattr(
        project_pipeline,
        "_write_interpretation_report_if_needed",
        lambda *args, **kwargs: pytest.fail("presentation must follow canonical creation"),
    )

    def controlled_runners(context, clock, **kwargs):
        real = _step_runners(context, clock, **kwargs)
        return {
            step_id: (
                runner
                if step_id == "PIPELINE-STEP-010"
                else (lambda: ("controlled offline phase", [], {}))
            )
            for step_id, runner in real.items()
        }

    monkeypatch.setattr(project_pipeline, "_step_runners", controlled_runners)

    with pytest.raises(ProjectPipelineFailed) as exc_info:
        run_project_pipeline(project_file, PIPELINE_PROFILE)

    assert exc_info.value.result.failed_step == "PIPELINE-STEP-010"
    failed = next(
        item
        for item in exc_info.value.result.steps
        if item.step_id == "PIPELINE-STEP-010"
    )
    assert failed.status == "failed"
    assert "canonical Operator Brief composition failed" in failed.message
