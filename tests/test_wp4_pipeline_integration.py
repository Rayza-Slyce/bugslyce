"""WP4 pipeline integration contracts over the real project step runners."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import bugslyce.project_pipeline as pipeline
import bugslyce.recon.recursive_evidence_feedback as recursive_feedback
from bugslyce.recon.content_plan import (
    CONTENT_DISCOVERY_TINY_PROFILE,
    DEEP_BOUNDED_CORE_PROFILE,
    STANDARD_BOUNDED_CORE_PROFILE,
)
from bugslyce.core.project import build_project_state as build_real_project_state
from bugslyce.recon.content_followup import select_content_followup_urls
from bugslyce.recon.content_run import ContentBaselineDecision
from bugslyce.recon.deep_html_route_extraction import (
    build_deep_html_route_extraction,
)
from bugslyce.recon.deep_initial_retained_javascript_route_extraction import (
    empty_deep_initial_retained_javascript_route_extraction,
)
from bugslyce.recon.deep_javascript_route_extraction import (
    build_deep_javascript_route_extraction,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.http_enforcement import HTTPRateRejected
from bugslyce.recon.native_content_discovery import (
    NativeContentDiscoveryArtifact,
    NativeContentDiscoveryBaselineRefused,
    NativeContentDiscoveryLimits,
    NativeContentDiscoveryPlan,
    NativeContentDiscoveryRequest,
    NativeContentDiscoveryResult,
)
from bugslyce.recon.programme_orchestration import (
    build_programme_orchestration_plan,
)

from test_native_content_discovery import _executor, _runtime
from test_recursive_evidence_feedback import (
    _empty_metadata_collection,
    _metadata_collection,
    _root_plan,
    _sitemap_item,
    _state_with_evidence,
)


def _pipeline_context(
    tmp_path: Path,
    runtime,
    *,
    profile: str = pipeline.DEEP_PIPELINE_PROFILE,
) -> dict[str, object]:
    output_dir = Path(runtime.project.output_dir)
    return {
        "project_file": output_dir / "bugslyce_project.json",
        "scope_file": Path(runtime.project.scope_file),
        "output_dir": output_dir,
        "plan_dir": tmp_path / "content-plan",
        "plan_path": tmp_path / "content-plan" / "content_discovery_plan.json",
        "export_path": tmp_path / "evidence-pack.zip",
        "published_export_path": None,
        "target": runtime.project.target,
        "resume": False,
        "profile": profile,
        "deep_outputs": pipeline.DeepPipelineOutputs(),
        "project_runtime": runtime,
    }


def _empty_source_collection() -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=(),
        skipped=(),
        total_considered=0,
        total_collected=0,
        total_skipped=0,
    )


def _patch_deep_inputs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    state,
    source_collection: DeepSourceRouteCollectionResult,
    metadata_collection,
    written_sources: list[DeepSourceRouteCollectionResult] | None = None,
    fetcher_executors: list[object] | None = None,
) -> None:
    monkeypatch.setattr(pipeline, "build_project_state", lambda _path: state)
    monkeypatch.setattr(
        pipeline,
        "build_deep_collection_request_plan_from_project_state",
        lambda *_args, **_kwargs: SimpleNamespace(),
    )
    def build_fetcher(*_args, **kwargs):
        if fetcher_executors is not None:
            fetcher_executors.append(kwargs.get("executor"))
        return lambda *_args, **_kwargs: pytest.fail(
            "the patched empty Deep input must not fetch"
        )

    monkeypatch.setattr(pipeline, "build_deep_http_fetcher", build_fetcher)
    monkeypatch.setattr(
        pipeline,
        "collect_deep_source_routes_from_plan",
        lambda _plan, *, fetcher: source_collection,
    )
    monkeypatch.setattr(
        pipeline,
        "_deep_plan_for_source",
        lambda _plan, _source: SimpleNamespace(),
    )
    monkeypatch.setattr(
        pipeline,
        "collect_deep_metadata_from_plan",
        lambda _plan, *, fetcher: metadata_collection,
    )

    def write_source(result, output_dir):
        if written_sources is not None:
            written_sources.append(result)
        return (
            output_dir / "deep_source_route_collection.md",
            output_dir / "deep_source_route_collection.json",
        )

    monkeypatch.setattr(
        pipeline,
        "write_deep_source_route_collection_artifacts",
        write_source,
    )
    monkeypatch.setattr(
        pipeline,
        "write_deep_metadata_collection_artifacts",
        lambda _result, output_dir: (
            output_dir / "deep_metadata_collection.md",
            output_dir / "deep_metadata_collection.json",
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "build_deep_initial_retained_javascript_route_extraction",
        lambda *_args, **_kwargs: (
            empty_deep_initial_retained_javascript_route_extraction()
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "write_deep_recon_orchestration_artifacts",
        lambda _result, output_dir, **_kwargs: (
            output_dir / "deep_recon_review.md",
            output_dir / "deep_recon_runbook.md",
            output_dir / "deep_recon_orchestration.json",
        ),
    )


@pytest.mark.parametrize(
    ("pipeline_profile", "content_profile", "per_origin_limit"),
    (
        (
            pipeline.PIPELINE_PROFILE,
            CONTENT_DISCOVERY_TINY_PROFILE,
            25,
        ),
        (
            pipeline.STANDARD_PIPELINE_PROFILE,
            STANDARD_BOUNDED_CORE_PROFILE,
            220,
        ),
        (
            pipeline.DEEP_PIPELINE_PROFILE,
            DEEP_BOUNDED_CORE_PROFILE,
            1753,
        ),
    ),
)
def test_pipeline_content_execution_uses_native_root_plan_and_registers_internal_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline_profile: str,
    content_profile: str,
    per_origin_limit: int,
) -> None:
    runtime = _runtime(tmp_path / "runtime")
    state = _state_with_evidence(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    context = _pipeline_context(tmp_path, runtime, profile=pipeline_profile)
    manifest_path = Path(runtime.project.output_dir) / "recon_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": runtime.project.target,
                "artifacts": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    observed: dict[str, object] = {}
    progress_events: list[object] = []

    monkeypatch.setattr(pipeline, "build_project_state", lambda _path: state)
    monkeypatch.setattr(
        pipeline,
        "build_programme_orchestration_plan",
        lambda actual_runtime, actual_state: orchestration,
        raising=False,
    )

    def build_native_plan(
        actual_runtime,
        actual_state,
        actual_orchestration,
        *,
        profile,
        limits,
    ):
        observed["build_inputs"] = (
            actual_runtime,
            actual_state,
            actual_orchestration,
            profile,
            limits,
        )
        plan = NativeContentDiscoveryPlan(
            profile=profile,
            limits=limits,
            baseline_requests_per_origin=3,
            candidate_requests_planned=1,
            requests=(
                NativeContentDiscoveryRequest(
                    url="https://app.example.test/health",
                    canonical_origin="https://app.example.test",
                    depth=0,
                    selection_reason="profile_wordlist",
                    evidence_ids=(),
                ),
            ),
        )
        observed["root_plan"] = plan
        return plan

    def run_native(
        actual_runtime,
        actual_state,
        actual_orchestration,
        actual_plan,
        *,
        output_dir,
        progress_callback,
        **_kwargs,
    ):
        observed["progress_callback"] = progress_callback
        progress_callback(SimpleNamespace(completed=1, total=1))
        observed["run_inputs"] = (
            actual_runtime,
            actual_state,
            actual_orchestration,
            actual_plan,
            output_dir,
        )
        artifact_path = output_dir / (
            "content-discovery-internal-https-app.example.test-443-root.txt"
        )
        baseline_path = output_dir / "content_discovery_baseline.json"
        artifact_path.write_text("/health (Status: 200) [Size: 2]\n", encoding="utf-8")
        baseline_path.write_text('{"schema_version": "1.0"}\n', encoding="utf-8")
        result = NativeContentDiscoveryResult(
            external_commands_started=0,
            origin_results=(),
            artifacts=(
                NativeContentDiscoveryArtifact(
                    artifact_type="content_discovery_internal",
                    canonical_origin="https://app.example.test",
                    profile=actual_plan.profile,
                    selection_reason="profile_wordlist",
                    path=artifact_path,
                ),
            ),
            baseline_artifact_path=baseline_path,
        )
        observed["root_result"] = result
        return result

    monkeypatch.setattr(
        pipeline,
        "build_native_content_discovery_plan",
        build_native_plan,
        raising=False,
    )
    monkeypatch.setattr(
        pipeline,
        "run_native_content_discovery",
        run_native,
        raising=False,
    )
    message, output_paths, _updates = pipeline._step_runners(
        context,
        None,
        gobuster_progress_callback=progress_events.append,
    )["PIPELINE-STEP-007"]()

    build_inputs = observed["build_inputs"]
    limits = build_inputs[4]
    assert isinstance(limits, NativeContentDiscoveryLimits)
    assert limits.maximum_candidate_requests_per_origin == per_origin_limit
    assert limits.maximum_total_candidate_requests == 4096
    assert build_inputs[:4] == (
        runtime,
        state,
        orchestration,
        content_profile,
    )
    assert observed["run_inputs"] == (
        runtime,
        state,
        orchestration,
        observed["root_plan"],
        Path(runtime.project.output_dir),
    )
    assert observed["progress_callback"] is not None
    assert len(progress_events) == 1
    assert progress_events[0].completed == progress_events[0].total == 1
    assert context["wp4_root_plan"] is observed["root_plan"]
    assert context["wp4_root_result"] is observed["root_result"]
    assert context["wp4_programme_orchestration"] is orchestration
    assert "native" in message.lower()
    assert len(output_paths) == 2
    assert Path(output_paths[1]).name == "content_discovery_baseline.json"
    assert observed["root_result"].external_commands_started == 0
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["artifacts"][-2] == {
        "type": "content_discovery_internal",
        "file": Path(output_paths[0]).name,
        "base_url": "https://app.example.test",
        "description": "BugSlyce-native bounded root content discovery",
        "tags": ["profile_wordlist", "wp4a_native"],
    }
    assert manifest["artifacts"][-1] == {
        "type": "content_discovery_baseline",
        "file": "content_discovery_baseline.json",
        "description": (
            "BugSlyce-native structured negative-response baseline provenance"
        ),
        "tags": ["native_baseline", "wp4a_native"],
    }
    parsed_state = build_real_project_state(Path(runtime.project.output_dir))
    considered, selected = select_content_followup_urls(
        parsed_state,
        runtime.project.target,
        manifest,
    )
    assert considered == 1
    assert selected == ["https://app.example.test/health"]
    assert parsed_state.discovered_paths[0].tags == [
        "profile_wordlist",
        "wp4a_native",
    ]


def test_deep_pipeline_threads_exact_typed_evidence_into_one_recursive_pass_and_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path / "runtime")
    state = _state_with_evidence(runtime, "EVID-SITEMAP-DOCS")
    root_plan = _root_plan()
    metadata = _metadata_collection(
        _sitemap_item(
            routes=("https://app.example.test/docs/websocket",),
            evidence_ids=("EVID-SITEMAP-DOCS",),
        )
    )
    source = _empty_source_collection()
    orchestration = build_programme_orchestration_plan(runtime, state)
    context = _pipeline_context(tmp_path, runtime)
    context["wp4_root_plan"] = root_plan
    context["wp4_programme_orchestration"] = orchestration
    written_sources: list[DeepSourceRouteCollectionResult] = []
    fetcher_executors: list[object] = []
    _patch_deep_inputs(
        monkeypatch,
        state=state,
        source_collection=source,
        metadata_collection=metadata,
        written_sources=written_sources,
        fetcher_executors=fetcher_executors,
    )
    observed: dict[str, object] = {}
    deep_executor = object()
    monkeypatch.setattr(
        pipeline,
        "build_programme_orchestration_http_executor",
        lambda actual_runtime, actual_state, actual_plan: (
            observed.setdefault(
                "deep_executor_inputs",
                (actual_runtime, actual_state, actual_plan),
            ),
            deep_executor,
        )[1],
        raising=False,
    )
    real_build_html = build_deep_html_route_extraction
    real_build_javascript = build_deep_javascript_route_extraction
    real_build_shallow = pipeline.build_deep_shallow_route_followup_plan

    def build_html(actual_source):
        result = real_build_html(actual_source)
        if actual_source is source:
            observed["html_extraction"] = result
        return result

    def build_javascript(actual_source):
        result = real_build_javascript(actual_source)
        if actual_source is source:
            observed["javascript_extraction"] = result
        return result

    def build_shallow(actual_html, actual_javascript, **kwargs):
        observed["shallow_planner_kwargs"] = kwargs
        return real_build_shallow(actual_html, actual_javascript, **kwargs)

    monkeypatch.setattr(pipeline, "build_deep_html_route_extraction", build_html)
    monkeypatch.setattr(
        pipeline,
        "build_deep_javascript_route_extraction",
        build_javascript,
    )
    monkeypatch.setattr(
        pipeline,
        "build_deep_shallow_route_followup_plan",
        build_shallow,
    )
    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        lambda _url: (
            200,
            b'<html><a href="/api/websocket">WebSocket API</a></html>',
        ),
    )
    monkeypatch.setattr(
        recursive_feedback,
        "build_native_content_discovery_http_executor",
        lambda *_args, **_kwargs: executor,
    )
    monkeypatch.setattr(
        pipeline,
        "build_programme_orchestration_plan",
        lambda actual_runtime, actual_state: orchestration,
        raising=False,
    )

    def build_recursive(*args, **kwargs):
        observed["planner_args"] = args
        observed["planner_kwargs"] = kwargs
        return recursive_feedback.build_recursive_evidence_feedback_plan(*args, **kwargs)

    def run_recursive(*args, **kwargs):
        observed["runner_args"] = args
        observed["runner_kwargs"] = kwargs
        result = recursive_feedback.run_recursive_evidence_feedback(*args, **kwargs)
        observed["recursive_result"] = result
        return result

    monkeypatch.setattr(
        pipeline,
        "build_recursive_evidence_feedback_plan",
        build_recursive,
        raising=False,
    )
    monkeypatch.setattr(
        pipeline,
        "run_recursive_evidence_feedback",
        run_recursive,
        raising=False,
    )

    runners = pipeline._step_runners(context, None)
    runners["PIPELINE-STEP-010D"]()
    runners["PIPELINE-STEP-011D"]()

    assert observed["deep_executor_inputs"] == (runtime, state, orchestration)
    assert fetcher_executors == [deep_executor]
    assert observed["shallow_planner_kwargs"]["materialised_origins"] == tuple(
        item.canonical_origin for item in orchestration.http_work_items
    )
    assert tuple(request.url for request in transport.requests) == (
        "https://app.example.test/docs/websocket",
    )
    planner_kwargs = observed["planner_kwargs"]
    assert planner_kwargs["root_plan"] is root_plan
    assert planner_kwargs["metadata_collection"] is metadata
    assert planner_kwargs["html_extraction"] is observed["html_extraction"]
    assert planner_kwargs["javascript_extraction"] is observed[
        "javascript_extraction"
    ]
    assert planner_kwargs["limits"] == recursive_feedback.RecursiveEvidenceFeedbackLimits(
        maximum_total_candidate_requests=800,
        maximum_candidate_requests_per_origin=100,
        maximum_depth=1,
    )
    runner_kwargs = observed["runner_kwargs"]
    assert runner_kwargs["root_plan"] is root_plan
    assert runner_kwargs["metadata_collection"] is metadata
    outputs = context["deep_outputs"]
    assert isinstance(outputs, pipeline.DeepPipelineOutputs)
    assert outputs.recursive_feedback_result is observed["recursive_result"]
    assert outputs.recursive_feedback_result.external_commands_started == 0
    assert outputs.recursive_feedback_result.collected[0].evidence_ids == (
        "EVID-SITEMAP-DOCS",
    )
    assert outputs.source_collection.total_collected == 1
    assert outputs.source_collection.collected[0].url == (
        "https://app.example.test/docs/websocket"
    )
    assert outputs.source_collection.collected[0].elapsed_seconds == (
        outputs.recursive_feedback_result.collected[0].elapsed_seconds
    )
    assert written_sources[-1] is outputs.source_collection
    routes = outputs.orchestration.html_route_extraction.routes
    assert tuple(route.safe_resolved_url for route in routes) == (
        "https://app.example.test/api/websocket",
    )
    assert routes[0].evidence_ids == ("EVID-SITEMAP-DOCS",)
    executor.close()


@pytest.mark.parametrize(
    ("routes", "expected_reason"),
    (
        ((), None),
        (("https://ghost.example.test/docs",), "unmaterialised_origin"),
    ),
)
def test_pipeline_recursive_no_work_and_unmaterialised_evidence_never_contact_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    routes: tuple[str, ...],
    expected_reason: str | None,
) -> None:
    runtime = _runtime(tmp_path / "runtime")
    state = _state_with_evidence(runtime, "EVID-LATER")
    metadata = (
        _metadata_collection(
            _sitemap_item(routes=routes, evidence_ids=("EVID-LATER",))
        )
        if routes
        else _empty_metadata_collection()
    )
    orchestration = build_programme_orchestration_plan(runtime, state)
    context = _pipeline_context(tmp_path, runtime)
    context["wp4_root_plan"] = _root_plan()
    context["wp4_programme_orchestration"] = orchestration
    _patch_deep_inputs(
        monkeypatch,
        state=state,
        source_collection=_empty_source_collection(),
        metadata_collection=metadata,
    )
    executor, transport = _executor(
        runtime,
        ("https://app.example.test",),
        lambda _url: pytest.fail("ineligible recursive evidence must not be contacted"),
    )
    monkeypatch.setattr(
        recursive_feedback,
        "build_native_content_discovery_http_executor",
        lambda *_args, **_kwargs: executor,
    )
    monkeypatch.setattr(
        pipeline,
        "build_programme_orchestration_plan",
        lambda *_args, **_kwargs: orchestration,
        raising=False,
    )
    monkeypatch.setattr(
        pipeline,
        "build_recursive_evidence_feedback_plan",
        recursive_feedback.build_recursive_evidence_feedback_plan,
        raising=False,
    )
    monkeypatch.setattr(
        pipeline,
        "run_recursive_evidence_feedback",
        recursive_feedback.run_recursive_evidence_feedback,
        raising=False,
    )

    pipeline._step_runners(context, None)["PIPELINE-STEP-010D"]()

    outputs = context["deep_outputs"]
    assert outputs.recursive_feedback_plan.requests == ()
    assert outputs.recursive_feedback_result.requests_attempted == 0
    assert outputs.recursive_feedback_result.external_commands_started == 0
    assert transport.requests == []
    reasons = tuple(decision.reason for decision in outputs.recursive_feedback_plan.decisions)
    assert reasons == (() if expected_reason is None else (expected_reason,))
    executor.close()


def test_pipeline_native_root_failure_propagates_without_legacy_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path / "runtime")
    state = _state_with_evidence(runtime)
    orchestration = build_programme_orchestration_plan(runtime, state)
    context = _pipeline_context(tmp_path, runtime)
    root_plan = _root_plan()
    manifest_path = Path(runtime.project.output_dir) / "recon_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": runtime.project.target,
                "artifacts": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    baseline_path = Path(runtime.project.output_dir) / "content_discovery_baseline.json"
    baseline_path.write_text('{"schema_version": "1.0"}\n', encoding="utf-8")
    refusal = NativeContentDiscoveryBaselineRefused(
        baseline_path,
        (
            ContentBaselineDecision(
                origin="https://app.example.test",
                classification="failed",
                selected_policy="refuse",
                required_observations=3,
                completed_observations=0,
                observations=(),
                failure_or_instability_reason="synthetic root refusal",
                limitations=("No candidate collection occurred.",),
            ),
        )
    )
    monkeypatch.setattr(pipeline, "build_project_state", lambda _path: state)
    monkeypatch.setattr(
        pipeline,
        "build_programme_orchestration_plan",
        lambda *_args, **_kwargs: orchestration,
        raising=False,
    )
    monkeypatch.setattr(
        pipeline,
        "build_native_content_discovery_plan",
        lambda *_args, **_kwargs: root_plan,
        raising=False,
    )
    monkeypatch.setattr(
        pipeline,
        "run_native_content_discovery",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(refusal),
        raising=False,
    )
    with pytest.raises(NativeContentDiscoveryBaselineRefused) as raised:
        pipeline._step_runners(context, None)["PIPELINE-STEP-007"]()

    assert raised.value is refusal
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["artifacts"] == [
        {
            "type": "content_discovery_baseline",
            "file": "content_discovery_baseline.json",
            "description": (
                "BugSlyce-native structured negative-response baseline provenance"
            ),
            "tags": ["native_baseline", "wp4a_native"],
        }
    ]


def test_pipeline_recursive_rate_rejection_propagates_from_deep_collection_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path / "runtime")
    state = _state_with_evidence(runtime, "EVID-RATE")
    metadata = _metadata_collection(
        _sitemap_item(
            routes=("https://app.example.test/docs",),
            evidence_ids=("EVID-RATE",),
        )
    )
    orchestration = build_programme_orchestration_plan(runtime, state)
    context = _pipeline_context(tmp_path, runtime)
    context["wp4_root_plan"] = _root_plan()
    context["wp4_programme_orchestration"] = orchestration
    _patch_deep_inputs(
        monkeypatch,
        state=state,
        source_collection=_empty_source_collection(),
        metadata_collection=metadata,
    )
    monkeypatch.setattr(
        pipeline,
        "build_programme_orchestration_plan",
        lambda *_args, **_kwargs: orchestration,
        raising=False,
    )
    monkeypatch.setattr(
        pipeline,
        "build_recursive_evidence_feedback_plan",
        recursive_feedback.build_recursive_evidence_feedback_plan,
        raising=False,
    )
    rejection = HTTPRateRejected("60")
    monkeypatch.setattr(
        pipeline,
        "run_recursive_evidence_feedback",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(rejection),
        raising=False,
    )

    with pytest.raises(HTTPRateRejected) as raised:
        pipeline._step_runners(context, None)["PIPELINE-STEP-010D"]()

    assert raised.value is rejection
