"""WP5D normal-pipeline application/service model integration tests."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from bugslyce import project_pipeline as pipeline
from bugslyce.core.models import DiscoveredPath
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.http_route_relationships import (
    HttpRouteRelationshipEdge,
    build_http_redirect_relationship_edges,
)


def _source_item(url: str, body: bytes, evidence_id: str) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=(("Content-Type", "text/html"),),
        body_preview=body.decode("utf-8"),
        body_sha256=sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.1,
        source="fixture",
        reason="fixture",
        evidence_ids=(evidence_id,),
        body=body,
    )


def _collection(*items: DeepSourceRouteCollectedItem) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=items,
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _context(tmp_path: Path, *, runtime: object | None = None) -> dict[str, object]:
    return {
        "output_dir": tmp_path,
        "scope_file": tmp_path / "scope.md",
        "plan_dir": tmp_path / "plan",
        "plan_path": tmp_path / "plan" / "content_discovery_plan.json",
        "export_path": tmp_path / "evidence-pack.zip",
        "target": "example.test",
        "project_file": tmp_path / "project.json",
        "resume": False,
        "profile": pipeline.DEEP_PIPELINE_PROFILE,
        "project_runtime": runtime,
        "deep_outputs": pipeline.DeepPipelineOutputs(),
    }


def test_public_redirect_edge_producer_preserves_direct_semantics_and_cluster_reuses_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = SimpleNamespace(
        discovered_paths=(
            DiscoveredPath(
                url="https://api.example.test/start",
                status_code=302,
                content_length=0,
                redirect_location="/login",
                source="fixture.txt",
                evidence_ids=["EVID-REDIRECT"],
                tags=[],
            ),
        ),
        input_dir="/tmp",
        http_artifacts=(),
    )

    direct = build_http_redirect_relationship_edges(
        state,
        source_collection=None,
    )

    assert direct == (
        HttpRouteRelationshipEdge(
            edge_type="redirect",
            source_url="https://api.example.test/start",
            target_url="https://api.example.test/login",
            evidence_ids=("EVID-REDIRECT",),
            artefact_references=("fixture.txt",),
            raw_references=("/login",),
            status_code=302,
        ),
    )

    observed: list[tuple[object, object]] = []
    monkeypatch.setattr(
        "bugslyce.recon.http_route_relationships.build_http_redirect_relationship_edges",
        lambda project_state, *, source_collection: observed.append(
            (project_state, source_collection)
        )
        or (),
    )
    from bugslyce.recon.http_route_relationships import (
        build_http_route_relationship_clusters,
    )

    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(),
    ) == ()
    assert observed == [(state, None)]


def test_deep_collection_builds_persists_and_hands_one_exact_model_to_html(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial = _collection(
        _source_item(
            "https://docs.example.test/initial",
            b"<html>initial</html>",
            "EVID-INITIAL",
        )
    )
    recursive_body = b"<html>recursive</html>"
    recursive_response = SimpleNamespace(
        request=SimpleNamespace(url="https://docs.example.test/recursive"),
        status_code=200,
        final_url="https://docs.example.test/recursive",
        headers=(("Content-Type", "text/html"),),
        body_bytes=len(recursive_body),
        body_sha256=sha256(recursive_body).hexdigest(),
        elapsed_seconds=0.2,
        evidence_ids=("EVID-RECURSIVE",),
        body=recursive_body,
    )
    state = SimpleNamespace(discovered_paths=(), http_artifacts=(), input_dir=str(tmp_path))
    metadata = object()
    html_routes = object()
    javascript_routes = object()
    shallow_followups = object()
    redirect_edges = (object(),)
    application_composition = object()
    documentation_assertions = object()
    application_service_model = object()
    calls: dict[str, list[object]] = {
        "a1": [], "a2": [], "a3": [], "persist": [], "html": [], "source_write": [],
    }
    runtime = SimpleNamespace(programme_scope_policy=None, http_executor=None)
    context = _context(tmp_path, runtime=runtime)
    context["wp4_root_plan"] = object()
    context["wp4_programme_orchestration"] = object()

    monkeypatch.setattr(pipeline, "build_project_state", lambda _root: state)
    monkeypatch.setattr(
        pipeline,
        "build_deep_collection_request_plan_from_project_state",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(pipeline, "build_deep_http_fetcher", lambda **_kwargs: object())
    monkeypatch.setattr(
        pipeline,
        "collect_deep_source_routes_from_plan",
        lambda *_args, **_kwargs: initial,
    )
    monkeypatch.setattr(pipeline, "_deep_plan_for_source", lambda *_args: object())
    monkeypatch.setattr(
        pipeline,
        "collect_deep_metadata_from_plan",
        lambda *_args, **_kwargs: metadata,
    )
    monkeypatch.setattr(
        pipeline,
        "write_deep_metadata_collection_artifacts",
        lambda _value, root: _write_paths(
            root,
            "deep_metadata_collection.md",
            "deep_metadata_collection.json",
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "build_deep_html_route_extraction",
        lambda value: _same(value, initial, html_routes),
    )
    monkeypatch.setattr(
        pipeline,
        "build_deep_javascript_route_extraction",
        lambda value: _same(value, initial, javascript_routes),
    )
    monkeypatch.setattr(
        pipeline,
        "build_deep_shallow_route_followup_plan",
        lambda html, javascript, **_kwargs: _same_pair(
            html, html_routes, javascript, javascript_routes, object()
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "collect_deep_shallow_route_followups",
        lambda *_args, **_kwargs: shallow_followups,
    )
    monkeypatch.setattr(pipeline, "NativeContentDiscoveryPlan", object)
    monkeypatch.setattr(pipeline, "ProgrammeOrchestrationPlan", object)
    monkeypatch.setattr(pipeline, "BugBountyProjectRuntime", object)
    monkeypatch.setattr(
        pipeline,
        "build_recursive_evidence_feedback_plan",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        pipeline,
        "run_recursive_evidence_feedback",
        lambda *_args, **_kwargs: SimpleNamespace(collected=(recursive_response,)),
    )
    def write_source(value: object, root: Path) -> tuple[Path, ...]:
        calls["source_write"].append(value)
        return _write_paths(
            root,
            "deep_source_route_collection.md",
            "deep_source_route_collection.json",
        )

    monkeypatch.setattr(
        pipeline,
        "write_deep_source_route_collection_artifacts",
        write_source,
    )
    monkeypatch.setattr(
        pipeline,
        "build_http_redirect_relationship_edges",
        lambda project_state, *, source_collection: _redirect_edges(
            project_state, state, source_collection, initial, redirect_edges
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "build_application_service_composition",
        lambda **kwargs: calls["a1"].append(kwargs) or application_composition,
    )
    monkeypatch.setattr(
        pipeline,
        "build_documentation_assertions",
        lambda value: calls["a2"].append(value) or documentation_assertions,
    )
    monkeypatch.setattr(
        pipeline,
        "build_application_service_model",
        lambda **kwargs: calls["a3"].append(kwargs) or application_service_model,
    )

    def persist(root: Path, model: object) -> Path:
        calls["persist"].append(model)
        path = root / "application_service_model.json"
        path.write_text("fixture\n", encoding="utf-8")
        return path

    monkeypatch.setattr(pipeline, "write_application_service_model_artifact", persist)
    runners = pipeline._step_runners(context, None)
    _message, collection_paths, _updates = runners["PIPELINE-STEP-010D"]()

    final_collection = calls["a2"][0]
    assert final_collection is not initial
    assert calls["source_write"] == [final_collection]
    assert tuple(item.url for item in final_collection.collected) == (
        "https://docs.example.test/initial",
        "https://docs.example.test/recursive",
    )
    assert calls["a1"] == [
        {
            "redirect_edges": redirect_edges,
            "metadata_collection": metadata,
            "html_extraction": html_routes,
            "javascript_extraction": javascript_routes,
        }
    ]
    assert calls["a3"] == [
        {
            "application_composition": application_composition,
            "documentation_assertions": documentation_assertions,
        }
    ]
    assert calls["persist"] == [application_service_model]
    assert "application_service_model.json" in {Path(path).name for path in collection_paths}
    outputs = context["deep_outputs"]
    assert isinstance(outputs, pipeline.DeepPipelineOutputs)
    assert outputs.application_service_model is application_service_model

    orchestration_paths = _write_paths(
        tmp_path,
        "deep_recon_review.md",
        "deep_recon_runbook.md",
        "deep_recon_orchestration.json",
    )
    context["deep_outputs"] = replace(
        outputs,
        deep_artifact_paths=(
            *outputs.deep_artifact_paths[:-1],
            *orchestration_paths,
            outputs.deep_artifact_paths[-1],
        ),
    )
    monkeypatch.setattr(pipeline, "_evidence_pack_reference_requirements", lambda *_args: ())
    monkeypatch.setattr(
        pipeline,
        "write_project_html_report",
        lambda _root, *, application_service_model: calls["html"].append(
            application_service_model
        )
        or _root / "report.html",
    )
    monkeypatch.setattr(
        pipeline,
        "export_recon_evidence_pack",
        lambda _root, output, **_kwargs: SimpleNamespace(output_path=str(output)),
    )
    runners["PIPELINE-STEP-012"]()
    assert calls["html"] == [application_service_model]


@pytest.mark.parametrize(
    ("shape", "expect_model"),
    (("legacy", False), ("pre_wp5d", False), ("current", True)),
)
def test_completed_deep_resume_keeps_old_shapes_and_requires_current_model(
    tmp_path: Path,
    shape: str,
    expect_model: bool,
) -> None:
    names = {
        "legacy": pipeline.LEGACY_DEEP_FIXED_ARTEFACT_FILENAMES,
        "pre_wp5d": pipeline.PRE_WP5D_DEEP_FIXED_ARTEFACT_FILENAMES,
        "current": pipeline.DEEP_FIXED_ARTEFACT_FILENAMES,
    }[shape]
    export_path = tmp_path / "evidence-pack.zip"
    export_path.write_text("pack", encoding="utf-8")
    for name in (*names, "report.md", "recon_status.md", "recon_status.json", "runbook.md"):
        (tmp_path / name).write_text(name, encoding="utf-8")
    prior = {
        "profile": pipeline.DEEP_PIPELINE_PROFILE,
        "final_status": "completed",
        "export_path": str(export_path),
        "steps": [
            {
                "step_id": "PIPELINE-STEP-010D",
                "output_paths": [str(tmp_path / name) for name in names],
            }
        ],
    }
    statuses = {
        step_id: "completed"
        for step_id in (
            "PIPELINE-STEP-010D", "PIPELINE-STEP-011D", "PIPELINE-STEP-010",
            "PIPELINE-STEP-011", "PIPELINE-STEP-012",
        )
    }

    assert pipeline._deep_completed_resume_verified(
        output_dir=tmp_path,
        export_path=export_path,
        prior_pipeline=prior,
        prior_statuses=statuses,
    )
    if expect_model:
        (tmp_path / "application_service_model.json").unlink()
        assert not pipeline._deep_completed_resume_verified(
            output_dir=tmp_path,
            export_path=export_path,
            prior_pipeline=prior,
            prior_statuses=statuses,
        )


def test_fresh_deep_run_rejects_stale_application_service_model(tmp_path: Path) -> None:
    (tmp_path / "application_service_model.json").write_text("stale", encoding="utf-8")

    with pytest.raises(ValueError, match="application_service_model.json"):
        pipeline._reject_existing_deep_fixed_artefacts(tmp_path)


def _write_paths(root: Path, *names: str) -> tuple[Path, ...]:
    paths = tuple(root / name for name in names)
    for path in paths:
        path.write_text(path.name, encoding="utf-8")
    return paths


def _same(value: object, expected: object, result: object) -> object:
    assert value is expected
    return result


def _same_pair(
    first: object,
    expected_first: object,
    second: object,
    expected_second: object,
    result: object,
) -> object:
    assert first is expected_first
    assert second is expected_second
    return result


def _redirect_edges(
    project_state: object,
    expected_state: object,
    source_collection: object,
    initial: object,
    result: tuple[object, ...],
) -> tuple[object, ...]:
    assert project_state is expected_state
    assert source_collection is not initial
    return result
