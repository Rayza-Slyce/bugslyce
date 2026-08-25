"""RED contract for canonical Operator Brief resume and report loading."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import runpy

import pytest

import bugslyce.project_pipeline as project_pipeline
from bugslyce.core.project import build_project_state
from bugslyce.project_pipeline import (
    DEEP_PIPELINE_PROFILE,
    PIPELINE_JSON_FILENAME,
    PIPELINE_PROFILE,
    STANDARD_PIPELINE_PROFILE,
    _assess_resume_state,
    _content_discovery_profile_for_pipeline,
    _step_runners,
)
from bugslyce.reports import html as html_module
from bugslyce.reports import html_model
from bugslyce.reports.html import write_html_report, write_project_html_report
from bugslyce.reports.markdown import export_project_state_json
from bugslyce.reports.operator_brief import write_operator_brief_artifact
from bugslyce.reports.operator_brief_assembly import OperatorBriefComposition
from bugslyce.reports.operator_brief_composition_persistence import (
    OPERATOR_BRIEF_COMPOSITION_FILENAME,
    load_operator_brief_composition_artifact,
    write_operator_brief_composition_artifact,
)
from bugslyce.triage.candidates import generate_candidates
from bugslyce.cli import main


_ROOT = Path(__file__).resolve().parents[1]
_PROJECT_HELPERS = runpy.run_path(str(_ROOT / "tests/test_project_pipeline.py"))
_STAGE6C_HELPERS = runpy.run_path(
    str(_ROOT / "tests/test_operator_brief_project_integration.py")
)
_FIXTURES_ROOT = _ROOT / "examples/demo_recon/lab_raw_recon_pack"
_CANONICAL_PATH = OPERATOR_BRIEF_COMPOSITION_FILENAME


def _representative_composition(root: Path) -> OperatorBriefComposition:
    state = _STAGE6C_HELPERS["_project_state"](root)
    return _STAGE6C_HELPERS["_closed_composition"](root, state)


def _write_html_pack(root: Path) -> Path:
    root.mkdir()
    state = build_project_state(_FIXTURES_ROOT)
    candidates = generate_candidates(state)
    (root / "project_state.json").write_text(
        export_project_state_json(state, candidates),
        encoding="utf-8",
    )
    return root


def _write_canonical_html_pack(
    root: Path,
) -> tuple[Path, OperatorBriefComposition, bytes]:
    pack = _write_html_pack(root)
    composition = _representative_composition(pack)
    path = write_operator_brief_composition_artifact(pack, composition)
    return pack, composition, path.read_bytes()


def _completed_resume_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
) -> tuple[dict[str, object], Path, Path]:
    project_file, output_dir = _PROJECT_HELPERS["_fresh_project"](tmp_path)
    export_path = Path(f"{output_dir}-evidence-pack.zip")
    content_profile = _content_discovery_profile_for_pipeline(profile)

    if profile == DEEP_PIPELINE_PROFILE:
        _PROJECT_HELPERS["_write_completed_deep_resume_state"](
            project_file,
            output_dir,
            export_path,
        )
    else:
        _PROJECT_HELPERS["_write_resume_evidence"](
            output_dir,
            [
                "nmap-allports.txt",
                "nmap-services-all.txt",
                "curl-headers-10.10.10.10-80.txt",
                "curl-headers-followup-10.10.10.10-80-manual.txt",
                "gobuster-tiny-10.10.10.10-80-root.txt",
                "curl-headers-content-followup-10.10.10.10-80-admin.txt",
                "body-fetch-10.10.10.10-80-admin.html",
            ],
        )
        _PROJECT_HELPERS["_write_named_files"](
            output_dir,
            (
                "report.md",
                "recon_status.md",
                "recon_status.json",
                "runbook.md",
            ),
        )
        export_path.write_bytes(b"completed evidence pack")
        _PROJECT_HELPERS["_write_prior_pipeline"](
            project_file,
            output_dir,
            export_path,
            profile=profile,
            final_status="completed",
            step_statuses={
                "PIPELINE-STEP-002": "completed",
                "PIPELINE-STEP-003": "completed",
                "PIPELINE-STEP-003S": "noop",
                "PIPELINE-STEP-004": "completed",
                "PIPELINE-STEP-005": "completed",
                "PIPELINE-STEP-006": "completed",
                "PIPELINE-STEP-007": "completed",
                "PIPELINE-STEP-008": "completed",
                "PIPELINE-STEP-009": "completed",
                "PIPELINE-STEP-010": "completed",
                "PIPELINE-STEP-011": "completed",
                "PIPELINE-STEP-012": "completed",
            },
        )

    plan_path = _PROJECT_HELPERS["_write_plan_file"](
        output_dir,
        profile=content_profile,
    )
    _PROJECT_HELPERS["_patch_plan_loader_for_profile"](
        monkeypatch,
        project_file,
        output_dir,
        plan_path,
        content_profile,
    )
    project_payload = json.loads(project_file.read_text(encoding="utf-8"))
    arguments: dict[str, object] = {
        "target": "10.10.10.10",
        "project_file": project_file,
        "scope_file": Path(project_payload["scope_file"]),
        "output_dir": output_dir,
        "plan_dir": plan_path.parent,
        "plan_path": plan_path,
        "export_path": export_path,
        "profile": profile,
    }
    return arguments, output_dir, project_file


def _declare_canonical_output(output_dir: Path, declared: Path | None = None) -> None:
    pipeline_path = output_dir / PIPELINE_JSON_FILENAME
    payload = json.loads(pipeline_path.read_text(encoding="utf-8"))
    step = next(
        item for item in payload["steps"] if item["step_id"] == "PIPELINE-STEP-010"
    )
    step["output_paths"] = [str(declared or output_dir / _CANONICAL_PATH)]
    pipeline_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")


def _guard_semantic_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("canonical semantic replay is forbidden while loading")

    seams = (
        ("bugslyce.reports.operator_brief_project", "build_project_operator_brief_composition"),
        ("bugslyce.reports.operator_brief_assembly", "assemble_operator_brief"),
        (
            "bugslyce.reports.operator_brief_multi_family_assembly",
            "assemble_operator_brief_policy_subjects",
        ),
        ("bugslyce.reports.operator_brief_http", "compose_operator_brief_http"),
        ("bugslyce.reports.operator_brief_network", "compose_operator_brief_network"),
        (
            "bugslyce.reports.operator_brief_web_context",
            "compose_operator_brief_web_context",
        ),
        (
            "bugslyce.reports.operator_brief_source_native",
            "compose_operator_brief_source_native",
        ),
        (
            "bugslyce.reports.operator_brief_thread_policy",
            "apply_operator_brief_thread_policy",
        ),
    )
    for module_name, attribute in seams:
        monkeypatch.setattr(f"{module_name}.{attribute}", forbidden)

    for consumer in (html_model, html_module, project_pipeline):
        for _module_name, attribute in seams:
            if hasattr(consumer, attribute):
                monkeypatch.setattr(consumer, attribute, forbidden)


def _counted_html_loader(
    monkeypatch: pytest.MonkeyPatch,
) -> list[Path]:
    calls: list[Path] = []

    def load(root: Path) -> OperatorBriefComposition | None:
        calls.append(root.resolve())
        return load_operator_brief_composition_artifact(root)

    monkeypatch.setattr(
        html_model,
        "load_operator_brief_composition_artifact",
        load,
        raising=False,
    )
    return calls


def _counted_resume_loader(
    monkeypatch: pytest.MonkeyPatch,
) -> list[Path]:
    calls: list[Path] = []

    def load(root: Path) -> OperatorBriefComposition | None:
        calls.append(root.resolve())
        return load_operator_brief_composition_artifact(root)

    monkeypatch.setattr(
        project_pipeline,
        "load_operator_brief_composition_artifact",
        load,
        raising=False,
    )
    return calls


# Existing-source controls.


def test_source_control_representative_snapshot_round_trip_is_nontrivial(
    tmp_path: Path,
) -> None:
    composition = _representative_composition(tmp_path)

    write_operator_brief_composition_artifact(tmp_path, composition)
    loaded = load_operator_brief_composition_artifact(tmp_path)

    assert loaded == composition
    assert loaded is not None
    assert loaded.policy_subjects
    assert loaded.thread_policy_result.decisions
    assert any(decision.rank is not None for decision in loaded.thread_policy_result.decisions)
    assert loaded.source_native.subjects


def test_source_control_current_and_legacy_stage010_declarations_are_distinct(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, output_dir, _project_file = _completed_resume_fixture(
        tmp_path,
        monkeypatch,
        PIPELINE_PROFILE,
    )
    payload_path = output_dir / PIPELINE_JSON_FILENAME
    legacy = json.loads(payload_path.read_text(encoding="utf-8"))
    legacy_step = next(
        item for item in legacy["steps"] if item["step_id"] == "PIPELINE-STEP-010"
    )
    assert _CANONICAL_PATH not in legacy_step.get("output_paths", ())

    _declare_canonical_output(output_dir)
    current = json.loads(payload_path.read_text(encoding="utf-8"))
    current_step = next(
        item for item in current["steps"] if item["step_id"] == "PIPELINE-STEP-010"
    )
    assert tuple(current_step["output_paths"]) == (
        str(output_dir / _CANONICAL_PATH),
    )
    assert Path(current_step["output_paths"][0]).resolve() == (
        output_dir / _CANONICAL_PATH
    ).resolve()
    assert arguments["output_dir"] == output_dir


@pytest.mark.parametrize("profile", (PIPELINE_PROFILE, STANDARD_PIPELINE_PROFILE))
def test_source_control_legacy_quick_and_standard_resume_remain_compatible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
) -> None:
    arguments, output_dir, _project_file = _completed_resume_fixture(
        tmp_path,
        monkeypatch,
        profile,
    )
    _guard_semantic_replay(monkeypatch)

    assessment = _assess_resume_state(**arguments)

    assert "PIPELINE-STEP-012" in assessment.skipped_step_ids
    assert not (output_dir / _CANONICAL_PATH).exists()


def test_source_control_legacy_deep_completed_resume_remains_compatible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, output_dir, _project_file = _completed_resume_fixture(
        tmp_path,
        monkeypatch,
        DEEP_PIPELINE_PROFILE,
    )
    _guard_semantic_replay(monkeypatch)

    assessment = _assess_resume_state(**arguments)

    assert {"PIPELINE-STEP-010", "PIPELINE-STEP-011"}.issubset(
        assessment.skipped_step_ids
    )
    assert assessment.preserve_canonical_pipeline_metadata is True
    assert not (output_dir / _CANONICAL_PATH).exists()


def test_source_control_legacy_html_rendering_does_not_create_canonical_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _write_html_pack(tmp_path / "legacy-pack")
    output = tmp_path / "legacy-report.html"
    _guard_semantic_replay(monkeypatch)

    write_html_report(pack, output)

    assert output.is_file()
    assert not (pack / _CANONICAL_PATH).exists()


def test_source_control_fresh_stage010_does_not_load_just_written_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir, state, context = _STAGE6C_HELPERS["_stage010_consumer_context"](
        tmp_path
    )
    composition = _STAGE6C_HELPERS["_closed_composition"](output_dir, state)
    calls: list[tuple[str, object]] = []

    def build(**kwargs: object) -> OperatorBriefComposition:
        calls.append(("build", kwargs))
        return composition

    def write(root: Path, supplied: OperatorBriefComposition) -> Path:
        calls.append(("write", supplied))
        assert supplied is composition
        return root / _CANONICAL_PATH

    def forbidden_load(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("fresh Stage 010 must not reload canonical composition")

    monkeypatch.setattr(project_pipeline, "build_project_operator_brief_composition", build)
    monkeypatch.setattr(project_pipeline, "write_operator_brief_composition_artifact", write)
    monkeypatch.setattr(
        project_pipeline,
        "load_operator_brief_composition_artifact",
        forbidden_load,
        raising=False,
    )
    monkeypatch.setattr(project_pipeline, "build_project_state", lambda _root: state)
    monkeypatch.setattr(
        "bugslyce.recon.status.build_project_state",
        lambda _root: state,
    )
    runners = _step_runners(context, None)

    _message, outputs, _updates = runners["PIPELINE-STEP-010"]()

    assert [name for name, _value in calls] == ["build", "write"]
    assert calls[1][1] is composition
    assert str(output_dir / _CANONICAL_PATH) in outputs


# Future resume contract.


@pytest.mark.parametrize(
    "profile",
    (PIPELINE_PROFILE, STANDARD_PIPELINE_PROFILE, DEEP_PIPELINE_PROFILE),
)
def test_future_current_resume_rejects_declared_missing_canonical_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
) -> None:
    arguments, output_dir, _project_file = _completed_resume_fixture(
        tmp_path,
        monkeypatch,
        profile,
    )
    _declare_canonical_output(output_dir)

    with pytest.raises(ValueError, match="(?i)canonical|composition|missing"):
        _assess_resume_state(**arguments)


@pytest.mark.parametrize(
    "profile",
    (PIPELINE_PROFILE, STANDARD_PIPELINE_PROFILE, DEEP_PIPELINE_PROFILE),
)
def test_future_current_resume_rejects_declared_corrupt_canonical_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
) -> None:
    arguments, output_dir, _project_file = _completed_resume_fixture(
        tmp_path,
        monkeypatch,
        profile,
    )
    _declare_canonical_output(output_dir)
    (output_dir / _CANONICAL_PATH).write_text("{broken\n", encoding="utf-8")
    calls = _counted_resume_loader(monkeypatch)

    with pytest.raises(ValueError):
        _assess_resume_state(**arguments)

    assert calls == [output_dir.resolve()]


@pytest.mark.parametrize(
    "profile",
    (PIPELINE_PROFILE, STANDARD_PIPELINE_PROFILE, DEEP_PIPELINE_PROFILE),
)
def test_future_current_completed_resume_loads_once_reuses_tail_and_never_rebuilds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
) -> None:
    arguments, output_dir, _project_file = _completed_resume_fixture(
        tmp_path,
        monkeypatch,
        profile,
    )
    composition = _representative_composition(output_dir)
    write_operator_brief_composition_artifact(output_dir, composition)
    _declare_canonical_output(output_dir)
    calls = _counted_resume_loader(monkeypatch)
    _guard_semantic_replay(monkeypatch)

    assessment = _assess_resume_state(**arguments)

    assert calls == [output_dir.resolve()]
    assert {"PIPELINE-STEP-010", "PIPELINE-STEP-011"}.issubset(
        assessment.skipped_step_ids
    )
    if profile == DEEP_PIPELINE_PROFILE:
        assert {"PIPELINE-STEP-010D", "PIPELINE-STEP-011D"}.issubset(
            assessment.skipped_step_ids
        )


def test_future_resume_rejects_undeclared_present_canonical_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, output_dir, _project_file = _completed_resume_fixture(
        tmp_path,
        monkeypatch,
        STANDARD_PIPELINE_PROFILE,
    )
    composition = _representative_composition(output_dir)
    write_operator_brief_composition_artifact(output_dir, composition)

    with pytest.raises(ValueError, match="(?i)ambiguous|canonical|declar"):
        _assess_resume_state(**arguments)


def test_future_resume_rejects_noncanonical_stage010_declaration_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, output_dir, _project_file = _completed_resume_fixture(
        tmp_path,
        monkeypatch,
        STANDARD_PIPELINE_PROFILE,
    )
    other = tmp_path / "other" / _CANONICAL_PATH
    other.parent.mkdir()
    composition = _representative_composition(output_dir)
    write_operator_brief_composition_artifact(other.parent, composition)
    assert other.is_file()
    assert not (output_dir / _CANONICAL_PATH).exists()
    _declare_canonical_output(output_dir, other)

    with pytest.raises(ValueError, match="(?i)canonical|declar|path"):
        _assess_resume_state(**arguments)


# Future report-model and regeneration contract.


def test_future_html_model_loads_canonical_snapshot_exactly_once_without_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack, composition, _before = _write_canonical_html_pack(tmp_path / "pack")
    calls = _counted_html_loader(monkeypatch)
    _guard_semantic_replay(monkeypatch)

    model = html_model.build_html_report_model(pack)

    assert calls == [pack.resolve()]
    assert model.operator_brief_composition == composition


def test_future_html_model_preserves_canonical_policy_snapshot_parity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack, composition, _before = _write_canonical_html_pack(tmp_path / "pack")
    loaded = load_operator_brief_composition_artifact(pack)
    assert loaded is not None
    monkeypatch.setattr(
        html_model,
        "load_operator_brief_composition_artifact",
        lambda _root: loaded,
        raising=False,
    )

    model = html_model.build_html_report_model(pack)
    retained = model.operator_brief_composition

    assert tuple(subject.policy_key for subject in retained.policy_subjects) == tuple(
        subject.policy_key for subject in composition.policy_subjects
    )
    assert tuple(
        (decision.policy_key, decision.rank, decision.thread_id, decision.disposition)
        for decision in retained.thread_policy_result.decisions
    ) == tuple(
        (decision.policy_key, decision.rank, decision.thread_id, decision.disposition)
        for decision in composition.thread_policy_result.decisions
    )
    assert tuple(
        (subject.family, subject.interpretation)
        for subject in retained.source_native.subjects
    ) == tuple(
        (subject.family, subject.interpretation)
        for subject in composition.source_native.subjects
    )


def test_future_corrupt_canonical_blocks_legacy_operator_brief_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _write_html_pack(tmp_path / "pack")
    legacy_model = html_model.build_html_report_model(pack)
    write_operator_brief_artifact(pack, legacy_model.operator_brief)
    canonical = pack / _CANONICAL_PATH
    canonical.write_bytes(b"{corrupt\n")
    before = canonical.read_bytes()
    legacy_calls: list[Path] = []

    monkeypatch.setattr(
        html_model,
        "load_operator_brief_composition_artifact",
        load_operator_brief_composition_artifact,
        raising=False,
    )

    def forbidden_legacy(root: Path) -> object:
        legacy_calls.append(root)
        raise AssertionError("corrupt canonical state must block legacy fallback")

    monkeypatch.setattr(html_model, "load_operator_brief_artifact", forbidden_legacy)
    _guard_semantic_replay(monkeypatch)

    with pytest.raises(ValueError):
        html_model.build_html_report_model(pack)

    assert legacy_calls == []
    assert canonical.read_bytes() == before


def test_future_project_local_html_regeneration_is_canonical_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack, _composition, before = _write_canonical_html_pack(tmp_path / "pack")
    calls = _counted_html_loader(monkeypatch)
    _guard_semantic_replay(monkeypatch)

    def forbidden_write(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("report regeneration must not write canonical state")

    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_composition_persistence."
        "write_operator_brief_composition_artifact",
        forbidden_write,
    )
    monkeypatch.setattr(
        html_model,
        "write_operator_brief_composition_artifact",
        forbidden_write,
        raising=False,
    )

    written = write_project_html_report(pack)

    assert written == pack / "report.html"
    assert (pack / _CANONICAL_PATH).read_bytes() == before
    assert calls == [pack.resolve()]


def test_future_standalone_html_regeneration_is_canonical_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack, _composition, before = _write_canonical_html_pack(tmp_path / "pack")
    calls = _counted_html_loader(monkeypatch)
    _guard_semantic_replay(monkeypatch)
    output = tmp_path / "standalone.html"

    def forbidden_write(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("standalone rendering must not write canonical state")

    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_composition_persistence."
        "write_operator_brief_composition_artifact",
        forbidden_write,
    )
    monkeypatch.setattr(
        html_model,
        "write_operator_brief_composition_artifact",
        forbidden_write,
        raising=False,
    )

    exit_code = main(
        [
            "report",
            "html",
            "--input-dir",
            str(pack),
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    assert output.is_file()
    assert (pack / _CANONICAL_PATH).read_bytes() == before
    assert calls == [pack.resolve()]
