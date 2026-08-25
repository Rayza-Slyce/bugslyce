"""RED contract for canonical Operator Brief composition evidence-pack portability."""

from __future__ import annotations

from datetime import datetime, timezone
import importlib
import json
from pathlib import Path, PurePosixPath
import runpy
import sys
from types import ModuleType
import zipfile

import pytest

import bugslyce.project_pipeline as project_pipeline
from bugslyce.project_pipeline import STANDARD_PIPELINE_PROFILE, _step_runners
from bugslyce.recon.evidence_pack_closure import (
    REFERENCE_CLOSURE_FILENAME,
    validate_evidence_pack_root,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.reports.operator_brief import OperatorBriefView, write_operator_brief_artifact
from bugslyce.reports.operator_brief_assembly import OperatorBriefComposition
from bugslyce.reports.operator_brief_composition_persistence import (
    OPERATOR_BRIEF_COMPOSITION_FILENAME,
    load_operator_brief_composition_artifact,
    write_operator_brief_composition_artifact,
)


_ROOT = Path(__file__).resolve().parents[1]
_PERSISTENCE_HELPERS = runpy.run_path(
    str(_ROOT / "tests/test_operator_brief_composition_persistence.py")
)
_EXPORT_HELPERS = runpy.run_path(str(_ROOT / "tests/test_recon_export.py"))
_FIXED_TIME = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
_CANONICAL = OPERATOR_BRIEF_COMPOSITION_FILENAME


def _composition_references(
    composition: OperatorBriefComposition,
) -> tuple[str, ...]:
    references = {
        *(
            reference
            for subject in composition.http.subjects
            for reference in subject.artefact_references
        ),
        *(
            reference
            for fact in composition.http.facts
            for reference in fact.artefact_references
        ),
        *(
            reference
            for conflict in composition.http.conflicts
            for observation in conflict.observations
            for reference in observation.artefact_references
        ),
        *(
            reference
            for subject in composition.network.subjects
            for reference in subject.artefact_references
        ),
        *(
            reference
            for fact in composition.network.facts
            for reference in fact.artefact_references
        ),
        *(
            reference
            for observation in composition.network.smb_shares
            for reference in (
                *observation.trigger_artefact_references,
                *observation.artefact_references,
            )
        ),
        *(
            reference
            for observation in composition.network.services
            for reference in observation.artefact_references
        ),
        *(
            reference
            for subject in composition.web_context.subjects
            for reference in subject.artefact_references
        ),
        *(
            reference
            for fact in composition.web_context.facts
            for reference in fact.artefact_references
        ),
        *(
            reference
            for clue in composition.web_context.clues
            for reference in clue.artefact_references
        ),
        *(
            reference
            for route in composition.web_context.routes
            for reference in (
                *route.artefact_references,
                *(nested for record in route.provenance_records for nested in record.artefact_references),
            )
        ),
        *(
            reference
            for relationship in composition.web_context.relationships
            for reference in relationship.artefact_references
        ),
        *(
            reference
            for subject in composition.source_native.subjects
            for reference in subject.artefact_references
        ),
    }
    return tuple(sorted(references))


def _write_evidence(root: Path, reference: str) -> None:
    path = root / Path(*PurePosixPath(reference).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"fixture evidence for {reference}\n", encoding="utf-8")


def _canonical_project(
    tmp_path: Path,
    *,
    missing_references: tuple[str, ...] = (),
) -> tuple[Path, OperatorBriefComposition, Path, bytes]:
    root = _EXPORT_HELPERS["_export_input"](tmp_path)
    composition = _PERSISTENCE_HELPERS["_representative_composition"]()
    assert isinstance(composition, OperatorBriefComposition)
    for reference in _composition_references(composition):
        if reference not in missing_references:
            _write_evidence(root, reference)
    path = write_operator_brief_composition_artifact(root, composition)
    return root, composition, path, path.read_bytes()


def _export(root: Path, output: Path):
    return export_recon_evidence_pack(root, output, clock=lambda: _FIXED_TIME)


def _extract(output: Path, destination: Path) -> None:
    with zipfile.ZipFile(output) as archive:
        archive.extractall(destination)


def _closure_payload(output: Path) -> dict[str, object]:
    with zipfile.ZipFile(output) as archive:
        return json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))


def _owners(closure: dict[str, object], portable_path: str) -> list[dict[str, object]]:
    return [
        owner
        for record in closure["references"]
        if record["portable_path"] == portable_path
        for owner in record["owners"]
    ]


def _guard_semantic_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("canonical composition semantic replay is forbidden")

    for module_name, attribute in (
        ("bugslyce.reports.operator_brief_project", "build_project_operator_brief_composition"),
        ("bugslyce.reports.operator_brief_assembly", "assemble_operator_brief"),
        (
            "bugslyce.reports.operator_brief_multi_family_assembly",
            "assemble_operator_brief_policy_subjects",
        ),
        ("bugslyce.reports.operator_brief_http", "compose_operator_brief_http"),
        ("bugslyce.reports.operator_brief_network", "compose_operator_brief_network"),
        ("bugslyce.reports.operator_brief_web_context", "compose_operator_brief_web_context"),
        ("bugslyce.reports.operator_brief_source_native", "compose_operator_brief_source_native"),
        ("bugslyce.reports.operator_brief_thread_policy", "apply_operator_brief_thread_policy"),
    ):
        monkeypatch.setattr(f"{module_name}.{attribute}", forbidden)


def _guarded_export_module(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.delitem(sys.modules, "bugslyce.recon.export", raising=False)
    monkeypatch.delitem(sys.modules, "bugslyce.recon.evidence_pack_closure", raising=False)
    _guard_semantic_replay(monkeypatch)

    def forbidden_writer(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("canonical composition writing is forbidden during export")

    monkeypatch.setattr(
        "bugslyce.reports.operator_brief_composition_persistence."
        "write_operator_brief_composition_artifact",
        forbidden_writer,
    )
    return importlib.import_module("bugslyce.recon.export")


def test_source_control_canonical_snapshot_is_nontrivial_and_round_trips_locally(
    tmp_path: Path,
) -> None:
    root, composition, path, before = _canonical_project(tmp_path)

    loaded = load_operator_brief_composition_artifact(root)

    assert path.read_bytes() == before
    assert loaded == composition
    assert composition.http.conflicts
    assert composition.network.smb_shares
    assert composition.web_context.routes
    assert composition.source_native.subjects
    assert composition.thread_policy_result.decisions


def test_source_control_canonical_references_use_safe_relative_posix_grammar(
    tmp_path: Path,
) -> None:
    _root, composition, _path, _before = _canonical_project(tmp_path)
    references = _composition_references(composition)

    assert references
    for reference in references:
        path = PurePosixPath(reference)
        assert not path.is_absolute()
        assert ".." not in path.parts
        assert "\\" not in reference
        assert path.as_posix() == reference


def test_source_control_legacy_export_and_validation_remain_valid_without_canonical(
    tmp_path: Path,
) -> None:
    root = _EXPORT_HELPERS["_export_input"](tmp_path)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    _export(root, first)
    _export(root, second)
    extracted = tmp_path / "legacy-extracted"
    _extract(first, extracted)

    assert first.read_bytes() == second.read_bytes()
    assert _CANONICAL not in zipfile.ZipFile(first).namelist()
    assert not (root / _CANONICAL).exists()
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


def test_future_export_includes_canonical_snapshot_at_top_level_with_closure_owner(
    tmp_path: Path,
) -> None:
    root, _composition, _path, _before = _canonical_project(tmp_path)
    output = tmp_path / "pack.zip"

    _export(root, output)

    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("bugslyce_export_manifest.json"))
    closure = _closure_payload(output)

    assert _CANONICAL in names
    assert f"raw/{_CANONICAL}" not in names
    assert _CANONICAL in manifest["files_included"]
    assert {
        (owner["owner_kind"], owner["owner_id"])
        for owner in _owners(closure, _CANONICAL)
    } >= {("operator_brief_composition", _CANONICAL)}


def test_future_export_preserves_canonical_bytes_and_loaded_snapshot_parity(
    tmp_path: Path,
) -> None:
    root, composition, _path, before = _canonical_project(tmp_path)
    output = tmp_path / "pack.zip"

    _export(root, output)

    with zipfile.ZipFile(output) as archive:
        assert _CANONICAL in archive.namelist()
        assert archive.read(_CANONICAL) == before
        archive.extractall(tmp_path / "extracted")
    extracted = tmp_path / "extracted"
    assert (extracted / _CANONICAL).read_bytes() == before
    loaded = load_operator_brief_composition_artifact(extracted)
    assert loaded == composition
    assert loaded is not None
    assert loaded.thread_policy_result.decisions == composition.thread_policy_result.decisions
    assert loaded.policy_subjects == composition.policy_subjects
    assert [item.policy_key for item in loaded.policy_subjects] == [
        item.policy_key for item in composition.policy_subjects
    ]
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


def test_future_closure_maps_immutable_canonical_references_to_packed_members(
    tmp_path: Path,
) -> None:
    root, composition, _path, before = _canonical_project(tmp_path)
    output = tmp_path / "pack.zip"
    http_reference = composition.http.facts[0].artefact_references[0]
    nested_reference = composition.http.conflicts[0].observations[0].artefact_references[0]
    network_reference = composition.network.smb_shares[0].trigger_artefact_references[0]

    _export(root, output)

    with zipfile.ZipFile(output) as archive:
        assert _CANONICAL in archive.namelist()
        packed = json.loads(archive.read(_CANONICAL))
        members = set(archive.namelist())
    closure = _closure_payload(output)

    assert packed == json.loads(before)
    assert packed["http"]["facts"][0]["artefact_references"] == [http_reference]
    for reference in (http_reference, nested_reference, network_reference):
        packed_path = f"raw/{reference}"
        assert packed_path in members
        assert any(
            owner["owner_kind"].startswith("operator_brief_composition")
            for owner in _owners(closure, packed_path)
        )


def test_future_missing_canonical_reference_is_explicitly_incomplete(
    tmp_path: Path,
) -> None:
    missing = "native/source.js"
    root, composition, _path, _before = _canonical_project(
        tmp_path,
        missing_references=(missing,),
    )
    output = tmp_path / "pack.zip"

    result = _export(root, output)

    with zipfile.ZipFile(output) as archive:
        assert _CANONICAL in archive.namelist()
    closure = _closure_payload(output)
    assert missing in _composition_references(composition)
    assert result.reference_closure_status == "incomplete"
    assert f"raw/{missing}" in result.unresolved_reference_paths
    assert any(
        record["portable_path"] == f"raw/{missing}"
        and record["included"] is False
        for record in closure["unresolved_references"]
    )
    extracted = tmp_path / "extracted"
    _extract(output, extracted)
    assert validate_evidence_pack_root(extracted).validation_status == "incomplete"


def test_future_export_rejects_corrupt_present_canonical_without_legacy_substitution(
    tmp_path: Path,
) -> None:
    root, _composition, path, before = _canonical_project(tmp_path)
    write_operator_brief_artifact(root, OperatorBriefView(threads=(), dispositions=()))
    path.write_text("{not valid canonical json", encoding="utf-8")

    with pytest.raises(ValueError):
        _export(root, tmp_path / "pack.zip")

    assert path.read_bytes() == b"{not valid canonical json"
    assert before != path.read_bytes()


@pytest.mark.parametrize("kind", ("symlink", "directory"))
def test_future_export_rejects_unsafe_present_canonical_path(
    tmp_path: Path,
    kind: str,
) -> None:
    root, _composition, path, _before = _canonical_project(tmp_path)
    path.unlink()
    if kind == "symlink":
        target = root / "canonical-target.json"
        target.write_text("{}\n", encoding="utf-8")
        path.symlink_to(target)
    else:
        path.mkdir()

    with pytest.raises(ValueError):
        _export(root, tmp_path / f"{kind}.zip")


def test_future_canonical_export_performs_no_semantic_replay_or_canonical_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _composition, _path, _before = _canonical_project(tmp_path)
    export_module = _guarded_export_module(monkeypatch)
    output = tmp_path / "guarded.zip"

    export_module.export_recon_evidence_pack(root, output, clock=lambda: _FIXED_TIME)

    with zipfile.ZipFile(output) as archive:
        assert _CANONICAL in archive.namelist()


def test_future_repeated_export_preserves_canonical_member_and_closure_mapping(
    tmp_path: Path,
) -> None:
    root, composition, _path, before = _canonical_project(tmp_path)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    _export(root, first)
    _export(root, second)

    with zipfile.ZipFile(first) as archive:
        assert _CANONICAL in archive.namelist()
        first_bytes = archive.read(_CANONICAL)
    with zipfile.ZipFile(second) as archive:
        assert _CANONICAL in archive.namelist()
        second_bytes = archive.read(_CANONICAL)
    assert first_bytes == second_bytes == before
    assert _closure_payload(first) == _closure_payload(second)
    first_root = tmp_path / "first-extracted"
    second_root = tmp_path / "second-extracted"
    _extract(first, first_root)
    _extract(second, second_root)
    assert load_operator_brief_composition_artifact(first_root) == composition
    assert load_operator_brief_composition_artifact(second_root) == composition


def test_future_pipeline_step_012_exports_existing_canonical_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _composition, _path, _before = _canonical_project(tmp_path)
    output = tmp_path / "pipeline.zip"
    (root / "plan").mkdir()
    (root / "project.json").write_text("{}\n", encoding="utf-8")

    def write_html(input_dir: Path) -> Path:
        path = input_dir / "report.html"
        path.write_text("<!doctype html><title>fixture</title>\n", encoding="utf-8")
        return path

    _guard_semantic_replay(monkeypatch)
    monkeypatch.setattr(project_pipeline, "write_project_html_report", write_html)
    context = {
        "output_dir": root,
        "scope_file": root / "scope.md",
        "plan_dir": root / "plan",
        "plan_path": root / "plan" / "content_discovery_plan.json",
        "export_path": output,
        "target": "10.10.10.10",
        "project_file": root / "project.json",
        "resume": False,
        "profile": STANDARD_PIPELINE_PROFILE,
        "project_runtime": None,
    }

    _step_runners(context, lambda: _FIXED_TIME)["PIPELINE-STEP-012"]()

    with zipfile.ZipFile(output) as archive:
        assert _CANONICAL in archive.namelist()


def test_future_standalone_legacy_export_does_not_migrate_canonical_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _EXPORT_HELPERS["_export_input"](tmp_path)
    _guard_semantic_replay(monkeypatch)

    result = _export(root, tmp_path / "legacy.zip")

    with zipfile.ZipFile(result.output_path) as archive:
        assert _CANONICAL not in archive.namelist()
    assert not (root / _CANONICAL).exists()
