"""Tests for local-only BugSlyce evidence pack export."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import zipfile

import pytest

from bugslyce.recon import export as export_module
from bugslyce.cli import main
from bugslyce.core.models import DiscoveredPath, Evidence, HTTPArtifact, ProjectState
from bugslyce.recon.evidence_pack_closure import (
    REFERENCE_CLOSURE_FILENAME,
    EvidencePackReference,
    validate_evidence_pack_root,
)
from bugslyce.recon.deep_source_route_collection_export import (
    write_deep_source_route_collection_artifacts,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.reports.markdown import export_project_state_json


FIXED_TIME = datetime(2026, 6, 14, 13, 45, 12, tzinfo=timezone.utc)


def test_export_refuses_missing_input_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Input directory does not exist"):
        export_recon_evidence_pack(tmp_path / "missing", tmp_path / "pack.zip")


def test_export_refuses_missing_manifest(tmp_path: Path) -> None:
    input_dir = tmp_path / "recon"
    input_dir.mkdir()

    with pytest.raises(ValueError, match="Recon manifest does not exist"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.zip")


def test_export_refuses_non_zip_output(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)

    with pytest.raises(ValueError, match="must end with .zip"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.tar")


def test_export_refuses_overwrite_without_force_and_allows_force(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    output_path.write_bytes(b"existing")

    with pytest.raises(ValueError, match="Re-run with --force"):
        export_recon_evidence_pack(input_dir, output_path)

    result = export_recon_evidence_pack(input_dir, output_path, force=True)

    assert result.output_path == str(output_path.resolve())
    assert zipfile.is_zipfile(output_path)


def test_export_failure_preserves_existing_pack_and_removes_temporary_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    output_path.write_bytes(b"previous pack")

    def fail_write(*args, **kwargs):
        raise OSError("archive write failed")

    monkeypatch.setattr(export_module, "_write_bytes", fail_write)

    with pytest.raises(OSError, match="archive write failed"):
        export_recon_evidence_pack(input_dir, output_path, force=True)

    assert output_path.read_bytes() == b"previous pack"
    assert list(tmp_path.glob(".pack.zip.*.tmp")) == []


def test_export_failure_without_existing_pack_does_not_publish_final_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    def fail_write(*args, **kwargs):
        raise OSError("archive write failed")

    monkeypatch.setattr(export_module, "_write_bytes", fail_write)

    with pytest.raises(OSError, match="archive write failed"):
        export_recon_evidence_pack(input_dir, output_path)

    assert not output_path.exists()
    assert list(tmp_path.glob(".pack.zip.*.tmp")) == []


def test_export_archive_failure_preserves_primary_error_when_temp_cleanup_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    output_path.write_bytes(b"previous pack")

    def fail_write(*args, **kwargs):
        raise OSError("archive write failed")

    original_unlink = Path.unlink

    def fail_temp_unlink(path, *args, **kwargs):
        if path.name.startswith(".pack.zip.") and path.suffix == ".tmp":
            raise PermissionError("temporary cleanup failed")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(export_module, "_write_bytes", fail_write)
    monkeypatch.setattr(Path, "unlink", fail_temp_unlink)

    with pytest.raises(OSError) as exc_info:
        export_recon_evidence_pack(input_dir, output_path, force=True)

    assert str(exc_info.value) == "archive write failed"
    assert any("temporary cleanup failed" in note for note in getattr(exc_info.value, "__notes__", ()))
    assert output_path.read_bytes() == b"previous pack"
    assert list(tmp_path.glob(".pack.zip.*.tmp"))


def test_export_replace_failure_preserves_primary_error_when_temp_cleanup_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    output_path.write_bytes(b"previous pack")

    original_replace = Path.replace
    original_unlink = Path.unlink

    def fail_replace(path, target):
        if path.name.startswith(".pack.zip.") and Path(target) == output_path:
            raise OSError("atomic replace failed")
        return original_replace(path, target)

    def fail_temp_unlink(path, *args, **kwargs):
        if path.name.startswith(".pack.zip.") and path.suffix == ".tmp":
            raise PermissionError("temporary cleanup failed")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "replace", fail_replace)
    monkeypatch.setattr(Path, "unlink", fail_temp_unlink)

    with pytest.raises(OSError) as exc_info:
        export_recon_evidence_pack(input_dir, output_path, force=True)

    assert str(exc_info.value) == "atomic replace failed"
    assert any("temporary cleanup failed" in note for note in getattr(exc_info.value, "__notes__", ()))
    assert output_path.read_bytes() == b"previous pack"
    assert list(tmp_path.glob(".pack.zip.*.tmp"))


def test_export_preserves_existing_positional_force_and_clock(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    output_path.write_bytes(b"existing")

    result = export_recon_evidence_pack(input_dir, output_path, True, lambda: FIXED_TIME)

    assert result.exported_at == "2026-06-14T13:45:12Z"
    assert zipfile.is_zipfile(output_path)


def test_export_rejects_positional_deep_evidence_paths(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    deep_file = input_dir / "deep.md"
    deep_file.write_text("# deep\n", encoding="utf-8")

    with pytest.raises(TypeError):
        export_recon_evidence_pack(
            input_dir,
            tmp_path / "pack.zip",
            False,
            lambda: FIXED_TIME,
            (deep_file,),
        )


def test_export_contains_pack_metadata_scope_and_manifest_artifacts(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    result = export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
    )

    with zipfile.ZipFile(output_path) as archive:
        names = set(archive.namelist())
        export_manifest = json.loads(
            archive.read("bugslyce_export_manifest.json").decode("utf-8")
        )
        readme = archive.read("BUGSLYCE_EXPORT_README.md").decode("utf-8")
    compact_readme = " ".join(readme.split())

    assert {
        "BUGSLYCE_EXPORT_README.md",
        "bugslyce_export_manifest.json",
        "report.md",
        "project_state.json",
        "recon_manifest.json",
        "recon_status.md",
        "recon_status.json",
        "scope.md",
        "metadata/recon_execution.md",
        "metadata/recon_execution.json",
        "metadata/recon_execution_content_run.md",
        "metadata/recon_execution_content_run.json",
        "metadata/content_discovery_execution.md",
        "metadata/content_discovery_execution.json",
        "raw/nmap-allports.txt",
        "raw/nested/homepage-target-80.html",
    }.issubset(names)
    assert result.files_included == export_manifest["files_included"]
    assert export_manifest["target"] == "10.10.10.10"
    assert export_manifest["raw_profile"] == "lab-tcp-full-plus-services"
    assert export_manifest["exported_at"] == "2026-06-14T13:45:12Z"
    assert export_manifest["file_count"] == len(names)
    assert export_manifest["warning"] == "sensitive recon evidence"
    assert export_manifest["no_live_commands_executed"] is True
    assert "may contain sensitive recon evidence" in readme
    assert "complete Set-Cookie headers" in compact_readme
    assert "session identifiers, tokens" in compact_readme
    assert "Restrict access" in compact_readme
    assert "Delete it, or sanitise retained" in compact_readme
    assert any("cookie values" in warning for warning in result.warnings)
    assert any("delete or sanitise" in warning for warning in result.warnings)
    assert "Exported at: `2026-06-14T13:45:12Z`" in readme
    assert "No live commands were executed during export." in readme


def test_exported_local_review_references_resolve_from_clean_pack_root(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    source_reference = Path("nested/homepage-target-80.html")
    deep_reference = Path("retained-review.json")
    (input_dir / deep_reference).write_text('{"collected": []}\n', encoding="utf-8")
    (input_dir / "report.md").write_text(
        "\n".join(
            (
                "# Report",
                "",
                f"Retained artefact: `{source_reference.as_posix()}`",
                f"Retained artefact: `{deep_reference.as_posix()}`",
                "",
            )
        ),
        encoding="utf-8",
    )
    (input_dir / "runbook.md").write_text(
        "\n".join(
            (
                "# Runbook",
                "",
                f"Inspect `{source_reference.as_posix()}` locally.",
                f"Inspect `{deep_reference.as_posix()}` locally.",
                "",
            )
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(input_dir / deep_reference,),
        reference_requirements=(
                EvidencePackReference(
                    portable_path=source_reference.as_posix(),
                    owner_kind="custom_relationship_reference",
                owner_id="ROUTE-CLUSTER-0001:source-reference",
                evidence_ids=("EVID-SOURCE",),
            ),
                EvidencePackReference(
                    portable_path=deep_reference.as_posix(),
                    owner_kind="custom_successful_content",
                owner_id="DEEP-CONTENT-0001",
                evidence_ids=("EVID-RESPONSE",),
            ),
        ),
    )
    extracted_root = tmp_path / "clean" / "different-depth" / "pack"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted_root)
    input_dir.rename(tmp_path / "original-project-unavailable")

    assert (extracted_root / source_reference).is_file()
    assert (extracted_root / deep_reference).is_file()
    assert (extracted_root / "report.md").is_file()
    assert (extracted_root / "runbook.md").is_file()
    validation = validate_evidence_pack_root(extracted_root)
    assert validation.validation_status == "complete"
    assert validation.unresolved_reference_count == 0
    assert validation.unsafe_path_count == 0
    assert validation.collision_count == 0


def test_current_deep_detail_references_resolve_at_their_reported_paths(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / "runbook.md").write_text("# Runbook\n", encoding="utf-8")
    deep_names = (
        "deep_recon_review.md",
        "deep_recon_runbook.md",
        "deep_recon_orchestration.json",
    )
    all_deep_names = (
        "deep_source_route_collection.md",
        "deep_source_route_collection.json",
        *deep_names,
    )
    write_deep_source_route_collection_artifacts(
        DeepSourceRouteCollectionResult(
            collected=(),
            skipped=(),
            total_considered=0,
            total_collected=0,
            total_skipped=0,
        ),
        input_dir,
    )
    json_content = {
        "deep_recon_orchestration.json": json.dumps(
            {
                "report_markdown_file": "deep_recon_review.md",
                "runbook_markdown_file": "deep_recon_runbook.md",
            }
        )
        + "\n",
    }
    for name in deep_names:
        (input_dir / name).write_text(
            json_content.get(name, f"# {name}\n"),
            encoding="utf-8",
        )
    (input_dir / "report.md").write_text(
        "\n".join(f"Retained Deep artefact: `{name}`" for name in deep_names) + "\n",
        encoding="utf-8",
    )
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=tuple(input_dir / name for name in all_deep_names),
        reference_requirements=(),
    )

    extracted = tmp_path / "clean" / "current-pack"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
        closure = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))
    closure_paths = {item["portable_path"] for item in closure["references"]}
    assert set(deep_names).issubset(closure_paths)
    assert all((extracted / name).is_file() for name in deep_names)
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


def test_validator_rejects_removed_declared_raw_evidence_member(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / "runbook.md").write_text("# Runbook\n", encoding="utf-8")
    output_path = tmp_path / "pack.zip"
    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        reference_requirements=(),
    )
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)

    (extracted / "raw" / "nmap-allports.txt").unlink()
    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert validation.missing_declared_member_paths == ("raw/nmap-allports.txt",)


def test_validator_rejects_removed_current_export_manifest(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / "runbook.md").write_text("# Runbook\n", encoding="utf-8")
    output_path = tmp_path / "pack.zip"
    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        reference_requirements=(),
    )
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)

    (extracted / "bugslyce_export_manifest.json").unlink()
    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert validation.required_metadata_errors == ("bugslyce_export_manifest.json",)


def test_validator_rejects_export_manifest_missing_files(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / "runbook.md").write_text("# Runbook\n", encoding="utf-8")
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"].append(
        {"type": "headers", "file": "missing-headers.txt"}
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output_path = tmp_path / "pack.zip"
    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        reference_requirements=(),
    )
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert validation.manifest_missing_file_paths == ("raw/missing-headers.txt",)


@pytest.mark.parametrize(
    "required_name",
    (
        "BUGSLYCE_EXPORT_README.md",
        "report.md",
        "runbook.md",
    ),
)
def test_validator_rejects_removed_required_current_member(
    tmp_path: Path,
    required_name: str,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)

    (extracted / required_name).unlink()
    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert required_name in validation.required_metadata_errors
    assert required_name in validation.missing_declared_member_paths


def test_missing_declared_current_closure_is_not_legacy_unknown(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)

    (extracted / REFERENCE_CLOSURE_FILENAME).unlink()
    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert validation.legacy_metadata_absent is False
    assert REFERENCE_CLOSURE_FILENAME in validation.required_metadata_errors


def test_validator_reconciles_closure_and_manifest_member_declarations(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    closure["included_paths"].remove("raw/nmap-allports.txt")
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert validation.declaration_mismatch_paths == ("raw/nmap-allports.txt",)


@pytest.mark.parametrize(
    "unsafe_path",
    ("/absolute/member", "../outside", "nested/../../outside", "..\\outside"),
)
def test_validator_rejects_unsafe_current_metadata_member_paths(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    closure["included_paths"].append(unsafe_path)
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert unsafe_path in validation.unsafe_paths


def test_validator_rejects_external_symlink_declared_as_current_member(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    escape = extracted / "raw" / "escape.txt"
    escape.symlink_to(outside)
    for metadata_name, field in (
        (REFERENCE_CLOSURE_FILENAME, "included_paths"),
        ("bugslyce_export_manifest.json", "files_included"),
    ):
        metadata_path = extracted / metadata_name
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        payload[field].append("raw/escape.txt")
        metadata_path.write_text(json.dumps(payload), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert validation.unsafe_paths == ("raw/escape.txt",)


def test_validator_rejects_duplicate_current_member_declarations(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"
    export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    closure["included_paths"].append("raw/nmap-allports.txt")
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert validation.collision_paths == ("raw/nmap-allports.txt",)


def test_validator_rederives_structured_reference_missing_from_closure(
    tmp_path: Path,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    closure["references"] = [
        item
        for item in closure["references"]
        if item["portable_path"] != "raw/nmap-allports.txt"
    ]
    _refresh_closure_counts(closure)
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    missing = validation.expected_references_missing_from_closure
    assert tuple(item.portable_path for item in missing) == ("raw/nmap-allports.txt",)
    assert missing[0].owners[0].evidence_ids == ("EVID-PORT-0001",)


def test_validator_detects_coordinated_structured_evidence_omission(
    tmp_path: Path,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    raw_path = "raw/nmap-allports.txt"
    (extracted / raw_path).unlink()
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    closure["references"] = [
        item for item in closure["references"] if item["portable_path"] != raw_path
    ]
    closure["included_paths"].remove(raw_path)
    _refresh_closure_counts(closure)
    closure_path.write_text(json.dumps(closure), encoding="utf-8")
    manifest_path = extracted / "bugslyce_export_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files_included"].remove(raw_path)
    manifest["file_count"] = len(manifest["files_included"])
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert tuple(
        item.portable_path
        for item in validation.expected_references_missing_from_closure
    ) == (raw_path,)


@pytest.mark.parametrize(
    "required_path",
    ("report.md", REFERENCE_CLOSURE_FILENAME),
)
def test_validator_requires_core_member_in_both_declarations(
    tmp_path: Path,
    required_path: str,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    closure["included_paths"].remove(required_path)
    closure_path.write_text(json.dumps(closure), encoding="utf-8")
    manifest_path = extracted / "bugslyce_export_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files_included"].remove(required_path)
    manifest["file_count"] = len(manifest["files_included"])
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert any(
        error.startswith(f"{required_path}:")
        for error in validation.required_declaration_errors
    )


@pytest.mark.parametrize(
    ("closure_status", "manifest_status"),
    (("complete", "incomplete"), ("incomplete", "complete")),
)
def test_validator_rejects_closure_status_disagreement(
    tmp_path: Path,
    closure_status: str,
    manifest_status: str,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    _set_metadata_field(
        extracted / REFERENCE_CLOSURE_FILENAME,
        "status",
        closure_status,
    )
    _set_metadata_field(
        extracted / "bugslyce_export_manifest.json",
        "reference_closure_status",
        manifest_status,
    )

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert "reference_closure_status_mismatch" in validation.metadata_consistency_errors


def test_validator_rejects_empty_structured_reference_owners(tmp_path: Path) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    record = next(
        item
        for item in closure["references"]
        if item["portable_path"] == "raw/nmap-allports.txt"
    )
    record["owners"] = []
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert validation.owner_association_errors[0].portable_path == (
        "raw/nmap-allports.txt"
    )
    assert validation.owner_association_errors[0].owners[0].evidence_ids == (
        "EVID-PORT-0001",
    )


def test_validator_rejects_missing_structured_evidence_id(tmp_path: Path) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    record = next(
        item
        for item in closure["references"]
        if item["portable_path"] == "raw/nmap-allports.txt"
    )
    record["owners"][0]["evidence_ids"] = []
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert validation.owner_association_errors[0].owners[0].evidence_ids == (
        "EVID-PORT-0001",
    )


@pytest.mark.parametrize("closure_version", (None, "0.9"))
def test_validator_rejects_missing_or_unsupported_closure_version(
    tmp_path: Path,
    closure_version: str | None,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    if closure_version is None:
        closure.pop("closure_version")
    else:
        closure["closure_version"] = closure_version
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert "unsupported_closure_version" in validation.metadata_consistency_errors


def test_validator_rejects_incorrect_closure_counts(tmp_path: Path) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    closure["counts"]["referenced_paths"] += 1
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert "closure_counts_mismatch" in validation.metadata_consistency_errors


def test_validator_rejects_incorrect_manifest_file_count(tmp_path: Path) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    manifest_path = extracted / "bugslyce_export_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["file_count"] += 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert "export_manifest_file_count_mismatch" in (
        validation.metadata_consistency_errors
    )


def test_validator_rejects_incorrect_manifest_closure_filename(tmp_path: Path) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    _set_metadata_field(
        extracted / "bugslyce_export_manifest.json",
        "reference_closure",
        "other-closure.json",
    )

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert "export_manifest_reference_closure_mismatch" in (
        validation.metadata_consistency_errors
    )


def test_pack_aware_validation_is_deterministic_under_reversed_metadata_order(
    tmp_path: Path,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    expected = validate_evidence_pack_root(extracted)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    closure["references"].reverse()
    closure["included_paths"].reverse()
    closure_path.write_text(json.dumps(closure), encoding="utf-8")
    manifest_path = extracted / "bugslyce_export_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files_included"].reverse()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    actual = validate_evidence_pack_root(extracted)

    assert actual == expected
    assert actual.validation_status == "complete"


def test_direct_api_deep_export_discovers_successful_and_relationship_owners(
    tmp_path: Path,
) -> None:
    input_dir = _deep_relationship_export_input(tmp_path)
    output_path = tmp_path / "api-deep.zip"

    export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)
    extracted = tmp_path / "api-deep"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
        closure = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))

    owners = _closure_owner_associations(closure)
    assert _expected_deep_relationship_owners() <= owners
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


def test_standalone_cli_deep_export_matches_direct_api_known_owners(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = _deep_relationship_export_input(tmp_path)
    api_path = tmp_path / "api.zip"
    cli_path = tmp_path / "cli.zip"
    export_recon_evidence_pack(input_dir, api_path, clock=lambda: FIXED_TIME)

    assert main(
        [
            "recon",
            "export",
            "--input-dir",
            str(input_dir),
            "--output",
            str(cli_path),
        ]
    ) == 0
    capsys.readouterr()
    with zipfile.ZipFile(api_path) as api_archive, zipfile.ZipFile(cli_path) as cli_archive:
        api_closure = json.loads(api_archive.read(REFERENCE_CLOSURE_FILENAME))
        cli_closure = json.loads(cli_archive.read(REFERENCE_CLOSURE_FILENAME))
        cli_archive.extractall(tmp_path / "cli-clean")

    assert _closure_owner_associations(cli_closure) == (
        _closure_owner_associations(api_closure)
    )
    assert _expected_deep_relationship_owners() <= _closure_owner_associations(
        cli_closure
    )
    assert validate_evidence_pack_root(tmp_path / "cli-clean").validation_status == (
        "complete"
    )


def test_validator_rejects_one_missing_relationship_owner_on_shared_parent(
    tmp_path: Path,
) -> None:
    extracted = _deep_relationship_pack_root_with_explicit_owners(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    parent_record = next(
        item for item in closure["references"] if item["portable_path"] == "parent.html"
    )
    relationship_owners = [
        owner
        for owner in parent_record["owners"]
        if owner["owner_kind"] == "http_route_relationship_edge"
    ]
    assert len(relationship_owners) == 2
    removed = relationship_owners[0]
    parent_record["owners"].remove(removed)
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    error = next(
        item
        for item in validation.owner_association_errors
        if item.portable_path == "parent.html"
    )
    assert any(owner.owner_id == removed["owner_id"] for owner in error.owners)
    assert any(owner.evidence_ids == tuple(removed["evidence_ids"]) for owner in error.owners)


def test_validator_rejects_missing_relationship_owner_on_shared_deep_json(
    tmp_path: Path,
) -> None:
    extracted = _deep_relationship_pack_root_with_explicit_owners(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    deep_record = next(
        item
        for item in closure["references"]
        if item["portable_path"] == "deep_source_route_collection.json"
    )
    removed = next(
        owner
        for owner in deep_record["owners"]
        if owner["owner_kind"] == "http_route_relationship_edge"
    )
    deep_record["owners"].remove(removed)
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    error = next(
        item
        for item in validation.owner_association_errors
        if item.portable_path == "deep_source_route_collection.json"
    )
    assert any(owner.owner_id == removed["owner_id"] for owner in error.owners)
    assert any(owner.evidence_ids == tuple(removed["evidence_ids"]) for owner in error.owners)


def test_validator_rejects_unexpected_known_relationship_owner(tmp_path: Path) -> None:
    extracted = _deep_relationship_pack_root_with_explicit_owners(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    parent_record = next(
        item for item in closure["references"] if item["portable_path"] == "parent.html"
    )
    parent_record["owners"].append(
        {
            "owner_kind": "http_route_relationship_edge",
            "owner_id": (
                "ROUTE-CLUSTER-9999:source_reference:"
                "https://portal.example.test/false->https://portal.example.test/claim"
            ),
            "evidence_ids": ["EVID-FABRICATED"],
        }
    )
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert any(
        any(owner.owner_id.startswith("ROUTE-CLUSTER-9999:") for owner in item.owners)
        for item in validation.owner_association_errors
    )


@pytest.mark.parametrize("content", ("{", "[]"))
def test_present_malformed_closure_is_incomplete_not_legacy(
    tmp_path: Path,
    content: str,
) -> None:
    pack_root = tmp_path / "malformed-current"
    pack_root.mkdir()
    (pack_root / "report.md").write_text("# Report\n", encoding="utf-8")
    (pack_root / REFERENCE_CLOSURE_FILENAME).write_text(content, encoding="utf-8")

    validation = validate_evidence_pack_root(pack_root)

    assert validation.validation_status == "incomplete"
    assert validation.legacy_metadata_absent is False
    assert any(
        REFERENCE_CLOSURE_FILENAME in error
        for error in validation.required_metadata_errors
    )


def test_present_symlinked_closure_is_incomplete_not_legacy(tmp_path: Path) -> None:
    pack_root = tmp_path / "symlink-current"
    pack_root.mkdir()
    outside = tmp_path / "outside-closure.json"
    outside.write_text("{}", encoding="utf-8")
    (pack_root / REFERENCE_CLOSURE_FILENAME).symlink_to(outside)

    validation = validate_evidence_pack_root(pack_root)

    assert validation.validation_status == "incomplete"
    assert validation.legacy_metadata_absent is False
    assert any("unsafe_symlink" in error for error in validation.required_metadata_errors)


def test_validator_rejects_complete_status_with_declared_unresolved_reference(
    tmp_path: Path,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    record = closure["references"][0]
    record["included"] = False
    record["unresolved_reason"] = "declared_missing"
    closure["unresolved_references"] = [dict(record)]
    _refresh_closure_counts(closure)
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert "complete_closure_has_unresolved_references" in (
        validation.metadata_consistency_errors
    )


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    (
        ("unsafe_paths", ["unsafe/member"], "complete_closure_has_unsafe_paths"),
        ("collision_paths", ["duplicate/member"], "complete_closure_has_collisions"),
    ),
)
def test_validator_rejects_complete_status_with_declared_closure_failures(
    tmp_path: Path,
    field: str,
    value: list[str],
    expected_error: str,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    closure[field] = value
    _refresh_closure_counts(closure)
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert expected_error in validation.metadata_consistency_errors


def test_validator_rejects_unresolved_array_not_matching_reference_state(
    tmp_path: Path,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    closure["unresolved_references"] = [dict(closure["references"][0])]
    closure["status"] = "incomplete"
    manifest_path = extracted / "bugslyce_export_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["reference_closure_status"] = "incomplete"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _refresh_closure_counts(closure)
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert "unresolved_reference_set_mismatch" in validation.metadata_consistency_errors


def test_reference_closure_groups_duplicate_owners_and_evidence_deterministically(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / "runbook.md").write_text("# Runbook\n", encoding="utf-8")
    shared = input_dir / "shared.json"
    shared.write_text('{"retained": true}\n', encoding="utf-8")
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    forward = (
        EvidencePackReference(
            "shared.json",
            "successful_deep_content",
            "DEEP-CONTENT-0001",
            ("EVID-B", "EVID-A"),
        ),
        EvidencePackReference(
            "shared.json",
            "http_route_relationship_edge",
            "ROUTE-CLUSTER-0001:edge",
            ("EVID-C", "EVID-A"),
        ),
        EvidencePackReference(
            "shared.json",
            "successful_deep_content",
            "DEEP-CONTENT-0001",
            ("EVID-A",),
        ),
    )

    export_recon_evidence_pack(
        input_dir,
        first,
        clock=lambda: FIXED_TIME,
        reference_requirements=forward,
    )
    export_recon_evidence_pack(
        input_dir,
        second,
        clock=lambda: FIXED_TIME,
        reference_requirements=tuple(reversed(forward)),
    )

    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        closure = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))
    assert names.count("shared.json") == 1
    shared_record = next(
        item for item in closure["references"] if item["portable_path"] == "shared.json"
    )
    assert shared_record["owners"] == [
        {
            "owner_kind": "http_route_relationship_edge",
            "owner_id": "ROUTE-CLUSTER-0001:edge",
            "evidence_ids": ["EVID-A", "EVID-C"],
        },
        {
            "owner_kind": "successful_deep_content",
            "owner_id": "DEEP-CONTENT-0001",
            "evidence_ids": ["EVID-A", "EVID-B"],
        },
    ]


def test_missing_reference_is_explicitly_incomplete_with_exact_ownership(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / "runbook.md").write_text("# Runbook\n", encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    result = export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        reference_requirements=(
            EvidencePackReference(
                "missing-source.html",
                "http_route_relationship_edge",
                "ROUTE-CLUSTER-0001:edge",
                ("EVID-SOURCE",),
            ),
        ),
    )
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
        closure = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))

    assert result.reference_closure_status == "incomplete"
    assert result.unresolved_reference_paths == ("missing-source.html",)
    assert closure["status"] == "incomplete"
    assert closure["counts"]["unresolved_references"] == 1
    validation = validate_evidence_pack_root(extracted)
    assert validation.validation_status == "incomplete"
    assert validation.unresolved_references[0].portable_path == "missing-source.html"
    assert validation.unresolved_references[0].owners[0].evidence_ids == (
        "EVID-SOURCE",
    )
    assert validation.metadata_consistency_errors == ()


def test_missing_shared_reference_reports_one_path_with_all_owners(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / "runbook.md").write_text("# Runbook\n", encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        reference_requirements=(
            EvidencePackReference(
                "deep_source_route_collection.json",
                "successful_deep_content",
                "DEEP-CONTENT-0001",
                ("EVID-ONE",),
            ),
            EvidencePackReference(
                "deep_source_route_collection.json",
                "http_route_relationship_edge",
                "ROUTE-CLUSTER-0001:edge",
                ("EVID-TWO",),
            ),
        ),
    )
    with zipfile.ZipFile(output_path) as archive:
        closure = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))

    assert closure["counts"]["unresolved_references"] == 1
    unresolved = closure["unresolved_references"][0]
    assert unresolved["portable_path"] == "deep_source_route_collection.json"
    assert {owner["owner_id"] for owner in unresolved["owners"]} == {
        "DEEP-CONTENT-0001",
        "ROUTE-CLUSTER-0001:edge",
    }


@pytest.mark.parametrize(
    "unsafe_reference",
    (
        "/absolute/source.html",
        "../outside.html",
        "nested/../../outside.html",
        "..\\outside.html",
    ),
)
def test_reference_closure_rejects_unsafe_portable_paths(
    tmp_path: Path,
    unsafe_reference: str,
) -> None:
    input_dir = _export_input(tmp_path)

    with pytest.raises(ValueError, match="Unsafe portable artefact path"):
        export_recon_evidence_pack(
            input_dir,
            tmp_path / "pack.zip",
            reference_requirements=(
                EvidencePackReference(
                    unsafe_reference,
                    "http_route_relationship_edge",
                    "ROUTE-CLUSTER-0001:edge",
                ),
            ),
        )

    assert not (tmp_path / "pack.zip").exists()


def test_reference_closure_rejects_external_symlink(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    outside = tmp_path / "outside.html"
    outside.write_text("outside\n", encoding="utf-8")
    link = input_dir / "escape.html"
    link.symlink_to(outside)

    with pytest.raises(ValueError, match="outside input directory"):
        export_recon_evidence_pack(
            input_dir,
            tmp_path / "pack.zip",
            reference_requirements=(
                EvidencePackReference(
                    "escape.html",
                    "http_route_relationship_edge",
                    "ROUTE-CLUSTER-0001:edge",
                ),
            ),
        )


def test_clean_root_validator_reports_external_symlink_as_unsafe(
    tmp_path: Path,
) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir()
    outside = tmp_path / "outside.html"
    outside.write_text("outside\n", encoding="utf-8")
    (pack_root / "escape.html").symlink_to(outside)
    closure = {
        "closure_version": "1.0",
        "status": "complete",
        "references": [
            {
                "portable_path": "escape.html",
                "included": True,
                "unresolved_reason": None,
                "owners": [
                    {
                        "owner_kind": "http_route_relationship_edge",
                        "owner_id": "ROUTE-CLUSTER-0001:edge",
                        "evidence_ids": ["EVID-SOURCE"],
                    }
                ],
            }
        ],
        "included_paths": ["escape.html"],
        "unresolved_references": [],
        "unsafe_paths": [],
        "collision_paths": [],
    }
    (pack_root / REFERENCE_CLOSURE_FILENAME).write_text(
        json.dumps(closure),
        encoding="utf-8",
    )

    validation = validate_evidence_pack_root(pack_root)

    assert validation.validation_status == "incomplete"
    assert validation.unsafe_paths == ("escape.html",)
    assert validation.unresolved_references[0].unresolved_reason == "unsafe_path"


def test_archive_path_collision_cannot_silently_overwrite(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("first\n", encoding="utf-8")
    second.write_text("second\n", encoding="utf-8")
    included = {"same.txt": first}

    with pytest.raises(ValueError, match="Archive path collision"):
        export_module._add_file(included, second, "same.txt")

    assert included == {"same.txt": first}


def test_legacy_pack_without_closure_metadata_is_reported_as_unknown(
    tmp_path: Path,
) -> None:
    legacy_root = tmp_path / "legacy-pack"
    legacy_root.mkdir()
    (legacy_root / "report.md").write_text("# Legacy report\n", encoding="utf-8")

    validation = validate_evidence_pack_root(legacy_root)

    assert validation.validation_status == "legacy_unknown"
    assert validation.legacy_metadata_absent is True
    assert validation.unresolved_reference_count == 0
    assert "cannot be classified as current or reference-complete" in validation.summary


def test_current_export_manifest_contains_no_absolute_source_directory(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / "project_state.json").write_text(
        json.dumps(
            {
                "project_state": {
                    "input_dir": str(input_dir),
                    "processed_files": [str(input_dir / "nmap-allports.txt")],
                    "evidence": [
                        {
                            "id": "EVID-PORT-0001",
                            "source_file": str(input_dir / "nmap-allports.txt"),
                            "evidence_type": "open_port",
                            "value": "80/tcp",
                            "context": {},
                        }
                    ],
                },
                "candidates": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (input_dir / "report.md").write_text(
        f"Inspect `{input_dir / 'nmap-allports.txt'}`.\n",
        encoding="utf-8",
    )
    (input_dir / "runbook.md").write_text(
        f"Use `{input_dir / 'report.md'}` from `{input_dir}`.\n",
        encoding="utf-8",
    )
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        reference_requirements=(),
    )
    with zipfile.ZipFile(output_path) as archive:
        manifest = json.loads(archive.read("bugslyce_export_manifest.json"))
        project = json.loads(archive.read("bugslyce_project.json"))
        project_state = json.loads(archive.read("project_state.json"))
        closure = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))
        report = archive.read("report.md").decode("utf-8")
        runbook = archive.read("runbook.md").decode("utf-8")

    assert manifest["source_input_dir"] == "."
    assert manifest["reference_closure"] == REFERENCE_CLOSURE_FILENAME
    assert manifest["reference_closure_status"] == "complete"
    assert project["output_dir"] == "."
    assert project["scope_file"] == "scope.md"
    assert project_state["project_state"]["input_dir"] == "."
    assert project_state["project_state"]["processed_files"] == [
        "raw/nmap-allports.txt"
    ]
    assert project_state["project_state"]["evidence"][0]["source_file"] == (
        "raw/nmap-allports.txt"
    )
    nmap_reference = next(
        item
        for item in closure["references"]
        if item["portable_path"] == "raw/nmap-allports.txt"
    )
    assert nmap_reference["owners"][0]["evidence_ids"] == ["EVID-PORT-0001"]
    assert str(input_dir) not in report
    assert str(input_dir) not in runbook
    assert "raw/nmap-allports.txt" in report
    assert "report.md" in runbook


def test_export_accepts_absolute_manifest_path_inside_input_dir(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["file"] = str(input_dir / "nmap-allports.txt")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        assert "raw/nmap-allports.txt" in archive.namelist()


def test_export_rejects_path_traversal_reference(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["file"] = "../outside.txt"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="Unsafe path traversal"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.zip")


def test_export_rejects_absolute_path_outside_input_dir(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["file"] = str(outside)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="outside input directory"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.zip")


def test_export_records_missing_manifest_artifacts_without_failing(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"].append(
        {"type": "robots", "file": "missing-robots.txt", "url": "http://10.10.10.10/robots.txt"}
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    result = export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        export_manifest = json.loads(
            archive.read("bugslyce_export_manifest.json").decode("utf-8")
        )
        assert "raw/missing-robots.txt" not in archive.namelist()
    assert result.missing_files == ["raw/missing-robots.txt"]
    assert export_manifest["missing_files"] == ["raw/missing-robots.txt"]


def test_export_excludes_unrelated_and_cache_files(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / ".git").mkdir()
    (input_dir / ".git" / "config").write_text("private", encoding="utf-8")
    (input_dir / ".venv").mkdir()
    (input_dir / ".venv" / "secret").write_text("private", encoding="utf-8")
    (input_dir / "__pycache__").mkdir()
    (input_dir / "__pycache__" / "cache.pyc").write_bytes(b"cache")
    (input_dir / ".pytest_cache").mkdir()
    (input_dir / ".pytest_cache" / "state").write_text("cache", encoding="utf-8")
    (input_dir / "unrelated.txt").write_text("not evidence", encoding="utf-8")
    output_path = input_dir / "evidence-pack.zip"

    export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
    assert not any(".git" in name for name in names)
    assert not any(".venv" in name for name in names)
    assert not any("__pycache__" in name for name in names)
    assert not any(".pytest_cache" in name for name in names)
    assert "unrelated.txt" not in names
    assert "evidence-pack.zip" not in names


def test_export_is_deterministic_for_unchanged_input(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    export_recon_evidence_pack(input_dir, first, clock=lambda: FIXED_TIME)
    export_recon_evidence_pack(input_dir, second, clock=lambda: FIXED_TIME)

    assert first.read_bytes() == second.read_bytes()


def test_export_deep_evidence_omitted_none_and_empty_are_unchanged(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    baseline = tmp_path / "baseline.zip"
    explicit_none = tmp_path / "none.zip"
    explicit_empty = tmp_path / "empty.zip"

    export_recon_evidence_pack(input_dir, baseline, clock=lambda: FIXED_TIME)
    export_recon_evidence_pack(
        input_dir,
        explicit_none,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=None,
    )
    export_recon_evidence_pack(
        input_dir,
        explicit_empty,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(),
    )

    assert explicit_none.read_bytes() == baseline.read_bytes()
    assert explicit_empty.read_bytes() == baseline.read_bytes()


def test_export_accepts_tuple_and_list_of_path_deep_evidence(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    first_file = input_dir / "deep-one.md"
    second_file = input_dir / "deep-two.md"
    first_file.write_text("one\n", encoding="utf-8")
    second_file.write_text("two\n", encoding="utf-8")
    supplied_list = [second_file]

    export_recon_evidence_pack(
        input_dir,
        tmp_path / "tuple.zip",
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(first_file,),
    )
    export_recon_evidence_pack(
        input_dir,
        tmp_path / "list.zip",
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=supplied_list,
    )

    assert supplied_list == [second_file]


@pytest.mark.parametrize(
    "invalid_value",
    [
        "deep.md",
        b"deep.md",
        Path("deep.md"),
        ("deep.md",),
        (1,),
    ],
)
def test_export_rejects_invalid_deep_evidence_path_types(
    tmp_path: Path,
    invalid_value,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    with pytest.raises(
        TypeError,
        match="deep_evidence_paths must be a sequence of pathlib.Path values",
    ):
        export_recon_evidence_pack(
            input_dir,
            output_path,
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=invalid_value,
        )

    assert not output_path.exists()


def test_export_rejects_object_deep_evidence_without_string_coercion(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    class StringTrap:
        def __str__(self) -> str:
            raise AssertionError("__str__ must not be called for invalid Deep evidence paths")

    with pytest.raises(
        TypeError,
        match="deep_evidence_paths must be a sequence of pathlib.Path values",
    ):
        export_recon_evidence_pack(
            input_dir,
            output_path,
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=(StringTrap(),),
        )

    assert not output_path.exists()


def test_export_resolves_relative_deep_evidence_against_input_dir(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    deep_dir = input_dir / "deep"
    deep_dir.mkdir()
    (deep_dir / "relative.md").write_text("relative\n", encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(Path("deep/relative.md"),),
    )

    with zipfile.ZipFile(output_path) as archive:
        assert archive.read("raw/deep/relative.md") == b"relative\n"


def test_export_rejects_deep_evidence_path_traversal(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)

    with pytest.raises(ValueError, match="Unsafe path traversal"):
        export_recon_evidence_pack(
            input_dir,
            tmp_path / "pack.zip",
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=(Path("../outside.md"),),
        )


def test_export_includes_explicit_deep_evidence_files_deterministically(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    deep_dir = input_dir / "deep"
    deep_dir.mkdir()
    alpha = deep_dir / "deep-alpha.md"
    beta = deep_dir / "deep-beta.json"
    alpha.write_bytes(b"# alpha\n")
    beta.write_bytes(b'{"beta": true}\n')
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    result = export_recon_evidence_pack(
        input_dir,
        first,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(beta, alpha, alpha),
    )
    export_recon_evidence_pack(
        input_dir,
        second,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(alpha, beta),
    )

    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        manifest = json.loads(archive.read("bugslyce_export_manifest.json").decode("utf-8"))
        assert archive.read("raw/deep/deep-alpha.md") == b"# alpha\n"
        assert archive.read("raw/deep/deep-beta.json") == b'{"beta": true}\n'
    assert names.count("raw/deep/deep-alpha.md") == 1
    assert names.count("raw/deep/deep-beta.json") == 1
    assert "raw/nmap-allports.txt" in names
    assert all(not name.startswith("/") for name in names)
    assert all(".." not in Path(name).parts for name in names)
    assert manifest["files_included"] == sorted(manifest["files_included"])
    assert result.files_included == manifest["files_included"]


def test_export_skips_deep_evidence_already_included_as_top_level_file(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    result = export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(input_dir / "report.md",),
    )

    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
    assert "report.md" in names
    assert "raw/report.md" not in names
    assert "report.md" in result.files_included
    assert "raw/report.md" not in result.files_included
    assert result.missing_files == []


def test_export_skips_deep_evidence_already_included_as_manifest_artifact(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(input_dir / "nmap-allports.txt",),
    )

    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
    assert names.count("raw/nmap-allports.txt") == 1


def test_export_skips_symlink_alias_to_existing_in_root_source(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    alias = input_dir / "nmap-alias.txt"
    alias.symlink_to(input_dir / "nmap-allports.txt")
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(alias,),
    )

    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
    assert names.count("raw/nmap-allports.txt") == 1
    assert "raw/nmap-alias.txt" not in names


def test_export_includes_different_deep_files_with_same_basename_deterministically(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    first_dir = input_dir / "first"
    second_dir = input_dir / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    first_file = first_dir / "shared.md"
    second_file = second_dir / "shared.md"
    first_file.write_bytes(b"first\n")
    second_file.write_bytes(b"second\n")
    first_zip = tmp_path / "first.zip"
    second_zip = tmp_path / "second.zip"

    export_recon_evidence_pack(
        input_dir,
        first_zip,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(second_file, first_file),
    )
    export_recon_evidence_pack(
        input_dir,
        second_zip,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(first_file, second_file),
    )

    assert first_zip.read_bytes() == second_zip.read_bytes()
    with zipfile.ZipFile(first_zip) as archive:
        assert archive.read("raw/first/shared.md") == b"first\n"
        assert archive.read("raw/second/shared.md") == b"second\n"


def test_export_rejects_deep_evidence_self_inclusion_before_writing(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = input_dir / "pack.zip"

    with pytest.raises(ValueError, match="cannot be the export output path"):
        export_recon_evidence_pack(
            input_dir,
            output_path,
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=(output_path,),
        )

    assert not output_path.exists()


def test_export_rejects_existing_output_self_inclusion_without_truncating(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = input_dir / "pack.zip"
    output_path.write_bytes(b"keep this zip placeholder")

    with pytest.raises(ValueError, match="cannot be the export output path"):
        export_recon_evidence_pack(
            input_dir,
            output_path,
            force=True,
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=(output_path,),
        )

    assert output_path.read_bytes() == b"keep this zip placeholder"


def test_export_deep_evidence_uses_existing_missing_directory_and_outside_policy(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    missing = input_dir / "deep-missing.md"
    directory = input_dir / "deep-dir"
    directory.mkdir()
    output_path = tmp_path / "pack.zip"

    result = export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        deep_evidence_paths=(missing, directory),
    )

    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
    assert "raw/deep-missing.md" not in names
    assert "raw/deep-dir" not in names
    assert result.missing_files == ["raw/deep-dir", "raw/deep-missing.md"]

    outside = tmp_path / "outside-deep.md"
    outside.write_text("outside\n", encoding="utf-8")
    with pytest.raises(ValueError, match="outside input directory"):
        export_recon_evidence_pack(
            input_dir,
            tmp_path / "outside.zip",
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=(outside,),
        )


def test_export_deep_evidence_symlink_policy_matches_existing_root_policy(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    outside = tmp_path / "outside-secret.md"
    outside.write_text("secret\n", encoding="utf-8")
    link = input_dir / "deep-link.md"
    link.symlink_to(outside)

    with pytest.raises(ValueError, match="outside input directory"):
        export_recon_evidence_pack(
            input_dir,
            tmp_path / "pack.zip",
            clock=lambda: FIXED_TIME,
            deep_evidence_paths=(link,),
        )


def test_export_does_not_discover_deep_files_without_explicit_paths(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / "deep-unlisted.md").write_text("# deep\n", encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)

    with zipfile.ZipFile(output_path) as archive:
        assert "raw/deep-unlisted.md" not in archive.namelist()


def test_export_zip_entry_timestamps_remain_fixed(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)

    with zipfile.ZipFile(output_path) as archive:
        assert {info.date_time for info in archive.infolist()} == {
            (1980, 1, 1, 0, 0, 0)
        }


def test_cli_export_help(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["recon", "export", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce recon export" in captured.out
    assert "--input-dir" in captured.out
    assert "--output" in captured.out
    assert "--force" in captured.out


def test_cli_export_succeeds_without_live_activity(tmp_path: Path, capsys) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    exit_code = main(
        [
            "recon",
            "export",
            "--input-dir",
            str(input_dir),
            "--output",
            str(output_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "by Rayza Slyce" not in captured.out
    assert output_path.is_file()
    assert "BugSlyce evidence pack export complete" in captured.out
    assert "No live commands were executed." in captured.out
    assert "No network requests were made." in captured.out


def test_cli_export_uses_current_reference_closure_contract(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / "runbook.md").write_text("# Runbook\n", encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    exit_code = main(
        [
            "recon",
            "export",
            "--input-dir",
            str(input_dir),
            "--output",
            str(output_path),
        ]
    )
    capsys.readouterr()
    extracted = tmp_path / "clean-cli-pack"
    with zipfile.ZipFile(output_path) as archive:
        names = set(archive.namelist())
        archive.extractall(extracted)
        manifest = json.loads(archive.read("bugslyce_export_manifest.json"))

    assert exit_code == 0
    assert REFERENCE_CLOSURE_FILENAME in names
    assert manifest["reference_closure"] == REFERENCE_CLOSURE_FILENAME
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


def test_api_and_cli_exports_share_the_same_baseline_closure(
    tmp_path: Path,
    capsys,
) -> None:
    input_dir = _export_input(tmp_path)
    api_pack = tmp_path / "api.zip"
    additive_pack = tmp_path / "additive.zip"
    cli_pack = tmp_path / "cli.zip"
    shared = input_dir / "shared.json"
    shared.write_text('{"retained": true}\n', encoding="utf-8")

    export_recon_evidence_pack(input_dir, api_pack, clock=lambda: FIXED_TIME)
    export_recon_evidence_pack(
        input_dir,
        additive_pack,
        clock=lambda: FIXED_TIME,
        reference_requirements=(
            EvidencePackReference(
                "shared.json",
                "successful_deep_content",
                "DEEP-CONTENT-0001",
                ("EVID-SHARED",),
            ),
        ),
    )
    assert main(
        [
            "recon",
            "export",
            "--input-dir",
            str(input_dir),
            "--output",
            str(cli_pack),
        ]
    ) == 0
    capsys.readouterr()

    def closure_paths(path: Path) -> set[str]:
        with zipfile.ZipFile(path) as archive:
            payload = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))
        return {item["portable_path"] for item in payload["references"]}

    api_paths = closure_paths(api_pack)
    assert closure_paths(cli_pack) == api_paths
    assert closure_paths(additive_pack) == {*api_paths, "shared.json"}


@pytest.mark.parametrize(
    ("message", "note"),
    (
        ("archive write failed", None),
        (
            "archive write failed",
            "temporary export archive cleanup failed: permission denied",
        ),
        ("atomic replace failed", None),
    ),
)
def test_cli_export_handles_expected_oserror_without_traceback(
    tmp_path: Path,
    monkeypatch,
    capsys,
    message: str,
    note: str | None,
) -> None:
    input_dir = _export_input(tmp_path)
    output_path = tmp_path / "pack.zip"

    def fail_export(*args, **kwargs):
        error = OSError(message)
        if note is not None:
            error.add_note(note)
        raise error

    monkeypatch.setattr("bugslyce.cli.export_recon_evidence_pack", fail_export)

    exit_code = main(
        [
            "recon",
            "export",
            "--input-dir",
            str(input_dir),
            "--output",
            str(output_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert f"Error: {message}" in captured.err
    if note is not None:
        assert f"Cleanup warning: {note}." in captured.err
    assert "No live commands were executed." in captured.err
    assert "No network requests were made." in captured.err
    assert "Traceback" not in captured.err


def test_export_module_has_no_command_or_network_execution_apis() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "bugslyce"
        / "recon"
        / "export.py"
    ).read_text(encoding="utf-8")

    assert "subprocess" not in source
    assert "Popen" not in source
    assert "os.system" not in source
    assert "pexpect" not in source
    assert "requests." not in source
    assert "urlopen" not in source


def test_export_module_does_not_import_deep_implementation_modules() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "bugslyce"
        / "recon"
        / "export.py"
    ).read_text(encoding="utf-8")

    for forbidden in (
        "deep_collection_review_bundle",
        "deep_http_fingerprint_summary",
        "deep_redirect_auth_flow_review",
        "deep_response_similarity_review",
        "deep_html_route_extraction",
        "deep_javascript_route_extraction",
        "deep_shallow_route_followup",
        "deep_form_inventory",
        "deep_parameter_inventory",
    ):
        assert forbidden not in source


@pytest.mark.parametrize("absolute_scope", (False, True))
def test_current_export_maps_custom_scope_to_portable_core_path(
    tmp_path: Path,
    absolute_scope: bool,
) -> None:
    input_dir = _export_input(tmp_path)
    policies = input_dir / "policies"
    policies.mkdir()
    custom_scope = policies / "engagement.md"
    custom_scope.write_text("custom scope\n", encoding="utf-8")
    (input_dir / "scope.md").write_text("wrong scope\n", encoding="utf-8")
    manifest_path = input_dir / "recon_manifest.json"
    original = json.loads(manifest_path.read_text(encoding="utf-8"))
    original["scope_file"] = (
        str(custom_scope) if absolute_scope else "policies/engagement.md"
    )
    manifest_path.write_text(json.dumps(original), encoding="utf-8")
    output_path = tmp_path / f"scope-{absolute_scope}.zip"

    result = export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        packed_manifest = json.loads(archive.read("recon_manifest.json"))
        packed_scope = archive.read("scope.md").decode("utf-8")
        closure = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))
        archive.extractall(tmp_path / f"scope-{absolute_scope}")
    scope_record = next(
        item for item in closure["references"] if item["portable_path"] == "scope.md"
    )
    assert result.reference_closure_status == "complete"
    assert packed_scope == "custom scope\n"
    assert packed_manifest["scope_file"] == "scope.md"
    assert scope_record["included"] is True
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == original
    assert validate_evidence_pack_root(
        tmp_path / f"scope-{absolute_scope}"
    ).validation_status == "complete"


@pytest.mark.parametrize(
    ("manifest_value", "source_relative", "expected_member"),
    (
        ("absolute", "absolute.txt", "raw/absolute.txt"),
        ("raw/foo.txt", "raw/foo.txt", "raw/raw/foo.txt"),
        ("metadata/foo.txt", "metadata/foo.txt", "raw/metadata/foo.txt"),
        ("nested/foo.txt", "nested/foo.txt", "raw/nested/foo.txt"),
        ("report.md", "report.md", "raw/report.md"),
    ),
)
def test_packed_manifest_names_exact_archive_member(
    tmp_path: Path,
    manifest_value: str,
    source_relative: str,
    expected_member: str,
) -> None:
    input_dir = _export_input(tmp_path)
    source = input_dir / source_relative
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("manifest evidence\n", encoding="utf-8")
    manifest_path = input_dir / "recon_manifest.json"
    original = json.loads(manifest_path.read_text(encoding="utf-8"))
    original["artifacts"] = [
        {
            "type": "synthetic",
            "file": str(source) if manifest_value == "absolute" else manifest_value,
        }
    ]
    manifest_path.write_text(json.dumps(original), encoding="utf-8")
    output_path = tmp_path / f"manifest-{source.name}.zip"
    export_recon_evidence_pack(input_dir, output_path)
    extracted = tmp_path / f"manifest-{source.stem}"
    with zipfile.ZipFile(output_path) as archive:
        packed = json.loads(archive.read("recon_manifest.json"))
        names = set(archive.namelist())
        archive.extractall(extracted)

    assert packed["artifacts"][0]["file"] == expected_member
    assert expected_member in names
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == original
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


@pytest.mark.parametrize(
    ("member", "content"),
    (
        ("project_state.json", "{broken"),
        ("recon_manifest.json", "[]"),
        ("project_state.json", '{"project_state": []}'),
        ("project_state.json", '{"project_state": {"evidence": {}}}'),
        ("project_state.json", '{"project_state": {"processed_files": {}}}'),
    ),
)
def test_validator_rejects_malformed_required_structured_metadata(
    tmp_path: Path,
    member: str,
    content: str,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    (extracted / member).write_text(content, encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert "structured_reference_discovery_failed" in validation.metadata_consistency_errors


@pytest.mark.parametrize(
    ("member", "content"),
    (
        ("deep_source_route_collection.json", "{broken"),
        ("deep_recon_orchestration.json", "{broken"),
        (
            "deep_recon_orchestration.json",
            '{"report_markdown_file": 7, "runbook_markdown_file": []}',
        ),
    ),
)
def test_present_malformed_deep_metadata_is_not_treated_as_absent(
    tmp_path: Path,
    member: str,
    content: str,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    (extracted / member).write_text(content, encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert "structured_reference_discovery_failed" in validation.metadata_consistency_errors


@pytest.mark.parametrize(
    "orphan_member",
    (
        "deep_source_route_collection.md",
        "deep_recon_review.md",
        "deep_recon_runbook.md",
    ),
)
def test_present_deep_markdown_requires_its_structured_json_partner(
    tmp_path: Path,
    orphan_member: str,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    (extracted / orphan_member).write_text("# retained Deep output\n", encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert "structured_reference_discovery_failed" in validation.metadata_consistency_errors


@pytest.mark.parametrize(
    "mutation",
    ("included_text", "evidence_text", "reason_number", "duplicate_owner", "bool_count"),
)
def test_validator_rejects_malformed_closure_record_field_types(
    tmp_path: Path,
    mutation: str,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    record = closure["references"][0]
    if mutation == "included_text":
        record["included"] = "false"
    elif mutation == "evidence_text":
        record["owners"][0]["evidence_ids"] = "EVID-BAD"
    elif mutation == "reason_number":
        record["unresolved_reason"] = 7
    elif mutation == "duplicate_owner":
        record["owners"].append(dict(record["owners"][0]))
    else:
        closure["counts"]["referenced_paths"] = True
    closure_path.write_text(json.dumps(closure), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert validation.metadata_consistency_errors or validation.required_metadata_errors


@pytest.mark.parametrize(
    "member",
    (
        "project_state.json",
        "recon_manifest.json",
        "bugslyce_project.json",
        "deep_source_route_collection.json",
    ),
)
def test_validator_does_not_follow_external_structured_metadata_symlink(
    tmp_path: Path,
    member: str,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    outside = tmp_path / f"outside-{member}"
    outside.write_text(
        json.dumps(
            {
                "project_state": {
                    "evidence": [
                        {
                            "id": "EVID-OUTSIDE",
                            "source_file": "raw/outside.txt",
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    path = extracted / member
    path.unlink(missing_ok=True)
    path.symlink_to(outside)

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert member in validation.unsafe_paths
    assert all(
        item.portable_path != "raw/outside.txt"
        for item in validation.expected_references_missing_from_closure
    )


@pytest.mark.parametrize("source_file", ("/outside/source.html", "../outside.html"))
def test_export_rejects_unsafe_project_state_artefact_paths(
    tmp_path: Path,
    source_file: str,
) -> None:
    input_dir = _export_input(tmp_path)
    state_path = input_dir / "project_state.json"
    state_path.write_text(
        json.dumps(
            {
                "project_state": {
                    "input_dir": str(input_dir),
                    "http_artifacts": [
                        {
                            "url": "https://portal.example.test/files/",
                            "artifact_type": "link",
                            "value": "/notice.txt",
                            "source_file": source_file,
                            "evidence_ids": [],
                        }
                    ],
                    "discovered_paths": [
                        {
                            "url": "https://portal.example.test/files",
                            "redirect_location": "/files/",
                            "source": "source_route_coverage",
                        }
                    ],
                    "evidence": [],
                },
                "candidates": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="project state|artefact path|outside|traversal"):
        export_recon_evidence_pack(input_dir, tmp_path / "unsafe-state.zip")


def test_project_state_portability_rewrite_does_not_reclassify_urls_or_routes(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    state_path = input_dir / "project_state.json"
    state_path.write_text(
        json.dumps(
            {
                "project_state": {
                    "input_dir": str(input_dir),
                    "processed_files": [],
                    "evidence": [],
                    "http_artifacts": [],
                    "discovered_paths": [
                        {
                            "url": "https://portal.example.test/files",
                            "redirect_location": "/files/",
                            "source": "source_route_coverage",
                        }
                    ],
                },
                "candidates": [],
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "url-preservation.zip"

    export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        packed = json.loads(archive.read("project_state.json"))
    path = packed["project_state"]["discovered_paths"][0]
    assert path["url"] == "https://portal.example.test/files"
    assert path["redirect_location"] == "/files/"
    assert path["source"] == "source_route_coverage"


def test_packed_project_state_rewrites_all_established_file_provenance_fields(
    tmp_path: Path,
) -> None:
    input_dir = _project_state_provenance_export_input(tmp_path)
    original = (input_dir / "project_state.json").read_text(encoding="utf-8")
    output_path = tmp_path / "project-state-provenance.zip"

    export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        payload = json.loads(archive.read("project_state.json"))
    state = payload["project_state"]
    assert state["assets"][0]["sources"] == [
        "scope.md",
        "raw/nmap-allports.txt",
        "raw/nested/homepage-target-80.html",
    ]
    assert state["port_services"][0]["source_file"] == "raw/nmap-allports.txt"
    assert state["recon_manifest"]["source_file"] == "recon_manifest.json"
    assert state["recon_manifest"]["artifacts"][0]["file"] == (
        "raw/nmap-allports.txt"
    )
    assert state["evidence"][0]["source_file"] == "raw/robots.txt"
    assert state["evidence"][0]["value"] == "raw/robots.txt"
    assert state["http_artifacts"][0]["source_file"] == "raw/robots.txt"
    assert state["http_artifacts"][0]["value"] == "raw/robots.txt"
    assert [item["value"] for item in state["evidence"][1:]] == [
        "/",
        "/icons/text.gif",
        "https://portal.example.test/path",
        "arbitrary retained text",
    ]
    assert state["discovered_paths"][0]["url"] == (
        "https://portal.example.test/library"
    )
    assert state["discovered_paths"][0]["redirect_location"] == "/library/"
    assert (input_dir / "project_state.json").read_text(encoding="utf-8") == original


@pytest.mark.parametrize("absolute_alias", (False, True), ids=("relative", "absolute"))
def test_relative_source_file_rewrites_matching_file_alias(
    tmp_path: Path,
    absolute_alias: bool,
) -> None:
    input_dir = _project_state_provenance_export_input(tmp_path)
    state_path = input_dir / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    robots_path = input_dir / "robots.txt"
    alias = str(robots_path) if absolute_alias else "robots.txt"
    evidence = payload["project_state"]["evidence"][0]
    artifact = payload["project_state"]["http_artifacts"][0]
    evidence["source_file"] = "robots.txt"
    evidence["value"] = alias
    artifact["source_file"] = "robots.txt"
    artifact["value"] = alias
    state_path.write_text(json.dumps(payload), encoding="utf-8")
    output_path = tmp_path / f"relative-source-{absolute_alias}.zip"

    export_recon_evidence_pack(input_dir, output_path)

    extracted = tmp_path / f"relative-source-{absolute_alias}"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
    packed = json.loads(
        (extracted / "project_state.json").read_text(encoding="utf-8")
    )["project_state"]
    assert packed["evidence"][0]["source_file"] == "raw/robots.txt"
    assert packed["evidence"][0]["value"] == "raw/robots.txt"
    assert packed["http_artifacts"][0]["source_file"] == "raw/robots.txt"
    assert packed["http_artifacts"][0]["value"] == "raw/robots.txt"
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("asset", "/outside/asset.txt"),
        ("asset", "../outside.txt"),
        ("port_service", "/outside/nmap.txt"),
        ("port_service", "../outside.txt"),
        ("recon_manifest", "/outside/recon_manifest.json"),
        ("recon_manifest", "../outside.json"),
    ),
)
def test_export_rejects_unsafe_established_project_state_provenance(
    tmp_path: Path,
    field: str,
    unsafe_value: str,
) -> None:
    input_dir = _project_state_provenance_export_input(tmp_path)
    state_path = input_dir / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    state = payload["project_state"]
    if field == "asset":
        state["assets"][0]["sources"] = [unsafe_value]
    elif field == "port_service":
        state["port_services"][0]["source_file"] = unsafe_value
    else:
        state["recon_manifest"]["source_file"] = unsafe_value
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="project state|outside|traversal"):
        export_recon_evidence_pack(input_dir, tmp_path / f"unsafe-{field}.zip")


def test_export_rejects_external_symlink_in_asset_sources(tmp_path: Path) -> None:
    input_dir = _project_state_provenance_export_input(tmp_path)
    outside = tmp_path / "outside-source.txt"
    outside.write_text("outside\n", encoding="utf-8")
    link = input_dir / "external-source.txt"
    link.symlink_to(outside)
    state_path = input_dir / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["project_state"]["assets"][0]["sources"] = [str(link)]
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="outside input directory"):
        export_recon_evidence_pack(input_dir, tmp_path / "symlink-source.zip")


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("asset", "/host/asset.txt"),
        ("port_service", "../nmap.txt"),
        ("recon_manifest", "/host/recon_manifest.json"),
        ("evidence", "raw/missing-evidence.txt"),
    ),
)
def test_validator_rejects_nonportable_project_state_provenance_fields(
    tmp_path: Path,
    field: str,
    unsafe_value: str,
) -> None:
    extracted = _project_state_provenance_pack_root(tmp_path)
    state_path = extracted / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    state = payload["project_state"]
    if field == "asset":
        state["assets"][0]["sources"][0] = unsafe_value
    elif field == "port_service":
        state["port_services"][0]["source_file"] = unsafe_value
    elif field == "recon_manifest":
        state["recon_manifest"]["source_file"] = unsafe_value
    else:
        state["evidence"][0]["source_file"] = unsafe_value
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert any(
        error.startswith("portable_project_state_")
        for error in validation.metadata_consistency_errors
    )


def test_validator_preserves_route_and_content_values_in_project_state(
    tmp_path: Path,
) -> None:
    extracted = _project_state_provenance_pack_root(tmp_path)
    state = json.loads(
        (extracted / "project_state.json").read_text(encoding="utf-8")
    )["project_state"]

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "complete"
    assert [item["value"] for item in state["evidence"][1:]] == [
        "/",
        "/icons/text.gif",
        "https://portal.example.test/path",
        "arbitrary retained text",
    ]
    assert state["discovered_paths"][0]["redirect_location"] == "/library/"


@pytest.mark.parametrize(
    ("member", "field_path", "value"),
    (
        ("bugslyce_export_manifest.json", ("source_input_dir",), "/host/project"),
        ("bugslyce_project.json", ("output_dir",), "/host/output"),
        ("bugslyce_project.json", ("scope_file",), "/host/scope.md"),
        ("project_state.json", ("project_state", "input_dir"), "/host/project"),
        ("recon_manifest.json", ("scope_file",), "/host/scope.md"),
    ),
)
def test_validator_rejects_nonportable_current_metadata_fields(
    tmp_path: Path,
    member: str,
    field_path: tuple[str, ...],
    value: str,
) -> None:
    extracted = _structured_current_pack_root(tmp_path)
    path = extracted / member
    payload = json.loads(path.read_text(encoding="utf-8"))
    target = payload
    for key in field_path[:-1]:
        target = target[key]
    target[field_path[-1]] = value
    path.write_text(json.dumps(payload), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert any("portable" in error for error in validation.metadata_consistency_errors)


def test_missing_manifest_artefact_is_recorded_once_as_portable_path(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    missing = input_dir / "nested" / "missing.txt"
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"] = [{"type": "text", "file": str(missing)}]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = export_recon_evidence_pack(input_dir, tmp_path / "missing-portable.zip")

    with zipfile.ZipFile(tmp_path / "missing-portable.zip") as archive:
        packed_manifest = json.loads(archive.read("bugslyce_export_manifest.json"))
    assert result.missing_files == ["raw/nested/missing.txt"]
    assert packed_manifest["missing_files"] == ["raw/nested/missing.txt"]
    assert str(input_dir) not in json.dumps(packed_manifest)


def test_export_reconstructs_bounded_and_deep_confidence_owners(tmp_path: Path) -> None:
    input_dir = _deep_relationship_export_input(tmp_path)
    discovery = input_dir / "gobuster-deep-bounded-core.txt"
    discovery.write_text("/library/\n", encoding="utf-8")
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"].append(
        {"type": "gobuster", "file": discovery.name}
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    state_path = input_dir / "project_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["project_state"]["evidence"].append(
        {
            "id": "EVID-DISCOVERY",
            "source_file": str(discovery),
            "evidence_type": "discovered_path",
            "value": "/library/",
            "context": {},
        }
    )
    state_path.write_text(json.dumps(state), encoding="utf-8")
    output_path = tmp_path / "confidence-owners.zip"

    export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        closure = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))
        members = set(archive.namelist())
    owners = _closure_owner_associations(closure)
    assert (
        "recon_manifest.json",
        "collection_confidence_notice",
        "CONFIDENCE-BOUNDED-CONTENT-DISCOVERY",
        ("EVID-DISCOVERY",),
    ) in owners
    deep_owner = next(
        owner
        for owner in owners
        if owner[0] == "deep_source_route_collection.json"
        and owner[1] == "collection_confidence_notice"
        and owner[2] == "CONFIDENCE-DEEP-SOURCE-ROUTES"
    )
    assert deep_owner[3] == (
        "EVID-LINK-NOTICE",
        "EVID-LINK-README",
        "EVID-REDIRECT",
    )
    assert "recon_manifest.json" in members
    assert "deep_source_route_collection.json" in members


def test_failed_pipeline_notice_is_portable_and_required_by_closure(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    pipeline_path = input_dir / "project_pipeline.json"
    pipeline_payload = {
        "project_file": str(input_dir / "bugslyce_project.json"),
        "scope_file": str(input_dir / "scope.md"),
        "output_dir": str(input_dir),
        "report_path": str(input_dir / "report.md"),
        "runbook_path": str(input_dir / "runbook.md"),
        "export_path": str(tmp_path / "pack.zip"),
        "final_status": "failed",
        "steps": [
            {
                "step_id": "PIPELINE-STEP-FAILED",
                "name": "bounded collector",
                "command_kind": "content-run",
                "status": "failed",
                "message": "collector failed while reviewing /api/login",
                "started_at": "2026-07-21T12:00:00Z",
                "completed_at": "2026-07-21T12:00:01Z",
                "output_paths": [str(input_dir / "partial-output.txt")],
            }
        ],
    }
    source_bytes = json.dumps(pipeline_payload).encode("utf-8")
    pipeline_path.write_bytes(source_bytes)
    output_path = tmp_path / "failed-stage.zip"
    export_recon_evidence_pack(input_dir, output_path)
    extracted = tmp_path / "failed-stage"
    with zipfile.ZipFile(output_path) as archive:
        closure = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))
        packed_pipeline = json.loads(archive.read("project_pipeline.json"))
        archive.extractall(extracted)

    assert pipeline_path.read_bytes() == source_bytes
    assert packed_pipeline["portable_confidence_schema"] == 1
    assert packed_pipeline["generated_by"] == "bugslyce.collection_confidence.pipeline"
    assert packed_pipeline["steps"][0]["status"] == "failed"
    assert packed_pipeline["steps"][0]["message"] == (
        "collector failed while reviewing /api/login"
    )
    for field in (
        "project_file",
        "scope_file",
        "output_dir",
        "report_path",
        "runbook_path",
        "export_path",
    ):
        assert field not in packed_pipeline
    assert "output_paths" not in packed_pipeline["steps"][0]
    assert "project_pipeline.json" in {
        record[0]
        for record in _closure_owner_associations(closure)
        if record[1] == "collection_confidence_notice"
        and record[2] == "CONFIDENCE-STAGE-PIPELINE-STEP-FAILED"
    }
    assert validate_evidence_pack_root(extracted).validation_status == "complete"

    closure_path = extracted / REFERENCE_CLOSURE_FILENAME
    packed_closure = json.loads(closure_path.read_text(encoding="utf-8"))
    pipeline_record = next(
        record
        for record in packed_closure["references"]
        if record["portable_path"] == "project_pipeline.json"
    )
    pipeline_record["owners"] = [
        owner
        for owner in pipeline_record["owners"]
        if owner["owner_kind"] != "collection_confidence_notice"
    ]
    closure_path.write_text(json.dumps(packed_closure), encoding="utf-8")
    owner_validation = validate_evidence_pack_root(extracted)
    assert owner_validation.validation_status == "incomplete"
    assert any(
        record.portable_path == "project_pipeline.json"
        for record in owner_validation.owner_association_errors
    )

    closure_path.write_text(json.dumps(closure), encoding="utf-8")
    (extracted / "project_pipeline.json").unlink()
    validation = validate_evidence_pack_root(extracted)
    assert validation.validation_status == "incomplete"
    assert "project_pipeline.json" in validation.missing_declared_member_paths


def test_failed_command_notice_uses_included_portable_member(tmp_path: Path) -> None:
    input_dir = _export_input(tmp_path)
    execution = input_dir / "recon_execution_content_run.json"
    command_payload = {
        "input_dir": str(input_dir),
        "manifest_path": str(input_dir / "recon_manifest.json"),
        "project_state_path": str(input_dir / "project_state.json"),
        "report_path": str(input_dir / "report.md"),
        "scope_file": str(input_dir / "scope.md"),
        "output_dir": str(tmp_path / "plan-output"),
        "plan_path": str(tmp_path / "plan-output/content_discovery_plan.json"),
        "generated_paths": [str(tmp_path / "plan-output/result.txt")],
        "command_results": [
            {
                "command_id": "CONTENT-COMMAND-FAILED",
                "tool": "bounded-collector",
                "executed": True,
                "exit_code": 2,
                "error": "structured failure mentioning /tmp/example but not a field",
                "output_file": str(tmp_path / "plan-output/result.txt"),
                "started_at": "2026-07-21T12:00:00Z",
                "ended_at": "2026-07-21T12:00:01Z",
            }
        ],
    }
    source_bytes = json.dumps(command_payload).encode("utf-8")
    execution.write_bytes(source_bytes)
    output_path = tmp_path / "failed-command.zip"
    export_recon_evidence_pack(input_dir, output_path)
    extracted = tmp_path / "failed-command"
    with zipfile.ZipFile(output_path) as archive:
        closure = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))
        packed_command = json.loads(archive.read("recon_execution_content_run.json"))
        historical_command = archive.read(
            "metadata/recon_execution_content_run.json"
        )
        archive.extractall(extracted)

    assert execution.read_bytes() == source_bytes
    assert historical_command == source_bytes
    assert packed_command["portable_confidence_schema"] == 1
    assert packed_command["generated_by"] == (
        "bugslyce.collection_confidence.command_execution"
    )
    packed_result = packed_command["command_results"][0]
    assert packed_result["command_id"] == "CONTENT-COMMAND-FAILED"
    assert packed_result["tool"] == "bounded-collector"
    assert packed_result["executed"] is True
    assert packed_result["exit_code"] == 2
    assert packed_result["error"] == (
        "structured failure mentioning /tmp/example but not a field"
    )
    assert "output_file" not in packed_result
    for field in (
        "input_dir",
        "manifest_path",
        "project_state_path",
        "report_path",
        "scope_file",
        "output_dir",
        "plan_path",
        "generated_paths",
    ):
        assert field not in packed_command
    owner = next(
        record
        for record in _closure_owner_associations(closure)
        if record[1] == "collection_confidence_notice"
        and record[2] == "CONFIDENCE-COMMAND-CONTENT-COMMAND-FAILED"
    )
    assert owner[0] == "recon_execution_content_run.json"
    assert (extracted / owner[0]).is_file()
    assert (extracted / "metadata/recon_execution_content_run.json").is_file()
    assert validate_evidence_pack_root(extracted).validation_status == "complete"
    (extracted / owner[0]).unlink()
    assert validate_evidence_pack_root(extracted).validation_status == "incomplete"


def test_portable_confidence_projections_preserve_skipped_unavailable_states(
    tmp_path: Path,
) -> None:
    input_dir = _export_input(tmp_path)
    (input_dir / "project_pipeline.json").write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "step_id": "PIPELINE-STEP-SKIPPED",
                        "name": "profile stage",
                        "command_kind": "optional-stage",
                        "status": "skipped",
                        "message": "excluded by profile /api/login",
                    },
                    {
                        "step_id": "PIPELINE-STEP-UNAVAILABLE",
                        "name": "local helper",
                        "command_kind": "local-helper",
                        "status": "unavailable",
                        "message": "dependency unavailable",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    (input_dir / "recon_execution_optional.json").write_text(
        json.dumps(
            {
                "command_results": [
                    {
                        "command_id": "COMMAND-NOT-EXECUTED",
                        "tool": "optional-collector",
                        "executed": False,
                        "exit_code": None,
                        "error": None,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    output_path = tmp_path / "skipped-unavailable.zip"
    export_recon_evidence_pack(input_dir, output_path)
    extracted = tmp_path / "skipped-unavailable"
    with zipfile.ZipFile(output_path) as archive:
        closure = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))
        pipeline = json.loads(archive.read("project_pipeline.json"))
        commands = json.loads(archive.read("recon_execution_optional.json"))
        archive.extractall(extracted)

    owners = _closure_owner_associations(closure)
    assert {
        owner[2]
        for owner in owners
        if owner[1] == "collection_confidence_notice"
    } == {
        "CONFIDENCE-COMMAND-COMMAND-NOT-EXECUTED",
        "CONFIDENCE-STAGE-PIPELINE-STEP-SKIPPED",
        "CONFIDENCE-STAGE-PIPELINE-STEP-UNAVAILABLE",
    }
    assert [step["status"] for step in pipeline["steps"]] == [
        "skipped",
        "unavailable",
    ]
    assert commands["command_results"][0]["executed"] is False
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


@pytest.mark.parametrize(
    ("member", "field", "value", "expected_error"),
    (
        (
            "project_pipeline.json",
            "portable_confidence_schema",
            2,
            "portable_confidence_pipeline_metadata_invalid:portable_confidence_schema",
        ),
        (
            "project_pipeline.json",
            "steps",
            {},
            "portable_confidence_pipeline_metadata_invalid:steps",
        ),
        (
            "recon_execution_content_run.json",
            "portable_confidence_schema",
            "1",
            (
                "portable_confidence_command_metadata_invalid:"
                "recon_execution_content_run.json:portable_confidence_schema"
            ),
        ),
        (
            "recon_execution_content_run.json",
            "command_results",
            {},
            (
                "portable_confidence_command_metadata_invalid:"
                "recon_execution_content_run.json:command_results"
            ),
        ),
    ),
)
def test_validator_rejects_malformed_confidence_projection_schema(
    tmp_path: Path,
    member: str,
    field: str,
    value: object,
    expected_error: str,
) -> None:
    input_dir = _export_input(tmp_path)
    if member == "project_pipeline.json":
        (input_dir / member).write_text(
            json.dumps(
                {
                    "steps": [
                        {
                            "step_id": "PIPELINE-STEP-FAILED",
                            "name": "collector",
                            "command_kind": "content-run",
                            "status": "failed",
                            "message": "failed at /api/login",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
    else:
        (input_dir / member).write_text(
            json.dumps(
                {
                    "command_results": [
                        {
                            "command_id": "COMMAND-FAILED",
                            "tool": "collector",
                            "executed": True,
                            "exit_code": 2,
                            "error": "failed at https://example.test/path",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
    output_path = tmp_path / f"malformed-{field}.zip"
    export_recon_evidence_pack(input_dir, output_path)
    extracted = tmp_path / f"malformed-{field}"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
    path = extracted / member
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[field] = value
    path.write_text(json.dumps(payload), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert expected_error in validation.metadata_consistency_errors


def test_portable_confidence_projection_is_deterministic_under_reversed_order(
    tmp_path: Path,
) -> None:
    outputs = []
    steps = [
        {
            "step_id": "PIPELINE-STEP-B",
            "name": "second",
            "command_kind": "collector",
            "status": "failed",
            "message": "failed at /api/login",
        },
        {
            "step_id": "PIPELINE-STEP-A",
            "name": "first",
            "command_kind": "collector",
            "status": "skipped",
            "message": "see https://example.test/path",
        },
    ]
    commands = [
        {
            "command_id": "COMMAND-B",
            "tool": "collector",
            "executed": True,
            "exit_code": 2,
            "error": "failed /tmp/text only",
        },
        {
            "command_id": "COMMAND-A",
            "tool": "collector",
            "executed": False,
            "exit_code": None,
            "error": None,
        },
    ]
    for index, reverse in enumerate((False, True)):
        root = tmp_path / f"case-{index}"
        root.mkdir()
        input_dir = _export_input(root)
        (input_dir / "project_pipeline.json").write_text(
            json.dumps({"steps": list(reversed(steps)) if reverse else steps}),
            encoding="utf-8",
        )
        (input_dir / "recon_execution_content_run.json").write_text(
            json.dumps(
                {"command_results": list(reversed(commands)) if reverse else commands}
            ),
            encoding="utf-8",
        )
        output_path = root / "pack.zip"
        export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)
        with zipfile.ZipFile(output_path) as archive:
            outputs.append(
                (
                    archive.read("project_pipeline.json"),
                    archive.read("recon_execution_content_run.json"),
                    _closure_owner_associations(
                        json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))
                    ),
                )
            )

    assert outputs[0] == outputs[1]


@pytest.mark.parametrize(
    ("kind", "field", "unsafe_value", "expected_error"),
    (
        (
            "pipeline",
            "output_dir",
            "/host/project",
            "portable_confidence_pipeline_metadata_invalid:output_dir",
        ),
        (
            "pipeline_step",
            "output_paths",
            ["../outside"],
            "portable_confidence_pipeline_metadata_invalid:steps[0].output_paths",
        ),
        (
            "command",
            "input_dir",
            "/host/project",
            (
                "portable_confidence_command_metadata_invalid:"
                "recon_execution_content_run.json:input_dir"
            ),
        ),
        (
            "command_result",
            "output_file",
            "../outside",
            (
                "portable_confidence_command_metadata_invalid:"
                "recon_execution_content_run.json:command_results[0].output_file"
            ),
        ),
    ),
)
def test_validator_rejects_nonportable_confidence_metadata_fields(
    tmp_path: Path,
    kind: str,
    field: str,
    unsafe_value: object,
    expected_error: str,
) -> None:
    if kind.startswith("pipeline"):
        input_dir = _export_input(tmp_path)
        (input_dir / "project_pipeline.json").write_text(
            json.dumps(
                {
                    "steps": [
                        {
                            "step_id": "PIPELINE-STEP-FAILED",
                            "name": "collector",
                            "command_kind": "content-run",
                            "status": "failed",
                            "message": "failed at /api/login",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        member = "project_pipeline.json"
    else:
        input_dir = _export_input(tmp_path)
        (input_dir / "recon_execution_content_run.json").write_text(
            json.dumps(
                {
                    "command_results": [
                        {
                            "command_id": "COMMAND-FAILED",
                            "tool": "collector",
                            "executed": True,
                            "exit_code": 2,
                            "error": "failed at https://example.test/path",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        member = "recon_execution_content_run.json"
    output_path = tmp_path / f"{kind}.zip"
    export_recon_evidence_pack(input_dir, output_path)
    extracted = tmp_path / f"{kind}-root"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
    member_path = extracted / member
    payload = json.loads(member_path.read_text(encoding="utf-8"))
    target = payload["steps"][0] if kind == "pipeline_step" else payload
    if kind == "command_result":
        target = payload["command_results"][0]
    target[field] = unsafe_value
    member_path.write_text(json.dumps(payload), encoding="utf-8")

    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert expected_error in validation.metadata_consistency_errors


def _deep_relationship_export_input(tmp_path: Path) -> Path:
    input_dir = _export_input(tmp_path)
    parent_url = "https://portal.example.test/library/"
    notice_url = f"{parent_url}notice.txt"
    readme_url = f"{parent_url}readme.txt"
    parent_path = input_dir / "parent.html"
    parent_path.write_text(
        '<a href="notice.txt">Notice</a><a href="readme.txt">Readme</a>\n',
        encoding="utf-8",
    )
    state = ProjectState(
        project_name="deep-portable-test",
        input_dir=str(input_dir),
        processed_files=[str(parent_path)],
        scope_summary="synthetic same-origin scope",
        assets=[],
        http_services=[],
        endpoints=[],
        port_services=[],
        http_artifacts=[
            HTTPArtifact(
                url=parent_url,
                artifact_type="link",
                value="notice.txt",
                source_file=str(parent_path),
                evidence_ids=["EVID-LINK-NOTICE"],
                tags=[],
            ),
            HTTPArtifact(
                url=parent_url,
                artifact_type="link",
                value="readme.txt",
                source_file=str(parent_path),
                evidence_ids=["EVID-LINK-README"],
                tags=[],
            ),
        ],
        discovered_paths=[],
        recon_summary=None,
        recon_manifest=None,
        evidence=[
            Evidence(
                id="EVID-LINK-NOTICE",
                source_file=str(parent_path),
                evidence_type="link",
                value="notice.txt",
                context={"url": parent_url},
            ),
            Evidence(
                id="EVID-LINK-README",
                source_file=str(parent_path),
                evidence_type="link",
                value="readme.txt",
                context={"url": parent_url},
            ),
        ],
        warnings=[],
        generated_at="2026-06-14T13:45:12Z",
    )
    (input_dir / "project_state.json").write_text(
        export_project_state_json(state, []),
        encoding="utf-8",
    )
    manifest = json.loads((input_dir / "recon_manifest.json").read_text(encoding="utf-8"))
    manifest["artifacts"].append(
        {
            "type": "html",
            "file": "parent.html",
            "url": parent_url,
        }
    )
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    items = (
        _deep_collected_item(
            "https://portal.example.test/library",
            status_code=301,
            body=b"redirect",
            evidence_ids=("EVID-REDIRECT",),
            headers=(("Location", "/library/"), ("Content-Type", "text/html")),
        ),
        _deep_collected_item(
            notice_url,
            status_code=200,
            body=b"notice body",
            evidence_ids=("EVID-LINK-NOTICE",),
        ),
        _deep_collected_item(
            readme_url,
            status_code=200,
            body=b"readme body",
            evidence_ids=("EVID-LINK-README",),
        ),
    )
    write_deep_source_route_collection_artifacts(
        DeepSourceRouteCollectionResult(
            collected=items,
            skipped=(),
            total_considered=len(items),
            total_collected=len(items),
            total_skipped=0,
        ),
        input_dir,
    )
    return input_dir


def _deep_collected_item(
    url: str,
    *,
    status_code: int,
    body: bytes,
    evidence_ids: tuple[str, ...],
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/plain"),),
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=status_code,
        final_url=url,
        headers=headers,
        body_preview=body.decode("ascii"),
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.1,
        source="source_route_coverage",
        reason="bounded source review",
        evidence_ids=evidence_ids,
        body=body,
    )


def _expected_deep_relationship_owners() -> set[tuple[str, str, str, tuple[str, ...]]]:
    parent = "https://portal.example.test/library/"
    return {
        (
            "deep_source_route_collection.json",
            "successful_deep_content",
            "DEEP-CONTENT-0001",
            ("EVID-LINK-NOTICE",),
        ),
        (
            "deep_source_route_collection.json",
            "successful_deep_content",
            "DEEP-CONTENT-0002",
            ("EVID-LINK-README",),
        ),
        (
            "deep_source_route_collection.json",
            "http_route_relationship_edge",
            (
                "ROUTE-CLUSTER-0001:redirect:"
                "https://portal.example.test/library->"
                "https://portal.example.test/library/"
            ),
            ("EVID-REDIRECT",),
        ),
        (
            "parent.html",
            "http_route_relationship_edge",
            (
                "ROUTE-CLUSTER-0001:source_reference:"
                f"{parent}->{parent}notice.txt"
            ),
            ("EVID-LINK-NOTICE",),
        ),
        (
            "parent.html",
            "http_route_relationship_edge",
            (
                "ROUTE-CLUSTER-0001:source_reference:"
                f"{parent}->{parent}readme.txt"
            ),
            ("EVID-LINK-README",),
        ),
    }


def _closure_owner_associations(
    closure: dict[str, object],
) -> set[tuple[str, str, str, tuple[str, ...]]]:
    return {
        (
            record["portable_path"],
            owner["owner_kind"],
            owner["owner_id"],
            tuple(owner["evidence_ids"]),
        )
        for record in closure["references"]
        for owner in record["owners"]
    }


def _deep_relationship_pack_root_with_explicit_owners(tmp_path: Path) -> Path:
    input_dir = _deep_relationship_export_input(tmp_path)
    output_path = tmp_path / "deep-explicit.zip"
    explicit = tuple(
        EvidencePackReference(
            portable_path=path,
            owner_kind=kind,
            owner_id=owner_id,
            evidence_ids=evidence_ids,
        )
        for path, kind, owner_id, evidence_ids in sorted(
            _expected_deep_relationship_owners()
        )
    )
    export_recon_evidence_pack(
        input_dir,
        output_path,
        clock=lambda: FIXED_TIME,
        reference_requirements=explicit,
    )
    extracted = tmp_path / "deep-explicit"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
    assert validate_evidence_pack_root(extracted).validation_status == "complete"
    return extracted


def _structured_current_pack_root(tmp_path: Path) -> Path:
    input_dir = _export_input(tmp_path)
    (input_dir / "project_state.json").write_text(
        json.dumps(
            {
                "project_state": {
                    "input_dir": str(input_dir),
                    "processed_files": [str(input_dir / "nmap-allports.txt")],
                    "evidence": [
                        {
                            "id": "EVID-PORT-0001",
                            "source_file": str(input_dir / "nmap-allports.txt"),
                            "evidence_type": "open_port",
                            "value": "80/tcp",
                            "context": {},
                        }
                    ],
                },
                "candidates": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    output_path = tmp_path / "current-pack.zip"
    export_recon_evidence_pack(input_dir, output_path, clock=lambda: FIXED_TIME)
    extracted = tmp_path / "current-pack"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
    return extracted


def _project_state_provenance_export_input(tmp_path: Path) -> Path:
    input_dir = _export_input(tmp_path)
    robots = input_dir / "robots.txt"
    robots.write_text("User-agent: *\n", encoding="utf-8")
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"].append(
        {
            "type": "robots",
            "file": "robots.txt",
            "url": "https://portal.example.test/robots.txt",
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    state = {
        "project_state": {
            "input_dir": str(input_dir),
            "processed_files": [str(input_dir / "nmap-allports.txt")],
            "assets": [
                {
                    "hostname": "portal.example.test",
                    "in_scope": True,
                    "sources": [
                        str(input_dir / "scope.md"),
                        "nmap-allports.txt",
                        str(input_dir / "nested/homepage-target-80.html"),
                    ],
                    "evidence_ids": [],
                    "tags": [],
                }
            ],
            "port_services": [
                {
                    "host": "portal.example.test",
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": None,
                    "version": None,
                    "source_file": str(input_dir / "nmap-allports.txt"),
                    "evidence_ids": ["EVID-PORT"],
                    "tags": [],
                }
            ],
            "recon_manifest": {
                "schema_version": "1.0",
                "target": "portal.example.test",
                "artifacts": [{"type": "nmap", "file": "nmap-allports.txt"}],
                "source_file": str(manifest_path),
            },
            "evidence": [
                {
                    "id": "EVID-ROBOTS",
                    "source_file": str(robots),
                    "evidence_type": "robots",
                    "value": "robots.txt",
                    "context": {},
                },
                *[
                    {
                        "id": f"EVID-TEXT-{index}",
                        "source_file": str(robots),
                        "evidence_type": "text",
                        "value": value,
                        "context": {},
                    }
                    for index, value in enumerate(
                        (
                            "/",
                            "/icons/text.gif",
                            "https://portal.example.test/path",
                            "arbitrary retained text",
                        ),
                        start=1,
                    )
                ],
            ],
            "http_artifacts": [
                {
                    "url": "https://portal.example.test/robots.txt",
                    "artifact_type": "robots",
                    "value": str(robots),
                    "source_file": str(robots),
                    "evidence_ids": ["EVID-ROBOTS"],
                    "tags": [],
                }
            ],
            "discovered_paths": [
                {
                    "url": "https://portal.example.test/library",
                    "status_code": 301,
                    "content_length": 0,
                    "redirect_location": "/library/",
                    "source": "source_route_coverage",
                    "evidence_ids": [],
                    "tags": [],
                }
            ],
        },
        "candidates": [
            {
                "id": "CAND-0001",
                "rationale": "Review /without/treating/this/as/a/file",
            }
        ],
    }
    (input_dir / "project_state.json").write_text(
        json.dumps(state), encoding="utf-8"
    )
    return input_dir


def _project_state_provenance_pack_root(tmp_path: Path) -> Path:
    input_dir = _project_state_provenance_export_input(tmp_path)
    output_path = tmp_path / "project-state-provenance-pack.zip"
    export_recon_evidence_pack(input_dir, output_path)
    extracted = tmp_path / "project-state-provenance-pack"
    with zipfile.ZipFile(output_path) as archive:
        archive.extractall(extracted)
    assert validate_evidence_pack_root(extracted).validation_status == "complete"
    return extracted


def _refresh_closure_counts(closure: dict[str, object]) -> None:
    references = closure["references"]
    unresolved = closure["unresolved_references"]
    collisions = closure["collision_paths"]
    unsafe = closure["unsafe_paths"]
    closure["counts"] = {
        "referenced_paths": len(references),
        "included_references": len(references) - len(unresolved),
        "unresolved_references": len(unresolved),
        "unsafe_paths": len(unsafe),
        "collisions": len(collisions),
    }


def _set_metadata_field(path: Path, key: str, value: object) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[key] = value
    path.write_text(json.dumps(payload), encoding="utf-8")


def _export_input(tmp_path: Path) -> Path:
    input_dir = tmp_path / "recon"
    input_dir.mkdir()
    (input_dir / "nested").mkdir()
    files = {
        "report.md": "# BugSlyce Recon Pack\n",
        "bugslyce_project.json": json.dumps(
            {
                "schema_version": "1.0",
                "name": "portable-test",
                "target": "10.10.10.10",
                "scope_file": str(input_dir / "scope.md"),
                "output_dir": str(input_dir),
            }
        )
        + "\n",
        "project_state.json": '{"project_state": {}, "candidates": []}\n',
        "runbook.md": "# BugSlyce Runbook\n",
        "recon_status.md": "# BugSlyce Recon Status\n",
        "recon_status.json": '{"target": "10.10.10.10"}\n',
        "recon_execution.md": "# Latest execution\n",
        "recon_execution.json": '{"mode": "content-run"}\n',
        "recon_execution_content_run.md": "# Content discovery\n",
        "recon_execution_content_run.json": '{"mode": "content-run"}\n',
        "content_discovery_execution.md": "# Content discovery\n",
        "content_discovery_execution.json": '{"mode": "content-run"}\n',
        "scope.md": "## In Scope\n\n- 10.10.10.10\n",
        "nmap-allports.txt": "80/tcp open http\n",
        "nested/homepage-target-80.html": "<title>Home</title>\n",
    }
    for name, content in files.items():
        (input_dir / name).write_text(content, encoding="utf-8")
    manifest = {
        "schema_version": "1.0",
        "target": "10.10.10.10",
        "scope_file": "scope.md",
        "profile": "lab-tcp-full-plus-services",
        "artifacts": [
            {"type": "nmap", "file": "nmap-allports.txt"},
            {
                "type": "html",
                "file": "nested/homepage-target-80.html",
                "url": "http://10.10.10.10/",
            },
        ],
    }
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    return input_dir
