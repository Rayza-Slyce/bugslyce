"""Portable, local-only BugSlyce evidence pack export."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
import json
from pathlib import Path, PurePosixPath
import tempfile
import zipfile

from bugslyce.core.sensitive_evidence import (
    EXPORT_RESULT_SENSITIVE_WARNINGS,
    PACK_SENSITIVE_EVIDENCE_NOTICE,
)
from bugslyce.recon.evidence_pack_closure import (
    REFERENCE_CLOSURE_FILENAME,
    EvidencePackReference,
    EvidencePackReferenceRecord,
    discover_evidence_pack_references,
    group_evidence_pack_references,
    render_reference_closure_payload,
)
from bugslyce.time_utils import Clock, utc_now_iso


EXPORT_VERSION = "1.0"
EXPORT_README_TEMPLATE = (
    "# BugSlyce Evidence Pack Export\n\n"
    "Exported at: `{exported_at}`\n\n"
    + "\n\n".join(PACK_SENSITIVE_EVIDENCE_NOTICE)
    + "\n\n"
    "BugSlyce output is evidence for manual review. It does not establish confirmed\n"
    "vulnerabilities.\n\n"
    "No live commands were executed during export.\n"
)


@dataclass(frozen=True)
class ReconExportResult:
    """Summary of one local evidence-pack export."""

    input_dir: str
    output_path: str
    target: str
    raw_profile: str | None
    exported_at: str
    files_included: list[str]
    missing_files: list[str]
    warnings: list[str]
    no_live_commands_executed: bool
    reference_closure_status: str = "not_evaluated"
    unresolved_reference_paths: tuple[str, ...] = ()


def export_recon_evidence_pack(
    input_dir: Path,
    output_path: Path,
    force: bool = False,
    clock: Clock | None = None,
    *,
    deep_evidence_paths: Sequence[Path] | None = None,
    reference_requirements: Sequence[EvidencePackReference] | None = None,
) -> ReconExportResult:
    """Create a deterministic ZIP containing only approved local evidence files."""

    input_dir = input_dir.expanduser().resolve()
    output_path = output_path.expanduser().resolve()
    if not input_dir.exists():
        raise ValueError(f"Input directory does not exist: {input_dir}")
    if not input_dir.is_dir():
        raise ValueError(f"Input path is not a directory: {input_dir}")
    if output_path.suffix.lower() != ".zip":
        raise ValueError(f"Export output path must end with .zip: {output_path}")
    if output_path.exists() and not force:
        raise ValueError(
            f"Export output already exists: {output_path}. Re-run with --force to overwrite it."
        )
    if output_path.exists() and not output_path.is_file():
        raise ValueError(f"Export output path is not a file: {output_path}")

    manifest_path = input_dir / "recon_manifest.json"
    manifest = _load_manifest(manifest_path)
    target = _required_text(manifest, "target", "Recon manifest does not contain a target.")
    raw_profile = _optional_text(manifest.get("profile"))
    exported_at = utc_now_iso(clock)

    included: dict[str, Path] = {}
    missing_files: list[str] = []
    for name in (
        "report.md",
        "project_state.json",
        "recon_manifest.json",
        "bugslyce_project.json",
    ):
        _add_optional_file(included, missing_files, input_dir / name, name)

    for name in ("recon_status.md", "recon_status.json", "runbook.md"):
        _add_optional_file(included, missing_files, input_dir / name, name, record_missing=False)

    metadata_paths = {
        path
        for pattern in (
            "recon_execution*.md",
            "recon_execution*.json",
            "content_discovery_execution*.md",
            "content_discovery_execution*.json",
        )
        for path in input_dir.glob(pattern)
        if path.is_file()
    }
    for path in sorted(metadata_paths, key=lambda item: item.name):
        _add_file(included, path, f"metadata/{path.name}")

    scope_reference = _optional_text(manifest.get("scope_file")) or "scope.md"
    scope_path, scope_relative = _resolve_reference(input_dir, scope_reference, "scope file")
    if scope_path.is_file():
        _add_file(included, scope_path, "scope.md")
    elif scope_reference != "scope.md" or (input_dir / "scope.md").exists():
        missing_files.append("scope.md")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("Recon manifest field 'artifacts' must be a list.")
    for index, artifact in enumerate(artifacts, start=1):
        if not isinstance(artifact, dict):
            raise ValueError(f"Recon manifest artefact #{index} must be a JSON object.")
        reference = _optional_text(artifact.get("file"))
        if reference is None:
            raise ValueError(f"Recon manifest artefact #{index} does not contain a file path.")
        source_path, relative_path = _resolve_reference(
            input_dir,
            reference,
            f"manifest artefact #{index}",
        )
        archive_path = f"raw/{relative_path.as_posix()}"
        if not source_path.is_file():
            missing_files.append(archive_path)
            continue
        _add_file(included, source_path, archive_path)

    represented_source_paths = {source_path.resolve() for source_path in included.values()}
    for source_path, relative_path, reference in _canonical_deep_evidence_paths(
        input_dir,
        output_path,
        deep_evidence_paths,
    ):
        if source_path in represented_source_paths:
            continue
        archive_path = f"raw/{relative_path.as_posix()}"
        if not source_path.is_file():
            missing_files.append(archive_path)
            continue
        _add_file(included, source_path, archive_path)
        represented_source_paths.add(source_path)

    baseline_requirements = discover_evidence_pack_references(input_dir)
    closure_records = _include_reference_closure(
        input_dir,
        included,
        (
            *baseline_requirements,
            *(reference_requirements or ()),
        ),
    )
    missing_files.extend(
        record.portable_path
        for record in closure_records
        if not record.included
        and (record.source_path or record.portable_path) not in missing_files
    )
    closure_status = (
        "complete"
        if all(record.included for record in closure_records) and not missing_files
        else "incomplete"
    )

    archive_files = sorted(
        [
            "BUGSLYCE_EXPORT_README.md",
            "bugslyce_export_manifest.json",
            REFERENCE_CLOSURE_FILENAME,
            *included,
        ]
    )
    export_manifest = {
        "export_version": EXPORT_VERSION,
        "created_by": "bugslyce",
        "exported_at": exported_at,
        "source_input_dir": ".",
        "target": target,
        "raw_profile": raw_profile,
        "files_included": archive_files,
        "file_count": len(archive_files),
        "missing_files": sorted(set(missing_files)),
        "reference_closure": REFERENCE_CLOSURE_FILENAME,
        "reference_closure_status": closure_status,
        "warning": "sensitive recon evidence",
        "no_live_commands_executed": True,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    primary_error: BaseException | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            dir=output_path.parent,
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
        with zipfile.ZipFile(
            temp_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            export_readme = EXPORT_README_TEMPLATE.format(exported_at=exported_at)
            _write_bytes(archive, "BUGSLYCE_EXPORT_README.md", export_readme.encode("utf-8"))
            _write_bytes(
                archive,
                "bugslyce_export_manifest.json",
                (json.dumps(export_manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            )
            closure_payload = render_reference_closure_payload(
                closure_records,
                included_paths=tuple(archive_files),
                declared_status=closure_status,
            )
            _write_bytes(
                archive,
                REFERENCE_CLOSURE_FILENAME,
                (json.dumps(closure_payload, indent=2, sort_keys=True) + "\n").encode(
                    "utf-8"
                ),
            )
            for archive_name, source_path in sorted(included.items()):
                _write_bytes(
                    archive,
                    archive_name,
                    _portable_pack_content(
                        source_path,
                        archive_name,
                        input_dir,
                        included,
                    ),
                )
        temp_path.replace(output_path)
        temp_path = None
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                if primary_error is not None:
                    primary_error.add_note(
                        f"temporary export archive cleanup failed: {exc}"
                    )
                else:
                    raise

    warnings = list(EXPORT_RESULT_SENSITIVE_WARNINGS)
    if missing_files:
        warnings.append(
            f"{len(set(missing_files))} referenced or expected file(s) were missing and not included."
        )
    return ReconExportResult(
        input_dir=str(input_dir),
        output_path=str(output_path),
        target=target,
        raw_profile=raw_profile,
        exported_at=exported_at,
        files_included=archive_files,
        missing_files=sorted(set(missing_files)),
        warnings=warnings,
        no_live_commands_executed=True,
        reference_closure_status=closure_status,
        unresolved_reference_paths=tuple(
            record.portable_path
            for record in closure_records
            if not record.included
        ),
    )


def render_recon_export_summary(result: ReconExportResult) -> str:
    """Render concise CLI output for a completed local export."""

    lines = [
        "BugSlyce evidence pack export complete",
        f"Input directory: {result.input_dir}",
        f"Output path: {result.output_path}",
        f"Target: {result.target}",
        f"Raw profile: {result.raw_profile or 'not recorded'}",
        f"Exported at: {result.exported_at}",
        f"Files included: {len(result.files_included)}",
        f"Missing files recorded: {len(result.missing_files)}",
        f"Reference closure: {result.reference_closure_status}",
        f"Unresolved local references: {len(result.unresolved_reference_paths)}",
    ]
    lines.extend(f"Warning: {warning}" for warning in result.warnings)
    lines.extend(
        [
            "No live commands were executed.",
            "No network requests were made.",
        ]
    )
    return "\n".join(lines)


def _include_reference_closure(
    input_dir: Path,
    included: dict[str, Path],
    reference_requirements: Sequence[EvidencePackReference],
) -> tuple[EvidencePackReferenceRecord, ...]:
    records = group_evidence_pack_references(reference_requirements)
    resolved_records: list[EvidencePackReferenceRecord] = []
    for record in records:
        if record.portable_path in {
            "BUGSLYCE_EXPORT_README.md",
            "bugslyce_export_manifest.json",
            REFERENCE_CLOSURE_FILENAME,
        }:
            raise ValueError(
                "Locally reviewable artefact path collides with generated pack metadata: "
                + record.portable_path
            )
        source_path, _relative_path = _resolve_reference(
            input_dir,
            record.source_path or record.portable_path,
            "locally reviewable artefact",
        )
        if not source_path.is_file():
            resolved_records.append(
                replace(
                    record,
                    included=False,
                    unresolved_reason="missing_source_artefact",
                )
            )
            continue
        _add_file(included, source_path, record.portable_path)
        resolved_records.append(
            replace(record, included=True, unresolved_reason=None)
        )
    return tuple(resolved_records)


def _load_manifest(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ValueError(f"Recon manifest does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse recon manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Recon manifest must contain a JSON object: {path}")
    return payload


def _resolve_reference(
    input_dir: Path,
    reference: str,
    label: str,
) -> tuple[Path, Path]:
    candidate = Path(reference)
    if any(part == ".." for part in candidate.parts):
        raise ValueError(f"Unsafe path traversal in {label}: {reference}")
    resolved = candidate.resolve() if candidate.is_absolute() else (input_dir / candidate).resolve()
    try:
        relative = resolved.relative_to(input_dir)
    except ValueError as exc:
        raise ValueError(f"Unsafe path outside input directory in {label}: {reference}") from exc
    if not relative.parts:
        raise ValueError(f"Unsafe directory reference in {label}: {reference}")
    return resolved, relative


def _canonical_deep_evidence_paths(
    input_dir: Path,
    output_path: Path,
    deep_evidence_paths: Sequence[Path] | None,
) -> tuple[tuple[Path, PurePosixPath, str], ...]:
    if deep_evidence_paths is None:
        return ()
    if (
        isinstance(deep_evidence_paths, (str, bytes, Path))
        or not isinstance(deep_evidence_paths, Sequence)
    ):
        raise TypeError("deep_evidence_paths must be a sequence of pathlib.Path values")
    resolved_entries: dict[str, tuple[Path, PurePosixPath, str]] = {}
    for raw_path in deep_evidence_paths:
        if not isinstance(raw_path, Path):
            raise TypeError("deep_evidence_paths must be a sequence of pathlib.Path values")
        reference = str(raw_path)
        source_path, relative_path = _resolve_reference(
            input_dir,
            reference,
            "Deep evidence file",
        )
        if source_path == output_path:
            raise ValueError("Deep evidence file cannot be the export output path")
        resolved_entries[relative_path.as_posix()] = (
            source_path,
            relative_path,
            reference,
        )
    return tuple(
        resolved_entries[key]
        for key in sorted(resolved_entries)
    )


def _add_optional_file(
    included: dict[str, Path],
    missing_files: list[str],
    source_path: Path,
    archive_name: str,
    record_missing: bool = True,
) -> None:
    if source_path.is_file():
        _add_file(included, source_path, archive_name)
    elif record_missing:
        missing_files.append(source_path.name)


def _add_file(included: dict[str, Path], source_path: Path, archive_name: str) -> None:
    normalized = PurePosixPath(archive_name)
    if normalized.is_absolute() or ".." in normalized.parts:
        raise ValueError(f"Unsafe archive path: {archive_name}")
    key = normalized.as_posix()
    existing = included.get(key)
    if existing is not None and existing.resolve() != source_path.resolve():
        raise ValueError(
            f"Archive path collision for {key}: distinct source artefacts"
        )
    included[key] = source_path


def _portable_pack_content(
    source_path: Path,
    archive_name: str,
    input_dir: Path,
    included: dict[str, Path],
) -> bytes:
    content = source_path.read_bytes()
    preferred_paths = _preferred_portable_paths(included)
    if archive_name == "bugslyce_project.json":
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not make project descriptor portable: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("Project descriptor must contain a JSON object.")
        payload["output_dir"] = "."
        payload["scope_file"] = "scope.md"
        return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if archive_name == "recon_manifest.json":
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not make recon manifest portable: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("Recon manifest must contain a JSON object.")
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list):
            raise ValueError("Recon manifest field 'artifacts' must be a list.")
        portable_artifacts: list[dict[str, object]] = []
        for index, artifact in enumerate(artifacts, start=1):
            if not isinstance(artifact, dict):
                raise ValueError(f"Recon manifest artefact #{index} must be an object.")
            reference = _required_text(
                artifact, "file", f"Recon manifest artefact #{index} has no file path."
            )
            source, relative = _resolve_reference(
                input_dir, reference, f"manifest artefact #{index}"
            )
            archive_path = f"raw/{relative.as_posix()}"
            if source.is_file() and included.get(archive_path) != source:
                raise ValueError(
                    f"Recon manifest artefact #{index} is not mapped to {archive_path}."
                )
            portable_artifact = dict(artifact)
            portable_artifact["file"] = archive_path
            portable_artifacts.append(portable_artifact)
        payload["scope_file"] = "scope.md"
        payload["artifacts"] = portable_artifacts
        return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if archive_name == "project_state.json":
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not make project state portable: {exc}") from exc
        return (
            json.dumps(
                _portable_project_state_payload(
                    payload,
                    input_dir,
                    _preferred_project_state_paths(included),
                    preferred_paths,
                ),
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    if archive_name not in {"report.md", "runbook.md"}:
        return content
    try:
        rendered = content.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"Could not make {archive_name} portable: {exc}") from exc
    replacements = sorted(
        (
            (str(source), portable_path)
            for source, portable_path in preferred_paths.items()
        ),
        key=lambda item: (-len(item[0]), item[0]),
    )
    for original, portable_path in replacements:
        rendered = rendered.replace(original, portable_path)
    rendered = rendered.replace(
        f"{input_dir}-evidence-pack.zip",
        "bugslyce-evidence-pack.zip",
    )
    rendered = rendered.replace(str(input_dir), ".")
    return rendered.encode("utf-8")


def _preferred_portable_paths(included: dict[str, Path]) -> dict[Path, str]:
    preferred_paths: dict[Path, str] = {}
    for candidate_name, candidate_source in included.items():
        resolved_source = candidate_source.resolve()
        current = preferred_paths.get(resolved_source)
        if current is None or _portable_archive_path_preference(candidate_name) < (
            _portable_archive_path_preference(current)
        ):
            preferred_paths[resolved_source] = candidate_name
    return preferred_paths


def _preferred_project_state_paths(included: dict[str, Path]) -> dict[Path, str]:
    preferred_paths: dict[Path, str] = {}
    for candidate_name, candidate_source in included.items():
        resolved_source = candidate_source.resolve()
        current = preferred_paths.get(resolved_source)
        candidate_preference = (
            0 if candidate_name.startswith(("raw/", "metadata/")) else 1,
            len(PurePosixPath(candidate_name).parts),
            candidate_name,
        )
        if current is None:
            preferred_paths[resolved_source] = candidate_name
            continue
        current_preference = (
            0 if current.startswith(("raw/", "metadata/")) else 1,
            len(PurePosixPath(current).parts),
            current,
        )
        if candidate_preference < current_preference:
            preferred_paths[resolved_source] = candidate_name
    return preferred_paths


def _portable_project_state_payload(
    payload: object,
    input_dir: Path,
    preferred_paths: dict[Path, str],
    relationship_paths: dict[Path, str],
) -> object:
    if not isinstance(payload, dict):
        raise ValueError("Project state export must contain a JSON object.")
    portable = json.loads(json.dumps(payload))
    state = portable.get("project_state")
    if state is None:
        state = {}
        portable["project_state"] = state
    elif not isinstance(state, dict):
        raise ValueError("Project state export field 'project_state' must be an object.")
    state["input_dir"] = "."
    processed = state.get("processed_files", [])
    if not isinstance(processed, list):
        raise ValueError("Project state processed_files must be a list.")
    state["processed_files"] = [
        _portable_project_file(value, input_dir, preferred_paths, "processed file")
        for value in processed
    ]
    assets = state.get("assets", [])
    if not isinstance(assets, list):
        raise ValueError("Project state assets must be a list.")
    for index, asset in enumerate(assets, start=1):
        if not isinstance(asset, dict):
            raise ValueError(f"Project state asset #{index} must be an object.")
        sources = asset.get("sources", [])
        if not isinstance(sources, list):
            raise ValueError(f"Project state asset #{index} sources must be a list.")
        asset["sources"] = [
            _portable_project_file(
                value,
                input_dir,
                preferred_paths,
                f"asset #{index} source artefact",
            )
            for value in sources
        ]
    for collection_name, path_map in (
        ("evidence", preferred_paths),
        ("http_artifacts", relationship_paths),
    ):
        collection = state.get(collection_name, [])
        if not isinstance(collection, list):
            raise ValueError(f"Project state {collection_name} must be a list.")
        for index, item in enumerate(collection, start=1):
            if not isinstance(item, dict):
                raise ValueError(
                    f"Project state {collection_name} item #{index} must be an object."
                )
            source_file = item.get("source_file")
            if isinstance(source_file, str) and source_file.strip():
                portable_source = _portable_project_file(
                    source_file,
                    input_dir,
                    path_map,
                    f"{collection_name} source artefact",
                )
                if _is_exact_local_file_alias(item.get("value"), source_file, input_dir):
                    item["value"] = portable_source
                item["source_file"] = portable_source
    port_services = state.get("port_services", [])
    if not isinstance(port_services, list):
        raise ValueError("Project state port_services must be a list.")
    for index, service in enumerate(port_services, start=1):
        if not isinstance(service, dict):
            raise ValueError(f"Project state port service #{index} must be an object.")
        source_file = service.get("source_file")
        if isinstance(source_file, str) and source_file.strip():
            service["source_file"] = _portable_project_file(
                source_file,
                input_dir,
                preferred_paths,
                f"port service #{index} source artefact",
            )
    recon_manifest = state.get("recon_manifest")
    if recon_manifest is not None:
        if not isinstance(recon_manifest, dict):
            raise ValueError("Project state recon_manifest must be an object or null.")
        source_file = recon_manifest.get("source_file")
        if isinstance(source_file, str) and source_file.strip():
            recon_manifest["source_file"] = _portable_project_file(
                source_file,
                input_dir,
                relationship_paths,
                "embedded recon manifest source artefact",
            )
        manifest_artifacts = recon_manifest.get("artifacts", [])
        if not isinstance(manifest_artifacts, list):
            raise ValueError("Project state recon_manifest artifacts must be a list.")
        for index, artifact in enumerate(manifest_artifacts, start=1):
            if not isinstance(artifact, dict):
                raise ValueError(
                    f"Project state recon manifest artefact #{index} must be an object."
                )
            file_reference = artifact.get("file")
            if isinstance(file_reference, str) and file_reference.strip():
                artifact["file"] = _portable_project_file(
                    file_reference,
                    input_dir,
                    preferred_paths,
                    f"embedded recon manifest artefact #{index}",
                )
    discovered = state.get("discovered_paths", [])
    if not isinstance(discovered, list):
        raise ValueError("Project state discovered_paths must be a list.")
    for index, item in enumerate(discovered, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Project state discovered path #{index} must be an object.")
        source = item.get("source")
        if not isinstance(source, str) or not source.strip():
            continue
        candidate = Path(source)
        resolved = (
            candidate.resolve(strict=False)
            if candidate.is_absolute()
            else (input_dir / candidate).resolve(strict=False)
        )
        if resolved in relationship_paths or candidate.is_absolute() or ".." in candidate.parts:
            item["source"] = _portable_project_file(
                source,
                input_dir,
                relationship_paths,
                "discovered-path source artefact",
            )
    return portable


def _portable_project_file(
    value: object,
    input_dir: Path,
    path_map: dict[Path, str],
    label: str,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Project state {label} must be a non-empty path.")
    source, _relative = _resolve_reference(input_dir, value, f"project state {label}")
    portable_path = path_map.get(source)
    if portable_path is None:
        raise ValueError(
            f"Project state {label} is not represented in the evidence pack: {value}"
        )
    return portable_path


def _is_exact_local_file_alias(
    value: object,
    source_file: str,
    input_dir: Path,
) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    candidate = Path(value.strip())
    if ".." in candidate.parts:
        return False
    try:
        project_root = input_dir.resolve(strict=False)
        value_path = (
            candidate.resolve(strict=False)
            if candidate.is_absolute()
            else (project_root / candidate).resolve(strict=False)
        )
        source_candidate = Path(source_file)
        source_path = (
            source_candidate.resolve(strict=False)
            if source_candidate.is_absolute()
            else (project_root / source_candidate).resolve(strict=False)
        )
        value_path.relative_to(project_root)
        source_path.relative_to(project_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return value_path == source_path


def _portable_archive_path_preference(value: str) -> tuple[int, int, str]:
    return (
        1 if value.startswith(("raw/", "metadata/")) else 0,
        len(PurePosixPath(value).parts),
        value,
    )


def _write_bytes(archive: zipfile.ZipFile, archive_name: str, content: bytes) -> None:
    info = zipfile.ZipInfo(archive_name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _required_text(payload: dict[str, object], key: str, message: str) -> str:
    value = _optional_text(payload.get(key))
    if value is None:
        raise ValueError(message)
    return value


def _optional_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None
