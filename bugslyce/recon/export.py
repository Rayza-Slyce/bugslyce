"""Portable, local-only BugSlyce evidence pack export."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import zipfile

from bugslyce.time_utils import Clock, utc_now_iso


EXPORT_VERSION = "1.0"
EXPORT_README_TEMPLATE = """# BugSlyce Evidence Pack Export

Exported at: `{exported_at}`

This archive may contain sensitive recon evidence, including target IP
addresses, URLs, response headers, saved HTML, service banners, and discovered
paths.

Do not share this archive publicly unless sharing is authorised and the
contents have been reviewed.

BugSlyce output is evidence for manual review. It does not establish confirmed
vulnerabilities.

No live commands were executed during export.
"""


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


def export_recon_evidence_pack(
    input_dir: Path,
    output_path: Path,
    force: bool = False,
    clock: Clock | None = None,
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
    for name in ("report.md", "project_state.json", "recon_manifest.json"):
        _add_optional_file(included, missing_files, input_dir / name, name)

    for name in ("recon_status.md", "recon_status.json"):
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
        missing_files.append(scope_reference)

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
        if not source_path.is_file():
            missing_files.append(reference)
            continue
        _add_file(included, source_path, f"raw/{relative_path.as_posix()}")

    archive_files = sorted(
        [
            "BUGSLYCE_EXPORT_README.md",
            "bugslyce_export_manifest.json",
            *included,
        ]
    )
    export_manifest = {
        "export_version": EXPORT_VERSION,
        "created_by": "bugslyce",
        "exported_at": exported_at,
        "source_input_dir": str(input_dir),
        "target": target,
        "raw_profile": raw_profile,
        "files_included": archive_files,
        "file_count": len(archive_files),
        "missing_files": sorted(set(missing_files)),
        "warning": "sensitive recon evidence",
        "no_live_commands_executed": True,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        output_path,
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
        for archive_name, source_path in sorted(included.items()):
            _write_bytes(archive, archive_name, source_path.read_bytes())

    warnings = ["This export may contain sensitive recon evidence."]
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
    ]
    lines.extend(f"Warning: {warning}" for warning in result.warnings)
    lines.extend(
        [
            "No live commands were executed.",
            "No network requests were made.",
        ]
    )
    return "\n".join(lines)


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
    included[normalized.as_posix()] = source_path


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
