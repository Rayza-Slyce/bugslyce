"""Deterministic evidence-pack reference closure and offline validation."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath

from bugslyce.core.models import DiscoveredPath, Evidence, HTTPArtifact, ProjectState
from bugslyce.recon.deep_orchestration import (
    DEEP_RECON_ORCHESTRATION_JSON,
    DEEP_RECON_REVIEW_MARKDOWN,
    DEEP_RECON_RUNBOOK_MARKDOWN,
)
from bugslyce.recon.deep_source_route_collection_export import (
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN,
    load_deep_source_route_collection_result,
)
from bugslyce.recon.deep_successful_content import (
    SuccessfulDeepContentReview,
    build_successful_deep_content_reviews,
)
from bugslyce.recon.http_route_relationships import (
    HttpRouteRelationshipCluster,
    build_http_route_relationship_clusters,
)


REFERENCE_CLOSURE_FILENAME = "bugslyce_reference_closure.json"
REFERENCE_CLOSURE_VERSION = "1.0"
EXPORT_MANIFEST_FILENAME = "bugslyce_export_manifest.json"
CURRENT_REQUIRED_METADATA_PATHS = (
    "BUGSLYCE_EXPORT_README.md",
    EXPORT_MANIFEST_FILENAME,
    REFERENCE_CLOSURE_FILENAME,
    "report.md",
    "runbook.md",
    "project_state.json",
    "recon_manifest.json",
    "bugslyce_project.json",
    "scope.md",
)
_CORE_REFERENCE_OWNERS = (
    ("report.md", "primary_report"),
    ("runbook.md", "project_runbook"),
    ("project_state.json", "project_state"),
    ("recon_manifest.json", "recon_manifest"),
    ("bugslyce_project.json", "project_descriptor"),
    ("scope.md", "scope_policy"),
)
_DEEP_OUTPUT_PATHS = (
    DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN,
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    DEEP_RECON_REVIEW_MARKDOWN,
    DEEP_RECON_RUNBOOK_MARKDOWN,
    DEEP_RECON_ORCHESTRATION_JSON,
)
_KNOWN_RECONSTRUCTABLE_OWNER_KINDS = frozenset(
    {
        "evidence_pack_core",
        "structured_raw_evidence",
        "project_state_evidence",
        "deep_output",
        "successful_deep_content",
        "http_route_relationship_edge",
    }
)


@dataclass(frozen=True)
class EvidencePackReference:
    """One exact locally reviewable artefact reference owned by a model item."""

    portable_path: str
    owner_kind: str
    owner_id: str
    evidence_ids: tuple[str, ...] = ()
    source_path: str | None = None


@dataclass(frozen=True)
class EvidencePackReferenceOwner:
    """One deterministic owner/evidence association for a portable reference."""

    owner_kind: str
    owner_id: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class EvidencePackReferenceRecord:
    """One grouped portable reference and all of its exact model owners."""

    portable_path: str
    owners: tuple[EvidencePackReferenceOwner, ...]
    included: bool
    unresolved_reason: str | None = None
    source_path: str | None = None


@dataclass(frozen=True)
class EvidencePackClosureValidation:
    """Offline validation result derived from one extracted evidence-pack root."""

    validation_status: str
    declared_status: str
    referenced_paths: tuple[str, ...]
    included_paths: tuple[str, ...]
    unresolved_references: tuple[EvidencePackReferenceRecord, ...]
    unsafe_paths: tuple[str, ...]
    collision_paths: tuple[str, ...]
    missing_declared_member_paths: tuple[str, ...]
    manifest_missing_file_paths: tuple[str, ...]
    required_metadata_errors: tuple[str, ...]
    declaration_mismatch_paths: tuple[str, ...]
    expected_references_missing_from_closure: tuple[EvidencePackReferenceRecord, ...]
    owner_association_errors: tuple[EvidencePackReferenceRecord, ...]
    required_declaration_errors: tuple[str, ...]
    metadata_consistency_errors: tuple[str, ...]
    legacy_metadata_absent: bool
    summary: str

    @property
    def referenced_path_count(self) -> int:
        return len(self.referenced_paths)

    @property
    def unresolved_reference_count(self) -> int:
        return len(self.unresolved_references)

    @property
    def unsafe_path_count(self) -> int:
        return len(self.unsafe_paths)

    @property
    def collision_count(self) -> int:
        return len(self.collision_paths)

    @property
    def missing_declared_member_count(self) -> int:
        return len(self.missing_declared_member_paths)

    @property
    def manifest_missing_file_count(self) -> int:
        return len(self.manifest_missing_file_paths)

    @property
    def required_metadata_error_count(self) -> int:
        return len(self.required_metadata_errors)

    @property
    def expected_reference_missing_count(self) -> int:
        return len(self.expected_references_missing_from_closure)

    @property
    def owner_association_error_count(self) -> int:
        return len(self.owner_association_errors)

    @property
    def required_declaration_error_count(self) -> int:
        return len(self.required_declaration_errors)

    @property
    def metadata_consistency_error_count(self) -> int:
        return len(self.metadata_consistency_errors)


def discover_evidence_pack_references(
    input_dir: Path,
) -> tuple[EvidencePackReference, ...]:
    """Discover the current structured baseline closure from a project directory."""

    root = input_dir.expanduser().resolve()
    manifest = _load_structured_json_object(
        root, root / "recon_manifest.json", required=True, label="recon_manifest.json"
    )
    scope_source = _project_relative_source(
        root,
        (
            manifest.get("scope_file").strip()
            if isinstance(manifest.get("scope_file"), str)
            and manifest.get("scope_file").strip()
            else "scope.md"
        ),
    )
    references = [
        EvidencePackReference(
            portable_path=portable_path,
            owner_kind="evidence_pack_core",
            owner_id=owner_id,
            source_path=scope_source if portable_path == "scope.md" else portable_path,
        )
        for portable_path, owner_id in _CORE_REFERENCE_OWNERS
    ]
    evidence_by_source = _project_evidence_by_source(root)
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("recon manifest artefacts must be a list")
    for index, artifact in enumerate(artifacts, start=1):
        if not isinstance(artifact, dict):
            raise ValueError("recon manifest artefact must be an object")
        source_path = _project_relative_source(
            root, _required_text(artifact.get("file"), "recon manifest artefact file")
        )
        archive_path = f"raw/{source_path}"
        artifact_type = str(artifact.get("type") or "artefact").strip() or "artefact"
        references.append(
            EvidencePackReference(
                portable_path=archive_path,
                owner_kind="structured_raw_evidence",
                owner_id=f"manifest:{index}:{artifact_type}",
                evidence_ids=evidence_by_source.get(source_path, ()),
                source_path=source_path,
            )
        )

    represented_sources = {
        reference.source_path
        for reference in references
        if reference.source_path is not None
    }
    for source_path, evidence_ids in sorted(evidence_by_source.items()):
        if source_path in represented_sources:
            continue
        portable_path = _archive_path_for_project_source(source_path)
        references.append(
            EvidencePackReference(
                portable_path=portable_path,
                owner_kind="project_state_evidence",
                owner_id=portable_path,
                evidence_ids=evidence_ids,
                source_path=source_path,
            )
        )

    references.extend(_deep_output_references(root))
    references.extend(_deep_relationship_references(root))
    return tuple(
        sorted(
            references,
            key=lambda item: (
                item.portable_path,
                item.owner_kind,
                item.owner_id,
                item.evidence_ids,
                item.source_path or "",
            ),
        )
    )


def discover_expected_pack_references(
    pack_root: Path,
) -> tuple[EvidencePackReference, ...]:
    """Derive the current baseline from structured files inside an extracted pack."""

    root = pack_root.expanduser().resolve()
    references = [
        EvidencePackReference(
            portable_path=portable_path,
            owner_kind="evidence_pack_core",
            owner_id=owner_id,
        )
        for portable_path, owner_id in _CORE_REFERENCE_OWNERS
    ]
    evidence_by_source = _packed_project_evidence_by_source(root)
    represented_paths: set[str] = {
        portable_path for portable_path, _owner_id in _CORE_REFERENCE_OWNERS
    }
    manifest = _load_structured_json_object(
        root, root / "recon_manifest.json", required=True, label="recon_manifest.json"
    )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("packed recon manifest artefacts must be a list")
    for index, artifact in enumerate(artifacts, start=1):
        if not isinstance(artifact, dict):
            raise ValueError("packed recon manifest artefact must be an object")
        source_path = _normalise_portable_path(
            _required_text(artifact.get("file"), "packed recon manifest artefact file")
        )
        represented_paths.add(source_path)
        artifact_type = str(artifact.get("type") or "artefact").strip() or "artefact"
        references.append(
            EvidencePackReference(
                portable_path=source_path,
                owner_kind="structured_raw_evidence",
                owner_id=f"manifest:{index}:{artifact_type}",
                evidence_ids=evidence_by_source.get(source_path, ()),
            )
        )
    for portable_path, evidence_ids in sorted(evidence_by_source.items()):
        if portable_path in represented_paths:
            continue
        references.append(
            EvidencePackReference(
                portable_path=portable_path,
                owner_kind="project_state_evidence",
                owner_id=portable_path,
                evidence_ids=evidence_ids,
            )
        )
    references.extend(_deep_output_references(root))
    references.extend(_deep_relationship_references(root))
    return tuple(
        sorted(
            references,
            key=lambda item: (
                item.portable_path,
                item.owner_kind,
                item.owner_id,
                item.evidence_ids,
            ),
        )
    )


def evidence_pack_references_from_deep_models(
    successful_reviews: tuple[SuccessfulDeepContentReview, ...],
    relationship_clusters: tuple[HttpRouteRelationshipCluster, ...],
) -> tuple[EvidencePackReference, ...]:
    """Convert current Phase 3/4A models into exact portable owner references."""

    references: list[EvidencePackReference] = []
    for review in successful_reviews:
        references.extend(
            EvidencePackReference(
                portable_path=portable_path,
                owner_kind="successful_deep_content",
                owner_id=review.review_id,
                evidence_ids=tuple(review.evidence_ids),
            )
            for portable_path in review.artefact_references
        )
    for cluster in relationship_clusters:
        for edge in cluster.edges:
            owner_id = (
                f"{cluster.cluster_id}:{edge.edge_type}:"
                f"{edge.source_url}->{edge.target_url}"
            )
            references.extend(
                EvidencePackReference(
                    portable_path=portable_path,
                    owner_kind="http_route_relationship_edge",
                    owner_id=owner_id,
                    evidence_ids=tuple(edge.evidence_ids),
                )
                for portable_path in edge.artefact_references
            )
    return tuple(
        sorted(
            references,
            key=lambda item: (
                item.portable_path,
                item.owner_kind,
                item.owner_id,
                item.evidence_ids,
            ),
        )
    )


def group_evidence_pack_references(
    references: Sequence[EvidencePackReference],
) -> tuple[EvidencePackReferenceRecord, ...]:
    """Validate and group references by portable path and exact model owner."""

    if isinstance(references, (str, bytes)) or not isinstance(references, Sequence):
        raise TypeError("reference_requirements must be a sequence of EvidencePackReference values")
    grouped: dict[
        str,
        tuple[dict[tuple[str, str], set[str]], set[str]],
    ] = {}
    for reference in references:
        if not isinstance(reference, EvidencePackReference):
            raise TypeError(
                "reference_requirements must be a sequence of EvidencePackReference values"
            )
        portable_path = _normalise_portable_path(reference.portable_path)
        source_path = (
            _normalise_portable_path(reference.source_path)
            if reference.source_path is not None
            else portable_path
        )
        owner_kind = _required_text(reference.owner_kind, "reference owner kind")
        owner_id = _required_text(reference.owner_id, "reference owner ID")
        owners, source_paths = grouped.setdefault(portable_path, ({}, set()))
        source_paths.add(source_path)
        owner_evidence = owners.setdefault(
            (owner_kind, owner_id),
            set(),
        )
        owner_evidence.update(_nonempty_sorted(reference.evidence_ids))
    records: list[EvidencePackReferenceRecord] = []
    for portable_path, (owners, source_paths) in sorted(grouped.items()):
        if len(source_paths) != 1:
            raise ValueError(
                f"Archive path collision for {portable_path}: distinct source artefacts"
            )
        records.append(
            EvidencePackReferenceRecord(
                portable_path=portable_path,
                owners=tuple(
                    EvidencePackReferenceOwner(
                        owner_kind=owner_kind,
                        owner_id=owner_id,
                        evidence_ids=tuple(sorted(evidence_ids)),
                    )
                    for (owner_kind, owner_id), evidence_ids in sorted(owners.items())
                ),
                included=False,
                source_path=next(iter(source_paths)),
            )
        )
    return tuple(records)


def render_reference_closure_payload(
    records: tuple[EvidencePackReferenceRecord, ...],
    *,
    included_paths: tuple[str, ...],
    collision_paths: tuple[str, ...] = (),
    declared_status: str | None = None,
) -> dict[str, object]:
    """Build deterministic closure metadata without host paths or timestamps."""

    unresolved = tuple(record for record in records if not record.included)
    status = declared_status or (
        "complete" if not unresolved and not collision_paths else "incomplete"
    )
    if status not in {"complete", "incomplete"}:
        raise ValueError("Reference closure status must be complete or incomplete.")
    return {
        "closure_version": REFERENCE_CLOSURE_VERSION,
        "status": status,
        "references": [_record_to_dict(record) for record in records],
        "included_paths": sorted(set(included_paths)),
        "unresolved_references": [
            _record_to_dict(record) for record in unresolved
        ],
        "unsafe_paths": [],
        "collision_paths": sorted(set(collision_paths)),
        "counts": {
            "referenced_paths": len(records),
            "included_references": len(records) - len(unresolved),
            "unresolved_references": len(unresolved),
            "unsafe_paths": 0,
            "collisions": len(set(collision_paths)),
        },
        "summary": (
            "All locally reviewable artefact references resolve inside this evidence pack."
            if status == "complete"
            else "One or more locally reviewable artefact references are unresolved."
        ),
    }


def validate_evidence_pack_root(pack_root: Path) -> EvidencePackClosureValidation:
    """Validate reference closure using only an extracted evidence-pack root."""

    root = pack_root.expanduser().resolve(strict=False)
    if not root.is_dir():
        raise ValueError(f"Evidence-pack root does not exist or is not a directory: {root}")
    actual_paths, root_unsafe = _contained_pack_files(root)
    closure_path = root / REFERENCE_CLOSURE_FILENAME
    manifest_path = root / EXPORT_MANIFEST_FILENAME
    manifest_payload, manifest_error = _load_pack_metadata(root, manifest_path)
    closure_payload, closure_error = _load_pack_metadata(root, closure_path)
    current_declared = _manifest_declares_current_closure(manifest_payload)
    closure_present = closure_path.exists() or closure_path.is_symlink()
    if closure_payload is None and not current_declared and not closure_present:
        return EvidencePackClosureValidation(
            validation_status="legacy_unknown",
            declared_status="metadata_absent",
            referenced_paths=(),
            included_paths=actual_paths,
            unresolved_references=(),
            unsafe_paths=root_unsafe,
            collision_paths=(),
            missing_declared_member_paths=(),
            manifest_missing_file_paths=(),
            required_metadata_errors=(),
            declaration_mismatch_paths=(),
            expected_references_missing_from_closure=(),
            owner_association_errors=(),
            required_declaration_errors=(),
            metadata_consistency_errors=(),
            legacy_metadata_absent=True,
            summary=(
                "Reference-closure metadata is absent; this legacy pack cannot be "
                "classified as current or reference-complete."
            ),
        )

    required_metadata_errors: set[str] = set()
    required_declaration_errors: set[str] = set()
    metadata_consistency_errors: set[str] = set()
    if manifest_payload is None:
        required_metadata_errors.add(
            manifest_error or EXPORT_MANIFEST_FILENAME
        )
    if closure_payload is None:
        required_metadata_errors.add(
            closure_error or REFERENCE_CLOSURE_FILENAME
        )
        closure_payload = {}
    raw_references = closure_payload.get("references")
    if not isinstance(raw_references, list):
        required_metadata_errors.add(
            f"{REFERENCE_CLOSURE_FILENAME}:references"
        )
        raw_references = []
    if closure_payload.get("closure_version") != REFERENCE_CLOSURE_VERSION:
        metadata_consistency_errors.add("unsupported_closure_version")

    records: list[EvidencePackReferenceRecord] = []
    declared_records: list[EvidencePackReferenceRecord] = []
    unsafe_paths = set(root_unsafe)
    collision_paths = set(_string_list(closure_payload.get("collision_paths")))
    unsafe_paths.update(
        _metadata_path_list(closure_payload.get("unsafe_paths"), unsafe_paths)
    )
    seen_paths: set[str] = set()
    for index, raw_record in enumerate(raw_references, start=1):
        try:
            record = _record_from_dict(raw_record, index)
        except ValueError:
            required_metadata_errors.add(
                f"{REFERENCE_CLOSURE_FILENAME}:reference:{index}"
            )
            continue
        declared_records.append(record)
        if record.portable_path in seen_paths:
            collision_paths.add(record.portable_path)
        seen_paths.add(record.portable_path)
        portable_path, included = _validate_declared_path(
            root,
            record.portable_path,
            unsafe_paths,
        )
        if portable_path is None:
            unsafe_paths.add(record.portable_path)
            records.append(
                EvidencePackReferenceRecord(
                    portable_path=record.portable_path,
                    owners=record.owners,
                    included=False,
                    unresolved_reason="unsafe_path",
                )
            )
            continue
        records.append(
            EvidencePackReferenceRecord(
                portable_path=portable_path,
                owners=record.owners,
                included=included,
                unresolved_reason=None if included else "missing_from_extracted_pack",
            )
        )

    raw_closure_included = closure_payload.get("included_paths")
    if not isinstance(raw_closure_included, list):
        required_metadata_errors.add(
            f"{REFERENCE_CLOSURE_FILENAME}:included_paths"
        )
    closure_declared, closure_duplicates = _declared_paths(
        raw_closure_included,
        root,
        unsafe_paths,
    )
    collision_paths.update(closure_duplicates)
    manifest_declared: tuple[str, ...] = ()
    manifest_missing: tuple[str, ...] = ()
    if manifest_payload is not None:
        if not isinstance(manifest_payload.get("files_included"), list):
            required_metadata_errors.add(
                f"{EXPORT_MANIFEST_FILENAME}:files_included"
            )
        if not isinstance(manifest_payload.get("missing_files"), list):
            required_metadata_errors.add(
                f"{EXPORT_MANIFEST_FILENAME}:missing_files"
            )
        manifest_declared, manifest_duplicates = _declared_paths(
            manifest_payload.get("files_included"),
            root,
            unsafe_paths,
        )
        collision_paths.update(manifest_duplicates)
        manifest_missing = _metadata_path_list(
            manifest_payload.get("missing_files"),
            unsafe_paths,
        )

    expected_records: tuple[EvidencePackReferenceRecord, ...] = ()
    try:
        expected_records = group_evidence_pack_references(
            discover_expected_pack_references(root)
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        metadata_consistency_errors.add("structured_reference_discovery_failed")
    expected_missing, owner_errors = _compare_expected_references(
        root,
        expected_records,
        tuple(declared_records),
    )

    actual_set = set(actual_paths)
    declared_union = set(closure_declared) | set(manifest_declared)
    missing_declared = tuple(sorted(declared_union - actual_set))
    declaration_mismatch = tuple(
        sorted(set(closure_declared).symmetric_difference(manifest_declared))
    )
    for required_path in CURRENT_REQUIRED_METADATA_PATHS:
        if required_path not in actual_set:
            required_metadata_errors.add(required_path)
        if required_path not in closure_declared:
            required_declaration_errors.add(
                f"{required_path}:missing_from_closure_included_paths"
            )
        if required_path not in manifest_declared:
            required_declaration_errors.add(
                f"{required_path}:missing_from_export_manifest_files_included"
            )

    _collect_metadata_consistency_errors(
        closure_payload,
        manifest_payload,
        raw_references,
        tuple(declared_records),
        metadata_consistency_errors,
    )
    _collect_portability_errors(
        root,
        manifest_payload,
        closure_declared,
        manifest_declared,
        metadata_consistency_errors,
    )

    unresolved = tuple(record for record in records if not record.included)
    declared_status = str(closure_payload.get("status") or "unknown")
    validation_status = (
        "complete"
        if declared_status == "complete"
        and not unresolved
        and not unsafe_paths
        and not collision_paths
        and not missing_declared
        and not manifest_missing
        and not required_metadata_errors
        and not declaration_mismatch
        and not expected_missing
        and not owner_errors
        and not required_declaration_errors
        and not metadata_consistency_errors
        else "incomplete"
    )
    return EvidencePackClosureValidation(
        validation_status=validation_status,
        declared_status=declared_status,
        referenced_paths=tuple(sorted(record.portable_path for record in records)),
        included_paths=actual_paths,
        unresolved_references=unresolved,
        unsafe_paths=tuple(sorted(unsafe_paths)),
        collision_paths=tuple(sorted(collision_paths)),
        missing_declared_member_paths=missing_declared,
        manifest_missing_file_paths=manifest_missing,
        required_metadata_errors=tuple(sorted(required_metadata_errors)),
        declaration_mismatch_paths=declaration_mismatch,
        expected_references_missing_from_closure=expected_missing,
        owner_association_errors=owner_errors,
        required_declaration_errors=tuple(sorted(required_declaration_errors)),
        metadata_consistency_errors=tuple(sorted(metadata_consistency_errors)),
        legacy_metadata_absent=False,
        summary=(
            "All locally reviewable artefact references resolve inside this evidence pack."
            if validation_status == "complete"
            else "The evidence pack has unresolved references or inconsistent current metadata."
        ),
    )


def _compare_expected_references(
    root: Path,
    expected_records: tuple[EvidencePackReferenceRecord, ...],
    declared_records: tuple[EvidencePackReferenceRecord, ...],
) -> tuple[
    tuple[EvidencePackReferenceRecord, ...],
    tuple[EvidencePackReferenceRecord, ...],
]:
    declared_by_path = {record.portable_path: record for record in declared_records}
    missing: list[EvidencePackReferenceRecord] = []
    owner_errors: list[EvidencePackReferenceRecord] = []
    expected_paths: set[str] = set()
    expected_owner_keys_by_path: dict[str, set[tuple[str, str]]] = {}
    for expected in expected_records:
        expected_paths.add(expected.portable_path)
        declared = declared_by_path.get(expected.portable_path)
        if declared is None:
            missing.append(
                _validation_record(
                    root,
                    expected,
                    "missing_from_closure_reference_set",
                )
            )
            continue
        declared_owners = {
            (owner.owner_kind, owner.owner_id): owner.evidence_ids
            for owner in declared.owners
        }
        expected_owner_keys_by_path[expected.portable_path] = {
            (owner.owner_kind, owner.owner_id) for owner in expected.owners
        }
        mismatched = tuple(
            owner
            for owner in expected.owners
            if declared_owners.get((owner.owner_kind, owner.owner_id))
            != owner.evidence_ids
        )
        if mismatched:
            owner_errors.append(
                _validation_record(
                    root,
                    EvidencePackReferenceRecord(
                        portable_path=expected.portable_path,
                        owners=mismatched,
                        included=False,
                    ),
                    "missing_or_mismatched_owner_association",
                )
            )
    for declared in declared_records:
        if not declared.owners:
            owner_errors.append(
                _validation_record(
                    root,
                    declared,
                    "missing_owner_association",
                )
            )
            continue
        expected_keys = expected_owner_keys_by_path.get(declared.portable_path, set())
        unexpected_known = tuple(
            owner
            for owner in declared.owners
            if owner.owner_kind in _KNOWN_RECONSTRUCTABLE_OWNER_KINDS
            and (owner.owner_kind, owner.owner_id) not in expected_keys
        )
        if unexpected_known:
            owner_errors.append(
                _validation_record(
                    root,
                    EvidencePackReferenceRecord(
                        portable_path=declared.portable_path,
                        owners=unexpected_known,
                        included=declared.included,
                    ),
                    "unexpected_known_owner_association",
                )
            )
    return (
        tuple(sorted(missing, key=lambda item: item.portable_path)),
        tuple(
            sorted(
                owner_errors,
                key=lambda item: (
                    item.portable_path,
                    item.unresolved_reason or "",
                    tuple(
                        (owner.owner_kind, owner.owner_id, owner.evidence_ids)
                        for owner in item.owners
                    ),
                ),
            )
        ),
    )


def _validation_record(
    root: Path,
    record: EvidencePackReferenceRecord,
    reason: str,
) -> EvidencePackReferenceRecord:
    candidate = root / Path(*PurePosixPath(record.portable_path).parts)
    return EvidencePackReferenceRecord(
        portable_path=record.portable_path,
        owners=record.owners,
        included=candidate.is_file() and not candidate.is_symlink(),
        unresolved_reason=reason,
    )


def _collect_metadata_consistency_errors(
    closure_payload: dict[str, object],
    manifest_payload: dict[str, object] | None,
    raw_references: list[object],
    declared_records: tuple[EvidencePackReferenceRecord, ...],
    errors: set[str],
) -> None:
    closure_status = closure_payload.get("status")
    if closure_status not in {"complete", "incomplete"}:
        errors.add("unsupported_closure_status")
    raw_unresolved = closure_payload.get("unresolved_references")
    raw_unsafe = closure_payload.get("unsafe_paths")
    raw_collisions = closure_payload.get("collision_paths")
    counts = closure_payload.get("counts")
    declared_unresolved = tuple(
        record for record in declared_records if not record.included
    )
    for record in declared_records:
        if (record.included and record.unresolved_reason is not None) or (
            not record.included and not record.unresolved_reason
        ):
            errors.add("reference_state_mismatch")
    parsed_unresolved: list[EvidencePackReferenceRecord] = []
    if isinstance(raw_unresolved, list):
        for index, value in enumerate(raw_unresolved, start=1):
            try:
                parsed_unresolved.append(_record_from_dict(value, index))
            except ValueError:
                errors.add("unresolved_reference_set_malformed")
    if {
        _record_state_signature(record) for record in parsed_unresolved
    } != {
        _record_state_signature(record) for record in declared_unresolved
    }:
        errors.add("unresolved_reference_set_mismatch")
    if closure_status == "complete":
        if declared_unresolved or (isinstance(raw_unresolved, list) and raw_unresolved):
            errors.add("complete_closure_has_unresolved_references")
        if isinstance(raw_unsafe, list) and raw_unsafe:
            errors.add("complete_closure_has_unsafe_paths")
        if isinstance(raw_collisions, list) and raw_collisions:
            errors.add("complete_closure_has_collisions")
    if not all(
        isinstance(value, list)
        for value in (raw_unresolved, raw_unsafe, raw_collisions)
    ) or not isinstance(counts, dict):
        errors.add("closure_counts_mismatch")
    else:
        expected_counts = {
            "referenced_paths": len(raw_references),
            "included_references": len(raw_references) - len(raw_unresolved),
            "unresolved_references": len(raw_unresolved),
            "unsafe_paths": len(raw_unsafe),
            "collisions": len(raw_collisions),
        }
        if any(type(value) is not int for value in counts.values()) or counts != expected_counts:
            errors.add("closure_counts_mismatch")
    if manifest_payload is None:
        return
    files_included = manifest_payload.get("files_included")
    if (
        not isinstance(files_included, list)
        or type(manifest_payload.get("file_count")) is not int
        or manifest_payload.get("file_count")
        != len({item for item in files_included if isinstance(item, str)})
    ):
        errors.add("export_manifest_file_count_mismatch")
    if manifest_payload.get("reference_closure") != REFERENCE_CLOSURE_FILENAME:
        errors.add("export_manifest_reference_closure_mismatch")
    manifest_status = manifest_payload.get("reference_closure_status")
    if manifest_status not in {"complete", "incomplete"}:
        errors.add("unsupported_export_manifest_closure_status")
    if manifest_status != closure_status:
        errors.add("reference_closure_status_mismatch")


def _collect_portability_errors(
    root: Path,
    export_manifest: dict[str, object] | None,
    closure_declared: tuple[str, ...],
    manifest_declared: tuple[str, ...],
    errors: set[str],
) -> None:
    if export_manifest is not None and export_manifest.get("source_input_dir") != ".":
        errors.add("portable_export_manifest_source_input_dir_mismatch")
    try:
        project = _load_structured_json_object(
            root,
            root / "bugslyce_project.json",
            required=True,
            label="bugslyce_project.json",
        )
        state_payload = _load_structured_json_object(
            root,
            root / "project_state.json",
            required=True,
            label="project_state.json",
        )
        manifest = _load_structured_json_object(
            root,
            root / "recon_manifest.json",
            required=True,
            label="recon_manifest.json",
        )
    except ValueError:
        return
    if project.get("output_dir") != ".":
        errors.add("portable_project_output_dir_mismatch")
    if project.get("scope_file") != "scope.md":
        errors.add("portable_project_scope_file_mismatch")
    state = state_payload.get("project_state")
    if not isinstance(state, dict) or state.get("input_dir") != ".":
        errors.add("portable_project_state_input_dir_mismatch")
    if isinstance(state, dict):
        _collect_project_state_file_errors(
            root,
            state,
            set(closure_declared),
            set(manifest_declared),
            errors,
        )
    if manifest.get("scope_file") != "scope.md":
        errors.add("portable_recon_manifest_scope_file_mismatch")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        errors.add("portable_recon_manifest_artifacts_invalid")
        return
    for index, artifact in enumerate(artifacts, start=1):
        if not isinstance(artifact, dict):
            errors.add(f"portable_recon_manifest_artifact_invalid:{index}")
            continue
        try:
            portable_path = _normalise_portable_path(
                _required_text(
                    artifact.get("file"), "packed recon manifest artefact file"
                )
            )
            candidate = root / Path(*PurePosixPath(portable_path).parts)
            if candidate.is_symlink() or not candidate.is_file():
                raise ValueError("packed recon manifest artefact is unavailable")
            candidate.resolve().relative_to(root)
        except (OSError, RuntimeError, ValueError):
            errors.add(f"portable_recon_manifest_artifact_invalid:{index}")


def _collect_project_state_file_errors(
    root: Path,
    state: dict[str, object],
    closure_declared: set[str],
    manifest_declared: set[str],
    errors: set[str],
) -> None:
    processed = state.get("processed_files", [])
    if not isinstance(processed, list):
        errors.add("portable_project_state_processed_files_invalid")
    else:
        for index, value in enumerate(processed, start=1):
            _validate_project_state_member(
                root,
                value,
                f"portable_project_state_processed_file_invalid:{index}",
                closure_declared,
                manifest_declared,
                errors,
            )
    assets = state.get("assets", [])
    if not isinstance(assets, list):
        errors.add("portable_project_state_assets_invalid")
    else:
        for asset_index, asset in enumerate(assets, start=1):
            if not isinstance(asset, dict) or not isinstance(asset.get("sources", []), list):
                errors.add(f"portable_project_state_asset_sources_invalid:{asset_index}")
                continue
            for source_index, value in enumerate(asset.get("sources", []), start=1):
                _validate_project_state_member(
                    root,
                    value,
                    (
                        "portable_project_state_asset_source_invalid:"
                        f"{asset_index}:{source_index}"
                    ),
                    closure_declared,
                    manifest_declared,
                    errors,
                )
    _validate_source_file_collection(
        root,
        state.get("port_services", []),
        "port_service",
        closure_declared,
        manifest_declared,
        errors,
    )
    for collection_name in ("evidence", "http_artifacts"):
        collection = state.get(collection_name, [])
        _validate_source_file_collection(
            root,
            collection,
            collection_name,
            closure_declared,
            manifest_declared,
            errors,
        )
        if not isinstance(collection, list):
            continue
        for index, item in enumerate(collection, start=1):
            if not isinstance(item, dict):
                continue
            source_file = item.get("source_file")
            value = item.get("value")
            alias_contract = (
                collection_name == "evidence" and item.get("evidence_type") == "robots"
            ) or (
                collection_name == "http_artifacts"
                and item.get("artifact_type") == "robots"
            )
            if alias_contract and value != source_file:
                errors.add(
                    f"portable_project_state_{collection_name}_file_alias_invalid:{index}"
                )
    recon_manifest = state.get("recon_manifest")
    if recon_manifest is not None:
        if not isinstance(recon_manifest, dict):
            errors.add("portable_project_state_recon_manifest_invalid")
        else:
            _validate_project_state_member(
                root,
                recon_manifest.get("source_file"),
                "portable_project_state_recon_manifest_source_file_invalid",
                closure_declared,
                manifest_declared,
                errors,
            )
            artifacts = recon_manifest.get("artifacts", [])
            if not isinstance(artifacts, list):
                errors.add("portable_project_state_recon_manifest_artifacts_invalid")
            else:
                for index, artifact in enumerate(artifacts, start=1):
                    if not isinstance(artifact, dict):
                        errors.add(
                            f"portable_project_state_recon_manifest_artifact_invalid:{index}"
                        )
                        continue
                    file_reference = artifact.get("file")
                    if isinstance(file_reference, str) and file_reference.strip():
                        _validate_project_state_member(
                            root,
                            file_reference,
                            (
                                "portable_project_state_recon_manifest_artifact_file_invalid:"
                                f"{index}"
                            ),
                            closure_declared,
                            manifest_declared,
                            errors,
                        )
    discovered = state.get("discovered_paths", [])
    if not isinstance(discovered, list):
        errors.add("portable_project_state_discovered_paths_invalid")
    else:
        declared = closure_declared | manifest_declared
        for index, item in enumerate(discovered, start=1):
            if not isinstance(item, dict):
                errors.add(f"portable_project_state_discovered_path_invalid:{index}")
                continue
            source = item.get("source")
            if isinstance(source, str) and (
                source in declared or source.startswith(("raw/", "metadata/"))
            ):
                _validate_project_state_member(
                    root,
                    source,
                    f"portable_project_state_discovered_path_source_invalid:{index}",
                    closure_declared,
                    manifest_declared,
                    errors,
                )


def _validate_source_file_collection(
    root: Path,
    collection: object,
    label: str,
    closure_declared: set[str],
    manifest_declared: set[str],
    errors: set[str],
) -> None:
    if not isinstance(collection, list):
        errors.add(f"portable_project_state_{label}_collection_invalid")
        return
    for index, item in enumerate(collection, start=1):
        if not isinstance(item, dict):
            errors.add(f"portable_project_state_{label}_invalid:{index}")
            continue
        source_file = item.get("source_file")
        if isinstance(source_file, str) and source_file.strip():
            _validate_project_state_member(
                root,
                source_file,
                f"portable_project_state_{label}_source_file_invalid:{index}",
                closure_declared,
                manifest_declared,
                errors,
            )


def _validate_project_state_member(
    root: Path,
    value: object,
    error_label: str,
    closure_declared: set[str],
    manifest_declared: set[str],
    errors: set[str],
) -> None:
    try:
        portable_path = _normalise_portable_path(
            _required_text(value, "packed project-state artefact path")
        )
        candidate = root / Path(*PurePosixPath(portable_path).parts)
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("packed project-state artefact is unavailable")
        candidate.resolve().relative_to(root)
        if portable_path not in closure_declared or portable_path not in manifest_declared:
            raise ValueError("packed project-state artefact is undeclared")
    except (OSError, RuntimeError, ValueError):
        errors.add(error_label)


def _record_state_signature(record: EvidencePackReferenceRecord) -> tuple[object, ...]:
    return (
        record.portable_path,
        record.included,
        record.unresolved_reason,
        tuple(
            (owner.owner_kind, owner.owner_id, owner.evidence_ids)
            for owner in record.owners
        ),
    )


def _load_pack_metadata(
    root: Path,
    path: Path,
) -> tuple[dict[str, object] | None, str | None]:
    if path.is_symlink():
        return None, f"{path.name}:unsafe_symlink"
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None, f"{path.name}:unsafe_path"
    if not path.is_file():
        return None, path.name
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, f"{path.name}:malformed"
    if not isinstance(payload, dict):
        return None, f"{path.name}:malformed"
    return payload, None


def _manifest_declares_current_closure(payload: dict[str, object] | None) -> bool:
    if payload is None:
        return False
    return (
        payload.get("reference_closure") == REFERENCE_CLOSURE_FILENAME
        or REFERENCE_CLOSURE_FILENAME in _string_list(payload.get("files_included"))
    )


def _validate_declared_path(
    root: Path,
    value: str,
    unsafe_paths: set[str],
) -> tuple[str | None, bool]:
    try:
        portable_path = _normalise_portable_path(value)
        candidate_path = root / Path(*PurePosixPath(portable_path).parts)
        if candidate_path.is_symlink():
            raise ValueError("symlink metadata member")
        candidate = candidate_path.resolve(strict=False)
        candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        unsafe_paths.add(value)
        return None, False
    return portable_path, candidate_path.is_file()


def _declared_paths(
    value: object,
    root: Path,
    unsafe_paths: set[str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(value, list):
        return (), ()
    paths: list[str] = []
    duplicate_paths: set[str] = set()
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item.strip():
            unsafe_paths.add(str(item))
            continue
        portable_path, _included = _validate_declared_path(root, item, unsafe_paths)
        if portable_path is None:
            continue
        if portable_path in seen:
            duplicate_paths.add(portable_path)
        seen.add(portable_path)
        paths.append(portable_path)
    return tuple(sorted(set(paths))), tuple(sorted(duplicate_paths))


def _metadata_path_list(value: object, unsafe_paths: set[str]) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    paths: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item.strip():
            unsafe_paths.add(str(item))
            continue
        try:
            paths.add(_normalise_portable_path(item))
        except ValueError:
            unsafe_paths.add(item)
    return tuple(sorted(paths))


def _contained_pack_files(root: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    included: list[str] = []
    unsafe: list[str] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        try:
            resolved = path.resolve(strict=False)
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            unsafe.append(relative)
            continue
        if path.is_file():
            included.append(relative)
    return tuple(included), tuple(unsafe)


def _project_evidence_by_source(root: Path) -> dict[str, tuple[str, ...]]:
    payload = _load_structured_json_object(
        root, root / "project_state.json", required=True, label="project_state.json"
    )
    state = payload.get("project_state")
    if state is None:
        state = {}
    elif not isinstance(state, dict):
        raise ValueError("project_state.json project_state must be an object")
    grouped: dict[str, set[str]] = {}
    processed_files = state.get("processed_files", [])
    if not isinstance(processed_files, list):
        raise ValueError("project_state.json processed_files must be a list")
    for source_file in processed_files:
        if isinstance(source_file, str) and source_file.strip():
            grouped.setdefault(_project_relative_source(root, source_file), set())
    raw_evidence = state.get("evidence", [])
    if not isinstance(raw_evidence, list):
        raise ValueError("project_state.json evidence must be a list")
    for item in raw_evidence:
        if not isinstance(item, dict):
            continue
        source_file = item.get("source_file")
        evidence_id = item.get("id")
        if not isinstance(source_file, str) or not source_file.strip():
            continue
        source_path = _project_relative_source(root, source_file)
        evidence_ids = grouped.setdefault(source_path, set())
        if isinstance(evidence_id, str) and evidence_id.strip():
            evidence_ids.add(evidence_id.strip())
    return {
        source_path: tuple(sorted(evidence_ids))
        for source_path, evidence_ids in sorted(grouped.items())
    }


def _packed_project_evidence_by_source(root: Path) -> dict[str, tuple[str, ...]]:
    payload = _load_structured_json_object(
        root, root / "project_state.json", required=True, label="project_state.json"
    )
    state = payload.get("project_state")
    if not isinstance(state, dict):
        raise ValueError("packed project_state.json project_state must be an object")
    grouped: dict[str, set[str]] = {}
    processed_files = state.get("processed_files", [])
    if not isinstance(processed_files, list):
        raise ValueError("packed project_state.json processed_files must be a list")
    for source_file in processed_files:
        if isinstance(source_file, str) and source_file.strip():
            portable_path = _normalise_portable_path(source_file)
            grouped.setdefault(portable_path, set())
    raw_evidence = state.get("evidence", [])
    if not isinstance(raw_evidence, list):
        raise ValueError("packed project_state.json evidence must be a list")
    for item in raw_evidence:
        if not isinstance(item, dict):
            continue
        source_file = item.get("source_file")
        evidence_id = item.get("id")
        if not isinstance(source_file, str) or not source_file.strip():
            continue
        portable_path = _normalise_portable_path(source_file)
        evidence_ids = grouped.setdefault(portable_path, set())
        if isinstance(evidence_id, str) and evidence_id.strip():
            evidence_ids.add(evidence_id.strip())
    return {
        portable_path: tuple(sorted(evidence_ids))
        for portable_path, evidence_ids in sorted(grouped.items())
    }


def _deep_output_references(root: Path) -> tuple[EvidencePackReference, ...]:
    deep_paths: tuple[str, ...] = ()
    collection_path = root / DEEP_SOURCE_ROUTE_COLLECTION_JSON
    collection_markdown = root / DEEP_SOURCE_ROUTE_COLLECTION_MARKDOWN
    source_collection = _load_structured_json_object(
        root, collection_path, required=False, label=DEEP_SOURCE_ROUTE_COLLECTION_JSON
    )
    if collection_markdown.exists() and source_collection is None:
        raise ValueError("Deep collection Markdown requires valid collection JSON")
    if source_collection is not None:
        if (
            source_collection.get("schema_version") != 1
            or source_collection.get("generated_by")
            != "bugslyce.deep_source_route_collection"
        ):
            raise ValueError("Deep source-route collection metadata is invalid")
        deep_paths = _DEEP_OUTPUT_PATHS[:2]
    orchestration_path = root / DEEP_RECON_ORCHESTRATION_JSON
    orchestration = _load_structured_json_object(
        root, orchestration_path, required=False, label=DEEP_RECON_ORCHESTRATION_JSON
    )
    if (
        (root / DEEP_RECON_REVIEW_MARKDOWN).exists()
        or (root / DEEP_RECON_RUNBOOK_MARKDOWN).exists()
    ) and orchestration is None:
        raise ValueError("Deep review outputs require valid orchestration JSON")
    if orchestration is not None:
        if (
            orchestration.get("report_markdown_file") != DEEP_RECON_REVIEW_MARKDOWN
            or orchestration.get("runbook_markdown_file") != DEEP_RECON_RUNBOOK_MARKDOWN
        ):
            raise ValueError("Deep orchestration output markers are invalid")
        deep_paths = _DEEP_OUTPUT_PATHS
    return tuple(
        EvidencePackReference(
            portable_path=portable_path,
            owner_kind="deep_output",
            owner_id=portable_path,
        )
        for portable_path in deep_paths
    )


def _deep_relationship_references(root: Path) -> tuple[EvidencePackReference, ...]:
    collection_path = root / DEEP_SOURCE_ROUTE_COLLECTION_JSON
    if not collection_path.is_file():
        return ()
    payload = _load_structured_json_object(
        root, collection_path, required=False, label=DEEP_SOURCE_ROUTE_COLLECTION_JSON
    )
    if (
        payload is None
        or payload.get("schema_version") != 1
        or payload.get("generated_by") != "bugslyce.deep_source_route_collection"
    ):
        return ()
    try:
        collection = load_deep_source_route_collection_result(collection_path)
    except (OSError, ValueError) as exc:
        raise ValueError("could not reconstruct current Deep references") from exc
    reviews = build_successful_deep_content_reviews(collection)
    project_state = _load_relationship_project_state(root)
    clusters = (
        build_http_route_relationship_clusters(
            project_state,
            source_collection=collection,
            successful_reviews=reviews,
        )
        if project_state is not None
        else ()
    )
    return evidence_pack_references_from_deep_models(reviews, clusters)


def _load_relationship_project_state(root: Path) -> ProjectState | None:
    payload = _load_structured_json_object(
        root, root / "project_state.json", required=True, label="project_state.json"
    )
    raw_state = payload.get("project_state")
    if not isinstance(raw_state, dict):
        raise ValueError("project state relationship payload must be an object")
    raw_artifacts = raw_state.get("http_artifacts", [])
    raw_paths = raw_state.get("discovered_paths", [])
    raw_evidence = raw_state.get("evidence", [])
    if not all(isinstance(value, list) for value in (raw_artifacts, raw_paths, raw_evidence)):
        raise ValueError("project state relationship collections must be lists")
    return ProjectState(
        project_name=str(raw_state.get("project_name") or root.name),
        input_dir=str(root),
        processed_files=[],
        scope_summary=str(raw_state.get("scope_summary") or "not recorded"),
        assets=[],
        http_services=[],
        endpoints=[],
        port_services=[],
        http_artifacts=[_http_artifact_from_dict(item) for item in raw_artifacts],
        discovered_paths=[_discovered_path_from_dict(item) for item in raw_paths],
        recon_summary=None,
        recon_manifest=None,
        evidence=[_evidence_from_dict(item) for item in raw_evidence],
        warnings=[],
        generated_at=str(raw_state.get("generated_at") or "not recorded"),
        engagement_context=str(raw_state.get("engagement_context") or "unknown"),
    )


def _http_artifact_from_dict(value: object) -> HTTPArtifact:
    if not isinstance(value, dict):
        raise ValueError("project-state HTTP artefact must be an object")
    return HTTPArtifact(
        url=str(value.get("url") or ""),
        artifact_type=str(value.get("artifact_type") or ""),
        value=str(value.get("value") or ""),
        source_file=str(value.get("source_file") or ""),
        evidence_ids=list(_string_sequence(value.get("evidence_ids"))),
        tags=list(_string_sequence(value.get("tags"))),
    )


def _discovered_path_from_dict(value: object) -> DiscoveredPath:
    if not isinstance(value, dict):
        raise ValueError("project-state discovered path must be an object")
    status_code = value.get("status_code")
    content_length = value.get("content_length")
    redirect_location = value.get("redirect_location")
    return DiscoveredPath(
        url=str(value.get("url") or ""),
        status_code=status_code if isinstance(status_code, int) else None,
        content_length=content_length if isinstance(content_length, int) else None,
        redirect_location=(
            str(redirect_location) if redirect_location is not None else None
        ),
        source=str(value.get("source") or ""),
        evidence_ids=list(_string_sequence(value.get("evidence_ids"))),
        tags=list(_string_sequence(value.get("tags"))),
    )


def _evidence_from_dict(value: object) -> Evidence:
    if not isinstance(value, dict):
        raise ValueError("project-state evidence must be an object")
    context = value.get("context")
    return Evidence(
        id=str(value.get("id") or ""),
        source_file=str(value.get("source_file") or ""),
        evidence_type=str(value.get("evidence_type") or ""),
        value=str(value.get("value") or ""),
        context=context if isinstance(context, dict) else {},
    )


def _string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _project_relative_source(root: Path, value: str) -> str:
    text = _required_text(value, "project artefact path")
    candidate = Path(text)
    if "\\" in text or ".." in candidate.parts:
        raise ValueError(f"Unsafe project artefact path: {value}")
    try:
        resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
        relative = resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"Unsafe project artefact path: {value}") from exc
    if not relative.parts:
        raise ValueError(f"Unsafe project artefact path: {value}")
    return PurePosixPath(*relative.parts).as_posix()


def _archive_path_for_project_source(source_path: str) -> str:
    if source_path in {path for path, _owner in _CORE_REFERENCE_OWNERS}:
        return source_path
    if source_path.startswith(("recon_execution", "content_discovery_execution")):
        return f"metadata/{PurePosixPath(source_path).name}"
    return f"raw/{source_path}"


def _load_structured_json_object(
    root: Path,
    path: Path,
    *,
    required: bool,
    label: str,
) -> dict[str, object] | None:
    if path.is_symlink():
        raise ValueError(f"{label} is an unsafe symlink")
    try:
        path.resolve(strict=False).relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{label} is outside the structured metadata root") from exc
    if not path.exists():
        if required:
            raise ValueError(f"required structured metadata is missing: {label}")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"malformed structured metadata: {label}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"structured metadata must be an object: {label}")
    return payload


def _normalise_portable_path(value: str) -> str:
    text = _required_text(value, "portable artefact path")
    if "\\" in text:
        raise ValueError(f"Unsafe portable artefact path: {value}")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or path.as_posix() in {"", "."}:
        raise ValueError(f"Unsafe portable artefact path: {value}")
    return path.as_posix()


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    return value.strip()


def _nonempty_sorted(values: Sequence[object]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value.strip()
                for value in values
                if isinstance(value, str) and value.strip()
            }
        )
    )


def _record_to_dict(record: EvidencePackReferenceRecord) -> dict[str, object]:
    return {
        "portable_path": record.portable_path,
        "included": record.included,
        "unresolved_reason": record.unresolved_reason,
        "owners": [
            {
                "owner_kind": owner.owner_kind,
                "owner_id": owner.owner_id,
                "evidence_ids": list(owner.evidence_ids),
            }
            for owner in record.owners
        ],
    }


def _record_from_dict(value: object, index: int) -> EvidencePackReferenceRecord:
    if not isinstance(value, dict):
        raise ValueError(f"Reference-closure item #{index} must be a JSON object.")
    portable_path = value.get("portable_path")
    if not isinstance(portable_path, str):
        raise ValueError(f"Reference-closure item #{index} has no portable path.")
    raw_owners = value.get("owners")
    if not isinstance(raw_owners, list):
        raise ValueError(f"Reference-closure item #{index} owners must be a list.")
    owners: list[EvidencePackReferenceOwner] = []
    seen_owners: set[tuple[str, str]] = set()
    for owner_index, raw_owner in enumerate(raw_owners, start=1):
        if not isinstance(raw_owner, dict):
            raise ValueError(
                f"Reference-closure item #{index} owner #{owner_index} must be an object."
            )
        owner_kind = _required_text(raw_owner.get("owner_kind"), "reference owner kind")
        owner_id = _required_text(raw_owner.get("owner_id"), "reference owner ID")
        owner_key = (owner_kind, owner_id)
        if owner_key in seen_owners:
            raise ValueError(f"Reference-closure item #{index} has duplicate owners.")
        seen_owners.add(owner_key)
        evidence_ids = raw_owner.get("evidence_ids")
        if not isinstance(evidence_ids, list) or any(
            not isinstance(item, str) or not item.strip() for item in evidence_ids
        ):
            raise ValueError(f"Reference-closure item #{index} evidence IDs must be text.")
        owners.append(
            EvidencePackReferenceOwner(
                owner_kind=owner_kind,
                owner_id=owner_id,
                evidence_ids=tuple(sorted(set(item.strip() for item in evidence_ids))),
            )
        )
    included = value.get("included")
    if type(included) is not bool:
        raise ValueError(f"Reference-closure item #{index} included must be boolean.")
    unresolved_reason = value.get("unresolved_reason")
    if unresolved_reason is not None and (
        not isinstance(unresolved_reason, str) or not unresolved_reason.strip()
    ):
        raise ValueError(
            f"Reference-closure item #{index} unresolved reason must be text or null."
        )
    return EvidencePackReferenceRecord(
        portable_path=portable_path,
        owners=tuple(sorted(owners, key=lambda owner: (owner.owner_kind, owner.owner_id))),
        included=included,
        unresolved_reason=unresolved_reason.strip() if unresolved_reason is not None else None,
    )


def _string_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return _nonempty_sorted(value)
