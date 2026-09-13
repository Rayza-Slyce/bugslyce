"""Canonical persistence for native-observation semantic evidence."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
import stat
import tempfile

from bugslyce.recon.native_observation_facts import (
    NativeMobileAssociationDeclaration,
    NativeObservationSemanticEvidence,
    NativeRedirectRelationship,
    NativeSemanticProcessingSource,
    NativeStructuredResponseFact,
)


NATIVE_OBSERVATION_SEMANTIC_EVIDENCE_FILENAME = (
    "native_observation_semantic_evidence.json"
)
SCHEMA_VERSION = 1
GENERATED_BY = "bugslyce.native_observation_semantic_evidence"
_MAX_FILE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class NativeObservationSemanticCheckpoint:
    """Durable semantic facts plus exact source-processing coverage."""

    evidence: NativeObservationSemanticEvidence
    processed_sources: tuple[NativeSemanticProcessingSource, ...] = ()

    def __post_init__(self) -> None:
        expected = tuple(
            sorted(
                set(self.processed_sources),
                key=lambda value: (
                    value.candidate_index,
                    value.exchange_index,
                    value.request_url,
                ),
            )
        )
        if not isinstance(self.evidence, NativeObservationSemanticEvidence):
            raise TypeError("native semantic checkpoint requires typed evidence")
        if not isinstance(self.processed_sources, tuple) or self.processed_sources != expected:
            raise ValueError("native semantic processing coverage is not deterministic.")



def _mapping(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} has missing or unexpected fields")
    return value


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _processing_to_dict(value: NativeSemanticProcessingSource) -> dict[str, object]:
    return {
        "body_sha256": value.body_sha256,
        "candidate_index": value.candidate_index,
        "capture_state": value.capture_state,
        "captured_bytes": value.captured_bytes,
        "exchange_index": value.exchange_index,
        "headers_capture_state": value.headers_capture_state,
        "request_url": value.request_url,
        "status_code": value.status_code,
    }


def _processing_from_dict(
    value: object,
    label: str,
) -> NativeSemanticProcessingSource:
    item = _mapping(
        value,
        {
            "body_sha256",
            "candidate_index",
            "capture_state",
            "captured_bytes",
            "exchange_index",
            "headers_capture_state",
            "request_url",
            "status_code",
        },
        label,
    )
    return NativeSemanticProcessingSource(
        request_url=_text(item["request_url"], f"{label}.request_url"),
        status_code=_integer(item["status_code"], f"{label}.status_code"),
        candidate_index=_integer(
            item["candidate_index"], f"{label}.candidate_index"
        ),
        exchange_index=_integer(
            item["exchange_index"], f"{label}.exchange_index"
        ),
        captured_bytes=_integer(
            item["captured_bytes"], f"{label}.captured_bytes"
        ),
        body_sha256=_text(item["body_sha256"], f"{label}.body_sha256"),
        capture_state=_text(item["capture_state"], f"{label}.capture_state"),
        headers_capture_state=_text(
            item["headers_capture_state"],
            f"{label}.headers_capture_state",
        ),
    )



def _structured_to_dict(value: NativeStructuredResponseFact) -> dict[str, object]:
    return {
        "body_sha256": value.body_sha256,
        "candidate_index": value.candidate_index,
        "confirmed_api": value.confirmed_api,
        "direct_observation": value.direct_observation,
        "exchange_index": value.exchange_index,
        "request_url": value.request_url,
        "status_code": value.status_code,
    }


def _structured_from_dict(value: object, label: str) -> NativeStructuredResponseFact:
    item = _mapping(
        value,
        {
            "body_sha256",
            "candidate_index",
            "confirmed_api",
            "direct_observation",
            "exchange_index",
            "request_url",
            "status_code",
        },
        label,
    )
    return NativeStructuredResponseFact(
        request_url=_text(item["request_url"], f"{label}.request_url"),
        status_code=_integer(item["status_code"], f"{label}.status_code"),
        candidate_index=_integer(
            item["candidate_index"], f"{label}.candidate_index"
        ),
        exchange_index=_integer(item["exchange_index"], f"{label}.exchange_index"),
        body_sha256=_text(item["body_sha256"], f"{label}.body_sha256"),
        direct_observation=_boolean(
            item["direct_observation"], f"{label}.direct_observation"
        ),
        confirmed_api=_boolean(item["confirmed_api"], f"{label}.confirmed_api"),
    )


def _redirect_to_dict(value: NativeRedirectRelationship) -> dict[str, object]:
    return {
        "candidate_index": value.candidate_index,
        "destination_fetched": value.destination_fetched,
        "direct_observation": value.direct_observation,
        "exchange_index": value.exchange_index,
        "raw_location": value.raw_location,
        "source_url": value.source_url,
        "target_url": value.target_url,
    }


def _redirect_from_dict(value: object, label: str) -> NativeRedirectRelationship:
    item = _mapping(
        value,
        {
            "candidate_index",
            "destination_fetched",
            "direct_observation",
            "exchange_index",
            "raw_location",
            "source_url",
            "target_url",
        },
        label,
    )
    return NativeRedirectRelationship(
        source_url=_text(item["source_url"], f"{label}.source_url"),
        raw_location=_text(item["raw_location"], f"{label}.raw_location"),
        target_url=_text(item["target_url"], f"{label}.target_url"),
        candidate_index=_integer(
            item["candidate_index"], f"{label}.candidate_index"
        ),
        exchange_index=_integer(item["exchange_index"], f"{label}.exchange_index"),
        direct_observation=_boolean(
            item["direct_observation"], f"{label}.direct_observation"
        ),
        destination_fetched=_boolean(
            item["destination_fetched"], f"{label}.destination_fetched"
        ),
    )


def _association_to_dict(
    value: NativeMobileAssociationDeclaration,
) -> dict[str, object]:
    return {
        "body_sha256": value.body_sha256,
        "candidate_index": value.candidate_index,
        "direct_observation": value.direct_observation,
        "document_url": value.document_url,
        "exchange_index": value.exchange_index,
        "ownership_confirmed": value.ownership_confirmed,
        "package_name": value.package_name,
        "platform": value.platform,
    }


def _association_from_dict(
    value: object,
    label: str,
) -> NativeMobileAssociationDeclaration:
    item = _mapping(
        value,
        {
            "body_sha256",
            "candidate_index",
            "direct_observation",
            "document_url",
            "exchange_index",
            "ownership_confirmed",
            "package_name",
            "platform",
        },
        label,
    )
    return NativeMobileAssociationDeclaration(
        document_url=_text(item["document_url"], f"{label}.document_url"),
        platform=_text(item["platform"], f"{label}.platform"),
        package_name=_text(item["package_name"], f"{label}.package_name"),
        candidate_index=_integer(
            item["candidate_index"], f"{label}.candidate_index"
        ),
        exchange_index=_integer(item["exchange_index"], f"{label}.exchange_index"),
        body_sha256=_text(item["body_sha256"], f"{label}.body_sha256"),
        direct_observation=_boolean(
            item["direct_observation"], f"{label}.direct_observation"
        ),
        ownership_confirmed=_boolean(
            item["ownership_confirmed"], f"{label}.ownership_confirmed"
        ),
    )


def native_observation_semantic_evidence_to_dict(
    evidence: NativeObservationSemanticEvidence,
    *,
    processed_sources: tuple[NativeSemanticProcessingSource, ...] = (),
) -> dict[str, object]:
    """Return the canonical schema-1 checkpoint representation."""

    checkpoint = NativeObservationSemanticCheckpoint(
        evidence=evidence,
        processed_sources=processed_sources,
    )
    return {
        "generated_by": GENERATED_BY,
        "mobile_association_declarations": [
            _association_to_dict(item)
            for item in evidence.mobile_association_declarations
        ],
        "processed_sources": [
            _processing_to_dict(item)
            for item in checkpoint.processed_sources
        ],
        "redirect_relationships": [
            _redirect_to_dict(item) for item in evidence.redirect_relationships
        ],
        "schema_version": SCHEMA_VERSION,
        "structured_responses": [
            _structured_to_dict(item) for item in evidence.structured_responses
        ],
    }


def native_observation_semantic_checkpoint_from_dict(
    payload: object,
) -> NativeObservationSemanticCheckpoint:
    """Strictly reconstruct one supported checkpoint payload."""

    top = _mapping(
        payload,
        {
            "generated_by",
            "mobile_association_declarations",
            "processed_sources",
            "redirect_relationships",
            "schema_version",
            "structured_responses",
        },
        NATIVE_OBSERVATION_SEMANTIC_EVIDENCE_FILENAME,
    )
    if _integer(top["schema_version"], "schema_version") != SCHEMA_VERSION:
        raise ValueError("native semantic checkpoint has an unsupported schema version")
    if _text(top["generated_by"], "generated_by") != GENERATED_BY:
        raise ValueError("native semantic checkpoint has an invalid generated_by value")
    evidence = NativeObservationSemanticEvidence(
        structured_responses=tuple(
            _structured_from_dict(item, f"structured_responses[{index}]")
            for index, item in enumerate(
                _array(top["structured_responses"], "structured_responses")
            )
        ),
        redirect_relationships=tuple(
            _redirect_from_dict(item, f"redirect_relationships[{index}]")
            for index, item in enumerate(
                _array(top["redirect_relationships"], "redirect_relationships")
            )
        ),
        mobile_association_declarations=tuple(
            _association_from_dict(
                item,
                f"mobile_association_declarations[{index}]",
            )
            for index, item in enumerate(
                _array(
                    top["mobile_association_declarations"],
                    "mobile_association_declarations",
                )
            )
        ),
    )
    processed_sources = tuple(
        _processing_from_dict(item, f"processed_sources[{index}]")
        for index, item in enumerate(
            _array(top["processed_sources"], "processed_sources")
        )
    )
    checkpoint = NativeObservationSemanticCheckpoint(
        evidence=evidence,
        processed_sources=processed_sources,
    )
    if native_observation_semantic_evidence_to_dict(
        evidence,
        processed_sources=processed_sources,
    ) != top:
        raise ValueError("native semantic checkpoint payload is not canonical")
    return checkpoint


def native_observation_semantic_evidence_from_dict(
    payload: object,
) -> NativeObservationSemanticEvidence:
    """Strictly reconstruct the semantic-evidence component."""

    return native_observation_semantic_checkpoint_from_dict(payload).evidence


def _object_without_duplicate_members(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("native semantic checkpoint JSON has a duplicate member")
        result[key] = value
    return result


def _path(root: Path) -> Path:
    if not isinstance(root, Path):
        raise TypeError("native semantic checkpoint root must be a Path")
    return root / NATIVE_OBSERVATION_SEMANTIC_EVIDENCE_FILENAME


def _validate_file(path: Path, *, allow_absent: bool) -> bool:
    if path.is_symlink():
        raise ValueError("native semantic checkpoint must be a regular file")
    if not path.exists():
        return not allow_absent
    if not path.is_file():
        raise ValueError("native semantic checkpoint must be a regular file")
    return True


def write_native_observation_semantic_evidence_artifact(
    root: Path,
    evidence: NativeObservationSemanticEvidence,
    *,
    processed_sources: tuple[NativeSemanticProcessingSource, ...] = (),
) -> Path:
    """Atomically write one canonical native semantic checkpoint."""

    payload = native_observation_semantic_evidence_to_dict(
        evidence,
        processed_sources=processed_sources,
    )
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    root.mkdir(parents=True, exist_ok=True)
    path = _path(root)
    _validate_file(path, allow_absent=False)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{NATIVE_OBSERVATION_SEMANTIC_EVIDENCE_FILENAME}.",
            dir=root,
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_file(path, allow_absent=False)
        os.replace(temporary_name, path)
        temporary_name = None
    except OSError as exc:
        raise ValueError(
            f"could not write {NATIVE_OBSERVATION_SEMANTIC_EVIDENCE_FILENAME}: {exc}"
        ) from exc
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass
    return path


def load_native_observation_semantic_checkpoint_artifact(
    root: Path,
) -> NativeObservationSemanticCheckpoint | None:
    """Load the optional canonical native semantic checkpoint."""

    path = _path(root)
    if not _validate_file(path, allow_absent=True):
        return None
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_FILE_BYTES:
            raise ValueError("native semantic checkpoint is not a bounded regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            content = handle.read(_MAX_FILE_BYTES + 1)
        if len(content) > _MAX_FILE_BYTES:
            raise ValueError("native semantic checkpoint exceeds the size limit")
        payload = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_members,
        )
        return native_observation_semantic_checkpoint_from_dict(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"could not parse {NATIVE_OBSERVATION_SEMANTIC_EVIDENCE_FILENAME} JSON: {exc}"
        ) from exc
    except ValueError:
        raise
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError) as exc:
        raise ValueError(
            f"{NATIVE_OBSERVATION_SEMANTIC_EVIDENCE_FILENAME} is malformed"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_native_observation_semantic_evidence_artifact(
    root: Path,
) -> NativeObservationSemanticEvidence | None:
    """Load only the semantic-fact component for existing consumers."""

    checkpoint = load_native_observation_semantic_checkpoint_artifact(root)
    return None if checkpoint is None else checkpoint.evidence
