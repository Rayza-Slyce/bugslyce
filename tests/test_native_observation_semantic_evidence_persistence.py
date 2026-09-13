"""Canonical checkpoint contracts for native observation semantic evidence."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from bugslyce.recon.native_observation_facts import (
    NativeMobileAssociationDeclaration,
    NativeObservationSemanticEvidence,
    NativeRedirectRelationship,
    NativeSemanticProcessingSource,
    NativeStructuredResponseFact,
)


def _owner():
    return importlib.import_module(
        "bugslyce.recon.native_observation_semantic_evidence_persistence"
    )


def _evidence() -> NativeObservationSemanticEvidence:
    digest = "a" * 64
    return NativeObservationSemanticEvidence(
        structured_responses=(
            NativeStructuredResponseFact(
                request_url="https://app.example.test/api/search/",
                status_code=200,
                candidate_index=7,
                exchange_index=0,
                body_sha256=digest,
            ),
        ),
        redirect_relationships=(
            NativeRedirectRelationship(
                source_url="https://app.example.test/login",
                raw_location="/account",
                target_url="https://app.example.test/account",
                candidate_index=8,
                exchange_index=0,
            ),
        ),
        mobile_association_declarations=(
            NativeMobileAssociationDeclaration(
                document_url="https://app.example.test/.well-known/assetlinks.json",
                platform="android",
                package_name="com.example.mobile",
                candidate_index=9,
                exchange_index=0,
                body_sha256="b" * 64,
            ),
        ),
    )


def test_native_semantic_checkpoint_round_trips_exactly_and_deterministically(
    tmp_path: Path,
) -> None:
    owner = _owner()
    evidence = _evidence()

    first = owner.write_native_observation_semantic_evidence_artifact(
        tmp_path,
        evidence,
    )
    first_bytes = first.read_bytes()
    loaded = owner.load_native_observation_semantic_evidence_artifact(tmp_path)
    second = owner.write_native_observation_semantic_evidence_artifact(
        tmp_path,
        evidence,
    )

    assert loaded == evidence
    assert second.read_bytes() == first_bytes
    assert json.loads(first_bytes) == owner.native_observation_semantic_evidence_to_dict(
        evidence
    )


def test_native_semantic_checkpoint_absence_is_optional(tmp_path: Path) -> None:
    assert _owner().load_native_observation_semantic_evidence_artifact(tmp_path) is None


@pytest.mark.parametrize(
    "damage",
    ("unknown_schema", "unexpected_field", "missing_field", "duplicate_member"),
)
def test_native_semantic_checkpoint_malformed_payload_fails_closed(
    tmp_path: Path,
    damage: str,
) -> None:
    owner = _owner()
    path = owner.write_native_observation_semantic_evidence_artifact(
        tmp_path,
        _evidence(),
    )
    if damage == "duplicate_member":
        content = path.read_text(encoding="utf-8")
        path.write_text(content.replace('"schema_version": 1,', '"schema_version": 1,\n  "schema_version": 1,'), encoding="utf-8")
    else:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if damage == "unknown_schema":
            payload["schema_version"] = 99
        elif damage == "missing_field":
            del payload["structured_responses"]
        else:
            payload["unexpected"] = None
        path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        owner.load_native_observation_semantic_evidence_artifact(tmp_path)


def test_native_semantic_checkpoint_rejects_non_regular_or_symlink_path(
    tmp_path: Path,
) -> None:
    owner = _owner()
    path = tmp_path / owner.NATIVE_OBSERVATION_SEMANTIC_EVIDENCE_FILENAME
    path.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        owner.load_native_observation_semantic_evidence_artifact(tmp_path)
    path.rmdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    path.symlink_to(outside)
    with pytest.raises(ValueError, match="regular file"):
        owner.load_native_observation_semantic_evidence_artifact(tmp_path)


def test_native_semantic_checkpoint_preserves_no_fact_processing_coverage(
    tmp_path: Path,
) -> None:
    owner = _owner()
    source = NativeSemanticProcessingSource(
        request_url="https://app.example.test/ordinary/",
        status_code=200,
        candidate_index=12,
        exchange_index=0,
        captured_bytes=61,
        body_sha256="c" * 64,
    )

    owner.write_native_observation_semantic_evidence_artifact(
        tmp_path,
        NativeObservationSemanticEvidence(),
        processed_sources=(source,),
    )

    checkpoint = owner.load_native_observation_semantic_checkpoint_artifact(
        tmp_path
    )

    assert checkpoint is not None
    assert checkpoint.evidence == NativeObservationSemanticEvidence()
    assert checkpoint.processed_sources == (source,)
