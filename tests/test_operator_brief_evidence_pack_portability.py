"""RED contract for nested Operator Brief evidence-pack provenance."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import zipfile

import pytest

from bugslyce.recon.deep_source_route_collection_export import (
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    write_deep_source_route_collection_artifacts,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.deep_metadata_collection_export import (
    DEEP_METADATA_COLLECTION_JSON,
    write_deep_metadata_collection_artifacts,
)
from bugslyce.recon.deep_metadata_collector import DeepMetadataCollectionResult
from bugslyce.recon.evidence_pack_closure import (
    REFERENCE_CLOSURE_FILENAME,
    discover_expected_pack_references,
    validate_evidence_pack_root,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.reports.operator_brief import (
    OPERATOR_BRIEF_FILENAME,
    PRIMARY_THREAD,
    OperatorBriefConflict,
    OperatorBriefConflictKind,
    OperatorBriefConflictObservation,
    OperatorBriefDisposition,
    OperatorBriefDispositionReason,
    OperatorBriefFact,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSourceReference,
    OperatorBriefSubjectKind,
    OperatorBriefThread,
    OperatorBriefView,
    load_operator_brief_artifact,
    write_operator_brief_artifact,
)


FIXED_TIME = datetime(2026, 8, 22, 12, 30, tzinfo=timezone.utc)
MANIFEST_HTML = "nested/homepage-example.test-443.html"
PACKED_MANIFEST_HTML = f"raw/{MANIFEST_HTML}"
SMB_ARTEFACT = "smb-shares-files.example.test-445.txt"
PACKED_SMB_ARTEFACT = f"raw/{SMB_ARTEFACT}"
ROBOTS_ARTEFACT = "robots-example.test-443.txt"
PACKED_ROBOTS_ARTEFACT = f"raw/{ROBOTS_ARTEFACT}"


def _project(tmp_path: Path, name: str = "project") -> Path:
    root = tmp_path / name
    root.mkdir()
    (root / "nested").mkdir()
    files = {
        "report.md": "# Report\n",
        "runbook.md": "# Runbook\n",
        "scope.md": "## In Scope\n\n- example.test\n",
        "bugslyce_project.json": json.dumps(
            {
                "schema_version": "1.0",
                "name": "operator-brief-portability",
                "target": "example.test",
                "scope_file": str(root / "scope.md"),
                "output_dir": str(root),
            }
        )
        + "\n",
        "project_state.json": '{"project_state": {}, "candidates": []}\n',
        MANIFEST_HTML: "<title>Retained page</title>\n",
        SMB_ARTEFACT: "Disk|nt4wrksv|Retained share\n",
        ROBOTS_ARTEFACT: "User-agent: unusual\nDisallow: /private\n",
    }
    for relative, content in files.items():
        (root / relative).write_text(content, encoding="utf-8")
    manifest = {
        "schema_version": "1.0",
        "target": "example.test",
        "scope_file": "scope.md",
        "profile": "test",
        "artifacts": [
            {
                "type": "html",
                "file": MANIFEST_HTML,
                "url": "https://example.test/",
            },
            {"type": "smb_shares", "file": SMB_ARTEFACT},
            {
                "type": "robots",
                "file": ROBOTS_ARTEFACT,
                "url": "https://example.test/robots.txt",
            },
        ],
    }
    (root / "recon_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_deep_source_route_collection_artifacts(
        DeepSourceRouteCollectionResult(
            collected=(),
            skipped=(),
            total_considered=0,
            total_collected=0,
            total_skipped=0,
        ),
        root,
    )
    return root


def _brief(
    *,
    fact_references: tuple[str, ...] = (),
    thread_references: tuple[str, ...] = (),
    conflict_references: tuple[str, ...] = (),
) -> OperatorBriefView:
    fact = OperatorBriefFact(
        fact_id="FACT-PORTABLE-HTTP",
        kind=OperatorBriefFactKind.RETAINED_CONTENT,
        semantic_class=OperatorBriefSemanticClass.OBSERVED,
        role=OperatorBriefFactRole.DIRECT_EVIDENCE,
        label="Retained content",
        summary="Exact retained content is available for offline review.",
        endpoints=("https://example.test/",),
        origins=("https://example.test",),
        evidence_ids=("EVID-PORTABLE-HTTP",),
        artefact_references=fact_references,
        source_references=(
            OperatorBriefSourceReference(
                source_kind="manifest_retained_html",
                source_id="MANIFEST-HTML-PORTABLE",
            ),
        ),
        route="https://example.test/",
        body_sha256="a" * 64,
    )
    conflicts = ()
    if conflict_references:
        conflicts = (
            OperatorBriefConflict(
                conflict_id="CONFLICT-PORTABLE-HTTP",
                kind=OperatorBriefConflictKind.DIFFERING_HTTP_STATUS,
                subject_endpoint="https://example.test/",
                observations=(
                    OperatorBriefConflictObservation(
                        observation_id="OBS-PORTABLE-200",
                        endpoint="https://example.test/",
                        method="GET",
                        status_code=200,
                        collection_stage="metadata_collection",
                        evidence_ids=("EVID-PORTABLE-200",),
                        artefact_references=conflict_references,
                    ),
                    OperatorBriefConflictObservation(
                        observation_id="OBS-PORTABLE-404",
                        endpoint="https://example.test/",
                        method="GET",
                        status_code=404,
                        collection_stage="source_route_collection",
                        evidence_ids=("EVID-PORTABLE-404",),
                        artefact_references=conflict_references,
                    ),
                ),
                summary="Retained observations have differing status codes.",
            ),
        )
    thread = OperatorBriefThread(
        thread_id="THREAD-PORTABLE-HTTP",
        identity_key="http_subject:HTTP-SUBJECT-PORTABLE",
        subject_kind=OperatorBriefSubjectKind.CONTENT_SURFACE,
        title="Retained HTTP content",
        rank=1,
        signal="direct retained evidence",
        source_lead_ids=("LEAD-PORTABLE-HTTP",),
        endpoints=("https://example.test/",),
        origins=("https://example.test",),
        evidence_ids=("EVID-PORTABLE-HTTP",),
        why_review="Retained content warrants offline review.",
        next_review_step="Review the retained evidence locally.",
        facts=(fact,),
        conflicts=conflicts,
        source_artefacts=thread_references,
    )
    return OperatorBriefView(
        threads=(thread,),
        dispositions=(
            OperatorBriefDisposition(
                source_kind="operator_summary_lead",
                source_id="LEAD-PORTABLE-HTTP",
                disposition=PRIMARY_THREAD,
                thread_id=thread.thread_id,
                reason_code=OperatorBriefDispositionReason.PRIMARY_SUBJECT,
                represented_fact_ids=(fact.fact_id,),
            ),
        ),
    )


def _export(
    root: Path,
    brief: OperatorBriefView,
    output: Path,
) -> tuple[dict[str, object], dict[str, object], set[str]]:
    write_operator_brief_artifact(root, brief)
    export_recon_evidence_pack(root, output, clock=lambda: FIXED_TIME)
    with zipfile.ZipFile(output) as archive:
        return (
            json.loads(archive.read(OPERATOR_BRIEF_FILENAME)),
            json.loads(archive.read(REFERENCE_CLOSURE_FILENAME)),
            set(archive.namelist()),
        )


def _thread(payload: dict[str, object]) -> dict[str, object]:
    return payload["threads"][0]


def _fact(payload: dict[str, object]) -> dict[str, object]:
    return _thread(payload)["facts"][0]


def _owners(
    closure: dict[str, object], portable_path: str
) -> set[tuple[str, str, tuple[str, ...]]]:
    return {
        (
            owner["owner_kind"],
            owner["owner_id"],
            tuple(owner["evidence_ids"]),
        )
        for record in closure["references"]
        if record["portable_path"] == portable_path
        for owner in record["owners"]
    }


def _extract(output: Path, destination: Path) -> None:
    with zipfile.ZipFile(output) as archive:
        archive.extractall(destination)


def test_top_level_operator_brief_remains_a_packed_closure_member(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    packed, closure, members = _export(root, _brief(), tmp_path / "pack.zip")

    assert packed["schema_version"] == 2
    assert OPERATOR_BRIEF_FILENAME in members
    assert (
        "operator_brief",
        OPERATOR_BRIEF_FILENAME,
        (),
    ) in _owners(closure, OPERATOR_BRIEF_FILENAME)


def test_deep_top_level_reference_remains_name_stable_and_resolvable(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    packed, closure, members = _export(
        root,
        _brief(fact_references=(DEEP_SOURCE_ROUTE_COLLECTION_JSON,)),
        tmp_path / "pack.zip",
    )

    assert _fact(packed)["artefact_references"] == [
        DEEP_SOURCE_ROUTE_COLLECTION_JSON
    ]
    assert DEEP_SOURCE_ROUTE_COLLECTION_JSON in members
    assert (
        "operator_brief_fact",
        "FACT-PORTABLE-HTTP",
        ("EVID-PORTABLE-HTTP",),
    ) in _owners(closure, DEEP_SOURCE_ROUTE_COLLECTION_JSON)


def test_late_collection_confidence_owner_uses_the_same_portable_path_as_brief(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    write_deep_metadata_collection_artifacts(
        DeepMetadataCollectionResult(
            collected=(),
            skipped=(),
            total_considered=0,
            total_collected=0,
            total_skipped=0,
        ),
        root,
    )
    output = tmp_path / "pack.zip"
    packed, closure, members = _export(
        root,
        _brief(fact_references=(DEEP_METADATA_COLLECTION_JSON,)),
        output,
    )

    assert _fact(packed)["artefact_references"] == [DEEP_METADATA_COLLECTION_JSON]
    assert DEEP_METADATA_COLLECTION_JSON in members
    extracted = tmp_path / "extracted"
    _extract(output, extracted)
    assert validate_evidence_pack_root(extracted).validation_status == "complete"
    expected_references = discover_expected_pack_references(extracted)
    assert any(
        reference.portable_path == DEEP_METADATA_COLLECTION_JSON
        and reference.owner_kind == "operator_brief_fact"
        and reference.owner_id == "FACT-PORTABLE-HTTP"
        for reference in expected_references
    )
    assert not any(
        reference.portable_path == f"raw/{DEEP_METADATA_COLLECTION_JSON}"
        and reference.owner_kind == "operator_brief_fact"
        for reference in expected_references
    )
    assert f"raw/{DEEP_METADATA_COLLECTION_JSON}" not in members
    owners = _owners(closure, DEEP_METADATA_COLLECTION_JSON)
    assert (
        "collection_confidence_notice",
        "CONFIDENCE-DEEP-SOURCE-ROUTES",
        (),
    ) in owners
    assert (
        "operator_brief_fact",
        "FACT-PORTABLE-HTTP",
        ("EVID-PORTABLE-HTTP",),
    ) in owners
    assert not _owners(closure, f"raw/{DEEP_METADATA_COLLECTION_JSON}")


@pytest.mark.parametrize(
    ("live_reference", "packed_reference"),
    (
        (MANIFEST_HTML, PACKED_MANIFEST_HTML),
        (SMB_ARTEFACT, PACKED_SMB_ARTEFACT),
        (ROBOTS_ARTEFACT, PACKED_ROBOTS_ARTEFACT),
    ),
)
def test_fact_references_rewrite_to_actual_pack_members(
    tmp_path: Path,
    live_reference: str,
    packed_reference: str,
) -> None:
    root = _project(tmp_path)
    packed, closure, members = _export(
        root,
        _brief(fact_references=(live_reference,)),
        tmp_path / "pack.zip",
    )

    assert _fact(packed)["artefact_references"] == [packed_reference]
    assert packed_reference in members
    assert (
        "operator_brief_fact",
        "FACT-PORTABLE-HTTP",
        ("EVID-PORTABLE-HTTP",),
    ) in _owners(closure, packed_reference)


def test_thread_source_artefacts_rewrite_to_actual_pack_members(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    packed, closure, members = _export(
        root,
        _brief(thread_references=(MANIFEST_HTML, SMB_ARTEFACT)),
        tmp_path / "pack.zip",
    )

    assert _thread(packed)["source_artefacts"] == [
        PACKED_MANIFEST_HTML,
        PACKED_SMB_ARTEFACT,
    ]
    for reference in _thread(packed)["source_artefacts"]:
        assert reference in members
        assert (
            "operator_brief_thread",
            "THREAD-PORTABLE-HTTP",
            ("EVID-PORTABLE-HTTP",),
        ) in _owners(closure, reference)


def test_conflict_observation_references_rewrite_and_gain_closure_ownership(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    packed, closure, members = _export(
        root,
        _brief(conflict_references=(MANIFEST_HTML,)),
        tmp_path / "pack.zip",
    )

    observations = _thread(packed)["conflicts"][0]["observations"]
    assert all(
        item["artefact_references"] == [PACKED_MANIFEST_HTML]
        for item in observations
    )
    assert PACKED_MANIFEST_HTML in members
    assert (
        "operator_brief_conflict",
        "CONFLICT-PORTABLE-HTTP",
        ("EVID-PORTABLE-200", "EVID-PORTABLE-404"),
    ) in _owners(closure, PACKED_MANIFEST_HTML)


def test_all_packed_nested_references_resolve_to_physical_members(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    packed, _closure, members = _export(
        root,
        _brief(
            fact_references=(DEEP_SOURCE_ROUTE_COLLECTION_JSON, MANIFEST_HTML),
            thread_references=(SMB_ARTEFACT, ROBOTS_ARTEFACT),
            conflict_references=(MANIFEST_HTML,),
        ),
        tmp_path / "pack.zip",
    )

    nested = {
        *_fact(packed)["artefact_references"],
        *_thread(packed)["source_artefacts"],
        *(
            reference
            for conflict in _thread(packed)["conflicts"]
            for observation in conflict["observations"]
            for reference in observation["artefact_references"]
        ),
    }
    assert nested <= members


def test_export_preserves_semantic_ids_evidence_and_source_references(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    brief = _brief(
        fact_references=(MANIFEST_HTML,),
        thread_references=(SMB_ARTEFACT,),
        conflict_references=(ROBOTS_ARTEFACT,),
    )
    packed, _closure, _members = _export(root, brief, tmp_path / "pack.zip")
    source_thread = brief.threads[0]
    packed_thread = _thread(packed)
    packed_fact = _fact(packed)

    assert packed_thread["thread_id"] == source_thread.thread_id
    assert packed_thread["identity_key"] == source_thread.identity_key
    assert packed_thread["source_lead_ids"] == list(source_thread.source_lead_ids)
    assert packed_thread["evidence_ids"] == list(source_thread.evidence_ids)
    assert packed_fact["fact_id"] == source_thread.facts[0].fact_id
    assert packed_fact["evidence_ids"] == list(source_thread.facts[0].evidence_ids)
    assert packed_fact["source_references"] == [
        {
            "source_kind": "manifest_retained_html",
            "source_id": "MANIFEST-HTML-PORTABLE",
        }
    ]
    assert packed_thread["conflicts"][0]["conflict_id"] == (
        source_thread.conflicts[0].conflict_id
    )


def test_export_does_not_mutate_live_brief_or_in_memory_view(tmp_path: Path) -> None:
    root = _project(tmp_path)
    brief = _brief(
        fact_references=(MANIFEST_HTML,),
        thread_references=(SMB_ARTEFACT,),
    )
    live_path = write_operator_brief_artifact(root, brief)
    before = live_path.read_bytes()

    export_recon_evidence_pack(
        root,
        tmp_path / "pack.zip",
        clock=lambda: FIXED_TIME,
    )

    assert live_path.read_bytes() == before
    assert load_operator_brief_artifact(root) == brief
    assert brief.threads[0].facts[0].artefact_references == (MANIFEST_HTML,)
    assert brief.threads[0].source_artefacts == (SMB_ARTEFACT,)


def test_packed_brief_contains_no_live_absolute_or_traversing_reference(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    packed, _closure, _members = _export(
        root,
        _brief(
            fact_references=(MANIFEST_HTML,),
            thread_references=(SMB_ARTEFACT,),
            conflict_references=(ROBOTS_ARTEFACT,),
        ),
        tmp_path / "pack.zip",
    )
    rendered = json.dumps(packed, sort_keys=True)

    assert str(root) not in rendered
    for reference in (
        *_fact(packed)["artefact_references"],
        *_thread(packed)["source_artefacts"],
    ):
        path = PurePosixPath(reference)
        assert not path.is_absolute()
        assert ".." not in path.parts


def test_missing_nested_reference_is_explicitly_unresolved_not_silent(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    brief = _brief(fact_references=("missing/retained.html",))
    write_operator_brief_artifact(root, brief)

    result = export_recon_evidence_pack(
        root,
        tmp_path / "pack.zip",
        clock=lambda: FIXED_TIME,
    )
    with zipfile.ZipFile(tmp_path / "pack.zip") as archive:
        packed = json.loads(archive.read(OPERATOR_BRIEF_FILENAME))
        closure = json.loads(archive.read(REFERENCE_CLOSURE_FILENAME))

    expected = "raw/missing/retained.html"
    assert result.reference_closure_status == "incomplete"
    assert result.unresolved_reference_paths == (expected,)
    assert _fact(packed)["artefact_references"] == [expected]
    assert any(
        item["portable_path"] == expected
        and item["unresolved_reason"] == "missing_source_artefact"
        for item in closure["unresolved_references"]
    )
    assert (
        "operator_brief_fact",
        "FACT-PORTABLE-HTTP",
        ("EVID-PORTABLE-HTTP",),
    ) in _owners(closure, expected)


@pytest.mark.parametrize(
    "unsafe_reference",
    ("../outside.html", "/outside/operator-brief-evidence.html"),
)
def test_unsafe_nested_reference_fails_export(
    tmp_path: Path,
    unsafe_reference: str,
) -> None:
    root = _project(tmp_path)
    write_operator_brief_artifact(
        root,
        _brief(fact_references=(unsafe_reference,)),
    )
    output = tmp_path / "pack.zip"

    with pytest.raises(ValueError, match="Unsafe"):
        export_recon_evidence_pack(root, output, clock=lambda: FIXED_TIME)

    assert not output.exists()


def test_duplicate_nested_references_share_one_member_and_consistent_rewrite(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    output = tmp_path / "pack.zip"
    packed, closure, members = _export(
        root,
        _brief(
            fact_references=(MANIFEST_HTML,),
            thread_references=(MANIFEST_HTML,),
            conflict_references=(MANIFEST_HTML,),
        ),
        output,
    )

    with zipfile.ZipFile(output) as archive:
        assert archive.namelist().count(PACKED_MANIFEST_HTML) == 1
    assert PACKED_MANIFEST_HTML in members
    assert _fact(packed)["artefact_references"] == [PACKED_MANIFEST_HTML]
    assert _thread(packed)["source_artefacts"] == [PACKED_MANIFEST_HTML]
    assert all(
        item["artefact_references"] == [PACKED_MANIFEST_HTML]
        for item in _thread(packed)["conflicts"][0]["observations"]
    )
    owners = _owners(closure, PACKED_MANIFEST_HTML)
    assert {kind for kind, _owner_id, _evidence in owners} >= {
        "structured_raw_evidence",
        "operator_brief_fact",
        "operator_brief_thread",
        "operator_brief_conflict",
    }


def test_packed_operator_brief_reloads_with_resolving_nested_references(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    output = tmp_path / "pack.zip"
    _export(
        root,
        _brief(
            fact_references=(MANIFEST_HTML,),
            thread_references=(SMB_ARTEFACT,),
            conflict_references=(ROBOTS_ARTEFACT,),
        ),
        output,
    )
    extracted = tmp_path / "extracted"
    _extract(output, extracted)

    packed_brief = load_operator_brief_artifact(extracted)
    assert packed_brief is not None
    references = {
        *packed_brief.threads[0].facts[0].artefact_references,
        *packed_brief.threads[0].source_artefacts,
        *(
            reference
            for conflict in packed_brief.threads[0].conflicts
            for observation in conflict.observations
            for reference in observation.artefact_references
        ),
    }
    assert references == {
        PACKED_MANIFEST_HTML,
        PACKED_SMB_ARTEFACT,
        PACKED_ROBOTS_ARTEFACT,
    }
    assert all((extracted / reference).is_file() for reference in references)
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


def test_nested_closure_detects_removed_referenced_member(tmp_path: Path) -> None:
    root = _project(tmp_path)
    output = tmp_path / "pack.zip"
    _export(
        root,
        _brief(fact_references=(MANIFEST_HTML,)),
        output,
    )
    extracted = tmp_path / "extracted"
    _extract(output, extracted)

    (extracted / PACKED_MANIFEST_HTML).unlink()
    validation = validate_evidence_pack_root(extracted)

    assert validation.validation_status == "incomplete"
    assert PACKED_MANIFEST_HTML in validation.missing_declared_member_paths


def test_reference_ordering_is_canonical_in_packed_brief(tmp_path: Path) -> None:
    first_root = _project(tmp_path, "first")
    second_root = _project(tmp_path, "second")
    first, _closure, _members = _export(
        first_root,
        _brief(thread_references=(ROBOTS_ARTEFACT, SMB_ARTEFACT, MANIFEST_HTML)),
        tmp_path / "first.zip",
    )
    second, _closure, _members = _export(
        second_root,
        _brief(thread_references=(MANIFEST_HTML, SMB_ARTEFACT, ROBOTS_ARTEFACT)),
        tmp_path / "second.zip",
    )

    assert first == second
    assert _thread(first)["source_artefacts"] == sorted(
        _thread(first)["source_artefacts"]
    )


def test_exported_brief_and_closure_are_semantically_deterministic(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    brief = _brief(
        fact_references=(MANIFEST_HTML, ROBOTS_ARTEFACT),
        thread_references=(SMB_ARTEFACT,),
    )
    first_brief, first_closure, first_members = _export(
        root, brief, tmp_path / "first.zip"
    )
    second_brief, second_closure, second_members = _export(
        root, brief, tmp_path / "second.zip"
    )

    assert first_brief == second_brief
    assert first_closure == second_closure
    assert first_members == second_members
