"""Package 4B2 native observation-store compaction contracts."""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import runpy

import pytest

from bugslyce.recon import native_observation_compaction as compaction_module
from bugslyce.recon.evidence_pack_closure import (
    discover_evidence_pack_references,
    validate_evidence_pack_root,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.recon.native_observation_compaction import (
    compact_native_observation_store,
    validate_compacted_native_observation_store,
)
from bugslyce.recon.native_observation_facts import (
    NativeObservationSemanticEvidence,
    build_native_observation_semantic_evidence,
    build_native_observation_semantic_processing_sources,
)
from bugslyce.recon.native_observation_retention import (
    NativeObservationRetentionPlan,
    build_native_observation_retention_plan,
)
from bugslyce.recon.native_observation_retention_persistence import (
    NATIVE_OBSERVATION_RETENTION_PLAN_FILENAME,
    load_native_observation_retention_plan_artifact,
    write_native_observation_retention_plan_artifact,
)
from bugslyce.recon.native_observation_semantic_evidence_persistence import (
    load_native_observation_semantic_checkpoint_artifact,
    write_native_observation_semantic_evidence_artifact,
)
from bugslyce.recon.native_observation_store import (
    NativeCandidateObservation,
    NativeObservationStore,
    NativeReceivedExchange,
    validate_native_observation_store,
)


_ROOT = Path(__file__).resolve().parents[1]
_RETENTION_HELPERS = runpy.run_path(
    str(_ROOT / "tests/test_native_observation_retention.py")
)


def _manually_rebuild_compacted_store(
    project_root: Path,
    plan: NativeObservationRetentionPlan,
    *,
    omitted_source_ids: set[str],
) -> Path:
    source_root = project_root / "native-observations"
    source = NativeObservationStore.open_published(source_root)
    before = validate_native_observation_store(source_root)
    replacement_root = project_root / "replacement-native-observations"
    replacement = NativeObservationStore(
        replacement_root,
        before.body_byte_allowance,
        metadata_byte_allowance=before.metadata_byte_allowance,
    )
    decisions = {item.source_id: item for item in plan.decisions}
    for candidate_index in before.observation_indices:
        observation = source.load_observation(candidate_index)
        exchanges = []
        for exchange_index, exchange in enumerate(observation.exchanges):
            source_id = f"native-observation:{candidate_index}:{exchange_index}"
            decision = decisions.get(source_id)
            if source_id in omitted_source_ids:
                assert decision is not None
                exchanges.append(
                    replace(
                        exchange,
                        body=None,
                        body_retention_state="intentionally_not_retained",
                        body_retention_reason="semantic_processing_checkpointed",
                    )
                )
            elif exchange.body is None:
                exchanges.append(exchange)
            else:
                body = source.read_body(exchange.body)
                reference = replacement.commit_body(
                    replacement.reserve_body_bytes(len(body)),
                    body,
                )
                exchanges.append(replace(exchange, body=reference))
        rebuilt = replace(observation, exchanges=tuple(exchanges))
        replacement.publish_observation(
            rebuilt,
            replacement.reserve_candidate_metadata(
                candidate_index,
                maximum_redirect_hops=max(0, len(exchanges) - 1),
            ),
        )
    replacement.publish_index("complete")
    backup = project_root / "original-native-observations"
    os.rename(source_root, backup)
    os.rename(replacement_root, source_root)
    return backup


def _project(tmp_path: Path):
    root, _store, plan = _RETENTION_HELPERS["_closure_project"](tmp_path)
    checkpoint = load_native_observation_semantic_checkpoint_artifact(root)
    assert checkpoint is not None
    eligible = {
        item.source_id
        for item in plan.decisions
        if item.action == "eligible_for_omission"
    }
    assert len(eligible) == 2
    return root, plan, eligible


def _three_member_project(tmp_path: Path):
    root = _RETENTION_HELPERS["_EXPORT_HELPERS"]["_export_input"](tmp_path)
    records = tuple(
        {
            "candidate_index": index,
            "url": f"https://app.example.test/{name}",
            "body": f"<html>missing /{name}</html>".encode(),
        }
        for index, name in enumerate(("alpha", "beta", "gamma"))
    )
    store = _RETENTION_HELPERS["_store"](root, records)
    evidence = NativeObservationSemanticEvidence()
    processed = build_native_observation_semantic_processing_sources(store)
    write_native_observation_semantic_evidence_artifact(
        root, evidence, processed_sources=processed
    )
    plan = build_native_observation_retention_plan(
        store,
        semantic_evidence=evidence,
        processed_sources=processed,
    )
    write_native_observation_retention_plan_artifact(root, plan)
    return root, store, plan


def _tree_bytes(root: Path) -> dict[Path, bytes]:
    return {
        path.relative_to(root): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_closure_accepts_a_fully_compacted_retention_plan_graph(
    tmp_path: Path,
) -> None:
    root, plan, eligible = _project(tmp_path)
    _manually_rebuild_compacted_store(root, plan, omitted_source_ids=eligible)

    references = discover_evidence_pack_references(root)

    assert any(
        item.owner_kind == "native_observation_retention_plan"
        for item in references
    )


def test_closure_refuses_a_mixed_partially_applied_retention_plan(
    tmp_path: Path,
) -> None:
    root, plan, eligible = _project(tmp_path)
    _manually_rebuild_compacted_store(
        root,
        plan,
        omitted_source_ids={sorted(eligible)[0]},
    )

    with pytest.raises(ValueError, match="retention plan"):
        discover_evidence_pack_references(root)


def test_closure_refuses_omission_of_the_retained_representative(
    tmp_path: Path,
) -> None:
    root, plan, _eligible = _project(tmp_path)
    representative = plan.families[0].representative_source_id
    _manually_rebuild_compacted_store(
        root,
        plan,
        omitted_source_ids={representative},
    )

    with pytest.raises(ValueError, match="retained decision"):
        discover_evidence_pack_references(root)


def test_compaction_retains_representative_and_omits_two_exactly(
    tmp_path: Path,
) -> None:
    root, source, plan = _three_member_project(tmp_path)
    before = validate_native_observation_store(source.root)
    observations_before = {
        index: source.load_observation(index) for index in before.observation_indices
    }
    representative = plan.families[0].representative_source_id
    representative_decision = next(
        item for item in plan.decisions if item.source_id == representative
    )
    representative_bytes = source.read_body(
        observations_before[representative_decision.candidate_index].exchanges[0].body
    )

    result = compact_native_observation_store(root)
    compacted = NativeObservationStore.open_published(root / "native-observations")
    after = validate_compacted_native_observation_store(
        compacted,
        plan,
        load_native_observation_semantic_checkpoint_artifact(root),
    )

    assert result.changed
    assert result.omitted_exchange_count == 2
    assert after.body_bytes_committed < before.body_bytes_committed
    assert after.response_bytes_captured == before.response_bytes_captured
    assert after.body_byte_allowance == before.body_byte_allowance
    assert after.metadata_byte_allowance == before.metadata_byte_allowance
    assert after.observation_indices == before.observation_indices
    assert after.store_state == "complete"
    for decision in plan.decisions:
        old = observations_before[decision.candidate_index].exchanges[
            decision.exchange_index
        ]
        new = compacted.load_observation(decision.candidate_index).exchanges[
            decision.exchange_index
        ]
        assert (
            new.request_url,
            new.status_code,
            new.headers,
            new.capture_state,
            new.headers_capture_state,
            new.captured_bytes,
            new.body_sha256,
        ) == (
            old.request_url,
            old.status_code,
            old.headers,
            old.capture_state,
            old.headers_capture_state,
            old.captured_bytes,
            old.body_sha256,
        )
        if decision.action == "eligible_for_omission":
            assert new.body is None
            assert new.body_retention_state == "intentionally_not_retained"
            assert new.body_retention_reason == "semantic_processing_checkpointed"
        else:
            assert new.body_retention_state == "retained"
            assert new.body_retention_reason is None
    representative_exchange = compacted.load_observation(
        representative_decision.candidate_index
    ).exchanges[representative_decision.exchange_index]
    assert compacted.read_body(representative_exchange.body) == representative_bytes
    assert load_native_observation_retention_plan_artifact(root) == plan


def test_compaction_is_idempotent(tmp_path: Path) -> None:
    root, _source, plan = _three_member_project(tmp_path)
    first = compact_native_observation_store(root)
    durable_before = {
        path.relative_to(root / "native-observations"): path.read_bytes()
        for path in (root / "native-observations").rglob("*")
        if path.is_file()
    }

    second = compact_native_observation_store(root)

    assert first.changed
    assert not second.changed
    assert load_native_observation_retention_plan_artifact(root) == plan
    assert {
        path.relative_to(root / "native-observations"): path.read_bytes()
        for path in (root / "native-observations").rglob("*")
        if path.is_file()
    } == durable_before


def test_retry_discards_validated_premarker_replacement_residue(
    tmp_path: Path,
) -> None:
    root, _source, plan = _three_member_project(tmp_path)
    checkpoint = load_native_observation_semantic_checkpoint_artifact(root)
    assert checkpoint is not None

    canonical, replacement, backup, marker = compaction_module._transaction_paths(root)
    source = NativeObservationStore.open_published(canonical)
    source_index = compaction_module._validate_uncompacted_authority(
        source,
        plan,
        checkpoint,
    )
    rebuilt = compaction_module._build_replacement(
        source,
        source_index,
        plan,
        replacement,
    )
    validate_compacted_native_observation_store(rebuilt, plan, checkpoint)

    assert canonical.exists()
    assert replacement.exists()
    assert not backup.exists()
    assert not marker.exists()

    result = compact_native_observation_store(root)

    assert result.changed
    assert not replacement.exists()
    assert not backup.exists()
    assert not marker.exists()
    compacted = NativeObservationStore.open_published(canonical)
    validate_compacted_native_observation_store(compacted, plan, checkpoint)


def test_pipeline_retry_uses_durable_checkpoint_and_plan_after_compaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bugslyce import project_pipeline as pipeline

    root, _source, plan = _three_member_project(tmp_path)
    checkpoint = load_native_observation_semantic_checkpoint_artifact(root)
    assert checkpoint is not None
    compact_native_observation_store(root)

    def unexpected_reconstruction(*_args, **_kwargs):
        raise AssertionError("compacted bodies must not be required on retry")

    monkeypatch.setattr(
        pipeline,
        "build_native_observation_semantic_evidence",
        unexpected_reconstruction,
    )
    monkeypatch.setattr(
        pipeline,
        "build_native_observation_semantic_processing_sources",
        unexpected_reconstruction,
    )
    evidence, processed, store, existing_plan = (
        pipeline._native_observation_semantics_for_output(root)
    )

    assert evidence == checkpoint.evidence
    assert processed == checkpoint.processed_sources
    assert existing_plan == plan
    assert store is not None
    assert not compact_native_observation_store(root).changed


def test_compacted_closure_and_export_include_only_retained_cas_objects(
    tmp_path: Path,
) -> None:
    root, source, plan = _three_member_project(tmp_path)
    original_digests = {
        path.name for path in (source.root / "bodies/sha256").iterdir()
    }
    compact_native_observation_store(root)

    discover_evidence_pack_references(root)
    output = tmp_path / "compacted.zip"
    result = export_recon_evidence_pack(root, output)

    assert result.reference_closure_status == "complete"
    assert result.missing_files == []
    assert result.unresolved_reference_paths == ()

    extracted = tmp_path / "compacted-extracted"
    with __import__("zipfile").ZipFile(output) as archive:
        names = set(archive.namelist())
        archive.extractall(extracted)

    assert validate_evidence_pack_root(extracted).validation_status == "complete"
    packed_digests = {
        name.rsplit("/", 1)[-1]
        for name in names
        if name.startswith("native-observations/bodies/sha256/")
    }

    assert NATIVE_OBSERVATION_RETENTION_PLAN_FILENAME in names
    assert len(packed_digests) == 1
    assert packed_digests < original_digests
    assert packed_digests == {
        item.body_sha256
        for item in plan.decisions
        if item.action == "retain"
    }


def test_shared_required_digest_remains_physically_retained(tmp_path: Path) -> None:
    root, plan, eligible = _project(tmp_path)
    shared = tuple(
        item
        for item in plan.decisions
        if item.reason_code == "shared_required_digest"
    )
    assert shared

    compact_native_observation_store(root)

    store = NativeObservationStore.open_published(root / "native-observations")
    for decision in shared:
        exchange = store.load_observation(decision.candidate_index).exchanges[
            decision.exchange_index
        ]
        assert decision.source_id not in eligible
        assert exchange.body_retention_state == "retained"
        assert exchange.body is not None
        assert store.read_body(exchange.body)


def test_fact_bearing_and_unprocessed_sources_cannot_be_omitted(
    tmp_path: Path,
) -> None:
    root = _RETENTION_HELPERS["_EXPORT_HELPERS"]["_export_input"](tmp_path)
    records = (
        {
            "candidate_index": 0,
            "url": "https://app.example.test/api/status",
            "body": b'{"status":"ok"}',
            "status": 200,
            "headers": (("Content-Type", "application/json"),),
        },
        {
            "candidate_index": 1,
            "url": "https://app.example.test/unprocessed",
            "body": b"<html>ordinary retained response</html>",
        },
    )
    store = _RETENTION_HELPERS["_store"](root, records)
    evidence = build_native_observation_semantic_evidence(store)
    processed = tuple(
        item
        for item in build_native_observation_semantic_processing_sources(store)
        if item.source_id != "native-observation:1:0"
    )
    write_native_observation_semantic_evidence_artifact(
        root, evidence, processed_sources=processed
    )
    plan = build_native_observation_retention_plan(
        store, semantic_evidence=evidence, processed_sources=processed
    )
    write_native_observation_retention_plan_artifact(root, plan)

    result = compact_native_observation_store(root)

    decisions = {item.source_id: item for item in plan.decisions}
    assert not result.changed
    assert decisions["native-observation:0:0"].reason_code == "semantic_fact"
    assert decisions["native-observation:1:0"].reason_code == (
        "not_semantically_processed"
    )
    compacted = NativeObservationStore.open_published(root / "native-observations")
    assert all(
        compacted.load_observation(index).exchanges[0].body_retention_state
        == "retained"
        for index in (0, 1)
    )


def test_unavailable_incomplete_exchange_is_unchanged_by_compaction(
    tmp_path: Path,
) -> None:
    records = tuple(
        {
            "candidate_index": index,
            "url": f"https://app.example.test/{name}",
            "body": f"<html>missing /{name}</html>".encode(),
        }
        for index, name in enumerate(("alpha", "beta", "gamma"))
    )
    other_root = tmp_path / "with-unavailable"
    other_root.mkdir()
    store = NativeObservationStore(
        other_root / "native-observations",
        10_000_000,
        metadata_byte_allowance=10_000_000,
    )
    for record in records:
        body = record["body"]
        reference = store.commit_body(store.reserve_body_bytes(len(body)), body)
        exchange = NativeReceivedExchange(
            request_url=record["url"],
            status_code=404,
            headers=(("Content-Type", "text/html"),),
            capture_state="complete",
            captured_bytes=len(body),
            body_sha256=reference.sha256,
            body=reference,
        )
        index = record["candidate_index"]
        store.publish_observation(
            NativeCandidateObservation(
                candidate_index=index,
                request_url=record["url"],
                exchanges=(exchange,),
            ),
            store.reserve_candidate_metadata(index, maximum_redirect_hops=0),
        )
    unavailable = NativeReceivedExchange(
        request_url="https://app.example.test/interrupted",
        status_code=200,
        headers=(),
        capture_state="incomplete",
        captured_bytes=0,
        body_sha256=None,
        body=None,
        incomplete_reason="premature_eof",
    )
    store.publish_observation(
        NativeCandidateObservation(
            candidate_index=3,
            request_url=unavailable.request_url,
            exchanges=(unavailable,),
        ),
        store.reserve_candidate_metadata(3, maximum_redirect_hops=0),
    )
    store.publish_index("complete")
    evidence = NativeObservationSemanticEvidence()
    processed = build_native_observation_semantic_processing_sources(store)
    write_native_observation_semantic_evidence_artifact(
        other_root, evidence, processed_sources=processed
    )
    plan = build_native_observation_retention_plan(
        store, semantic_evidence=evidence, processed_sources=processed
    )
    write_native_observation_retention_plan_artifact(other_root, plan)

    compact_native_observation_store(other_root)

    compacted = NativeObservationStore.open_published(
        other_root / "native-observations"
    )
    assert compacted.load_observation(3).exchanges[0] == unavailable
    assert all(decision.candidate_index != 3 for decision in plan.decisions)


@pytest.mark.parametrize(
    "failure_phase",
    ("before_replacement_validation", "before_publication", "after_source_backup"),
)
def test_failure_before_publication_preserves_original_store_byte_for_byte(
    tmp_path: Path,
    failure_phase: str,
) -> None:
    root, _source, _plan = _three_member_project(tmp_path)
    store_root = root / "native-observations"
    before = _tree_bytes(store_root)

    def fail(phase: str) -> None:
        if phase == failure_phase:
            raise RuntimeError(f"injected {phase}")

    with pytest.raises(RuntimeError, match=failure_phase):
        compact_native_observation_store(root, failure_injector=fail)

    assert _tree_bytes(store_root) == before
    validate_native_observation_store(store_root)
    assert not any(root.glob(".native-observations.compaction-*"))


@pytest.mark.parametrize(
    "failure_phase",
    ("after_replacement_publish", "before_backup_cleanup"),
)
def test_cleanup_interruption_leaves_valid_compacted_store_and_retry_recovers(
    tmp_path: Path,
    failure_phase: str,
) -> None:
    root, _source, plan = _three_member_project(tmp_path)

    def fail(phase: str) -> None:
        if phase == failure_phase:
            raise RuntimeError(f"injected {phase}")

    with pytest.raises(RuntimeError, match=failure_phase):
        compact_native_observation_store(root, failure_injector=fail)

    canonical = NativeObservationStore.open_published(root / "native-observations")
    validate_compacted_native_observation_store(
        canonical,
        plan,
        load_native_observation_semantic_checkpoint_artifact(root),
    )
    retried = compact_native_observation_store(root)
    assert not retried.changed
    assert not any(root.glob(".native-observations.compaction-*"))


def test_unverified_tampered_plan_cannot_authorise_compaction(
    tmp_path: Path,
) -> None:
    root, source, plan = _three_member_project(tmp_path)
    before = _tree_bytes(source.root)
    eligible_index = next(
        index
        for index, decision in enumerate(plan.decisions)
        if decision.action == "eligible_for_omission"
    )
    decisions = list(plan.decisions)
    decisions[eligible_index] = replace(
        decisions[eligible_index],
        action="retain",
        reason_code="shared_required_digest",
    )
    tampered = replace(plan, decisions=tuple(decisions))
    write_native_observation_retention_plan_artifact(root, tampered)

    with pytest.raises(ValueError, match="retention plan"):
        compact_native_observation_store(root)

    assert _tree_bytes(source.root) == before


def test_missing_semantic_processing_coverage_cannot_authorise_omission(
    tmp_path: Path,
) -> None:
    root, source, plan = _three_member_project(tmp_path)
    before = _tree_bytes(source.root)
    checkpoint = load_native_observation_semantic_checkpoint_artifact(root)
    assert checkpoint is not None
    eligible = {
        item.source_id
        for item in plan.decisions
        if item.action == "eligible_for_omission"
    }
    damaged_coverage = tuple(
        item for item in checkpoint.processed_sources if item.source_id not in eligible
    )
    write_native_observation_semantic_evidence_artifact(
        root,
        checkpoint.evidence,
        processed_sources=damaged_coverage,
    )

    with pytest.raises(ValueError, match="semantic checkpoint"):
        compact_native_observation_store(root)

    assert _tree_bytes(source.root) == before


def test_transaction_symlink_is_refused_without_touching_store(
    tmp_path: Path,
) -> None:
    root, source, _plan = _three_member_project(tmp_path)
    before = _tree_bytes(source.root)
    transaction = root / ".native-observations.compaction-replacement"
    transaction.symlink_to(source.root, target_is_directory=True)

    with pytest.raises(ValueError, match="staging exists"):
        compact_native_observation_store(root)

    assert _tree_bytes(source.root) == before


def test_replacement_rename_failure_restores_original_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, source, _plan = _three_member_project(tmp_path)
    before = _tree_bytes(source.root)
    actual_rename = os.rename
    calls = 0

    def fail_second_rename(source_path, destination_path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected replacement publication failure")
        return actual_rename(source_path, destination_path)

    monkeypatch.setattr(
        "bugslyce.recon.native_observation_compaction.os.rename",
        fail_second_rename,
    )

    with pytest.raises(OSError, match="replacement publication failure"):
        compact_native_observation_store(root)

    assert _tree_bytes(source.root) == before
    validate_native_observation_store(source.root)
    assert not any(root.glob(".native-observations.compaction-*"))
