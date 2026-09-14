"""Recoverable whole-store compaction for native observation evidence."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from typing import Callable

from bugslyce.recon.native_observation_facts import (
    NativeObservationSemanticEvidence,
    NativeSemanticProcessingSource,
    build_native_observation_semantic_evidence,
)
from bugslyce.recon.native_observation_retention import (
    NativeObservationRetentionPlan,
    build_native_observation_retention_plan,
    native_retention_grade_signature,
)
from bugslyce.recon.native_observation_retention_persistence import (
    load_native_observation_retention_plan_artifact,
)
from bugslyce.recon.native_observation_semantic_evidence_persistence import (
    NativeObservationSemanticCheckpoint,
    load_native_observation_semantic_checkpoint_artifact,
)
from bugslyce.recon.native_observation_store import (
    NATIVE_OBSERVATION_STORE_PROJECT_PATH,
    STORE_SCHEMA_VERSION,
    NativeObservationStore,
    NativeObservationStoreIndex,
    NativeReceivedExchange,
    validate_native_observation_store,
)


_REPLACEMENT_SUFFIX = ".compaction-replacement"
_BACKUP_SUFFIX = ".compaction-backup"
_TRANSACTION_SUFFIX = ".compaction-transaction.json"
_TRANSACTION_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class NativeObservationCompactionResult:
    changed: bool
    omitted_exchange_count: int
    body_bytes_committed_before: int
    body_bytes_committed_after: int
    response_bytes_captured: int


def _fact_source_ids(evidence: NativeObservationSemanticEvidence) -> set[str]:
    return {
        *(
            f"native-observation:{item.candidate_index}:{item.exchange_index}"
            for item in evidence.structured_responses
        ),
        *(item.source_id for item in evidence.redirect_relationships),
        *(
            f"native-observation:{item.candidate_index}:{item.exchange_index}"
            for item in evidence.mobile_association_declarations
        ),
    }


def _processing_by_source(
    checkpoint: NativeObservationSemanticCheckpoint,
) -> dict[str, NativeSemanticProcessingSource]:
    return {item.source_id: item for item in checkpoint.processed_sources}


def _store_sources(
    store: NativeObservationStore,
    index: NativeObservationStoreIndex,
) -> dict[str, NativeReceivedExchange]:
    result: dict[str, NativeReceivedExchange] = {}
    for candidate_index in index.observation_indices:
        observation = store.load_observation(candidate_index)
        for exchange_index, exchange in enumerate(observation.exchanges):
            source_id = f"native-observation:{candidate_index}:{exchange_index}"
            if source_id in result:
                raise ValueError("Native observation source identity is duplicated.")
            result[source_id] = exchange
    return result


def _metadata_matches(
    exchange: NativeReceivedExchange,
    *,
    request_url: str,
    status_code: int,
    captured_bytes: int,
    body_sha256: str,
) -> bool:
    return (
        exchange.request_url == request_url
        and exchange.status_code == status_code
        and exchange.captured_bytes == captured_bytes
        and exchange.body_sha256 == body_sha256
    )


def _validate_plan_bindings(
    store: NativeObservationStore,
    plan: NativeObservationRetentionPlan,
    checkpoint: NativeObservationSemanticCheckpoint,
) -> tuple[NativeObservationStoreIndex, str]:
    if not isinstance(plan, NativeObservationRetentionPlan) or not isinstance(
        checkpoint, NativeObservationSemanticCheckpoint
    ):
        raise TypeError("Native compaction requires typed plan authority.")
    index = validate_native_observation_store(store.root)
    if index.schema_version != STORE_SCHEMA_VERSION:
        raise ValueError("Native compaction requires a schema-3 observation store.")
    if index.store_state != "complete":
        raise ValueError("Native compaction requires a complete observation store.")
    sources = _store_sources(store, index)
    decisions = {item.source_id: item for item in plan.decisions}
    processed = _processing_by_source(checkpoint)
    fact_sources = _fact_source_ids(checkpoint.evidence)
    eligible_retained = 0
    eligible_omitted = 0
    retained_digests: set[str] = set()

    for source_id, exchange in sources.items():
        decision = decisions.get(source_id)
        if decision is None:
            if exchange.body_retention_state == "intentionally_not_retained":
                raise ValueError("Native compaction contains an unplanned omission.")
            if exchange.body_retention_state == "retained":
                raise ValueError("Native retention plan omits a retained source.")
            continue
        if not _metadata_matches(
            exchange,
            request_url=decision.request_url,
            status_code=decision.status_code,
            captured_bytes=decision.captured_bytes,
            body_sha256=decision.body_sha256,
        ):
            raise ValueError("Native retention plan contradicts its source.")
        if decision.reason_code == "semantic_fact":
            if source_id not in fact_sources or source_id not in processed:
                raise ValueError(
                    "Native retention plan contradicts its semantic checkpoint."
                )
        elif decision.reason_code == "not_semantically_processed":
            if source_id in processed or source_id in fact_sources:
                raise ValueError(
                    "Native retention plan contradicts its semantic checkpoint."
                )
        elif source_id not in processed or source_id in fact_sources:
            raise ValueError(
                "Native retention plan contradicts its semantic checkpoint."
            )
        if decision.action == "retain":
            if (
                exchange.body_retention_state != "retained"
                or exchange.body_retention_reason is not None
                or exchange.body is None
            ):
                raise ValueError("Native retained decision has no retained body.")
            store.read_body(exchange.body)
            retained_digests.add(decision.body_sha256)
            continue

        if source_id in fact_sources:
            raise ValueError("Native semantic fact source cannot be omitted.")
        coverage = processed.get(source_id)
        if coverage is None or not _metadata_matches(
            exchange,
            request_url=coverage.request_url,
            status_code=coverage.status_code,
            captured_bytes=coverage.captured_bytes,
            body_sha256=coverage.body_sha256,
        ) or (
            coverage.capture_state != exchange.capture_state
            or coverage.headers_capture_state != exchange.headers_capture_state
        ):
            raise ValueError(
                "Native omitted source lacks exact semantic processing coverage."
            )
        if exchange.body_retention_state == "retained":
            if exchange.body_retention_reason is not None or exchange.body is None:
                raise ValueError("Native eligible retained source is contradictory.")
            store.read_body(exchange.body)
            eligible_retained += 1
        elif exchange.body_retention_state == "intentionally_not_retained":
            if (
                exchange.body is not None
                or exchange.body_retention_reason
                != "semantic_processing_checkpointed"
            ):
                raise ValueError("Native intentional omission reason is invalid.")
            eligible_omitted += 1
        else:
            raise ValueError("Native eligible source has an invalid retention state.")

    if set(decisions) != {
        source_id
        for source_id, exchange in sources.items()
        if exchange.body_retention_state in {"retained", "intentionally_not_retained"}
    }:
        raise ValueError("Native retention plan source coverage is incomplete.")
    eligible_digests = {
        item.body_sha256
        for item in plan.decisions
        if item.action == "eligible_for_omission"
    }
    if eligible_digests & retained_digests:
        raise ValueError("Native retention plan violates shared-digest safety.")
    if eligible_retained and eligible_omitted:
        raise ValueError("Native retention plan is only partially applied.")

    families = {item.family_id: item for item in plan.families}
    for family in families.values():
        representative = decisions.get(family.representative_source_id)
        exchange = sources.get(family.representative_source_id)
        if (
            representative is None
            or representative.action != "retain"
            or representative.reason_code != "family_representative"
            or representative.body_sha256 != family.representative_body_sha256
            or exchange is None
            or exchange.body is None
        ):
            raise ValueError("Native retention family representative is unavailable.")
        signature = native_retention_grade_signature(store, exchange)
        if signature != (
            family.canonical_origin,
            family.grouping_signature_sha256,
        ):
            raise ValueError("Native retention family representative is contradictory.")

    if build_native_observation_semantic_evidence(store) != checkpoint.evidence:
        raise ValueError("Native semantic checkpoint contradicts retained evidence.")

    state = "compacted" if eligible_omitted else "uncompacted"
    return index, state


def validate_compacted_native_observation_store(
    store: NativeObservationStore,
    plan: NativeObservationRetentionPlan,
    checkpoint: NativeObservationSemanticCheckpoint,
) -> NativeObservationStoreIndex:
    """Validate the durable plan against a fully compacted store graph."""

    index, state = _validate_plan_bindings(store, plan, checkpoint)
    if any(item.action == "eligible_for_omission" for item in plan.decisions):
        if state != "compacted":
            raise ValueError("Native retention plan has not been fully compacted.")
    return index


def validate_native_observation_retention_plan_state(
    store: NativeObservationStore,
    plan: NativeObservationRetentionPlan,
    checkpoint: NativeObservationSemanticCheckpoint,
) -> tuple[NativeObservationStoreIndex, str]:
    """Validate bindings and report ``uncompacted`` or ``compacted`` state."""

    return _validate_plan_bindings(store, plan, checkpoint)


def _validate_uncompacted_authority(
    store: NativeObservationStore,
    plan: NativeObservationRetentionPlan,
    checkpoint: NativeObservationSemanticCheckpoint,
) -> NativeObservationStoreIndex:
    index, state = _validate_plan_bindings(store, plan, checkpoint)
    if state != "uncompacted":
        raise ValueError("Native retention plan is not wholly uncompacted.")
    expected = build_native_observation_retention_plan(
        store,
        semantic_evidence=checkpoint.evidence,
        processed_sources=checkpoint.processed_sources,
    )
    if expected != plan:
        raise ValueError("Native retention plan contradicts pre-compaction evidence.")
    return index


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_remove_tree(path: Path, parent: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_dir() or path.parent.resolve() != parent:
        raise ValueError("Native compaction transaction path is unsafe.")
    shutil.rmtree(path)
    _fsync_directory(parent)


def _write_transaction_marker(path: Path, parent: Path) -> None:
    content = (
        json.dumps(
            {
                "schema_version": _TRANSACTION_SCHEMA_VERSION,
                "store_name": NATIVE_OBSERVATION_STORE_PROJECT_PATH,
            },
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path, follow_symlinks=False)
        _fsync_directory(parent)
    except FileExistsError:
        raise ValueError("Native compaction transaction already exists.") from None
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _remove_marker(path: Path, parent: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_file():
        raise ValueError("Native compaction transaction marker is unsafe.")
    path.unlink()
    _fsync_directory(parent)


def _validate_marker(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Native compaction transaction marker is unsafe.")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("Native compaction transaction marker is invalid.") from None
    if payload != {
        "schema_version": _TRANSACTION_SCHEMA_VERSION,
        "store_name": NATIVE_OBSERVATION_STORE_PROJECT_PATH,
    }:
        raise ValueError("Native compaction transaction marker is invalid.")


def _transaction_paths(project_root: Path) -> tuple[Path, Path, Path, Path]:
    canonical = project_root / NATIVE_OBSERVATION_STORE_PROJECT_PATH
    replacement = project_root / (
        f".{NATIVE_OBSERVATION_STORE_PROJECT_PATH}{_REPLACEMENT_SUFFIX}"
    )
    backup = project_root / (
        f".{NATIVE_OBSERVATION_STORE_PROJECT_PATH}{_BACKUP_SUFFIX}"
    )
    marker = project_root / (
        f".{NATIVE_OBSERVATION_STORE_PROJECT_PATH}{_TRANSACTION_SUFFIX}"
    )
    return canonical, replacement, backup, marker


def _recover_transaction(
    project_root: Path,
    plan: NativeObservationRetentionPlan,
    checkpoint: NativeObservationSemanticCheckpoint,
) -> None:
    canonical, replacement, backup, marker = _transaction_paths(project_root)
    artifacts_exist = any(
        path.exists() or path.is_symlink() for path in (replacement, backup)
    )
    if not marker.exists() and not marker.is_symlink():
        if not artifacts_exist:
            return
        if (
            backup.exists()
            or backup.is_symlink()
            or replacement.is_symlink()
            or not replacement.exists()
            or not replacement.is_dir()
            or not canonical.exists()
            or canonical.is_symlink()
        ):
            raise ValueError("Native compaction staging exists without a transaction.")
        canonical_store = NativeObservationStore.open_published(canonical)
        _index, canonical_state = _validate_plan_bindings(
            canonical_store,
            plan,
            checkpoint,
        )
        if canonical_state == "uncompacted":
            _validate_uncompacted_authority(canonical_store, plan, checkpoint)
        else:
            validate_compacted_native_observation_store(
                canonical_store,
                plan,
                checkpoint,
            )
        _safe_remove_tree(replacement, project_root)
        return
    _validate_marker(marker)

    canonical_exists = canonical.exists() and not canonical.is_symlink()
    backup_exists = backup.exists() and not backup.is_symlink()
    replacement_exists = replacement.exists() and not replacement.is_symlink()
    if any(path.is_symlink() for path in (canonical, backup, replacement)):
        raise ValueError("Native compaction transaction path is unsafe.")

    if canonical_exists and backup_exists:
        if replacement_exists:
            raise ValueError("Native compaction transaction state is contradictory.")
        try:
            validate_compacted_native_observation_store(
                NativeObservationStore.open_published(canonical), plan, checkpoint
            )
        except (OSError, ValueError):
            backup_store = NativeObservationStore.open_published(backup)
            _validate_uncompacted_authority(backup_store, plan, checkpoint)
            _safe_remove_tree(canonical, project_root)
            os.rename(backup, canonical)
            _fsync_directory(project_root)
            _remove_marker(marker, project_root)
            return
        _safe_remove_tree(backup, project_root)
        _remove_marker(marker, project_root)
        return
    if not canonical_exists and backup_exists:
        if replacement_exists:
            try:
                validate_compacted_native_observation_store(
                    NativeObservationStore.open_published(replacement),
                    plan,
                    checkpoint,
                )
            except (OSError, ValueError):
                os.rename(backup, canonical)
                _fsync_directory(project_root)
                _safe_remove_tree(replacement, project_root)
                _remove_marker(marker, project_root)
                return
            os.rename(replacement, canonical)
            _fsync_directory(project_root)
            _safe_remove_tree(backup, project_root)
            _remove_marker(marker, project_root)
            return
        os.rename(backup, canonical)
        _fsync_directory(project_root)
        _remove_marker(marker, project_root)
        return
    if canonical_exists and not backup_exists:
        if replacement_exists:
            _safe_remove_tree(replacement, project_root)
        _remove_marker(marker, project_root)
        return
    raise ValueError("Native compaction transaction cannot be recovered safely.")


def _build_replacement(
    source: NativeObservationStore,
    source_index: NativeObservationStoreIndex,
    plan: NativeObservationRetentionPlan,
    replacement_root: Path,
) -> NativeObservationStore:
    replacement = NativeObservationStore(
        replacement_root,
        source_index.body_byte_allowance,
        metadata_byte_allowance=source_index.metadata_byte_allowance,
    )
    decisions = {item.source_id: item for item in plan.decisions}
    copied_references = {}
    for candidate_index in source_index.observation_indices:
        observation = source.load_observation(candidate_index)
        exchanges: list[NativeReceivedExchange] = []
        for exchange_index, exchange in enumerate(observation.exchanges):
            source_id = f"native-observation:{candidate_index}:{exchange_index}"
            decision = decisions.get(source_id)
            if decision is not None and decision.action == "eligible_for_omission":
                exchanges.append(
                    replace(
                        exchange,
                        body=None,
                        body_retention_state="intentionally_not_retained",
                        body_retention_reason="semantic_processing_checkpointed",
                    )
                )
                continue
            if exchange.body is None:
                exchanges.append(exchange)
                continue
            reference = copied_references.get(exchange.body.sha256)
            if reference is None:
                body = source.read_body(exchange.body)
                reference = replacement.commit_body(
                    replacement.reserve_body_bytes(len(body)), body
                )
                copied_references[exchange.body.sha256] = reference
            exchanges.append(replace(exchange, body=reference))
        rebuilt = replace(observation, exchanges=tuple(exchanges))
        replacement.publish_observation(
            rebuilt,
            replacement.reserve_candidate_metadata(
                candidate_index,
                maximum_redirect_hops=max(0, len(exchanges) - 1),
            ),
        )
    replacement.publish_index(source_index.store_state)
    return NativeObservationStore.open_published(replacement_root)


def _project_root(path: Path) -> Path:
    if not isinstance(path, Path) or path.is_symlink():
        raise ValueError("Native compaction project root is unsafe.")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError:
        raise ValueError("Native compaction project root is unsafe.") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("Native compaction project root is unsafe.")
    return resolved


def compact_native_observation_store(
    project_root: Path,
    *,
    failure_injector: Callable[[str], None] | None = None,
) -> NativeObservationCompactionResult:
    """Compact one canonical store through a recoverable sibling transaction."""

    root = _project_root(project_root)
    plan = load_native_observation_retention_plan_artifact(root)
    checkpoint = load_native_observation_semantic_checkpoint_artifact(root)
    if plan is None or checkpoint is None:
        raise ValueError("Native compaction authority is incomplete.")
    canonical, replacement, backup, marker = _transaction_paths(root)
    _recover_transaction(root, plan, checkpoint)
    source = NativeObservationStore.open_published(canonical)
    source_index, state = _validate_plan_bindings(source, plan, checkpoint)
    eligible_count = sum(
        item.action == "eligible_for_omission" for item in plan.decisions
    )
    if state == "compacted":
        validated = validate_compacted_native_observation_store(
            source, plan, checkpoint
        )
        return NativeObservationCompactionResult(
            changed=False,
            omitted_exchange_count=eligible_count,
            body_bytes_committed_before=validated.body_bytes_committed,
            body_bytes_committed_after=validated.body_bytes_committed,
            response_bytes_captured=validated.response_bytes_captured,
        )
    source_index = _validate_uncompacted_authority(source, plan, checkpoint)
    if eligible_count == 0:
        return NativeObservationCompactionResult(
            changed=False,
            omitted_exchange_count=0,
            body_bytes_committed_before=source_index.body_bytes_committed,
            body_bytes_committed_after=source_index.body_bytes_committed,
            response_bytes_captured=source_index.response_bytes_captured,
        )
    if any(path.exists() or path.is_symlink() for path in (replacement, backup, marker)):
        raise ValueError("Native compaction transaction state is not clean.")

    try:
        rebuilt = _build_replacement(source, source_index, plan, replacement)
        if failure_injector is not None:
            failure_injector("before_replacement_validation")
        replacement_index = validate_compacted_native_observation_store(
            rebuilt, plan, checkpoint
        )
        if (
            replacement_index.body_byte_allowance != source_index.body_byte_allowance
            or replacement_index.metadata_byte_allowance
            != source_index.metadata_byte_allowance
            or replacement_index.observation_indices != source_index.observation_indices
            or replacement_index.observation_count != source_index.observation_count
            or replacement_index.store_state != source_index.store_state
            or replacement_index.response_bytes_captured
            != source_index.response_bytes_captured
        ):
            raise ValueError("Native compacted replacement changes capture truth.")
    except BaseException:
        _safe_remove_tree(replacement, root)
        raise

    published = False
    try:
        _write_transaction_marker(marker, root)
        if failure_injector is not None:
            failure_injector("before_publication")
        os.rename(canonical, backup)
        _fsync_directory(root)
        if failure_injector is not None:
            failure_injector("after_source_backup")
        os.rename(replacement, canonical)
        published = True
        _fsync_directory(root)
        validate_compacted_native_observation_store(
            NativeObservationStore.open_published(canonical), plan, checkpoint
        )
        if failure_injector is not None:
            failure_injector("after_replacement_publish")
        if failure_injector is not None:
            failure_injector("before_backup_cleanup")
        _safe_remove_tree(backup, root)
        _remove_marker(marker, root)
    except BaseException:
        if published:
            try:
                validate_compacted_native_observation_store(
                    NativeObservationStore.open_published(canonical),
                    plan,
                    checkpoint,
                )
            except BaseException:
                if canonical.exists() and not canonical.is_symlink():
                    _safe_remove_tree(canonical, root)
                if backup.exists() and not backup.is_symlink():
                    os.rename(backup, canonical)
                    _fsync_directory(root)
                _safe_remove_tree(replacement, root)
                _remove_marker(marker, root)
            raise
        if not canonical.exists() and backup.exists() and not backup.is_symlink():
            os.rename(backup, canonical)
            _fsync_directory(root)
        _safe_remove_tree(replacement, root)
        _remove_marker(marker, root)
        raise

    after = validate_compacted_native_observation_store(
        NativeObservationStore.open_published(canonical), plan, checkpoint
    )
    return NativeObservationCompactionResult(
        changed=True,
        omitted_exchange_count=eligible_count,
        body_bytes_committed_before=source_index.body_bytes_committed,
        body_bytes_committed_after=after.body_bytes_committed,
        response_bytes_captured=after.response_bytes_captured,
    )
