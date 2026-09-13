"""Package 4B1 native body-retention planning contracts."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import runpy
import zipfile

import pytest

from bugslyce.recon.native_observation_facts import (
    NativeObservationSemanticEvidence,
    NativeStructuredResponseFact,
    build_native_observation_semantic_processing_sources,
)
from bugslyce.recon.evidence_pack_closure import (
    discover_evidence_pack_references,
    validate_evidence_pack_root,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.recon.native_observation_retention import (
    RETENTION_GROUPING_RULE,
    NativeObservationRetentionPlan,
    build_native_observation_retention_plan,
)
from bugslyce.recon.native_observation_retention_persistence import (
    NATIVE_OBSERVATION_RETENTION_PLAN_FILENAME,
    load_native_observation_retention_plan_artifact,
    native_observation_retention_plan_to_dict,
    write_native_observation_retention_plan_artifact,
)
from bugslyce.recon.native_observation_semantic_evidence_persistence import (
    write_native_observation_semantic_evidence_artifact,
)
from bugslyce.recon.native_observation_store import (
    NativeCandidateObservation,
    NativeObservationStore,
    NativeReceivedExchange,
    validate_native_observation_store,
)


_ROOT = Path(__file__).resolve().parents[1]
_EXPORT_HELPERS = runpy.run_path(str(_ROOT / "tests/test_recon_export.py"))


def _records() -> tuple[dict[str, object], ...]:
    return (
        {
            "candidate_index": 0,
            "url": "https://app.example.test/missing?a=1",
            "body": b"<html>missing /missing</html>",
        },
        {
            "candidate_index": 1,
            "url": "https://app.example.test/missing?a=2",
            "body": b"<html>missing /missing</html>",
        },
        {
            "candidate_index": 2,
            "url": "https://app.example.test/one",
            "body": b"<html>missing /one</html>",
        },
        {
            "candidate_index": 3,
            "url": "https://app.example.test/two",
            "body": b"<html>missing /two</html>",
        },
        {
            "candidate_index": 4,
            "url": "https://app.example.test/static",
            "body": b"<html>ordinary not-found page</html>",
        },
    )


def _store(
    root: Path,
    records: tuple[dict[str, object], ...],
) -> NativeObservationStore:
    root.mkdir(parents=True, exist_ok=True)
    store = NativeObservationStore(
        root / "native-observations",
        10_000_000,
        metadata_byte_allowance=10_000_000,
    )
    for record in records:
        body = record["body"]
        reservation = store.reserve_body_bytes(len(body))
        reference = store.commit_body(reservation, body)
        headers = record.get("headers", (("Content-Type", "text/html; charset=utf-8"),))
        exchange = NativeReceivedExchange(
            request_url=record["url"],
            status_code=record.get("status", 404),
            headers=headers,
            capture_state="complete",
            captured_bytes=len(body),
            body_sha256=reference.sha256,
            body=reference,
        )
        candidate_index = record["candidate_index"]
        store.publish_observation(
            NativeCandidateObservation(
                candidate_index=candidate_index,
                request_url=record["url"],
                exchanges=(exchange,),
            ),
            store.reserve_candidate_metadata(
                candidate_index,
                maximum_redirect_hops=0,
            ),
        )
    store.publish_index("complete")
    return store


def _plan(
    store: NativeObservationStore,
    *,
    semantic_evidence: NativeObservationSemanticEvidence | None = None,
    excluded_from_processing: tuple[str, ...] = (),
):
    processed = tuple(
        item
        for item in build_native_observation_semantic_processing_sources(store)
        if item.source_id not in excluded_from_processing
    )
    return build_native_observation_retention_plan(
        store,
        semantic_evidence=semantic_evidence or NativeObservationSemanticEvidence(),
        processed_sources=processed,
    )


def _by_source(plan):
    return {item.source_id: item for item in plan.decisions}


def test_request_reflecting_corpus_records_family_representative_and_cas_safety(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, _records())
    durable_before = {
        path.relative_to(store.root): path.read_bytes()
        for path in store.root.rglob("*")
        if path.is_file()
    }

    plan = _plan(store)
    decisions = _by_source(plan)

    assert len(plan.decisions) == 5
    assert len(plan.families) == 1
    family = plan.families[0]
    assert family.grouping_rule == "full_body_request_reflection_v1"
    assert family.representative_source_id == "native-observation:0:0"
    assert family.member_source_ids == (
        "native-observation:0:0",
        "native-observation:1:0",
        "native-observation:2:0",
        "native-observation:3:0",
    )
    assert decisions["native-observation:0:0"].reason_code == "family_representative"
    assert decisions["native-observation:1:0"].reason_code == "shared_required_digest"
    assert decisions["native-observation:1:0"].action == "retain"
    assert decisions["native-observation:2:0"].action == "eligible_for_omission"
    assert decisions["native-observation:3:0"].action == "eligible_for_omission"
    assert decisions["native-observation:4:0"].reason_code == "unique_or_unclassified"
    assert validate_native_observation_store(store.root).body_bytes_committed == sum(
        path.stat().st_size for path in (store.root / "bodies/sha256").iterdir()
    )
    assert len(tuple((store.root / "bodies/sha256").iterdir())) == 4
    assert {
        path.relative_to(store.root): path.read_bytes()
        for path in store.root.rglob("*")
        if path.is_file()
    } == durable_before
    assert all(
        store.load_observation(index).exchanges[0].body_retention_state
        == "retained"
        for index in range(5)
    )


def test_digest_shared_with_required_source_retains_every_reference(
    tmp_path: Path,
) -> None:
    records = _records()[:4]
    store = _store(tmp_path, records)

    plan = _plan(
        store,
        excluded_from_processing=("native-observation:1:0",),
    )

    same_digest = {
        item.action for item in plan.decisions if item.candidate_index in {0, 1}
    }
    assert same_digest == {"retain"}
    assert _by_source(plan)["native-observation:1:0"].reason_code == (
        "not_semantically_processed"
    )


def test_semantic_fact_and_unprocessed_sources_are_never_omission_eligible(
    tmp_path: Path,
) -> None:
    records = (
        {
            "candidate_index": 0,
            "url": "https://app.example.test/fact",
            "body": b'{"path":"/fact"}',
        },
        {
            "candidate_index": 1,
            "url": "https://app.example.test/other",
            "body": b'{"path":"/other"}',
        },
    )
    store = _store(tmp_path, records)
    first = store.load_observation(0).exchanges[0]
    evidence = NativeObservationSemanticEvidence(
        structured_responses=(
            NativeStructuredResponseFact(
                request_url=first.request_url,
                status_code=first.status_code,
                candidate_index=0,
                exchange_index=0,
                body_sha256=first.body_sha256,
            ),
        )
    )

    plan = _plan(
        store,
        semantic_evidence=evidence,
        excluded_from_processing=("native-observation:1:0",),
    )

    decisions = _by_source(plan)
    assert decisions["native-observation:0:0"].reason_code == "semantic_fact"
    assert decisions["native-observation:1:0"].reason_code == (
        "not_semantically_processed"
    )
    assert {item.action for item in plan.decisions} == {"retain"}


@pytest.mark.parametrize("status", (200, 401, 403))
def test_non_404_status_is_excluded(tmp_path: Path, status: int) -> None:
    records = tuple(
        {
            "candidate_index": index,
            "url": f"https://app.example.test/{name}",
            "body": f"<p>/{name}</p>".encode(),
            "status": status,
        }
        for index, name in enumerate(("one", "two"))
    )
    plan = _plan(_store(tmp_path, records))
    assert plan.families == ()
    assert {item.action for item in plan.decisions} == {"retain"}


@pytest.mark.parametrize(
    "headers",
    (
        (("Content-Type", "application/json"),),
        (("Content-Type", "text/html"), ("Location", "/login")),
        (("Content-Type", "text/html"), ("Set-Cookie", "sid=value")),
    ),
)
def test_non_html_or_stateful_headers_prevent_grouping(
    tmp_path: Path,
    headers: tuple[tuple[str, str], ...],
) -> None:
    records = tuple(
        {
            "candidate_index": index,
            "url": f"https://app.example.test/{name}",
            "body": f"<p>/{name}</p>".encode(),
            "headers": headers,
        }
        for index, name in enumerate(("one", "two"))
    )
    assert _plan(_store(tmp_path, records)).families == ()


def test_different_origins_do_not_group(tmp_path: Path) -> None:
    records = tuple(
        {
            "candidate_index": index,
            "url": f"https://{host}/{name}",
            "body": f"<p>/{name}</p>".encode(),
        }
        for index, (host, name) in enumerate(
            (("one.example.test", "a"), ("two.example.test", "b"))
        )
    )
    assert _plan(_store(tmp_path, records)).families == ()


@pytest.mark.parametrize(
    "bodies",
    (
        (b"<p>ordinary</p>", b"<p>ordinary</p>"),
        (b"<p>/one random-A</p>", b"<p>/two random-B</p>"),
        (b"<p>/one alpha</p>", b"<p>/two beta</p>"),
    ),
)
def test_full_body_rule_rejects_no_reflection_or_other_differences(
    tmp_path: Path,
    bodies: tuple[bytes, bytes],
) -> None:
    records = tuple(
        {
            "candidate_index": index,
            "url": f"https://app.example.test/{name}",
            "body": bodies[index],
        }
        for index, name in enumerate(("one", "two"))
    )
    assert _plan(_store(tmp_path, records)).families == ()


def test_plan_is_stable_when_observations_are_published_in_another_order(
    tmp_path: Path,
) -> None:
    records = _records()
    forward = _plan(_store(tmp_path / "forward", records))
    reverse = _plan(_store(tmp_path / "reverse", tuple(reversed(records))))
    assert reverse == forward


def test_processing_metadata_mismatch_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path, _records())
    processed = build_native_observation_semantic_processing_sources(store)
    damaged = (replace(processed[0], captured_bytes=processed[0].captured_bytes + 1), *processed[1:])
    with pytest.raises(ValueError, match="processing coverage"):
        build_native_observation_retention_plan(
            store,
            semantic_evidence=NativeObservationSemanticEvidence(),
            processed_sources=damaged,
        )


def test_retention_plan_persistence_is_exact_and_deterministic(
    tmp_path: Path,
) -> None:
    plan = _plan(_store(tmp_path / "source", _records()))
    path = write_native_observation_retention_plan_artifact(tmp_path, plan)
    before = path.read_bytes()
    loaded = load_native_observation_retention_plan_artifact(tmp_path)
    write_native_observation_retention_plan_artifact(tmp_path, plan)
    assert loaded == plan
    assert path.read_bytes() == before
    assert json.loads(before) == native_observation_retention_plan_to_dict(plan)


@pytest.mark.parametrize(
    "damage",
    ("unknown_schema", "unknown_rule", "unexpected", "missing", "duplicate"),
)
def test_retention_plan_persistence_rejects_malformed_payload(
    tmp_path: Path,
    damage: str,
) -> None:
    plan = _plan(_store(tmp_path / "source", _records()))
    path = write_native_observation_retention_plan_artifact(tmp_path, plan)
    if damage == "duplicate":
        content = path.read_text(encoding="utf-8")
        path.write_text(
            content.replace(
                '"schema_version": 1',
                '"schema_version": 1, "schema_version": 1',
            ),
            encoding="utf-8",
        )
    else:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if damage == "unknown_schema":
            payload["schema_version"] = 99
        elif damage == "unknown_rule":
            payload["grouping_rule"] = "full_body_request_reflection_v999"
        elif damage == "unexpected":
            payload["unexpected"] = True
        else:
            del payload["decisions"]
        path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        load_native_observation_retention_plan_artifact(tmp_path)


def test_retention_plan_persistence_rejects_nonregular_and_symlink(
    tmp_path: Path,
) -> None:
    path = tmp_path / NATIVE_OBSERVATION_RETENTION_PLAN_FILENAME
    path.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        load_native_observation_retention_plan_artifact(tmp_path)
    path.rmdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    path.symlink_to(outside)
    with pytest.raises(ValueError, match="regular file"):
        load_native_observation_retention_plan_artifact(tmp_path)


def test_empty_plan_is_canonical() -> None:
    assert NativeObservationRetentionPlan() == NativeObservationRetentionPlan(
        decisions=(), families=()
    )


def test_empty_plan_persists_grouping_rule_provenance() -> None:
    plan = NativeObservationRetentionPlan()
    payload = native_observation_retention_plan_to_dict(plan)

    assert plan.grouping_rule == RETENTION_GROUPING_RULE
    assert payload["grouping_rule"] == RETENTION_GROUPING_RULE

    with pytest.raises(ValueError, match="grouping rule"):
        NativeObservationRetentionPlan(
            grouping_rule="full_body_request_reflection_v999"
        )


def _closure_project(tmp_path: Path):
    root = _EXPORT_HELPERS["_export_input"](tmp_path)
    store = _store(root, _records())
    evidence = NativeObservationSemanticEvidence()
    processed = build_native_observation_semantic_processing_sources(store)
    write_native_observation_semantic_evidence_artifact(
        root,
        evidence,
        processed_sources=processed,
    )
    plan = build_native_observation_retention_plan(
        store,
        semantic_evidence=evidence,
        processed_sources=processed,
    )
    write_native_observation_retention_plan_artifact(root, plan)
    return root, store, plan


def test_closure_and_export_preserve_plan_and_every_current_cas_body(
    tmp_path: Path,
) -> None:
    root, store, plan = _closure_project(tmp_path)
    body_digests = {path.name for path in (store.root / "bodies/sha256").iterdir()}

    references = discover_evidence_pack_references(root)
    output = tmp_path / "retention-plan.zip"
    export_recon_evidence_pack(root, output)
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        archive.extractall(extracted)

    assert any(
        item.portable_path == NATIVE_OBSERVATION_RETENTION_PLAN_FILENAME
        and item.owner_kind == "native_observation_retention_plan"
        for item in references
    )
    assert {
        name.rsplit("/", 1)[-1]
        for name in names
        if name.startswith("native-observations/bodies/sha256/")
    } == body_digests
    assert load_native_observation_retention_plan_artifact(extracted) == plan
    assert validate_evidence_pack_root(extracted).validation_status == "complete"


@pytest.mark.parametrize("damage", ("source_metadata", "representative", "decision"))
def test_closure_rejects_logically_valid_tampered_retention_plan(
    tmp_path: Path,
    damage: str,
) -> None:
    root, _store_value, plan = _closure_project(tmp_path)
    decisions = list(plan.decisions)
    families = list(plan.families)
    if damage == "source_metadata":
        decisions[0] = replace(
            decisions[0],
            request_url="https://app.example.test/tampered",
        )
    elif damage == "decision":
        index = next(
            index
            for index, decision in enumerate(decisions)
            if decision.action == "eligible_for_omission"
        )
        decisions[index] = replace(
            decisions[index],
            action="retain",
            reason_code="shared_required_digest",
        )
    else:
        family = families[0]
        replacement_source = "native-observation:2:0"
        replacement_digest = next(
            decision.body_sha256
            for decision in decisions
            if decision.source_id == replacement_source
        )
        old_representative = family.representative_source_id
        families[0] = replace(
            family,
            representative_source_id=replacement_source,
            representative_body_sha256=replacement_digest,
        )
        for index, decision in enumerate(decisions):
            if decision.source_id == old_representative:
                decisions[index] = replace(
                    decision,
                    reason_code="shared_required_digest",
                )
            elif decision.source_id == replacement_source:
                decisions[index] = replace(
                    decision,
                    action="retain",
                    reason_code="family_representative",
                )
    damaged = NativeObservationRetentionPlan(
        decisions=tuple(decisions),
        families=tuple(families),
    )
    write_native_observation_retention_plan_artifact(root, damaged)

    with pytest.raises(ValueError, match="retention plan contradicts"):
        discover_evidence_pack_references(root)


def test_historical_package4a_project_without_retention_plan_still_exports(
    tmp_path: Path,
) -> None:
    root = _EXPORT_HELPERS["_export_input"](tmp_path)
    store = _store(root, _records())
    write_native_observation_semantic_evidence_artifact(
        root,
        NativeObservationSemanticEvidence(),
        processed_sources=build_native_observation_semantic_processing_sources(store),
    )

    output = tmp_path / "historical-package4a.zip"
    export_recon_evidence_pack(root, output)
    extracted = tmp_path / "historical-extracted"
    with zipfile.ZipFile(output) as archive:
        assert NATIVE_OBSERVATION_RETENTION_PLAN_FILENAME not in archive.namelist()
        archive.extractall(extracted)

    assert validate_evidence_pack_root(extracted).validation_status == "complete"
