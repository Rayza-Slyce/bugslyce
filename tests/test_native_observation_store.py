"""Offline contracts for the native candidate observation evidence store."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from bugslyce.core.models import DiscoveredPath
import bugslyce.recon.native_observation_store as observation_store_module
from bugslyce.recon.native_observation_store import (
    BodyReservation,
    NativeBodyReference,
    NativeAttemptFailure,
    NativeCandidateObservation,
    NativeObservationStore,
    NativeReceivedExchange,
    validate_native_observation_store,
)
from bugslyce.core.programme_scope import MAX_PATH_LENGTH, MAX_URL_LENGTH


_TEST_METADATA_ALLOWANCE = 10_000_000


def _store(
    root: Path,
    body_byte_allowance: int,
    *,
    metadata_byte_allowance: int = _TEST_METADATA_ALLOWANCE,
    failure_injector=None,
) -> NativeObservationStore:
    return NativeObservationStore(
        root,
        body_byte_allowance,
        metadata_byte_allowance=metadata_byte_allowance,
        failure_injector=failure_injector,
    )


def _publish(
    store: NativeObservationStore,
    observation: NativeCandidateObservation,
    *,
    maximum_redirect_hops: int = 10,
) -> Path:
    return store.publish_observation(
        observation,
        store.reserve_candidate_metadata(
            observation.candidate_index,
            maximum_redirect_hops=maximum_redirect_hops,
        ),
    )


def _exchange(
    store: NativeObservationStore,
    url: str,
    body: bytes,
    *,
    state: str = "complete",
    reason: str | None = None,
    status_code: int = 200,
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/plain"),),
) -> NativeReceivedExchange:
    reservation = store.reserve_body_bytes(max(len(body), 1))
    body_reference = store.commit_body(reservation, body)
    return NativeReceivedExchange(
        request_url=url,
        status_code=status_code,
        headers=headers,
        capture_state=state,
        captured_bytes=len(body),
        body_sha256=hashlib.sha256(body).hexdigest(),
        body=body_reference,
        incomplete_reason=reason,
    )


def _observation(
    index: int,
    exchange: NativeReceivedExchange,
) -> NativeCandidateObservation:
    return NativeCandidateObservation(
        candidate_index=index,
        request_url=exchange.request_url,
        exchanges=(exchange,),
    )


def test_exact_body_round_trip_and_sha256_identity(tmp_path: Path) -> None:
    store = _store(tmp_path / "native-observations", 1024)
    body = b"\x00\xffraw\r\nbody"
    exchange = _exchange(store, "https://app.example.test/a", body)
    _publish(store, _observation(0, exchange))

    loaded = store.load_observation(0)

    assert loaded == _observation(0, exchange)
    assert loaded.exchanges[0].body_sha256 == hashlib.sha256(body).hexdigest()
    assert store.read_body(loaded.exchanges[0].body) == body


def test_identical_bodies_deduplicate_but_observations_remain_distinct(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations", 100)
    body = b"same"
    first = _exchange(store, "https://app.example.test/a", body)
    second = _exchange(store, "https://app.example.test/b", body)
    _publish(store, _observation(0, first))
    _publish(store, _observation(1, second))

    assert first.body == second.body
    assert len(list((store.root / "bodies" / "sha256").iterdir())) == 1
    assert len(list((store.root / "observations").iterdir())) == 2
    assert store.body_bytes_committed == len(body)
    assert store.response_bytes_captured == len(body) * 2
    assert store.metadata_observation_bytes == sum(
        len((store.root / f"observations/{index:08d}.json").read_bytes())
        for index in (0, 1)
    )


def test_same_length_different_bodies_are_distinct(tmp_path: Path) -> None:
    store = _store(tmp_path / "native-observations", 100)
    first = _exchange(store, "https://app.example.test/a", b"AAAA")
    second = _exchange(store, "https://app.example.test/b", b"BBBB")

    assert first.body != second.body
    assert store.body_bytes_committed == 8


def test_complete_zero_byte_body_is_evidence(tmp_path: Path) -> None:
    store = _store(tmp_path / "native-observations", 1)
    exchange = _exchange(store, "https://app.example.test/empty", b"")
    _publish(store, _observation(0, exchange))

    assert exchange.body_sha256 == hashlib.sha256(b"").hexdigest()
    assert store.read_body(exchange.body) == b""
    assert store.body_bytes_committed == 0


def test_response_less_failure_fabricates_no_body(tmp_path: Path) -> None:
    store = _store(tmp_path / "native-observations", 10)
    failure = NativeAttemptFailure(
        request_url="https://app.example.test/timeout",
        category="timeout",
    )
    observation = NativeCandidateObservation(
        candidate_index=0,
        request_url=failure.request_url,
        exchanges=(),
        failure=failure,
    )

    _publish(store, observation)

    assert store.load_observation(0) == observation
    assert list((store.root / "bodies" / "sha256").iterdir()) == []
    assert store.response_bytes_captured == 0


def test_received_response_followed_by_failure_is_distinct_and_round_trips(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations", 100)
    source_url = "https://app.example.test/redirect"
    destination_url = "https://cdn.example.test/final"
    exchange = _exchange(
        store,
        source_url,
        b"redirect",
        headers=(("Location", destination_url),),
    )
    observation = NativeCandidateObservation(
        candidate_index=0,
        request_url=source_url,
        exchanges=(exchange,),
        failure=NativeAttemptFailure(destination_url, "connect_error"),
    )

    _publish(store, observation)

    assert store.load_observation(0) == observation
    assert store.response_bytes_captured == len(b"redirect")


def test_refused_redirect_round_trips_with_raw_location_and_resolved_destination(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations", 100)
    source_url = "https://app.example.test/start"
    raw_location = "//other.test/landing"
    refusal = observation_store_module.NativeRedirectRefusal(
        source_url=source_url,
        destination_url="https://other.test/landing",
        reason="origin_not_approved",
    )
    exchange = _exchange(
        store,
        source_url,
        b"redirect",
        headers=(("Location", raw_location),),
        status_code=302,
    )
    observation = NativeCandidateObservation(
        candidate_index=0,
        request_url=source_url,
        exchanges=(exchange,),
        refused_redirect=refusal,
    )

    _publish(store, observation)
    store.publish_index("complete")
    reopened = _store(store.root, 100)

    assert reopened.load_observation(0) == observation
    assert reopened.load_observation(0).exchanges[0].headers == (
        ("Location", raw_location),
    )
    assert reopened.load_observation(0).refused_redirect == refusal
    payload = json.loads(
        (store.root / "observations" / "00000000.json").read_text(encoding="utf-8")
    )
    assert payload["observation"]["refused_redirect"] == {
        "destination_url": "https://other.test/landing",
        "reason": "origin_not_approved",
        "source_url": source_url,
    }


def test_refused_redirect_preserves_ordered_exchanges_without_transport_failure(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations", 100)
    first_url = "https://app.example.test/first"
    source_url = "https://app.example.test/second"
    first = _exchange(
        store,
        first_url,
        b"first",
        headers=(("Location", "/second"),),
        status_code=302,
    )
    refused = _exchange(
        store,
        source_url,
        b"second",
        headers=(("Location", "//other.test/landing"),),
        status_code=302,
    )
    observation = NativeCandidateObservation(
        candidate_index=0,
        request_url=first_url,
        exchanges=(first, refused),
        refused_redirect=observation_store_module.NativeRedirectRefusal(
            source_url=source_url,
            destination_url="https://other.test/landing",
            reason="origin_not_approved",
        ),
    )

    _publish(store, observation, maximum_redirect_hops=1)

    loaded = store.load_observation(0)
    assert [item.request_url for item in loaded.exchanges] == [first_url, source_url]
    assert loaded.failure is None
    assert loaded.refused_redirect is not None


def test_non_redirect_http_status_cannot_claim_redirect_refusal(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations", 100)
    source_url = "https://app.example.test/redirect"
    exchange = _exchange(
        store,
        source_url,
        b"not a redirect",
        headers=(("Location", "//other.test/landing"),),
        status_code=304,
    )

    with pytest.raises(ValueError, match="redirect refusal"):
        NativeCandidateObservation(
            candidate_index=0,
            request_url=source_url,
            exchanges=(exchange,),
            refused_redirect=observation_store_module.NativeRedirectRefusal(
                source_url=source_url,
                destination_url="https://other.test/landing",
                reason="origin_not_approved",
            ),
        )


def test_location_header_alone_does_not_classify_an_observation_as_refused(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations", 100)
    exchange = _exchange(
        store,
        "https://app.example.test/redirect",
        b"ordinary redirect",
        headers=(("Location", "https://app.example.test/final"),),
        status_code=302,
    )
    observation = _observation(0, exchange)

    _publish(store, observation)

    assert store.load_observation(0).refused_redirect is None


def test_existing_no_refusal_payload_reloads_as_non_refused(tmp_path: Path) -> None:
    store = _store(tmp_path / "native-observations", 100)
    exchange = _exchange(store, "https://app.example.test/ordinary", b"ordinary")
    observation = _observation(0, exchange)
    _publish(store, observation)
    payload_path = store.root / "observations" / "00000000.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    del payload["observation"]["refused_redirect"]
    payload_path.write_text(json.dumps(payload), encoding="utf-8")

    reopened = _store(store.root, 100)

    assert reopened.load_observation(0) == observation
    assert reopened.load_observation(0).refused_redirect is None


def test_redirect_refusal_is_distinct_from_attempt_failure(tmp_path: Path) -> None:
    store = _store(tmp_path / "native-observations", 100)
    source_url = "https://app.example.test/redirect"
    exchange = _exchange(store, source_url, b"redirect", status_code=302)
    refusal = observation_store_module.NativeRedirectRefusal(
        source_url=source_url,
        destination_url="https://other.test/landing",
        reason="origin_not_approved",
    )

    with pytest.raises(ValueError, match="refusal"):
        NativeCandidateObservation(
            candidate_index=0,
            request_url=source_url,
            exchanges=(exchange,),
            failure=NativeAttemptFailure("https://other.test/landing", "timeout"),
            refused_redirect=refusal,
        )


@pytest.mark.parametrize(
    "metadata",
    (
        {"source_url": "https://app.example.test/redirect", "destination_url": "https://other.test/landing", "reason": "unknown_reason"},
        {"source_url": "https://app.example.test/redirect", "destination_url": None, "reason": "origin_not_approved"},
        {"source_url": "https://app.example.test/redirect", "destination_url": "https://other.test/landing/../unsafe", "reason": "origin_not_approved"},
        {"source_url": "https://app.example.test/redirect", "destination_url": "https://other.test/landing", "reason": "malformed_location"},
        {"source_url": "https://app.example.test/redirect", "reason": "origin_not_approved"},
    ),
)
def test_malformed_persisted_redirect_refusal_is_rejected(
    tmp_path: Path,
    metadata: dict[str, object],
) -> None:
    store = _store(tmp_path / "native-observations", 100)
    exchange = _exchange(
        store,
        "https://app.example.test/redirect",
        b"redirect",
        status_code=302,
    )
    observation = _observation(0, exchange)
    _publish(store, observation)
    payload_path = store.root / "observations" / "00000000.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    payload["observation"]["refused_redirect"] = metadata
    payload_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="refusal|payload|canonical"):
        _store(store.root, 100)


def test_observation_and_index_json_are_deterministic(tmp_path: Path) -> None:
    store = _store(tmp_path / "native-observations", 100)
    second = _exchange(store, "https://app.example.test/b", b"b")
    first = _exchange(store, "https://app.example.test/a", b"a")
    _publish(store, _observation(1, second))
    _publish(store, _observation(0, first))

    index = store.publish_index("complete")
    payload = json.loads(index.read_text(encoding="utf-8"))

    assert payload["observations"] == [
        {"candidate_index": 0, "file": "observations/00000000.json"},
        {"candidate_index": 1, "file": "observations/00000001.json"},
    ]
    assert index.read_text(encoding="utf-8").endswith("\n")
    assert list(json.loads((store.root / "observations/00000000.json").read_text()).keys()) == sorted(
        json.loads((store.root / "observations/00000000.json").read_text()).keys()
    )


def test_duplicate_candidate_index_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path / "native-observations", 100)
    first = _exchange(store, "https://app.example.test/a", b"a")
    _publish(store, _observation(0, first))
    second = _exchange(store, "https://app.example.test/b", b"b")

    with pytest.raises(ValueError, match="already exists"):
        _publish(store, _observation(0, second))


@pytest.mark.parametrize(
    "state,reason",
    (("complete", "body_read_error"), ("incomplete", None), ("unknown", None)),
)
def test_capture_state_invariants_are_fail_closed(
    tmp_path: Path,
    state: str,
    reason: str | None,
) -> None:
    store = _store(tmp_path / "native-observations", 10)
    reference = store.commit_body(store.reserve_body_bytes(1), b"x")

    with pytest.raises(ValueError, match="capture"):
        NativeReceivedExchange(
            request_url="https://app.example.test/a",
            status_code=200,
            headers=(),
            capture_state=state,
            captured_bytes=1,
            body_sha256=hashlib.sha256(b"x").hexdigest(),
            body=reference,
            incomplete_reason=reason,
        )


def test_exchange_rejects_body_reference_length_or_hash_mismatch(tmp_path: Path) -> None:
    store = _store(tmp_path / "native-observations", 10)
    reference = store.commit_body(store.reserve_body_bytes(4), b"body")

    with pytest.raises(ValueError, match="capture"):
        NativeReceivedExchange(
            request_url="https://app.example.test/a",
            status_code=200,
            headers=(),
            capture_state="complete",
            captured_bytes=3,
            body_sha256=reference.sha256,
            body=reference,
        )
    with pytest.raises(ValueError, match="capture"):
        NativeReceivedExchange(
            request_url="https://app.example.test/a",
            status_code=200,
            headers=(),
            capture_state="complete",
            captured_bytes=4,
            body_sha256=hashlib.sha256(b"else").hexdigest(),
            body=reference,
        )


@pytest.mark.parametrize(
    "state,reason",
    (("complete", None), ("truncated", None), ("incomplete", "body_read_error")),
)
def test_capture_states_survive_round_trip_without_conflation(
    tmp_path: Path,
    state: str,
    reason: str | None,
) -> None:
    store = _store(tmp_path / "native-observations", 10)
    exchange = _exchange(
        store,
        "https://app.example.test/a",
        b"body",
        state=state,
        reason=reason,
    )
    _publish(store, _observation(0, exchange))

    loaded = store.load_observation(0).exchanges[0]
    assert loaded.capture_state == state
    assert loaded.incomplete_reason == reason


def test_candidate_outcome_combinations_are_fail_closed() -> None:
    with pytest.raises(ValueError, match="outcome"):
        NativeCandidateObservation(0, "https://app.example.test/a", ())
    with pytest.raises(ValueError, match="response-less"):
        NativeCandidateObservation(
            0,
            "https://app.example.test/a",
            (),
            NativeAttemptFailure("https://app.example.test/other", "timeout"),
        )


def test_reservations_enforce_collective_budget_and_body_bound(tmp_path: Path) -> None:
    store = _store(tmp_path / "native-observations", 10)
    first = store.reserve_body_bytes(6)
    second = store.reserve_body_bytes(4)
    assert store.outstanding_reserved_bytes == 10
    with pytest.raises(ValueError, match="budget"):
        store.reserve_body_bytes(1)
    with pytest.raises(ValueError, match="reservation"):
        store.commit_body(second, b"12345")
    store.release_reservation(second)
    reference = store.commit_body(first, b"abc")

    assert reference.captured_bytes == 3
    assert store.body_bytes_committed == 3
    assert store.outstanding_reserved_bytes == 0


def test_duplicate_body_releases_reservation_without_double_charge(tmp_path: Path) -> None:
    store = _store(tmp_path / "native-observations", 10)
    first = store.commit_body(store.reserve_body_bytes(10), b"same")
    second = store.commit_body(store.reserve_body_bytes(6), b"same")

    assert first == second
    assert store.body_bytes_committed == 4
    assert store.outstanding_reserved_bytes == 0


def test_consumed_released_unknown_and_foreign_reservations_are_rejected(
    tmp_path: Path,
) -> None:
    first = _store(tmp_path / "first", 20)
    second = _store(tmp_path / "second", 20)
    consumed = first.reserve_body_bytes(5)
    first.commit_body(consumed, b"x")
    released = first.reserve_body_bytes(5)
    first.release_reservation(released)

    for reservation in (consumed, released):
        with pytest.raises(ValueError, match="reservation"):
            first.release_reservation(reservation)
    with pytest.raises(ValueError, match="reservation"):
        first.commit_body(consumed, b"x")
    with pytest.raises(ValueError, match="reservation"):
        first.release_reservation(BodyReservation(object(), 999, 1))
    with pytest.raises(ValueError, match="reservation"):
        second.commit_body(first.reserve_body_bytes(1), b"x")


def test_verified_existing_object_is_reused_and_corruption_is_fatal(tmp_path: Path) -> None:
    root = tmp_path / "native-observations"
    store = _store(root, 100)
    body = b"existing"
    reference = store.commit_body(store.reserve_body_bytes(10), body)

    reopened = _store(root, 100)
    assert reopened.commit_body(reopened.reserve_body_bytes(10), body) == reference
    reference_path = root / reference.relative_path
    reference_path.write_bytes(b"corrupt!")

    with pytest.raises(ValueError, match="corrupt"):
        _store(root, 100)


@pytest.mark.parametrize("kind", ("symlink", "directory", "fifo"))
def test_non_regular_body_object_is_refused(tmp_path: Path, kind: str) -> None:
    root = tmp_path / "native-observations"
    bodies = root / "bodies" / "sha256"
    observations = root / "observations"
    bodies.mkdir(parents=True)
    observations.mkdir()
    digest = hashlib.sha256(b"x").hexdigest()
    path = bodies / digest
    if kind == "symlink":
        path.symlink_to(tmp_path / "outside")
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()

    with pytest.raises(ValueError, match="body object"):
        _store(root, 10)


def test_caller_url_cannot_escape_store(tmp_path: Path) -> None:
    store = _store(tmp_path / "native-observations", 10)
    exchange = _exchange(store, "https://app.example.test/a", b"x")

    with pytest.raises(ValueError, match="canonical"):
        NativeCandidateObservation(0, "https://app.example.test/../../escape", (exchange,))
    assert not (tmp_path / "escape").exists()


def test_failed_body_publication_creates_no_observation(tmp_path: Path) -> None:
    def fail(phase: str) -> None:
        if phase == "before_body_publish":
            raise OSError("synthetic body publication failure")

    store = _store(tmp_path / "native-observations", 10, failure_injector=fail)
    with pytest.raises(OSError, match="body publication"):
        store.commit_body(store.reserve_body_bytes(5), b"body")

    assert list((store.root / "observations").iterdir()) == []


def test_failed_observation_publication_leaves_accounted_orphan_and_no_index(
    tmp_path: Path,
) -> None:
    phases: set[str] = {"before_observation_publish"}

    def fail(phase: str) -> None:
        if phase in phases:
            raise OSError("synthetic observation publication failure")

    root = tmp_path / "native-observations"
    store = _store(root, 10, failure_injector=fail)
    exchange = _exchange(store, "https://app.example.test/a", b"body")
    reservation = store.reserve_candidate_metadata(0, maximum_redirect_hops=10)
    with pytest.raises(OSError, match="observation publication"):
        store.publish_observation(_observation(0, exchange), reservation)
    assert store.body_bytes_committed == 4
    assert store.observation_count == 0
    assert not (root / "index.json").exists()
    store.release_candidate_metadata(reservation)
    with pytest.raises(ValueError, match="partial"):
        store.publish_index("complete")

    reopened = _store(root, 10)
    assert reopened.body_bytes_committed == 4
    assert reopened.observation_count == 0
    reopened.publish_index("partial")
    validated = validate_native_observation_store(root)
    assert validated.body_bytes_committed == 4
    assert validated.response_bytes_captured == 0
    assert validated.observation_count == 0


def test_failed_index_publication_does_not_claim_success(tmp_path: Path) -> None:
    def fail(phase: str) -> None:
        if phase == "before_index_publish":
            raise OSError("synthetic index publication failure")

    store = _store(tmp_path / "native-observations", 10, failure_injector=fail)
    exchange = _exchange(store, "https://app.example.test/a", b"x")
    _publish(store, _observation(0, exchange))

    with pytest.raises(OSError, match="index publication"):
        store.publish_index("complete")
    assert store.observation_count == 1
    assert not (store.root / "index.json").exists()


@pytest.mark.parametrize("damage", ("missing", "malformed"))
def test_index_prepublication_validates_durable_observation_graph(
    tmp_path: Path,
    damage: str,
) -> None:
    root = tmp_path / "native-observations"
    store = _store(root, 10)
    exchange = _exchange(store, "https://app.example.test/a", b"body")
    _publish(store, _observation(0, exchange))
    observation_path = root / "observations/00000000.json"
    if damage == "missing":
        observation_path.unlink()
    else:
        observation_path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="observation"):
        store.publish_index("complete")

    assert not (root / "index.json").exists()


@pytest.mark.parametrize("store_state", ("complete", "partial"))
def test_index_refuses_active_reservation_without_consuming_it(
    tmp_path: Path,
    store_state: str,
) -> None:
    root = tmp_path / "native-observations"
    store = _store(root, 10)
    reservation = store.reserve_body_bytes(4)

    with pytest.raises(ValueError, match="reservation"):
        store.publish_index(store_state)

    assert not (root / "index.json").exists()
    assert store.outstanding_reserved_bytes == 4
    store.release_reservation(reservation)
    assert store.outstanding_reserved_bytes == 0


def test_incomplete_response_without_body_round_trips_without_fabricating_body(
    tmp_path: Path,
) -> None:
    root = tmp_path / "native-observations"
    store = _store(root, 10)
    exchange = NativeReceivedExchange(
        request_url="https://app.example.test/incomplete",
        status_code=200,
        headers=(("Content-Type", "text/plain"),),
        capture_state="incomplete",
        captured_bytes=0,
        body_sha256=None,
        body=None,
        incomplete_reason="body_read_error",
    )
    observation = _observation(0, exchange)

    _publish(store, observation)

    assert store.load_observation(0) == observation
    assert list((root / "bodies/sha256").iterdir()) == []
    assert store.response_bytes_captured == 0
    reopened = _store(root, 10)
    assert reopened.load_observation(0) == observation
    reopened.publish_index("complete")
    validated = validate_native_observation_store(root)
    assert validated.observation_count == 1
    assert validated.body_bytes_committed == 0
    assert validated.response_bytes_captured == 0


def test_incomplete_response_without_body_is_distinct_from_complete_empty_body(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations", 10)
    incomplete = NativeReceivedExchange(
        request_url="https://app.example.test/incomplete",
        status_code=200,
        headers=(),
        capture_state="incomplete",
        captured_bytes=0,
        body_sha256=None,
        body=None,
        incomplete_reason="body_read_error",
    )
    complete = _exchange(store, "https://app.example.test/complete", b"")

    assert incomplete != complete
    assert incomplete.body is None
    assert complete.body is not None
    assert complete.body_sha256 == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("capture_state", ("complete", "truncated"))
def test_body_evidence_is_required_for_complete_and_truncated_capture(
    capture_state: str,
) -> None:
    with pytest.raises(ValueError, match="capture"):
        NativeReceivedExchange(
            request_url="https://app.example.test/a",
            status_code=200,
            headers=(),
            capture_state=capture_state,
            captured_bytes=0,
            body_sha256=None,
            body=None,
        )


@pytest.mark.parametrize(
    "captured_bytes,body_sha256",
    ((1, None), (0, hashlib.sha256(b"").hexdigest())),
)
def test_incomplete_no_body_rejects_contradictory_capture_metadata(
    captured_bytes: int,
    body_sha256: str | None,
) -> None:
    with pytest.raises(ValueError, match="capture"):
        NativeReceivedExchange(
            request_url="https://app.example.test/a",
            status_code=200,
            headers=(),
            capture_state="incomplete",
            captured_bytes=captured_bytes,
            body_sha256=body_sha256,
            body=None,
            incomplete_reason="body_read_error",
        )


@pytest.mark.parametrize("damage", ("missing", "corrupt"))
def test_index_validation_rejects_missing_and_corrupt_referenced_body(
    tmp_path: Path,
    damage: str,
) -> None:
    root = tmp_path / "native-observations"
    store = _store(root, 100)
    exchange = _exchange(store, "https://app.example.test/a", b"body")
    _publish(store, _observation(0, exchange)
    )
    store.publish_index("partial")
    body_path = root / exchange.body.relative_path
    if damage == "missing":
        body_path.unlink()
    else:
        body_path.write_bytes(b"changed")

    with pytest.raises(ValueError, match="body"):
        validate_native_observation_store(root)


def test_intact_graph_validates_and_is_not_discovered_path(tmp_path: Path) -> None:
    root = tmp_path / "native-observations"
    store = _store(root, 100)
    exchange = _exchange(store, "https://app.example.test/a", b"body")
    observation = _observation(0, exchange)
    _publish(store, observation)
    store.publish_index("complete")

    validated = validate_native_observation_store(root)

    assert validated.store_state == "complete"
    assert validated.observation_count == 1
    assert validated.body_bytes_committed == 4
    assert validated.response_bytes_captured == 4
    assert not isinstance(observation, DiscoveredPath)


def test_invalid_body_reference_path_is_rejected() -> None:
    from bugslyce.recon.native_observation_store import NativeBodyReference

    with pytest.raises(ValueError, match="body reference"):
        NativeBodyReference(hashlib.sha256(b"x").hexdigest(), 1, "../escape")


def test_header_metadata_limits_and_provenance_are_explicit(tmp_path: Path) -> None:
    store = NativeObservationStore(
        tmp_path / "native-observations",
        10,
        metadata_byte_allowance=10_000_000,
    )
    body = _exchange(store, "https://app.example.test/a", b"x").body
    assert body is not None
    accepted_headers = tuple(("x", "") for _ in range(100))
    complete = NativeReceivedExchange(
        request_url="https://app.example.test/a",
        status_code=200,
        headers=accepted_headers,
        capture_state="complete",
        captured_bytes=1,
        body_sha256=body.sha256,
        body=body,
        headers_capture_state="complete",
    )
    exact_utf8 = NativeReceivedExchange(
        request_url="https://app.example.test/exact",
        status_code=200,
        headers=(("x", "\u20ac" * 21_845),),
        capture_state="complete",
        captured_bytes=1,
        body_sha256=body.sha256,
        body=body,
    )
    incomplete = NativeReceivedExchange(
        request_url="https://app.example.test/b",
        status_code=200,
        headers=(("x", "\u20ac"),),
        capture_state="incomplete",
        captured_bytes=1,
        body_sha256=body.sha256,
        body=body,
        incomplete_reason="body_read_error",
        headers_capture_state="incomplete",
        headers_incomplete_reason="response_header_limit",
    )

    assert complete.headers_capture_state == "complete"
    assert incomplete.headers_capture_state == "incomplete"
    assert len(exact_utf8.headers[0][0].encode("utf-8")) + len(
        exact_utf8.headers[0][1].encode("utf-8")
    ) == 65_536
    assert len("\u20ac".encode("utf-8")) == 3
    with pytest.raises(ValueError, match="header"):
        NativeReceivedExchange(
            request_url="https://app.example.test/a",
            status_code=200,
            headers=tuple(("x", "") for _ in range(101)),
            capture_state="complete",
            captured_bytes=1,
            body_sha256=body.sha256,
            body=body,
        )
    with pytest.raises(ValueError, match="header"):
        NativeReceivedExchange(
            request_url="https://app.example.test/a",
            status_code=200,
            headers=(("x", "\u20ac" * 21_846),),
            capture_state="complete",
            captured_bytes=1,
            body_sha256=body.sha256,
            body=body,
        )
    _publish(store, _observation(0, incomplete), maximum_redirect_hops=0)
    loaded = store.load_observation(0).exchanges[0]
    assert loaded.headers_capture_state == "incomplete"
    assert loaded.headers_incomplete_reason == "response_header_limit"
    header_incomplete_complete_body = NativeReceivedExchange(
        request_url="https://app.example.test/c",
        status_code=200,
        headers=(),
        capture_state="complete",
        captured_bytes=1,
        body_sha256=body.sha256,
        body=body,
        headers_capture_state="incomplete",
        headers_incomplete_reason="response_header_limit",
    )
    assert header_incomplete_complete_body.capture_state == "complete"
    header_incomplete_truncated_body = NativeReceivedExchange(
        request_url="https://app.example.test/d",
        status_code=200,
        headers=(),
        capture_state="truncated",
        captured_bytes=1,
        body_sha256=body.sha256,
        body=body,
        headers_capture_state="incomplete",
        headers_incomplete_reason="response_header_limit",
    )
    assert header_incomplete_truncated_body.capture_state == "truncated"
    with pytest.raises(ValueError, match="header"):
        NativeReceivedExchange(
            request_url="https://app.example.test/a",
            status_code=200,
            headers=(("x", "\ud800"),),
            capture_state="complete",
            captured_bytes=1,
            body_sha256=body.sha256,
            body=body,
        )
    with pytest.raises(ValueError, match="header"):
        NativeReceivedExchange(
            request_url="https://app.example.test/a",
            status_code=200,
            headers=(),
            capture_state="complete",
            captured_bytes=1,
            body_sha256=body.sha256,
            body=body,
            headers_capture_state="complete",
            headers_incomplete_reason="response_header_limit",
        )
    with pytest.raises(ValueError, match="header"):
        NativeReceivedExchange(
            request_url="https://app.example.test/a",
            status_code=200,
            headers=(),
            capture_state="complete",
            captured_bytes=1,
            body_sha256=body.sha256,
            body=body,
            headers_capture_state="incomplete",
        )


def test_native_metadata_candidate_and_exchange_limits_are_bounded(
    tmp_path: Path,
) -> None:
    store = NativeObservationStore(
        tmp_path / "native-observations",
        10,
        metadata_byte_allowance=10_000_000,
    )
    body = _exchange(store, "https://app.example.test/a", b"x").body
    assert body is not None
    exchange = NativeReceivedExchange(
        request_url="https://app.example.test/a",
        status_code=200,
        headers=(),
        capture_state="complete",
        captured_bytes=1,
        body_sha256=body.sha256,
        body=body,
    )
    legal = NativeCandidateObservation(35_059, exchange.request_url, (exchange,) * 11)
    assert legal.candidate_index == 35_059
    with pytest.raises(ValueError, match="index"):
        NativeCandidateObservation(35_060, exchange.request_url, (exchange,))
    with pytest.raises(ValueError, match="outcome"):
        NativeCandidateObservation(0, exchange.request_url, (exchange,) * 12)


def test_pending_metadata_reservations_cannot_bypass_candidate_slot_bound(
    tmp_path: Path,
) -> None:
    store = _store(
        tmp_path / "native-observations",
        0,
        metadata_byte_allowance=observation_store_module.UINT64_MAXIMUM,
    )
    reservations = [
        store.reserve_candidate_metadata(index, maximum_redirect_hops=0)
        for index in range(
            observation_store_module.MAXIMUM_NATIVE_OBSERVATION_CANDIDATES
        )
    ]

    assert len(reservations) == 35_060
    with pytest.raises(ValueError, match="already exists"):
        store.reserve_candidate_metadata(0, maximum_redirect_hops=0)
    with pytest.raises(ValueError, match="index"):
        store.reserve_candidate_metadata(35_060, maximum_redirect_hops=0)


def test_native_metadata_url_boundary_is_aligned_with_canonical_scope_limit() -> None:
    path = "/" + "a" * (MAX_PATH_LENGTH - 1)
    prefix = f"https://a.test{path}?"
    url = prefix + "a" * (MAX_URL_LENGTH - len(prefix))

    assert len(url.encode("ascii")) == MAX_URL_LENGTH
    assert NativeAttemptFailure(url, "timeout").request_url == url
    with pytest.raises(ValueError, match="canonical"):
        NativeAttemptFailure(url + "a", "timeout")


def test_metadata_reservations_preserve_index_headroom_and_charge_actual_json(
    tmp_path: Path,
) -> None:
    root = tmp_path / "native-observations"
    probe = NativeObservationStore(
        root,
        10,
        metadata_byte_allowance=10_000_000,
    )
    index_headroom = probe.reserved_final_index_capacity
    reservation = probe.reserve_candidate_metadata(0, maximum_redirect_hops=0)
    exchange = _exchange(probe, "https://app.example.test/a", b"x")
    observation = _observation(0, exchange)

    probe.publish_observation(observation, reservation)

    observation_bytes = len((root / "observations/00000000.json").read_bytes())
    assert probe.metadata_observation_bytes == observation_bytes
    assert probe.metadata_bytes_committed == observation_bytes
    assert probe.reserved_final_index_capacity == index_headroom
    probe.publish_index("complete")
    assert probe.metadata_bytes_committed == (
        observation_bytes + len((root / "index.json").read_bytes())
    )
    reopened = _store(root, 10)
    assert reopened.metadata_observation_bytes == observation_bytes
    assert reopened.metadata_bytes_committed == probe.metadata_bytes_committed


def test_metadata_reservation_releases_and_rejects_foreign_or_reused_tokens(
    tmp_path: Path,
) -> None:
    first = _store(tmp_path / "first", 10)
    second = _store(tmp_path / "second", 10)
    reservation = first.reserve_candidate_metadata(0, maximum_redirect_hops=0)

    with pytest.raises(ValueError, match="metadata reservation"):
        second.release_candidate_metadata(reservation)
    first.release_candidate_metadata(reservation)
    with pytest.raises(ValueError, match="metadata reservation"):
        first.release_candidate_metadata(reservation)


def test_candidate_metadata_reservations_cannot_collectively_consume_index_headroom(
    tmp_path: Path,
) -> None:
    probe = _store(tmp_path / "probe", 0)
    allowance = (
        probe.reserved_final_index_capacity
        + 2 * probe.maximum_observation_serialized_bytes(0)
    )
    store = _store(
        tmp_path / "native-observations",
        0,
        metadata_byte_allowance=allowance,
    )
    first = store.reserve_candidate_metadata(0, maximum_redirect_hops=0)
    second = store.reserve_candidate_metadata(1, maximum_redirect_hops=0)

    with pytest.raises(ValueError, match="metadata allowance"):
        store.reserve_candidate_metadata(2, maximum_redirect_hops=0)
    store.release_candidate_metadata(first)
    store.release_candidate_metadata(second)


def test_candidate_reservation_exact_headroom_still_permits_index(
    tmp_path: Path,
) -> None:
    probe = _store(tmp_path / "probe", 10)
    allowance = (
        probe.reserved_final_index_capacity
        + probe.maximum_observation_serialized_bytes(0)
    )
    store = _store(
        tmp_path / "native-observations",
        10,
        metadata_byte_allowance=allowance,
    )
    exchange = _exchange(store, "https://app.example.test/a", b"x")
    _publish(store, _observation(0, exchange), maximum_redirect_hops=0)

    store.publish_index("complete")
    assert store.metadata_bytes_committed <= allowance


def test_metadata_reservation_rejects_actual_observation_larger_than_reserved(
    tmp_path: Path,
) -> None:
    store = NativeObservationStore(
        tmp_path / "native-observations",
        10,
        metadata_byte_allowance=10_000_000,
    )
    reservation = store.reserve_candidate_metadata(0, maximum_redirect_hops=0)
    exchange = _exchange(store, "https://app.example.test/a", b"x")
    observation = _observation(0, exchange)
    object.__setattr__(reservation, "maximum_bytes", 0)

    with pytest.raises(ValueError, match="exceeds"):
        store.publish_observation(observation, reservation)


def test_metadata_reservation_enforces_its_redirect_depth(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations", 10)
    exchange = _exchange(store, "https://app.example.test/a", b"x")
    reservation = store.reserve_candidate_metadata(0, maximum_redirect_hops=0)
    observation = NativeCandidateObservation(
        0,
        exchange.request_url,
        (exchange, exchange),
    )

    with pytest.raises(ValueError, match="redirect reservation"):
        store.publish_observation(observation, reservation)


def test_metadata_serialization_bounds_are_deterministic_and_escape_safe(
    tmp_path: Path,
) -> None:
    store = NativeObservationStore(
        tmp_path / "native-observations",
        10,
        metadata_byte_allowance=10_000_000,
    )

    assert store.maximum_observation_serialized_bytes(0) == store.maximum_observation_serialized_bytes(0)
    assert store.maximum_observation_serialized_bytes(10) >= store.maximum_observation_serialized_bytes(0)
    with pytest.raises(ValueError, match="redirect"):
        store.maximum_observation_serialized_bytes(11)
    with pytest.raises(ValueError, match="allowance"):
        NativeObservationStore(
            tmp_path / "too-small",
            10,
            metadata_byte_allowance=store.reserved_final_index_capacity - 1,
        )


def test_metadata_serialization_bounds_cover_adversarial_legal_observations(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "native-observations", 10)
    source_url = observation_store_module._maximum_canonical_url("a")
    failure_url = observation_store_module._maximum_canonical_url("b")
    digest = "f" * 64
    body = NativeBodyReference(
        digest,
        observation_store_module.UINT64_MAXIMUM,
        f"bodies/sha256/{digest}",
    )
    exchange = NativeReceivedExchange(
        request_url=source_url,
        status_code=308,
        headers=observation_store_module._maximum_headers(),
        capture_state="incomplete",
        captured_bytes=observation_store_module.UINT64_MAXIMUM,
        body_sha256=digest,
        body=body,
        incomplete_reason="a" * 64,
        headers_capture_state="incomplete",
        headers_incomplete_reason="a" * 64,
    )
    for category in sorted(observation_store_module.ATTEMPT_FAILURE_CATEGORIES):
        one = NativeCandidateObservation(
            35_059,
            source_url,
            (exchange,),
            NativeAttemptFailure(failure_url, category),
        )
        eleven = NativeCandidateObservation(
            35_059,
            source_url,
            (exchange,) * 11,
            NativeAttemptFailure(failure_url, category),
        )

        assert len(
            observation_store_module._json_bytes(
                observation_store_module._observation_payload(one)
            )
        ) <= store.maximum_observation_serialized_bytes(0)
        assert len(
            observation_store_module._json_bytes(
                observation_store_module._observation_payload(eleven)
            )
        ) <= store.maximum_observation_serialized_bytes(10)
    assert (
        store.maximum_observation_serialized_bytes(10)
        >= store.maximum_observation_serialized_bytes(0)
    )
    maximum_outcomes = [
        NativeCandidateObservation(
            35_059,
            source_url,
            (exchange,) * 11,
            NativeAttemptFailure(failure_url, category),
        )
        for category in observation_store_module.ATTEMPT_FAILURE_CATEGORIES
    ]
    maximum_outcomes.extend(
        NativeCandidateObservation(
            35_059,
            source_url,
            (exchange,) * 11,
            refused_redirect=observation_store_module.NativeRedirectRefusal(
                source_url=source_url,
                destination_url=failure_url,
                reason=reason,
            ),
        )
        for reason in observation_store_module._REDIRECT_REFUSAL_REASONS_WITH_DESTINATION
    )
    assert store.maximum_observation_serialized_bytes(10) == max(
        len(
            observation_store_module._json_bytes(
                observation_store_module._observation_payload(observation)
            )
        )
        for observation in maximum_outcomes
    )


def test_owned_staging_and_oversized_metadata_json_are_refused_before_parse(
    tmp_path: Path,
) -> None:
    root = tmp_path / "native-observations"
    store = NativeObservationStore(
        root,
        10,
        metadata_byte_allowance=10_000_000,
    )
    staging = root / "observations/.00000000.json.synthetic.tmp"
    staging.write_bytes(b"staged")
    assert not staging.name.endswith(".json")
    with pytest.raises(ValueError, match="staging"):
        NativeObservationStore(root, 10, metadata_byte_allowance=10_000_000)

    staging.unlink()
    exchange = _exchange(store, "https://app.example.test/a", b"x")
    reservation = store.reserve_candidate_metadata(0, maximum_redirect_hops=0)
    store.publish_observation(_observation(0, exchange), reservation)
    observation_path = root / "observations/00000000.json"
    observation_path.write_bytes(b"{" + b"x" * 10_000_001)
    with pytest.raises(ValueError, match="too large"):
        NativeObservationStore(root, 10, metadata_byte_allowance=10_000_000)


def test_owned_staging_file_is_not_observation_evidence_after_index_publication(
    tmp_path: Path,
) -> None:
    root = tmp_path / "native-observations"
    store = _store(root, 10)
    exchange = _exchange(store, "https://app.example.test/a", b"x")
    _publish(store, _observation(0, exchange), maximum_redirect_hops=0)
    store.publish_index("complete")
    (root / "observations/.00000001.json.synthetic.tmp").write_bytes(b"staged")

    validated = validate_native_observation_store(root)

    assert validated.observation_count == 1


def test_oversized_index_and_corrupt_metadata_accounting_fail_closed(
    tmp_path: Path,
) -> None:
    root = tmp_path / "native-observations"
    store = _store(root, 10)
    exchange = _exchange(store, "https://app.example.test/a", b"x")
    _publish(store, _observation(0, exchange), maximum_redirect_hops=0)
    store.publish_index("complete")
    index_path = root / "index.json"
    payload = json.loads(index_path.read_text(encoding="utf-8"))
    payload["metadata_observation_bytes"] += 1
    index_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="accounting"):
        validate_native_observation_store(root)

    index_path.write_bytes(b"{" + b"x" * 10_000_000)
    with pytest.raises(ValueError, match="too large"):
        validate_native_observation_store(root)


@pytest.mark.parametrize(
    "relative_staging_path",
    (
        "observations/.00000000.json.abc_def.tmp",
        ".index.json.abc_def.tmp",
        f"bodies/sha256/.{'f' * 64}.abc_def.tmp",
    ),
)
def test_owned_staging_names_with_tempfile_underscore_are_refused(
    tmp_path: Path,
    relative_staging_path: str,
) -> None:
    root = tmp_path / "native-observations"
    _store(root, 10)
    staging = root / relative_staging_path
    staging.write_bytes(b"staged")

    with pytest.raises(ValueError, match="staging"):
        _store(root, 10)


def test_unrelated_dotfile_is_not_treated_as_owned_staging(tmp_path: Path) -> None:
    root = tmp_path / "native-observations"
    _store(root, 10)
    (root / "observations/.not-an-observation.abc_def.tmp").write_bytes(b"private")

    reopened = _store(root, 10)

    assert reopened.root == root


def test_oversized_durable_body_is_rejected_before_content_is_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "native-observations"
    _store(root, 1)
    body = b"xx"
    digest = hashlib.sha256(body).hexdigest()
    (root / "bodies" / "sha256" / digest).write_bytes(body)

    def unexpected_read(*_args, **_kwargs):
        raise AssertionError("oversized body must be rejected before os.read")

    monkeypatch.setattr(observation_store_module.os, "read", unexpected_read)
    with pytest.raises(ValueError, match="budget"):
        _store(root, 1)


def test_cumulative_oversized_durable_bodies_are_rejected_before_content_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "native-observations"
    _store(root, 2)
    for body in (b"a", b"bb"):
        digest = hashlib.sha256(body).hexdigest()
        (root / "bodies" / "sha256" / digest).write_bytes(body)

    def unexpected_read(*_args, **_kwargs):
        raise AssertionError("over-budget body scan must not materialize body bytes")

    monkeypatch.setattr(observation_store_module.os, "read", unexpected_read)
    with pytest.raises(ValueError, match="budget"):
        _store(root, 2)


def test_body_reads_and_existing_object_verification_are_bounded_by_expected_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "native-observations"
    store = _store(root, 2)
    expected = b"x"
    digest = hashlib.sha256(expected).hexdigest()
    path = root / "bodies" / "sha256" / digest
    path.write_bytes(b"xx")
    reference = NativeBodyReference(
        digest,
        len(expected),
        f"bodies/sha256/{digest}",
    )

    def unexpected_read(*_args, **_kwargs):
        raise AssertionError("oversized existing object must be rejected before os.read")

    monkeypatch.setattr(observation_store_module.os, "read", unexpected_read)
    with pytest.raises(ValueError, match="too large"):
        store.read_body(reference)
    reservation = store.reserve_body_bytes(len(expected))
    with pytest.raises(ValueError, match="too large"):
        store.commit_body(reservation, expected)


def test_observation_body_validation_is_bounded_by_reference_capture_length(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "native-observations"
    store = _store(root, 2)
    expected = b"x"
    digest = hashlib.sha256(expected).hexdigest()
    (root / "bodies" / "sha256" / digest).write_bytes(b"xx")
    reference = NativeBodyReference(
        digest,
        len(expected),
        f"bodies/sha256/{digest}",
    )
    exchange = NativeReceivedExchange(
        request_url="https://app.example.test/a",
        status_code=200,
        headers=(),
        capture_state="complete",
        captured_bytes=len(expected),
        body_sha256=digest,
        body=reference,
    )
    observation = _observation(0, exchange)

    def unexpected_read(*_args, **_kwargs):
        raise AssertionError("referenced body must be size-checked before os.read")

    monkeypatch.setattr(observation_store_module.os, "read", unexpected_read)
    with pytest.raises(ValueError, match="too large"):
        observation_store_module._validate_observation_bodies(
            root,
            observation,
            {digest: len(expected)},
        )
