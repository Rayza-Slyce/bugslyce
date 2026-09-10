"""Offline, bounded evidence storage for native HTTP candidate observations."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Callable

from bugslyce.core.programme_scope import (
    MAX_PATH_LENGTH,
    MAX_QUERY_LENGTH,
    MAX_URL_LENGTH,
    canonicalise_http_url_destination,
)
from bugslyce.recon.native_content_discovery import (
    MAXIMUM_NATIVE_TOTAL_CANDIDATE_REQUESTS,
)


STORE_SCHEMA_VERSION = 1
STORE_CREATED_BY = "bugslyce.native_observation_store"
CAPTURE_STATES = frozenset({"complete", "truncated", "incomplete"})
ATTEMPT_FAILURE_CATEGORIES = frozenset(
    {
        "connect_error",
        "dns_error",
        "no_usable_ipv4",
        "timeout",
        "tls_error",
        "transport_error",
    }
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REASON = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_OBSERVATION_NAME = re.compile(r"^(?P<index>[0-9]{8})\.json$")
_OWNED_STAGING_NAME = re.compile(
    r"^\.(?:[0-9a-f]{64}|[0-9]{8}\.json|index\.json)\.[A-Za-z0-9_]+\.tmp$"
)
MAXIMUM_NATIVE_OBSERVATION_CANDIDATES = MAXIMUM_NATIVE_TOTAL_CANDIDATE_REQUESTS
MAXIMUM_NATIVE_OBSERVATION_INDEX = MAXIMUM_NATIVE_OBSERVATION_CANDIDATES - 1
MAXIMUM_NATIVE_OBSERVATION_EXCHANGES = 11
MAXIMUM_RETAINED_HEADER_PAIRS = 100
MAXIMUM_RETAINED_HEADER_BYTES = 65_536
MAXIMUM_REDIRECT_HOPS_FOR_OBSERVATIONS = 10
UINT64_MAXIMUM = (1 << 64) - 1


@dataclass(frozen=True)
class NativeBodyReference:
    """One exact captured body object in the content-addressed store."""

    sha256: str
    captured_bytes: int
    relative_path: str

    def __post_init__(self) -> None:
        expected = f"bodies/sha256/{self.sha256}"
        if (
            not isinstance(self.sha256, str)
            or _DIGEST.fullmatch(self.sha256) is None
            or not _unsigned_64_bit_int(self.captured_bytes)
            or not isinstance(self.relative_path, str)
            or self.relative_path != expected
        ):
            raise ValueError("Native body reference is invalid.")


@dataclass(frozen=True)
class NativeReceivedExchange:
    """One received response exchange with caller-supplied capture provenance."""

    request_url: str
    status_code: int
    headers: tuple[tuple[str, str], ...]
    capture_state: str
    captured_bytes: int
    body_sha256: str | None
    body: NativeBodyReference | None
    incomplete_reason: str | None = None
    headers_capture_state: str = "complete"
    headers_incomplete_reason: str | None = None

    def __post_init__(self) -> None:
        _require_canonical_url(self.request_url)
        if not isinstance(self.headers, tuple) or not _valid_headers(self.headers):
            raise ValueError("Native received exchange headers are invalid.")
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
            or not isinstance(self.capture_state, str)
            or self.capture_state not in CAPTURE_STATES
            or not _unsigned_64_bit_int(self.captured_bytes)
        ):
            raise ValueError("Native received exchange capture is invalid.")
        if self.body is None:
            if (
                self.capture_state != "incomplete"
                or self.captured_bytes != 0
                or self.body_sha256 is not None
            ):
                raise ValueError("Native received exchange capture is invalid.")
        elif (
            not isinstance(self.body, NativeBodyReference)
            or not isinstance(self.body_sha256, str)
            or self.body_sha256 != self.body.sha256
            or self.captured_bytes != self.body.captured_bytes
        ):
            raise ValueError("Native received exchange capture is invalid.")
        if self.capture_state == "incomplete":
            if (
                not isinstance(self.incomplete_reason, str)
                or _SAFE_REASON.fullmatch(self.incomplete_reason) is None
            ):
                raise ValueError("Native received exchange capture reason is invalid.")
        elif self.incomplete_reason is not None:
            raise ValueError("Native received exchange capture reason is contradictory.")
        if self.headers_capture_state == "complete":
            if self.headers_incomplete_reason is not None:
                raise ValueError("Native received exchange header capture is contradictory.")
        elif self.headers_capture_state == "incomplete":
            if (
                not isinstance(self.headers_incomplete_reason, str)
                or _SAFE_REASON.fullmatch(self.headers_incomplete_reason) is None
            ):
                raise ValueError("Native received exchange header capture reason is invalid.")
        else:
            raise ValueError("Native received exchange header capture is invalid.")


@dataclass(frozen=True)
class NativeAttemptFailure:
    """One safe response-less or redirect-follow-up failure disposition."""

    request_url: str
    category: str

    def __post_init__(self) -> None:
        _require_canonical_url(self.request_url)
        if (
            not isinstance(self.category, str)
            or self.category not in ATTEMPT_FAILURE_CATEGORIES
        ):
            raise ValueError("Native attempt failure category is invalid.")


@dataclass(frozen=True)
class NativeCandidateObservation:
    """One logical candidate attempt, independent of interpretation."""

    candidate_index: int
    request_url: str
    exchanges: tuple[NativeReceivedExchange, ...]
    failure: NativeAttemptFailure | None = None

    def __post_init__(self) -> None:
        if (
            not _unsigned_64_bit_int(self.candidate_index)
            or self.candidate_index > MAXIMUM_NATIVE_OBSERVATION_INDEX
        ):
            raise ValueError("Native candidate index is invalid.")
        _require_canonical_url(self.request_url)
        if (
            not isinstance(self.exchanges, tuple)
            or any(not isinstance(item, NativeReceivedExchange) for item in self.exchanges)
            or len(self.exchanges) > MAXIMUM_NATIVE_OBSERVATION_EXCHANGES
            or (self.failure is not None and not isinstance(self.failure, NativeAttemptFailure))
        ):
            raise ValueError("Native candidate outcome is invalid.")
        if not self.exchanges:
            if self.failure is None:
                raise ValueError("Native candidate outcome is absent.")
            if self.failure.request_url != self.request_url:
                raise ValueError("Native response-less failure URL is invalid.")
        elif self.exchanges[0].request_url != self.request_url:
            raise ValueError("Native candidate first exchange URL is invalid.")
        elif (
            self.failure is not None
            and self.failure.request_url == self.exchanges[-1].request_url
        ):
            raise ValueError("Native candidate follow-up failure URL is invalid.")


@dataclass(frozen=True)
class NativeObservationStoreIndex:
    """Validated final or controlled-partial store accounting."""

    store_state: str
    body_byte_allowance: int
    metadata_byte_allowance: int
    body_bytes_committed: int
    response_bytes_captured: int
    metadata_observation_bytes: int
    metadata_index_bytes: int
    metadata_bytes_committed: int
    observation_count: int
    observation_indices: tuple[int, ...]


@dataclass(frozen=True)
class BodyReservation:
    """One in-memory maximum-capture reservation."""

    _owner: object
    token: int
    maximum_bytes: int


@dataclass(frozen=True)
class CandidateMetadataReservation:
    """One in-memory exact upper bound for one candidate observation record."""

    _owner: object
    token: int
    maximum_bytes: int
    candidate_index: int
    maximum_redirect_hops: int


class NativeObservationStore:
    """Single-writer, create-only native observation store."""

    def __init__(
        self,
        root: Path,
        body_byte_allowance: int,
        *,
        metadata_byte_allowance: int,
        failure_injector: Callable[[str], None] | None = None,
    ) -> None:
        if (
            not isinstance(root, Path)
            or not _unsigned_64_bit_int(body_byte_allowance)
            or not _unsigned_64_bit_int(metadata_byte_allowance)
        ):
            raise ValueError("Native observation store configuration is invalid.")
        self.root = _prepare_store_root(root)
        self._bodies_dir = _prepare_fixed_directory(self.root, "bodies")
        self._sha256_dir = _prepare_fixed_directory(self._bodies_dir, "sha256")
        self._observations_dir = _prepare_fixed_directory(self.root, "observations")
        self.body_byte_allowance = body_byte_allowance
        self.metadata_byte_allowance = metadata_byte_allowance
        self._failure_injector = failure_injector
        self._reservation_owner = object()
        self._next_reservation = 0
        self._reservations: dict[int, BodyReservation] = {}
        self._metadata_reservation_owner = object()
        self._next_metadata_reservation = 0
        self._metadata_reservations: dict[int, CandidateMetadataReservation] = {}
        self._metadata_reserved_bytes = 0
        self._reserved_candidate_indices: set[int] = set()
        self._body_sizes = _scan_body_objects(
            self._sha256_dir,
            self.body_byte_allowance,
        )
        self._observations, self._observation_sizes = _scan_observations(
            self.root,
            self._observations_dir,
            self._body_sizes,
        )
        if self.body_bytes_committed > self.body_byte_allowance:
            raise ValueError("Native observation store body budget is exceeded.")
        index_path = self.root / "index.json"
        if index_path.is_symlink():
            raise ValueError("Native observation store index is unsafe.")
        self._sealed = index_path.exists()
        self._requires_partial_index = False
        self._index_bytes = 0
        self._reserved_final_index_capacity = (
            0 if self._sealed else maximum_native_observation_index_bytes()
        )
        if not self._sealed:
            _reject_owned_staging_files(
                self.root,
                self._observations_dir,
                self._sha256_dir,
            )
        if self._sealed:
            validated = validate_native_observation_store(self.root)
            if (
                validated.body_byte_allowance != self.body_byte_allowance
                or validated.metadata_byte_allowance != self.metadata_byte_allowance
            ):
                raise ValueError("Native observation store allowance has changed.")
            self._index_bytes = validated.metadata_index_bytes
        if (
            self.metadata_bytes_committed + self._reserved_final_index_capacity
            > self.metadata_byte_allowance
        ):
            raise ValueError("Native observation store metadata allowance is insufficient.")

    @property
    def body_bytes_committed(self) -> int:
        return sum(self._body_sizes.values())

    @property
    def outstanding_reserved_bytes(self) -> int:
        return sum(item.maximum_bytes for item in self._reservations.values())

    @property
    def outstanding_candidate_metadata_reserved_bytes(self) -> int:
        return self._metadata_reserved_bytes

    @property
    def reserved_final_index_capacity(self) -> int:
        return self._reserved_final_index_capacity

    @property
    def observation_count(self) -> int:
        return len(self._observations)

    @property
    def response_bytes_captured(self) -> int:
        return _response_bytes_captured(self._observations)

    @property
    def metadata_observation_bytes(self) -> int:
        return sum(self._observation_sizes.values())

    @property
    def metadata_bytes_committed(self) -> int:
        return self.metadata_observation_bytes + self._index_bytes

    def reserve_body_bytes(self, maximum_bytes: int) -> BodyReservation:
        self._require_unsealed()
        if not _unsigned_64_bit_int(maximum_bytes):
            raise ValueError("Native body reservation is invalid.")
        if (
            self.body_bytes_committed
            + self.outstanding_reserved_bytes
            + maximum_bytes
            > self.body_byte_allowance
        ):
            raise ValueError("Native observation store body budget is exceeded.")
        reservation = BodyReservation(
            self._reservation_owner,
            self._next_reservation,
            maximum_bytes,
        )
        self._next_reservation += 1
        self._reservations[reservation.token] = reservation
        return reservation

    def maximum_observation_serialized_bytes(self, maximum_redirect_hops: int) -> int:
        return maximum_native_observation_serialized_bytes(maximum_redirect_hops)

    def reserve_candidate_metadata(
        self,
        candidate_index: int,
        *,
        maximum_redirect_hops: int,
    ) -> CandidateMetadataReservation:
        self._require_unsealed()
        _require_candidate_index(candidate_index)
        maximum_bytes = self.maximum_observation_serialized_bytes(
            maximum_redirect_hops
        )
        if (
            candidate_index in self._observations
            or candidate_index in self._reserved_candidate_indices
        ):
            raise ValueError("Native candidate metadata reservation already exists.")
        if (
            self.observation_count + len(self._metadata_reservations)
            >= MAXIMUM_NATIVE_OBSERVATION_CANDIDATES
            or self.metadata_bytes_committed
            + self.outstanding_candidate_metadata_reserved_bytes
            + self.reserved_final_index_capacity
            + maximum_bytes
            > self.metadata_byte_allowance
        ):
            raise ValueError("Native observation store metadata allowance is exceeded.")
        reservation = CandidateMetadataReservation(
            self._metadata_reservation_owner,
            self._next_metadata_reservation,
            maximum_bytes,
            candidate_index,
            maximum_redirect_hops,
        )
        self._next_metadata_reservation += 1
        self._metadata_reservations[reservation.token] = reservation
        self._metadata_reserved_bytes += reservation.maximum_bytes
        self._reserved_candidate_indices.add(reservation.candidate_index)
        return reservation

    def release_reservation(self, reservation: BodyReservation) -> None:
        self._require_active_reservation(reservation)
        del self._reservations[reservation.token]

    def release_candidate_metadata(
        self,
        reservation: CandidateMetadataReservation,
    ) -> None:
        self._require_active_metadata_reservation(reservation)
        del self._metadata_reservations[reservation.token]
        self._metadata_reserved_bytes -= reservation.maximum_bytes
        self._reserved_candidate_indices.remove(reservation.candidate_index)

    def commit_body(
        self,
        reservation: BodyReservation,
        body: bytes,
    ) -> NativeBodyReference:
        self._require_unsealed()
        self._require_active_reservation(reservation)
        if not isinstance(body, bytes) or len(body) > reservation.maximum_bytes:
            raise ValueError("Native body exceeds its reservation.")
        digest = hashlib.sha256(body).hexdigest()
        path = self._sha256_dir / digest
        try:
            if path.exists() or path.is_symlink():
                _verify_body_object(path, digest, body)
            else:
                _publish_new_bytes(
                    path,
                    body,
                    before_publish=lambda: self._fail("before_body_publish"),
                )
                _verify_body_object(path, digest, body)
                self._body_sizes[digest] = len(body)
        except BaseException:
            self._requires_partial_index = True
            raise
        del self._reservations[reservation.token]
        return NativeBodyReference(
            sha256=digest,
            captured_bytes=len(body),
            relative_path=f"bodies/sha256/{digest}",
        )

    def publish_observation(
        self,
        observation: NativeCandidateObservation,
        reservation: CandidateMetadataReservation,
    ) -> Path:
        self._require_unsealed()
        if not isinstance(observation, NativeCandidateObservation):
            raise ValueError("Native candidate observation is invalid.")
        self._require_active_metadata_reservation(reservation)
        if observation.candidate_index != reservation.candidate_index:
            raise ValueError("Native candidate metadata reservation is invalid.")
        if len(observation.exchanges) > reservation.maximum_redirect_hops + 1:
            raise ValueError("Native candidate observation exceeds its redirect reservation.")
        if observation.candidate_index in self._observations:
            raise ValueError("Native candidate observation already exists.")
        _validate_observation_bodies(self.root, observation, self._body_sizes)
        path = self._observation_path(observation.candidate_index)
        content = _json_bytes(_observation_payload(observation))
        if len(content) > reservation.maximum_bytes:
            raise ValueError("Native candidate observation exceeds its metadata reservation.")
        if (
            self.metadata_bytes_committed
            + self.outstanding_candidate_metadata_reserved_bytes
            - reservation.maximum_bytes
            + len(content)
            + self.reserved_final_index_capacity
            > self.metadata_byte_allowance
        ):
            raise ValueError("Native observation store metadata allowance is exceeded.")
        try:
            _publish_new_bytes(
                path,
                content,
                before_publish=lambda: self._fail("before_observation_publish"),
            )
        except BaseException:
            self._requires_partial_index = True
            raise
        loaded = _load_observation_file(self.root, path, self._body_sizes)
        if loaded != observation:
            raise ValueError("Published native candidate observation is corrupt.")
        self._observations[observation.candidate_index] = observation
        self._observation_sizes[observation.candidate_index] = len(content)
        del self._metadata_reservations[reservation.token]
        self._metadata_reserved_bytes -= reservation.maximum_bytes
        self._reserved_candidate_indices.remove(reservation.candidate_index)
        return path

    def load_observation(self, candidate_index: int) -> NativeCandidateObservation:
        if candidate_index not in self._observations:
            raise ValueError("Native candidate observation does not exist.")
        return self._observations[candidate_index]

    def read_body(self, reference: NativeBodyReference) -> bytes:
        if not isinstance(reference, NativeBodyReference):
            raise ValueError("Native body reference is invalid.")
        path = self.root / reference.relative_path
        body = _read_regular_file(
            path,
            "Native body object",
            maximum_bytes=reference.captured_bytes,
        )
        if len(body) != reference.captured_bytes or hashlib.sha256(body).hexdigest() != reference.sha256:
            raise ValueError("Native body object is corrupt.")
        return body

    def publish_index(self, store_state: str) -> Path:
        self._require_unsealed()
        if store_state not in {"complete", "partial"}:
            raise ValueError("Native observation store state is invalid.")
        if self._reservations or self._metadata_reservations:
            raise ValueError(
                "Native observation store has outstanding reservations."
            )
        if store_state == "complete" and self._requires_partial_index:
            raise ValueError("Native observation store requires a partial index.")
        (
            durable_body_sizes,
            durable_observations,
            durable_observation_sizes,
        ) = _validate_preindex_durable_graph(
            self.root,
            self.body_byte_allowance,
            self._body_sizes,
            self._observations,
            self._observation_sizes,
        )
        referenced = _referenced_body_digests(durable_observations)
        if store_state == "complete" and referenced != set(durable_body_sizes):
            raise ValueError("Complete native observation store contains orphan bodies.")
        path = self.root / "index.json"
        payload = _index_payload(
            store_state,
            self.body_byte_allowance,
            self.metadata_byte_allowance,
            durable_body_sizes,
            durable_observations,
            durable_observation_sizes,
        )
        content = _json_bytes(payload)
        if len(content) > self.reserved_final_index_capacity:
            raise ValueError("Native observation store index exceeds its metadata reservation.")
        _publish_new_bytes(
            path,
            content,
            before_publish=lambda: self._fail("before_index_publish"),
        )
        self._sealed = True
        self._index_bytes = len(content)
        self._reserved_final_index_capacity = 0
        validate_native_observation_store(self.root)
        return path

    def _observation_path(self, candidate_index: int) -> Path:
        return self._observations_dir / f"{candidate_index:08d}.json"

    def _require_active_reservation(self, reservation: BodyReservation) -> None:
        if (
            not isinstance(reservation, BodyReservation)
            or reservation._owner is not self._reservation_owner
            or self._reservations.get(reservation.token) is not reservation
        ):
            raise ValueError("Native body reservation is invalid or consumed.")

    def _require_active_metadata_reservation(
        self,
        reservation: CandidateMetadataReservation,
    ) -> None:
        if (
            not isinstance(reservation, CandidateMetadataReservation)
            or reservation._owner is not self._metadata_reservation_owner
            or self._metadata_reservations.get(reservation.token) is not reservation
        ):
            raise ValueError("Native candidate metadata reservation is invalid or consumed.")

    def _require_unsealed(self) -> None:
        if self._sealed:
            raise ValueError("Native observation store index is already published.")

    def _fail(self, phase: str) -> None:
        if self._failure_injector is not None:
            self._failure_injector(phase)


def validate_native_observation_store(root: Path) -> NativeObservationStoreIndex:
    """Independently validate one published observation-to-body graph."""

    resolved = _require_existing_store_root(root)
    bodies = _require_fixed_directory(resolved, "bodies")
    sha256_dir = _require_fixed_directory(bodies, "sha256")
    observations_dir = _require_fixed_directory(resolved, "observations")
    index_path = resolved / "index.json"
    index_content = _read_regular_file(
        index_path,
        "Native observation store index",
        maximum_bytes=maximum_native_observation_index_bytes(),
    )
    payload = _load_json_object_content(index_content, "Native observation store index")
    expected_keys = {
        "body_byte_allowance",
        "body_bytes_committed",
        "created_by",
        "metadata_byte_allowance",
        "metadata_observation_bytes",
        "observation_count",
        "observations",
        "response_bytes_captured",
        "schema_version",
        "store_state",
    }
    if (
        set(payload) != expected_keys
        or type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != STORE_SCHEMA_VERSION
        or payload.get("created_by") != STORE_CREATED_BY
    ):
        raise ValueError("Native observation store index schema is invalid.")
    state = payload.get("store_state")
    allowance = payload.get("body_byte_allowance")
    metadata_allowance = payload.get("metadata_byte_allowance")
    if not _unsigned_64_bit_int(allowance):
        raise ValueError("Native observation store index schema is invalid.")
    body_sizes = _scan_body_objects(sha256_dir, allowance)
    observations, observation_sizes = _scan_observations(
        resolved,
        observations_dir,
        body_sizes,
    )
    committed = sum(body_sizes.values())
    captured = _response_bytes_captured(observations)
    metadata_observation_bytes = sum(observation_sizes.values())
    entries = payload.get("observations")
    expected_entries = [
        {
            "candidate_index": index,
            "file": f"observations/{index:08d}.json",
        }
        for index in sorted(observations)
    ]
    if (
        state not in {"complete", "partial"}
        or not _unsigned_64_bit_int(metadata_allowance)
        or not _unsigned_64_bit_int(payload.get("body_bytes_committed"))
        or not _unsigned_64_bit_int(payload.get("response_bytes_captured"))
        or not _unsigned_64_bit_int(payload.get("metadata_observation_bytes"))
        or not _unsigned_64_bit_int(payload.get("observation_count"))
        or committed > allowance
        or payload.get("body_bytes_committed") != committed
        or payload.get("response_bytes_captured") != captured
        or payload.get("metadata_observation_bytes") != metadata_observation_bytes
        or payload.get("observation_count") != len(observations)
        or metadata_observation_bytes + len(index_content) > metadata_allowance
        or entries != expected_entries
        or (
            state == "complete"
            and _referenced_body_digests(observations) != set(body_sizes)
        )
    ):
        raise ValueError("Native observation store index accounting is invalid.")
    return NativeObservationStoreIndex(
        store_state=state,
        body_byte_allowance=allowance,
        metadata_byte_allowance=metadata_allowance,
        body_bytes_committed=committed,
        response_bytes_captured=captured,
        metadata_observation_bytes=metadata_observation_bytes,
        metadata_index_bytes=len(index_content),
        metadata_bytes_committed=metadata_observation_bytes + len(index_content),
        observation_count=len(observations),
        observation_indices=tuple(sorted(observations)),
    )


def _prepare_store_root(root: Path) -> Path:
    requested = root.expanduser()
    if requested.is_symlink():
        raise ValueError("Native observation store root is unsafe.")
    if requested.exists():
        if not requested.is_dir():
            raise ValueError("Native observation store root is unsafe.")
    else:
        parent = requested.parent.resolve(strict=True)
        if not parent.is_dir() or parent.is_symlink():
            raise ValueError("Native observation store parent is unsafe.")
        requested.mkdir(mode=0o700)
        _fsync_directory(parent)
    return _require_existing_store_root(requested)


def _require_existing_store_root(root: Path) -> Path:
    if not isinstance(root, Path) or root.is_symlink():
        raise ValueError("Native observation store root is unsafe.")
    try:
        resolved = root.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError:
        raise ValueError("Native observation store root is unsafe.") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("Native observation store root is unsafe.")
    return resolved


def _prepare_fixed_directory(parent: Path, name: str) -> Path:
    path = parent / name
    if path.is_symlink():
        raise ValueError("Native observation store hierarchy is unsafe.")
    if path.exists():
        if not path.is_dir():
            raise ValueError("Native observation store hierarchy is unsafe.")
    else:
        path.mkdir(mode=0o700)
        _fsync_directory(parent)
    return _require_fixed_directory(parent, name)


def _require_fixed_directory(parent: Path, name: str) -> Path:
    path = parent / name
    if path.is_symlink():
        raise ValueError("Native observation store hierarchy is unsafe.")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(parent.resolve(strict=True))
        metadata = resolved.stat(follow_symlinks=False)
    except (OSError, ValueError):
        raise ValueError("Native observation store hierarchy is unsafe.") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("Native observation store hierarchy is unsafe.")
    return resolved


def _scan_body_objects(
    directory: Path,
    body_byte_allowance: int,
) -> dict[str, int]:
    if not _unsigned_64_bit_int(body_byte_allowance):
        raise ValueError("Native observation store body allowance is invalid.")
    result: dict[str, int] = {}
    committed = 0
    for path in directory.iterdir():
        if path.name.startswith("."):
            continue
        if _DIGEST.fullmatch(path.name) is None:
            raise ValueError("Native body object name is invalid.")
        size = _regular_file_size(path, "Native body object")
        if size > body_byte_allowance - committed:
            raise ValueError("Native observation store body budget is exceeded.")
        result[path.name] = size
        committed += size
    for digest, expected_size in result.items():
        body = _read_regular_file(
            directory / digest,
            "Native body object",
            maximum_bytes=expected_size,
        )
        if len(body) != expected_size:
            raise ValueError("Native body object has changed during validation.")
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError("Native body object is corrupt.")
    return result


def _scan_observations(
    root: Path,
    directory: Path,
    body_sizes: dict[str, int],
) -> tuple[dict[int, NativeCandidateObservation], dict[int, int]]:
    result: dict[int, NativeCandidateObservation] = {}
    sizes: dict[int, int] = {}
    for path in directory.iterdir():
        if path.name.startswith("."):
            continue
        match = _OBSERVATION_NAME.fullmatch(path.name)
        if match is None:
            raise ValueError("Native candidate observation filename is invalid.")
        if len(result) >= MAXIMUM_NATIVE_OBSERVATION_CANDIDATES:
            raise ValueError("Native candidate observation count is invalid.")
        observation = _load_observation_file(root, path, body_sizes)
        index = int(match.group("index"))
        if observation.candidate_index != index or index in result:
            raise ValueError("Native candidate observation index is invalid.")
        result[index] = observation
        sizes[index] = path.stat(follow_symlinks=False).st_size
    return result, sizes


def _load_observation_file(
    root: Path,
    path: Path,
    body_sizes: dict[str, int],
) -> NativeCandidateObservation:
    content = _read_regular_file(
        path,
        "Native candidate observation",
        maximum_bytes=maximum_native_observation_serialized_bytes(
            MAXIMUM_REDIRECT_HOPS_FOR_OBSERVATIONS
        ),
    )
    payload = _load_json_object_content(content, "Native candidate observation")
    if (
        set(payload) != {"created_by", "observation", "schema_version"}
        or type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != STORE_SCHEMA_VERSION
        or payload.get("created_by") != STORE_CREATED_BY
    ):
        raise ValueError("Native candidate observation schema is invalid.")
    observation = _observation_from_payload(payload.get("observation"))
    _validate_observation_bodies(root, observation, body_sizes)
    return observation


def _validate_observation_graph(
    root: Path,
    observations: dict[int, NativeCandidateObservation],
    body_sizes: dict[str, int],
) -> None:
    for index, observation in observations.items():
        if observation.candidate_index != index:
            raise ValueError("Native candidate observation index is invalid.")
        _validate_observation_bodies(root, observation, body_sizes)


def _validate_preindex_durable_graph(
    root: Path,
    body_byte_allowance: int,
    expected_body_sizes: dict[str, int],
    expected_observations: dict[int, NativeCandidateObservation],
    expected_observation_sizes: dict[int, int],
) -> tuple[
    dict[str, int],
    dict[int, NativeCandidateObservation],
    dict[int, int],
]:
    bodies = _require_fixed_directory(root, "bodies")
    sha256_dir = _require_fixed_directory(bodies, "sha256")
    observations_dir = _require_fixed_directory(root, "observations")
    durable_body_sizes = _scan_body_objects(sha256_dir, body_byte_allowance)
    durable_observations, durable_observation_sizes = _scan_observations(
        root,
        observations_dir,
        durable_body_sizes,
    )
    if durable_body_sizes != expected_body_sizes:
        raise ValueError("Native observation store durable body graph has changed.")
    if durable_observations != expected_observations:
        raise ValueError(
            "Native observation store durable observation graph has changed."
        )
    if durable_observation_sizes != expected_observation_sizes:
        raise ValueError("Native observation store durable metadata graph has changed.")
    _validate_observation_graph(root, durable_observations, durable_body_sizes)
    return durable_body_sizes, durable_observations, durable_observation_sizes


def _validate_observation_bodies(
    root: Path,
    observation: NativeCandidateObservation,
    body_sizes: dict[str, int],
) -> None:
    for exchange in observation.exchanges:
        reference = exchange.body
        if reference is None:
            continue
        if body_sizes.get(reference.sha256) != reference.captured_bytes:
            raise ValueError("Native candidate observation body is missing or corrupt.")
        body = _read_regular_file(
            root / reference.relative_path,
            "Native body object",
            maximum_bytes=reference.captured_bytes,
        )
        if (
            len(body) != reference.captured_bytes
            or hashlib.sha256(body).hexdigest() != reference.sha256
        ):
            raise ValueError("Native candidate observation body is corrupt.")


def _referenced_body_digests(
    observations: dict[int, NativeCandidateObservation],
) -> set[str]:
    return {
        exchange.body.sha256
        for observation in observations.values()
        for exchange in observation.exchanges
        if exchange.body is not None
    }


def _verify_body_object(path: Path, digest: str, expected: bytes) -> None:
    body = _read_regular_file(
        path,
        "Native body object",
        maximum_bytes=len(expected),
    )
    if len(body) != len(expected) or hashlib.sha256(body).hexdigest() != digest or body != expected:
        raise ValueError("Native body object is corrupt or colliding.")


def _publish_new_bytes(
    path: Path,
    content: bytes,
    *,
    before_publish: Callable[[], None],
) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    published = False
    staged_identity: tuple[int, int] | None = None
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        staged = _read_regular_file(temporary, "Native observation staging file")
        if staged != content:
            raise OSError("Native observation staging verification failed.")
        metadata = temporary.lstat()
        staged_identity = (metadata.st_dev, metadata.st_ino)
        before_publish()
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
                raise ValueError("Native observation evidence already exists.") from None
        published = True
        _fsync_directory(path.parent)
    except BaseException:
        if published and staged_identity is not None:
            try:
                metadata = path.lstat()
                if (
                    stat.S_ISREG(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino) == staged_identity
                ):
                    path.unlink()
                    _fsync_directory(path.parent)
            except (FileNotFoundError, OSError):
                pass
        raise
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_regular_file(
    path: Path,
    label: str,
    *,
    maximum_bytes: int | None = None,
) -> bytes:
    if maximum_bytes is not None and not _unsigned_64_bit_int(maximum_bytes):
        raise ValueError(f"{label} bound is invalid.")
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ValueError(f"{label} is unavailable or unsafe.") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} is not a regular file.")
        if maximum_bytes is not None and metadata.st_size > maximum_bytes:
            raise ValueError(f"{label} is too large.")
        chunks: list[bytes] = []
        read_bytes = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            read_bytes += len(chunk)
            if maximum_bytes is not None and read_bytes > maximum_bytes:
                raise ValueError(f"{label} is too large.")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _regular_file_size(path: Path, label: str) -> int:
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ValueError(f"{label} is unavailable or unsafe.") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} is not a regular file.")
        if not _unsigned_64_bit_int(metadata.st_size):
            raise ValueError(f"{label} size is invalid.")
        return metadata.st_size
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _reject_owned_staging_files(*directories: Path) -> None:
    for directory in directories:
        for path in directory.iterdir():
            if _OWNED_STAGING_NAME.fullmatch(path.name) is not None:
                raise ValueError("Native observation store staging file requires resolution.")


def _valid_headers(headers: tuple[tuple[str, str], ...]) -> bool:
    if len(headers) > MAXIMUM_RETAINED_HEADER_PAIRS:
        return False
    total = 0
    for item in headers:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not all(isinstance(value, str) for value in item)
        ):
            return False
        try:
            total += len(item[0].encode("utf-8")) + len(item[1].encode("utf-8"))
        except UnicodeEncodeError:
            return False
        if total > MAXIMUM_RETAINED_HEADER_BYTES:
            return False
    return True


def _require_candidate_index(value: object) -> int:
    if (
        not _unsigned_64_bit_int(value)
        or value > MAXIMUM_NATIVE_OBSERVATION_INDEX
    ):
        raise ValueError("Native candidate index is invalid.")
    return value


def _response_bytes_captured(
    observations: dict[int, NativeCandidateObservation],
) -> int:
    total = sum(
        exchange.captured_bytes
        for observation in observations.values()
        for exchange in observation.exchanges
    )
    if not _unsigned_64_bit_int(total):
        raise ValueError("Native response byte accounting is invalid.")
    return total


@lru_cache(maxsize=None)
def maximum_native_observation_serialized_bytes(maximum_redirect_hops: int) -> int:
    """Return an exact JSON upper bound for one permitted candidate outcome."""

    if (
        isinstance(maximum_redirect_hops, bool)
        or not isinstance(maximum_redirect_hops, int)
        or not 0 <= maximum_redirect_hops <= MAXIMUM_REDIRECT_HOPS_FOR_OBSERVATIONS
    ):
        raise ValueError("Native observation redirect allowance is invalid.")
    source_url = _maximum_canonical_url("a")
    failure_url = _maximum_canonical_url("b")
    headers = _maximum_headers()
    digest = "f" * 64
    reference = NativeBodyReference(
        sha256=digest,
        captured_bytes=UINT64_MAXIMUM,
        relative_path=f"bodies/sha256/{digest}",
    )
    exchange = NativeReceivedExchange(
        request_url=source_url,
        status_code=599,
        headers=headers,
        capture_state="incomplete",
        captured_bytes=UINT64_MAXIMUM,
        body_sha256=digest,
        body=reference,
        incomplete_reason="a" * 64,
        headers_capture_state="incomplete",
        headers_incomplete_reason="a" * 64,
    )
    failure_category = max(
        ATTEMPT_FAILURE_CATEGORIES,
        key=lambda category: (
            len(
                _json_bytes(
                    _failure_payload(NativeAttemptFailure(failure_url, category))
                )
            ),
            category,
        ),
    )
    observation = NativeCandidateObservation(
        candidate_index=MAXIMUM_NATIVE_OBSERVATION_INDEX,
        request_url=source_url,
        exchanges=(exchange,) * (maximum_redirect_hops + 1),
        failure=NativeAttemptFailure(failure_url, failure_category),
    )
    return len(_json_bytes(_observation_payload(observation)))


@lru_cache(maxsize=1)
def maximum_native_observation_index_bytes() -> int:
    """Return an exact upper bound for the final deterministic index JSON."""

    entries = [
        {
            "candidate_index": index,
            "file": f"observations/{index:08d}.json",
        }
        for index in range(MAXIMUM_NATIVE_OBSERVATION_CANDIDATES)
    ]
    payloads = (
        {
            "body_byte_allowance": UINT64_MAXIMUM,
            "body_bytes_committed": UINT64_MAXIMUM,
            "created_by": STORE_CREATED_BY,
            "metadata_byte_allowance": UINT64_MAXIMUM,
            "metadata_observation_bytes": UINT64_MAXIMUM,
            "observation_count": MAXIMUM_NATIVE_OBSERVATION_CANDIDATES,
            "observations": entries,
            "response_bytes_captured": UINT64_MAXIMUM,
            "schema_version": STORE_SCHEMA_VERSION,
            "store_state": state,
        }
        for state in ("complete", "partial")
    )
    return max(len(_json_bytes(payload)) for payload in payloads)


def _maximum_canonical_url(marker: str) -> str:
    path = "/" + marker * (MAX_PATH_LENGTH - 1)
    prefix = f"https://a.test{path}?"
    query_length = min(MAX_QUERY_LENGTH, MAX_URL_LENGTH - len(prefix))
    value = prefix + marker * query_length
    if len(value) != MAX_URL_LENGTH:
        raise RuntimeError("Native observation maximum URL derivation is invalid.")
    _require_canonical_url(value)
    return value


def _maximum_headers() -> tuple[tuple[str, str], ...]:
    values = [("\x00", "") for _ in range(MAXIMUM_RETAINED_HEADER_PAIRS)]
    values[-1] = (
        "\x00",
        "\x00" * (MAXIMUM_RETAINED_HEADER_BYTES - MAXIMUM_RETAINED_HEADER_PAIRS),
    )
    headers = tuple(values)
    if not _valid_headers(headers):
        raise RuntimeError("Native observation maximum header derivation is invalid.")
    return headers


def _observation_payload(observation: NativeCandidateObservation) -> dict[str, object]:
    return {
        "created_by": STORE_CREATED_BY,
        "observation": {
            "candidate_index": observation.candidate_index,
            "exchanges": [_exchange_payload(item) for item in observation.exchanges],
            "failure": _failure_payload(observation.failure),
            "request_url": observation.request_url,
        },
        "schema_version": STORE_SCHEMA_VERSION,
    }


def _exchange_payload(exchange: NativeReceivedExchange) -> dict[str, object]:
    return {
        "body": (
            {
                "captured_bytes": exchange.body.captured_bytes,
                "relative_path": exchange.body.relative_path,
                "sha256": exchange.body.sha256,
            }
            if exchange.body is not None
            else None
        ),
        "body_sha256": exchange.body_sha256,
        "capture_state": exchange.capture_state,
        "captured_bytes": exchange.captured_bytes,
        "headers": [
            {"name": name, "value": value} for name, value in exchange.headers
        ],
        "headers_capture_state": exchange.headers_capture_state,
        "headers_incomplete_reason": exchange.headers_incomplete_reason,
        "incomplete_reason": exchange.incomplete_reason,
        "request_url": exchange.request_url,
        "status_code": exchange.status_code,
    }


def _failure_payload(failure: NativeAttemptFailure | None) -> dict[str, str] | None:
    if failure is None:
        return None
    return {"category": failure.category, "request_url": failure.request_url}


def _observation_from_payload(value: object) -> NativeCandidateObservation:
    if not isinstance(value, dict) or set(value) != {"candidate_index", "exchanges", "failure", "request_url"}:
        raise ValueError("Native candidate observation payload is invalid.")
    raw_exchanges = value["exchanges"]
    if not isinstance(raw_exchanges, list):
        raise ValueError("Native candidate observation exchanges are invalid.")
    return NativeCandidateObservation(
        candidate_index=value["candidate_index"],
        request_url=value["request_url"],
        exchanges=tuple(_exchange_from_payload(item) for item in raw_exchanges),
        failure=_failure_from_payload(value["failure"]),
    )


def _exchange_from_payload(value: object) -> NativeReceivedExchange:
    expected = {
        "body",
        "body_sha256",
        "capture_state",
        "captured_bytes",
        "headers",
        "headers_capture_state",
        "headers_incomplete_reason",
        "incomplete_reason",
        "request_url",
        "status_code",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("Native received exchange payload is invalid.")
    body = value["body"]
    headers = value["headers"]
    if (
        body is not None
        and (
            not isinstance(body, dict)
            or set(body) != {"captured_bytes", "relative_path", "sha256"}
        )
    ) or not isinstance(headers, list):
        raise ValueError("Native received exchange payload is invalid.")
    parsed_headers = []
    for item in headers:
        if not isinstance(item, dict) or set(item) != {"name", "value"}:
            raise ValueError("Native received exchange headers are invalid.")
        parsed_headers.append((item["name"], item["value"]))
    reference = (
        NativeBodyReference(
            sha256=body["sha256"],
            captured_bytes=body["captured_bytes"],
            relative_path=body["relative_path"],
        )
        if body is not None
        else None
    )
    return NativeReceivedExchange(
        request_url=value["request_url"],
        status_code=value["status_code"],
        headers=tuple(parsed_headers),
        capture_state=value["capture_state"],
        captured_bytes=value["captured_bytes"],
        body_sha256=value["body_sha256"],
        body=reference,
        incomplete_reason=value["incomplete_reason"],
        headers_capture_state=value["headers_capture_state"],
        headers_incomplete_reason=value["headers_incomplete_reason"],
    )


def _failure_from_payload(value: object) -> NativeAttemptFailure | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"category", "request_url"}:
        raise ValueError("Native attempt failure payload is invalid.")
    return NativeAttemptFailure(value["request_url"], value["category"])


def _index_payload(
    state: str,
    allowance: int,
    metadata_allowance: int,
    body_sizes: dict[str, int],
    observations: dict[int, NativeCandidateObservation],
    observation_sizes: dict[int, int],
) -> dict[str, object]:
    return {
        "body_byte_allowance": allowance,
        "body_bytes_committed": sum(body_sizes.values()),
        "created_by": STORE_CREATED_BY,
        "metadata_byte_allowance": metadata_allowance,
        "metadata_observation_bytes": sum(observation_sizes.values()),
        "observation_count": len(observations),
        "observations": [
            {
                "candidate_index": index,
                "file": f"observations/{index:08d}.json",
            }
            for index in sorted(observations)
        ],
        "response_bytes_captured": _response_bytes_captured(observations),
        "schema_version": STORE_SCHEMA_VERSION,
        "store_state": state,
    }


def _load_json_object_content(content: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_members)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError(f"{label} is malformed.") from None
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain an object.")
    return value


def _unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Native observation JSON contains a duplicate member.")
        result[key] = value
    return result


def _json_bytes(payload: dict[str, object]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _require_canonical_url(value: object) -> str:
    try:
        canonical = canonicalise_http_url_destination(value).canonical_value
    except (TypeError, ValueError):
        raise ValueError("Native observation URL is not canonical.") from None
    if value != canonical:
        raise ValueError("Native observation URL is not canonical.")
    return canonical


def _unsigned_64_bit_int(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int)
        and 0 <= value <= UINT64_MAXIMUM
    )
