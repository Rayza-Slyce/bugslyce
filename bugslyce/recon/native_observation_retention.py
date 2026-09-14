"""Deterministic retention planning for sealed native observation bodies."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import html
import json
import re
from urllib.parse import quote, quote_plus, urlsplit

from bugslyce.recon.native_observation_facts import (
    NativeObservationSemanticEvidence,
    NativeSemanticProcessingSource,
)
from bugslyce.recon.native_observation_store import (
    NativeObservationStore,
    NativeReceivedExchange,
    validate_native_observation_store,
)


RETENTION_GROUPING_RULE = "full_body_request_reflection_v1"
RETENTION_ACTIONS = frozenset({"retain", "eligible_for_omission"})
RETENTION_REASON_CODES = frozenset(
    {
        "semantic_fact",
        "not_semantically_processed",
        "unique_or_unclassified",
        "shared_required_digest",
        "family_representative",
        "redundant_request_reflecting_family_member",
    }
)
_SOURCE_ID = re.compile(r"^native-observation:(0|[1-9][0-9]*):(0|[1-9][0-9]*)$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_FAMILY_ID = re.compile(r"^NATIVE-RETENTION-FAMILY-[0-9a-f]{64}$")
_REFLECTION_MARKER = b"{{BUGSLYCE_REQUEST_REFLECTION}}"
_HTML_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})


def _source_components(source_id: str) -> tuple[int, int]:
    match = _SOURCE_ID.fullmatch(source_id) if isinstance(source_id, str) else None
    if match is None:
        raise ValueError("Native retention source identity is invalid.")
    return int(match.group(1)), int(match.group(2))


def _source_id(candidate_index: int, exchange_index: int) -> str:
    return f"native-observation:{candidate_index}:{exchange_index}"


@dataclass(frozen=True)
class NativeBodyRetentionDecision:
    source_id: str
    candidate_index: int
    exchange_index: int
    request_url: str
    status_code: int
    captured_bytes: int
    body_sha256: str
    action: str
    reason_code: str
    family_id: str | None = None

    def __post_init__(self) -> None:
        if (
            _source_components(self.source_id)
            != (self.candidate_index, self.exchange_index)
            or not isinstance(self.request_url, str)
            or not self.request_url
            or isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
            or isinstance(self.captured_bytes, bool)
            or not isinstance(self.captured_bytes, int)
            or self.captured_bytes < 0
            or not isinstance(self.body_sha256, str)
            or _DIGEST.fullmatch(self.body_sha256) is None
            or self.action not in RETENTION_ACTIONS
            or self.reason_code not in RETENTION_REASON_CODES
            or (
                self.family_id is not None
                and (
                    not isinstance(self.family_id, str)
                    or _FAMILY_ID.fullmatch(self.family_id) is None
                )
            )
        ):
            raise ValueError("Native body retention decision is invalid.")
        if self.action == "eligible_for_omission" and (
            self.reason_code != "redundant_request_reflecting_family_member"
            or self.family_id is None
        ):
            raise ValueError("Native body retention decision is contradictory.")
        if self.action == "retain" and self.reason_code == (
            "redundant_request_reflecting_family_member"
        ):
            raise ValueError("Native body retention decision is contradictory.")
        if self.reason_code in {"family_representative", "shared_required_digest"}:
            if self.family_id is None:
                raise ValueError("Native body retention family linkage is missing.")
        elif self.family_id is not None and self.action == "retain":
            raise ValueError("Native body retention family linkage is contradictory.")


@dataclass(frozen=True)
class NativeBodyRetentionFamily:
    family_id: str
    grouping_rule: str
    canonical_origin: str
    grouping_signature_sha256: str
    representative_source_id: str
    representative_body_sha256: str
    member_source_ids: tuple[str, ...]
    member_body_sha256: tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            source_order = tuple(
                sorted(self.member_source_ids, key=_source_components)
            )
        except ValueError as exc:
            raise ValueError("Native body retention family is invalid.") from exc
        if (
            not isinstance(self.family_id, str)
            or _FAMILY_ID.fullmatch(self.family_id) is None
            or self.grouping_rule != RETENTION_GROUPING_RULE
            or not isinstance(self.canonical_origin, str)
            or not self.canonical_origin
            or not isinstance(self.grouping_signature_sha256, str)
            or _DIGEST.fullmatch(self.grouping_signature_sha256) is None
            or _source_components(self.representative_source_id)
            not in tuple(_source_components(item) for item in self.member_source_ids)
            or not isinstance(self.representative_body_sha256, str)
            or _DIGEST.fullmatch(self.representative_body_sha256) is None
            or not isinstance(self.member_source_ids, tuple)
            or len(self.member_source_ids) < 2
            or len(set(self.member_source_ids)) != len(self.member_source_ids)
            or self.member_source_ids != source_order
            or not isinstance(self.member_body_sha256, tuple)
            or len(self.member_body_sha256) != len(self.member_source_ids)
            or any(
                not isinstance(item, str) or _DIGEST.fullmatch(item) is None
                for item in self.member_body_sha256
            )
        ):
            raise ValueError("Native body retention family is invalid.")
        representative_index = self.member_source_ids.index(
            self.representative_source_id
        )
        if self.member_body_sha256[representative_index] != (
            self.representative_body_sha256
        ):
            raise ValueError("Native body retention representative is contradictory.")


@dataclass(frozen=True)
class NativeObservationRetentionPlan:
    decisions: tuple[NativeBodyRetentionDecision, ...] = ()
    families: tuple[NativeBodyRetentionFamily, ...] = ()
    grouping_rule: str = RETENTION_GROUPING_RULE

    def __post_init__(self) -> None:
        if self.grouping_rule != RETENTION_GROUPING_RULE:
            raise ValueError("Native retention plan grouping rule is unsupported.")
        if not isinstance(self.decisions, tuple) or not isinstance(
            self.families, tuple
        ):
            raise TypeError("Native observation retention plan requires tuples.")
        if self.decisions != tuple(
            sorted(self.decisions, key=lambda item: (item.candidate_index, item.exchange_index))
        ) or len({item.source_id for item in self.decisions}) != len(self.decisions):
            raise ValueError("Native retention decisions are not deterministic.")
        if self.families != tuple(sorted(self.families, key=lambda item: item.family_id)):
            raise ValueError("Native retention families are not deterministic.")
        family_ids = {item.family_id for item in self.families}
        if len(family_ids) != len(self.families):
            raise ValueError("Native retention family identities are duplicated.")
        decisions = {item.source_id: item for item in self.decisions}
        if any(
            item.family_id is not None and item.family_id not in family_ids
            for item in self.decisions
        ):
            raise ValueError("Native retention decision family does not exist.")
        for family in self.families:
            for source_id, body_sha256 in zip(
                family.member_source_ids,
                family.member_body_sha256,
                strict=True,
            ):
                decision = decisions.get(source_id)
                if (
                    decision is None
                    or decision.family_id != family.family_id
                    or decision.body_sha256 != body_sha256
                ):
                    raise ValueError("Native retention family membership is contradictory.")
            representative = decisions[family.representative_source_id]
            if representative.reason_code != "family_representative":
                raise ValueError("Native retention representative decision is missing.")


@dataclass(frozen=True)
class _Source:
    source_id: str
    candidate_index: int
    exchange_index: int
    request_url: str
    status_code: int
    headers: tuple[tuple[str, str], ...]
    captured_bytes: int
    body_sha256: str
    body: bytes


def _semantic_source_ids(evidence: NativeObservationSemanticEvidence) -> set[str]:
    return {
        *(
            _source_id(item.candidate_index, item.exchange_index)
            for item in evidence.structured_responses
        ),
        *(item.source_id for item in evidence.redirect_relationships),
        *(
            _source_id(item.candidate_index, item.exchange_index)
            for item in evidence.mobile_association_declarations
        ),
    }


def _validated_processing_sources(
    sources: dict[str, _Source],
    processed_sources: tuple[NativeSemanticProcessingSource, ...],
) -> set[str]:
    if not isinstance(processed_sources, tuple):
        raise TypeError("Native semantic processing coverage must be a tuple.")
    covered: set[str] = set()
    for processed in processed_sources:
        if not isinstance(processed, NativeSemanticProcessingSource):
            raise TypeError("Native semantic processing coverage is invalid.")
        source = sources.get(processed.source_id)
        if source is None or (
            source.request_url != processed.request_url
            or source.status_code != processed.status_code
            or source.captured_bytes != processed.captured_bytes
            or source.body_sha256 != processed.body_sha256
            or processed.capture_state != "complete"
            or processed.headers_capture_state != "complete"
        ):
            raise ValueError("Native semantic processing coverage contradicts its source.")
        covered.add(processed.source_id)
    return covered


def _single_header(
    headers: tuple[tuple[str, str], ...],
    name: str,
) -> str | None:
    values = tuple(value for key, value in headers if key.casefold() == name)
    return values[0] if len(values) == 1 else None


def _has_header(headers: tuple[tuple[str, str], ...], name: str) -> bool:
    return any(key.casefold() == name for key, _value in headers)


def _canonical_origin(request_url: str) -> str:
    parsed = urlsplit(request_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _request_derived_forms(request_url: str) -> tuple[bytes, ...]:
    parsed = urlsplit(request_url)
    path_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    raw_forms = {request_url, path_query}
    if parsed.path != "/":
        raw_forms.add(parsed.path)
    derived: set[bytes] = set()
    for value in raw_forms:
        if not value or value == "/":
            continue
        for form in {
            value,
            html.escape(value, quote=True),
            html.escape(value, quote=False),
            quote(value, safe=""),
            quote_plus(value, safe=""),
        }:
            encoded = form.encode("utf-8")
            if len(encoded) >= 2:
                derived.add(encoded)
    return tuple(sorted(derived, key=lambda item: (-len(item), item)))


def _full_body_reflection_signature(
    request_url: str,
    body: bytes,
) -> tuple[str, bytes] | None:
    forms = tuple(item for item in _request_derived_forms(request_url) if item in body)
    if not forms:
        return None
    pattern = re.compile(b"|".join(re.escape(item) for item in forms))
    normalised = pattern.sub(_REFLECTION_MARKER, body)
    return hashlib.sha256(normalised).hexdigest(), normalised


def _candidate_signature(source: _Source) -> tuple[str, str] | None:
    if (
        source.status_code != 404
        or not source.body
        or _has_header(source.headers, "location")
        or _has_header(source.headers, "set-cookie")
    ):
        return None
    content_type = _single_header(source.headers, "content-type")
    if content_type is None or content_type.split(";", 1)[0].strip().casefold() not in (
        _HTML_CONTENT_TYPES
    ):
        return None
    reflected = _full_body_reflection_signature(source.request_url, source.body)
    if reflected is None:
        return None
    signature, _normalised = reflected
    return _canonical_origin(source.request_url), signature


def native_retention_grade_signature(
    store: NativeObservationStore,
    exchange: NativeReceivedExchange,
) -> tuple[str, str] | None:
    """Return the auditable v1 grouping signature for one retained exchange."""

    if not isinstance(store, NativeObservationStore) or not isinstance(
        exchange, NativeReceivedExchange
    ):
        raise TypeError("Native retention signature requires typed store evidence.")
    if exchange.body_retention_state != "retained" or exchange.body is None:
        return None
    source = _Source(
        source_id="native-observation:0:0",
        candidate_index=0,
        exchange_index=0,
        request_url=exchange.request_url,
        status_code=exchange.status_code,
        headers=exchange.headers,
        captured_bytes=exchange.captured_bytes,
        body_sha256=exchange.body_sha256,
        body=store.read_body(exchange.body),
    )
    return _candidate_signature(source)


def _family_identity(origin: str, signature: str) -> str:
    payload = json.dumps(
        {
            "canonical_origin": origin,
            "grouping_rule": RETENTION_GROUPING_RULE,
            "grouping_signature_sha256": signature,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"NATIVE-RETENTION-FAMILY-{hashlib.sha256(payload).hexdigest()}"


def build_native_observation_retention_plan(
    store: NativeObservationStore,
    *,
    semantic_evidence: NativeObservationSemanticEvidence,
    processed_sources: tuple[NativeSemanticProcessingSource, ...],
) -> NativeObservationRetentionPlan:
    """Build one conservative plan without mutating its sealed source store."""

    if not isinstance(store, NativeObservationStore):
        raise TypeError("Native retention planning requires a native observation store.")
    if not isinstance(semantic_evidence, NativeObservationSemanticEvidence):
        raise TypeError("Native retention planning requires typed semantic evidence.")
    index = validate_native_observation_store(store.root)
    sources: dict[str, _Source] = {}
    for candidate_index in index.observation_indices:
        observation = store.load_observation(candidate_index)
        for exchange_index, exchange in enumerate(observation.exchanges):
            if exchange.body_retention_state != "retained" or exchange.body is None:
                continue
            source_id = _source_id(candidate_index, exchange_index)
            sources[source_id] = _Source(
                source_id=source_id,
                candidate_index=candidate_index,
                exchange_index=exchange_index,
                request_url=exchange.request_url,
                status_code=exchange.status_code,
                headers=exchange.headers,
                captured_bytes=exchange.captured_bytes,
                body_sha256=exchange.body_sha256,
                body=store.read_body(exchange.body),
            )
    covered = _validated_processing_sources(sources, processed_sources)
    fact_sources = _semantic_source_ids(semantic_evidence)

    grouped: dict[tuple[str, str], list[_Source]] = {}
    for source in sources.values():
        if source.source_id not in covered or source.source_id in fact_sources:
            continue
        signature = _candidate_signature(source)
        if signature is not None:
            grouped.setdefault(signature, []).append(source)

    families: list[NativeBodyRetentionFamily] = []
    source_family: dict[str, NativeBodyRetentionFamily] = {}
    for (origin, signature), members in grouped.items():
        if len({item.request_url for item in members}) < 2:
            continue
        ordered = tuple(
            sorted(
                members,
                key=lambda item: (
                    item.request_url,
                    item.source_id,
                    item.body_sha256,
                ),
            )
        )
        representative = ordered[0]
        members_by_source = tuple(
            sorted(ordered, key=lambda item: (item.candidate_index, item.exchange_index))
        )
        family = NativeBodyRetentionFamily(
            family_id=_family_identity(origin, signature),
            grouping_rule=RETENTION_GROUPING_RULE,
            canonical_origin=origin,
            grouping_signature_sha256=signature,
            representative_source_id=representative.source_id,
            representative_body_sha256=representative.body_sha256,
            member_source_ids=tuple(item.source_id for item in members_by_source),
            member_body_sha256=tuple(item.body_sha256 for item in members_by_source),
        )
        families.append(family)
        source_family.update((item.source_id, family) for item in members)

    preliminary: dict[str, tuple[str, str, str | None]] = {}
    for source_id, source in sources.items():
        family = source_family.get(source_id)
        if source_id in fact_sources:
            preliminary[source_id] = ("retain", "semantic_fact", None)
        elif source_id not in covered:
            preliminary[source_id] = (
                "retain",
                "not_semantically_processed",
                None,
            )
        elif family is None:
            preliminary[source_id] = (
                "retain",
                "unique_or_unclassified",
                None,
            )
        elif source_id == family.representative_source_id:
            preliminary[source_id] = (
                "retain",
                "family_representative",
                family.family_id,
            )
        else:
            preliminary[source_id] = (
                "eligible_for_omission",
                "redundant_request_reflecting_family_member",
                family.family_id,
            )

    required_digests = {
        sources[source_id].body_sha256
        for source_id, (action, _reason, _family_id) in preliminary.items()
        if action == "retain"
    }
    decisions: list[NativeBodyRetentionDecision] = []
    for source in sorted(
        sources.values(), key=lambda item: (item.candidate_index, item.exchange_index)
    ):
        action, reason, family_id = preliminary[source.source_id]
        if action == "eligible_for_omission" and source.body_sha256 in required_digests:
            action = "retain"
            reason = "shared_required_digest"
        decisions.append(
            NativeBodyRetentionDecision(
                source_id=source.source_id,
                candidate_index=source.candidate_index,
                exchange_index=source.exchange_index,
                request_url=source.request_url,
                status_code=source.status_code,
                captured_bytes=source.captured_bytes,
                body_sha256=source.body_sha256,
                action=action,
                reason_code=reason,
                family_id=family_id,
            )
        )
    return NativeObservationRetentionPlan(
        decisions=tuple(decisions),
        families=tuple(sorted(families, key=lambda item: item.family_id)),
    )
