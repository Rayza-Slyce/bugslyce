"""Offline semantic facts derived from complete native HTTP observations."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from urllib.parse import urljoin

from bugslyce.recon.http_route_relationships import canonical_relationship_url
from bugslyce.recon.native_observation_store import (
    REDIRECT_STATUSES,
    NativeObservationStore,
    validate_native_observation_store,
)


def _native_source_id(candidate_index: int, exchange_index: int) -> str:
    return f"native-observation:{candidate_index}:{exchange_index}"


_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _valid_source_fields(
    *,
    request_url: str,
    candidate_index: int,
    exchange_index: int,
    body_sha256: str | None = None,
) -> bool:
    return (
        canonical_relationship_url(request_url) == request_url
        and isinstance(candidate_index, int)
        and not isinstance(candidate_index, bool)
        and candidate_index >= 0
        and isinstance(exchange_index, int)
        and not isinstance(exchange_index, bool)
        and exchange_index >= 0
        and (body_sha256 is None or _DIGEST.fullmatch(body_sha256) is not None)
    )


@dataclass(frozen=True)
class NativeStructuredResponseFact:
    request_url: str
    status_code: int
    candidate_index: int
    exchange_index: int
    body_sha256: str
    direct_observation: bool = True
    confirmed_api: bool = False

    def __post_init__(self) -> None:
        if (
            not _valid_source_fields(
                request_url=self.request_url,
                candidate_index=self.candidate_index,
                exchange_index=self.exchange_index,
                body_sha256=self.body_sha256,
            )
            or not isinstance(self.status_code, int)
            or isinstance(self.status_code, bool)
            or not 100 <= self.status_code <= 599
            or self.direct_observation is not True
            or self.confirmed_api is not False
        ):
            raise ValueError("Native structured response fact is invalid.")


@dataclass(frozen=True)
class NativeRedirectRelationship:
    source_url: str
    raw_location: str
    target_url: str
    candidate_index: int
    exchange_index: int
    direct_observation: bool = True
    destination_fetched: bool = False

    def __post_init__(self) -> None:
        if (
            not _valid_source_fields(
                request_url=self.source_url,
                candidate_index=self.candidate_index,
                exchange_index=self.exchange_index,
            )
            or not isinstance(self.raw_location, str)
            or not self.raw_location
            or canonical_relationship_url(self.target_url) != self.target_url
            or self.direct_observation is not True
            or self.destination_fetched is not False
        ):
            raise ValueError("Native redirect relationship is invalid.")

    @property
    def source_id(self) -> str:
        return _native_source_id(self.candidate_index, self.exchange_index)


@dataclass(frozen=True)
class NativeMobileAssociationDeclaration:
    document_url: str
    platform: str
    package_name: str
    candidate_index: int
    exchange_index: int
    body_sha256: str
    direct_observation: bool = True
    ownership_confirmed: bool = False

    def __post_init__(self) -> None:
        if (
            not _valid_source_fields(
                request_url=self.document_url,
                candidate_index=self.candidate_index,
                exchange_index=self.exchange_index,
                body_sha256=self.body_sha256,
            )
            or not self.document_url.endswith("/.well-known/assetlinks.json")
            or self.platform != "android"
            or not isinstance(self.package_name, str)
            or not self.package_name.strip()
            or self.direct_observation is not True
            or self.ownership_confirmed is not False
        ):
            raise ValueError("Native mobile association declaration is invalid.")


@dataclass(frozen=True)
class NativeObservationSemanticEvidence:
    structured_responses: tuple[NativeStructuredResponseFact, ...] = ()
    redirect_relationships: tuple[NativeRedirectRelationship, ...] = ()
    mobile_association_declarations: tuple[NativeMobileAssociationDeclaration, ...] = ()

    def __post_init__(self) -> None:
        for name, values, key in (
            ("structured responses", self.structured_responses, lambda value: (
                value.candidate_index, value.exchange_index, value.request_url,
            )),
            ("redirect relationships", self.redirect_relationships, lambda value: (
                value.candidate_index, value.exchange_index, value.source_url,
                value.target_url, value.raw_location,
            )),
            ("mobile association declarations", self.mobile_association_declarations,
             lambda value: (
                 value.candidate_index, value.exchange_index, value.document_url,
                 value.package_name,
             )),
        ):
            if not isinstance(values, tuple) or tuple(sorted(set(values), key=key)) != values:
                raise ValueError(f"Native {name} are not deterministic.")


def _complete_exchange(exchange) -> bool:
    return (
        exchange.capture_state == "complete"
        and exchange.headers_capture_state == "complete"
        and exchange.body is not None
        and exchange.body_sha256 is not None
    )


def _json_body(store: NativeObservationStore, exchange):
    if not _complete_exchange(exchange):
        return None
    try:
        value = json.loads(store.read_body(exchange.body).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, (dict, list)) else None


def _location(headers: tuple[tuple[str, str], ...]) -> str | None:
    for name, value in headers:
        if name.casefold() == "location" and value:
            return value
    return None


def _android_declarations(
    *,
    document_url: str,
    candidate_index: int,
    exchange_index: int,
    body_sha256: str,
    value: object,
) -> tuple[NativeMobileAssociationDeclaration, ...]:
    if not document_url.endswith("/.well-known/assetlinks.json") or not isinstance(value, list):
        return ()
    declarations = []
    for item in value:
        target = item.get("target") if isinstance(item, dict) else None
        package_name = target.get("package_name") if isinstance(target, dict) else None
        if (
            isinstance(target, dict)
            and target.get("namespace") == "android_app"
            and isinstance(package_name, str)
            and package_name.strip()
        ):
            declarations.append(
                NativeMobileAssociationDeclaration(
                    document_url=document_url,
                    platform="android",
                    package_name=package_name.strip(),
                    candidate_index=candidate_index,
                    exchange_index=exchange_index,
                    body_sha256=body_sha256,
                )
            )
    return tuple(declarations)


def build_native_observation_semantic_evidence(
    store: NativeObservationStore,
) -> NativeObservationSemanticEvidence:
    """Extract direct semantic evidence from one validated published store."""

    if not isinstance(store, NativeObservationStore):
        raise TypeError("native semantic extraction requires a native observation store")
    index = validate_native_observation_store(store.root)
    structured: list[NativeStructuredResponseFact] = []
    redirects: list[NativeRedirectRelationship] = []
    associations: list[NativeMobileAssociationDeclaration] = []
    for candidate_index in index.observation_indices:
        observation = store.load_observation(candidate_index)
        for exchange_index, exchange in enumerate(observation.exchanges):
            parsed_json = _json_body(store, exchange)
            if parsed_json is not None:
                structured.append(
                    NativeStructuredResponseFact(
                        request_url=exchange.request_url,
                        status_code=exchange.status_code,
                        candidate_index=candidate_index,
                        exchange_index=exchange_index,
                        body_sha256=exchange.body_sha256,
                    )
                )
                associations.extend(
                    _android_declarations(
                        document_url=exchange.request_url,
                        candidate_index=candidate_index,
                        exchange_index=exchange_index,
                        body_sha256=exchange.body_sha256,
                        value=parsed_json,
                    )
                )
            if not _complete_exchange(exchange) or exchange.status_code not in REDIRECT_STATUSES:
                continue
            raw_location = _location(exchange.headers)
            target_url = (
                canonical_relationship_url(urljoin(exchange.request_url, raw_location))
                if raw_location is not None
                else None
            )
            source_url = canonical_relationship_url(exchange.request_url)
            if raw_location is not None and source_url is not None and target_url is not None:
                redirects.append(
                    NativeRedirectRelationship(
                        source_url=source_url,
                        raw_location=raw_location,
                        target_url=target_url,
                        candidate_index=candidate_index,
                        exchange_index=exchange_index,
                    )
                )
    return NativeObservationSemanticEvidence(
        structured_responses=tuple(sorted(set(structured), key=lambda value: (
            value.candidate_index, value.exchange_index, value.request_url,
        ))),
        redirect_relationships=tuple(sorted(set(redirects), key=lambda value: (
            value.candidate_index, value.exchange_index, value.source_url,
            value.target_url, value.raw_location,
        ))),
        mobile_association_declarations=tuple(sorted(set(associations), key=lambda value: (
            value.candidate_index, value.exchange_index, value.document_url,
            value.package_name,
        ))),
    )
