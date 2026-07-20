"""Deterministic route evidence relationships for offline interpretation."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlparse

from bugslyce.core.models import ProjectState


ACCESS_BOUNDARY_STATUS_CODES = frozenset({401, 403})
REQUEST_EVIDENCE_TYPES = frozenset({"discovered_path", "http_headers", "robots"})
INDEPENDENT_REFERENCE_EVIDENCE_TYPES = frozenset(
    {"endpoint", "form", "link", "script_or_asset"}
)


@dataclass(frozen=True)
class RouteEvidenceProvenance:
    """Evidence attached to one canonical route, separated by provenance."""

    canonical_url: str
    request_evidence_ids: tuple[str, ...]
    access_boundary_evidence_ids: tuple[str, ...]
    independent_reference_evidence_ids: tuple[str, ...]
    access_boundary_status_codes: tuple[int, ...]


def route_evidence_provenance(
    project_state: ProjectState,
    url: str,
) -> RouteEvidenceProvenance:
    """Separate repeated request evidence from independent route references."""

    canonical = canonical_route_url(url)
    matching_paths = tuple(
        path
        for path in project_state.discovered_paths
        if canonical_route_url(path.url) == canonical
    )
    matching_endpoints = tuple(
        endpoint
        for endpoint in project_state.endpoints
        if canonical_route_url(endpoint.url) == canonical
    )
    evidence_by_id = {
        evidence.id: evidence
        for evidence in project_state.evidence
        if evidence.id
    }
    endpoint_ids = _unique_sorted(
        evidence_id
        for endpoint in matching_endpoints
        for evidence_id in endpoint.evidence_ids
    )
    path_request_ids = _unique_sorted(
        evidence_id
        for path in matching_paths
        for evidence_id in path.evidence_ids
    )
    semantic_request_ids = _unique_sorted(
        evidence_id
        for evidence_id in endpoint_ids
        if (
            (evidence := evidence_by_id.get(evidence_id)) is not None
            and evidence.evidence_type in REQUEST_EVIDENCE_TYPES
        )
    )
    request_ids = _unique_sorted((*path_request_ids, *semantic_request_ids))
    request_id_set = set(request_ids)
    access_paths = tuple(
        path
        for path in matching_paths
        if path.status_code in ACCESS_BOUNDARY_STATUS_CODES
    )
    semantic_access_ids = _unique_sorted(
        evidence_id
        for evidence_id in semantic_request_ids
        if _evidence_status_code(evidence_by_id[evidence_id])
        in ACCESS_BOUNDARY_STATUS_CODES
    )
    return RouteEvidenceProvenance(
        canonical_url=canonical,
        request_evidence_ids=request_ids,
        access_boundary_evidence_ids=_unique_sorted(
            (
                *(
                    evidence_id
                    for path in access_paths
                    for evidence_id in path.evidence_ids
                ),
                *semantic_access_ids,
            )
        ),
        independent_reference_evidence_ids=tuple(
            evidence_id
            for evidence_id in endpoint_ids
            if evidence_id not in request_id_set
            and (
                (evidence := evidence_by_id.get(evidence_id)) is not None
                and evidence.evidence_type
                in INDEPENDENT_REFERENCE_EVIDENCE_TYPES
            )
        ),
        access_boundary_status_codes=tuple(
            sorted(
                {
                    *(
                        path.status_code
                        for path in access_paths
                        if path.status_code is not None
                    ),
                    *(
                        status
                        for evidence_id in semantic_access_ids
                        if (
                            status := _evidence_status_code(
                                evidence_by_id[evidence_id]
                            )
                        )
                        is not None
                    ),
                }
            )
        ),
    )


def canonical_route_url(value: str | None) -> str:
    """Return a query-free canonical HTTP URL for evidence correlation."""

    if not value:
        return ""
    try:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except (TypeError, ValueError):
        return value.rstrip("/")
    if not scheme or not host:
        return value.rstrip("/")
    default_port = 80 if scheme == "http" else 443 if scheme == "https" else None
    netloc = host if port in {None, default_port} else f"{host}:{port}"
    path = parsed.path or "/"
    return f"{scheme}://{netloc}{path.rstrip('/') or '/'}"


def _unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}))


def _evidence_status_code(evidence) -> int | None:
    value = evidence.context.get("status_code")
    return value if isinstance(value, int) else None
