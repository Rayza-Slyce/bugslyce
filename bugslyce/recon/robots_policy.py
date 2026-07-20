"""Deterministic eligibility for interpreting retained robots responses."""

from __future__ import annotations

from collections.abc import Iterable

from bugslyce.core.models import Evidence, ProjectState
from bugslyce.recon.route_provenance import canonical_route_url


ROBOTS_RESPONSE_EVIDENCE_TYPES = frozenset(
    {"discovered_path", "http_headers", "robots"}
)


def robots_policy_review_eligible(project_state: ProjectState, url: str) -> bool:
    """Return false only when structured evidence establishes a missing policy."""

    return represented_robots_status_codes(project_state, url) != (404,)


def represented_robots_status_codes(
    project_state: ProjectState,
    url: str,
) -> tuple[int, ...]:
    """Return stable response statuses represented for one robots URL."""

    canonical = canonical_route_url(url)
    if not canonical:
        return ()
    related_evidence_ids = {
        evidence_id
        for path in project_state.discovered_paths
        if canonical_route_url(path.url) == canonical
        for evidence_id in path.evidence_ids
    }
    related_evidence_ids.update(
        evidence_id
        for endpoint in project_state.endpoints
        if canonical_route_url(endpoint.url) == canonical
        for evidence_id in endpoint.evidence_ids
    )
    related_evidence_ids.update(
        evidence_id
        for artefact in project_state.http_artifacts
        if canonical_route_url(artefact.url) == canonical
        for evidence_id in artefact.evidence_ids
    )
    statuses = {
        path.status_code
        for path in project_state.discovered_paths
        if canonical_route_url(path.url) == canonical
        and path.status_code is not None
    }
    statuses.update(
        status
        for evidence in project_state.evidence
        if evidence.id in related_evidence_ids
        and evidence.evidence_type in ROBOTS_RESPONSE_EVIDENCE_TYPES
        and _evidence_matches_url(evidence, canonical)
        if (status := _status_code(evidence)) is not None
    )
    return tuple(sorted(statuses))


def _evidence_matches_url(evidence: Evidence, canonical: str) -> bool:
    candidates: Iterable[object] = (
        evidence.context.get("url"),
        evidence.value
        if evidence.evidence_type in {"discovered_path", "http_headers"}
        else None,
    )
    represented = tuple(
        canonical_route_url(value)
        for value in candidates
        if isinstance(value, str) and value
    )
    return not represented or canonical in represented


def _status_code(evidence: Evidence) -> int | None:
    value = evidence.context.get("status_code")
    return value if isinstance(value, int) else None
