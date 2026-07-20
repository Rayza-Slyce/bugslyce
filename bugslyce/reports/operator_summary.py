"""Deterministic evidence-backed operator summary construction."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from bugslyce.core.models import Candidate, HTTPArtifact, ProjectState
from bugslyce.reports.artifact_classifier import (
    LIKELY_NOISE,
    LIKELY_SIGNAL,
    classify_encoded_artifact,
    classify_http_service_priority,
    effective_candidate_priority,
    is_generic_default_page_text,
)
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.route_provenance import (
    canonical_route_url,
    route_evidence_provenance,
)


REVIEW_TYPE_ORDER = (
    "credential_like_artifact_review",
    "high_port_http_service",
    "multiple_http_services",
)
INTERESTING_SEGMENTS = {
    "admin",
    "login",
    "upload",
    "uploads",
    "backup",
    "old",
    "dev",
    "test",
    "staging",
    "private",
    "secret",
    "hidden",
    "api",
    "portal",
    "dashboard",
    "config",
    "files",
}


@dataclass(frozen=True)
class OperatorSummaryLead:
    """One compact report lead grounded in existing evidence IDs."""

    title: str
    why: str
    endpoints: list[str]
    evidence_ids: list[str]
    next_action: str
    signal: str
    score: int


@dataclass(frozen=True)
class OperatorSummaryNoise:
    """One low-signal item that should not dominate operator attention."""

    title: str
    reason: str
    endpoints: list[str]
    evidence_ids: list[str]


@dataclass(frozen=True)
class OperatorSummary:
    """Derived summary data for the top of the recon pack."""

    review_first: list[OperatorSummaryLead]
    low_signal: list[OperatorSummaryNoise]
    coverage: list[str]


def build_operator_summary(
    project_state: ProjectState,
    candidates: list[Candidate],
    *,
    additional_leads: tuple[OperatorSummaryLead, ...] = (),
) -> OperatorSummary:
    """Build a conservative ranked summary from structured evidence."""

    body_leads = _body_page_leads(project_state)
    leads: list[OperatorSummaryLead] = list(additional_leads)
    candidates_by_type = {
        candidate_type: [
            candidate for candidate in candidates if candidate.candidate_type == candidate_type
        ]
        for candidate_type in REVIEW_TYPE_ORDER
    }
    for candidate_type in REVIEW_TYPE_ORDER:
        for candidate in candidates_by_type[candidate_type]:
            lead = _candidate_service_lead(
                candidate,
                project_state,
            )
            if lead:
                leads.append(lead)

    leads.extend(body_leads)
    encoded_lead = _encoded_artifact_lead(project_state)
    if encoded_lead:
        leads.append(encoded_lead)
    robots_lead = _unusual_robots_lead(project_state)
    if robots_lead:
        leads.append(robots_lead)
    leads.extend(_non_http_service_leads(project_state))

    deduped: dict[tuple[str, tuple[str, ...]], OperatorSummaryLead] = {}
    for lead in leads:
        key = (lead.title, tuple(lead.endpoints))
        current = deduped.get(key)
        if current is None or lead.score > current.score:
            deduped[key] = lead
    ranked = sorted(
        deduped.values(),
        key=lambda item: (-item.score, item.title, item.endpoints),
    )[:8]

    return OperatorSummary(
        review_first=ranked,
        low_signal=_low_signal_items(
            project_state,
            candidates,
        )[:8],
        coverage=_coverage_lines(project_state),
    )


def _candidate_service_lead(
    candidate: Candidate,
    project_state: ProjectState,
) -> OperatorSummaryLead | None:
    if not candidate.evidence_ids:
        return None
    if candidate.candidate_type == "credential_like_artifact_review":
        high_signal = candidate.priority == "high"
        homepage_context = any(urlparse(endpoint).path in {"", "/"} for endpoint in candidate.affected_endpoints)
        return OperatorSummaryLead(
            title=candidate.title,
            why=(
                "Parsed HTML evidence contains a comment referencing credential-like "
                "context and related sensitive keyword hits."
                if high_signal
                else "Parsed HTML evidence contains sensitive keyword context requiring manual review."
            ),
            endpoints=candidate.affected_endpoints,
            evidence_ids=candidate.evidence_ids,
            next_action=(
                "Review the saved HTML/source context manually. Do not submit forms, "
                "brute force, or treat any value as valid without explicit authorisation "
                "and manual validation."
            ),
            signal="high" if high_signal else "medium",
            score=(98 if homepage_context else 96) if high_signal else 84,
        )
    if candidate.candidate_type == "high_port_http_service":
        if _candidate_is_unconfirmed_default_service(
            candidate,
            project_state,
        ):
            return None
        return OperatorSummaryLead(
            title=candidate.title,
            why="A separate HTTP service is recorded on a non-default high port.",
            endpoints=candidate.affected_endpoints,
            evidence_ids=candidate.evidence_ids,
            next_action="Compare its metadata and functionality with other HTTP services before deeper manual review.",
            signal="medium",
            score=85,
        )
    if candidate.candidate_type == "multiple_http_services":
        if effective_candidate_priority(project_state, candidate) == "low":
            return None
        return OperatorSummaryLead(
            title=candidate.title,
            why="Multiple distinct HTTP service origins are recorded for the same host.",
            endpoints=candidate.affected_endpoints,
            evidence_ids=candidate.evidence_ids,
            next_action="Compare titles, technologies, and application behaviour across the service origins.",
            signal="medium",
            score=78,
        )
    return None


def _body_page_leads(project_state: ProjectState) -> list[OperatorSummaryLead]:
    artifacts_by_url: dict[str, list[HTTPArtifact]] = {}
    for artifact in project_state.http_artifacts:
        if artifact.url:
            artifacts_by_url.setdefault(artifact.url, []).append(artifact)
    status_by_url = {path.url: path.status_code for path in project_state.discovered_paths}

    leads: list[OperatorSummaryLead] = []
    for url, artifacts in artifacts_by_url.items():
        parsed = urlparse(url)
        if parsed.path in {"", "/"}:
            continue
        title_artifacts = [item for item in artifacts if item.artifact_type == "page_title"]
        if not title_artifacts:
            continue
        source_names = {Path(item.source_file).name for item in artifacts}
        body_fetch = any(name.startswith("body-fetch-") for name in source_names)
        status = status_by_url.get(url)
        if status != 200 and not body_fetch:
            continue
        evidence_ids = _dedupe(
            evidence_id
            for artifact in artifacts
            for evidence_id in artifact.evidence_ids
        )
        matching_paths = [path for path in project_state.discovered_paths if path.url == url]
        evidence_ids = _dedupe(
            [
                *evidence_ids,
                *(
                    evidence_id
                    for path in matching_paths
                    for evidence_id in path.evidence_ids
                ),
            ]
        )
        if not evidence_ids:
            continue
        title = title_artifacts[0].value
        if is_generic_default_page_text(title):
            continue
        interesting = _interesting_path(parsed.path)
        leads.append(
            OperatorSummaryLead(
                title=f"Fetched application page: {parsed.path or '/'}",
                why=(
                    f"Follow-up evidence records an HTTP 200 response and saved page title "
                    f'"{title}".'
                    if status == 200
                    else f'Saved followed-path HTML records page title "{title}".'
                ),
                endpoints=[url],
                evidence_ids=evidence_ids,
                next_action="Review the saved HTML and linked artefacts in context before escalating any lead.",
                signal="medium" if interesting or body_fetch else "low",
                score=82 if interesting or body_fetch else 58,
            )
        )
    return leads


def _encoded_artifact_lead(project_state: ProjectState) -> OperatorSummaryLead | None:
    artifacts = []
    classifications = []
    for artifact in project_state.http_artifacts:
        if artifact.artifact_type not in {"encoded_like_artifact", "hidden_element"}:
            continue
        classification = classify_encoded_artifact(artifact)
        if classification.category == LIKELY_NOISE:
            continue
        artifacts.append(artifact)
        classifications.append(classification)
    evidence_ids = _dedupe(
        evidence_id for artifact in artifacts for evidence_id in artifact.evidence_ids
    )
    if not evidence_ids:
        return None
    endpoints = _dedupe(artifact.url for artifact in artifacts if artifact.url)
    likely_count = sum(
        classification.category == LIKELY_SIGNAL for classification in classifications
    )
    return OperatorSummaryLead(
        title="Encoded or hidden HTML artefacts require contextual review",
        why=(
            "Saved HTML contains encoded-looking or hidden-element metadata classified as "
            "possible or likely signal. Obvious documentation and default-page noise is "
            "kept in the rabbit-hole section."
        ),
        endpoints=endpoints,
        evidence_ids=evidence_ids,
        next_action="Review surrounding saved HTML before decoding, interpreting, or escalating these artefacts.",
        signal="medium" if likely_count else "low",
        score=68 if likely_count else 52,
    )


def _unusual_robots_lead(project_state: ProjectState) -> OperatorSummaryLead | None:
    artifacts = [
        artifact
        for artifact in project_state.http_artifacts
        if artifact.artifact_type == "unusual_user_agent"
    ]
    evidence_ids = _dedupe(
        evidence_id for artifact in artifacts for evidence_id in artifact.evidence_ids
    )
    if not evidence_ids:
        return None
    return OperatorSummaryLead(
        title="Unusual robots user-agent context",
        why="Collected robots.txt evidence contains a non-default user-agent value.",
        endpoints=_dedupe(artifact.url for artifact in artifacts if artifact.url),
        evidence_ids=evidence_ids,
        next_action="Review the robots content and correlate it with other collected artefacts.",
        signal="low",
        score=48,
    )


def _non_http_service_leads(project_state: ProjectState) -> list[OperatorSummaryLead]:
    leads: list[OperatorSummaryLead] = []
    for service in project_state.port_services:
        if service.state != "open" or "http_service" in service.tags or not service.evidence_ids:
            continue
        service_name = (service.service or "unknown").lower()
        non_standard = (
            service_name == "ssh" and service.port != 22
        ) or (
            service_name == "ftp" and service.port != 21
        ) or (
            service_name == "smtp" and service.port != 25
        )
        label = service.service or "service"
        leads.append(
            OperatorSummaryLead(
                title=f"{label.upper()} service context on {service.port}/{service.protocol}",
                why=(
                    f"An open {label} service is recorded"
                    + (" on a non-standard port." if non_standard else ".")
                ),
                endpoints=[f"{service.host}:{service.port}/{service.protocol}"],
                evidence_ids=service.evidence_ids,
                next_action="Record expected service purpose and version context; do not brute force.",
                signal="low",
                score=45 if non_standard else 38,
            )
        )
    return leads


def _low_signal_items(
    project_state: ProjectState,
    candidates: list[Candidate],
) -> list[OperatorSummaryNoise]:
    items: list[OperatorSummaryNoise] = []
    for candidate in candidates:
        if candidate.candidate_type == "low_signal_static" and candidate.evidence_ids:
            items.append(
                OperatorSummaryNoise(
                    title="Static assets",
                    reason="Treat as low signal unless linked to stronger application context.",
                    endpoints=candidate.affected_endpoints,
                    evidence_ids=candidate.evidence_ids,
                )
            )
        if candidate.candidate_type == "dead_low_signal_path" and candidate.evidence_ids:
            items.append(
                OperatorSummaryNoise(
                    title="404/dead paths",
                    reason="Avoid repeated effort unless new evidence changes the response context.",
                    endpoints=candidate.affected_endpoints,
                    evidence_ids=candidate.evidence_ids,
                )
            )
        if (
            candidate.candidate_type == "high_port_http_service"
            and candidate.evidence_ids
            and _candidate_is_unconfirmed_default_service(
                candidate,
                project_state,
            )
        ):
            items.append(
                OperatorSummaryNoise(
                    title="Generic landing page on a high-port HTTP service",
                    reason=(
                        "The unusual port remains useful surface context, but the "
                        "collected title matches a generic/default landing page and "
                        "has no stronger independent application evidence."
                    ),
                    endpoints=candidate.affected_endpoints,
                    evidence_ids=candidate.evidence_ids,
                )
            )

    forbidden_paths = [
        path
        for path in project_state.discovered_paths
        if path.status_code in {401, 403} and path.evidence_ids
        and not _has_independent_endpoint_reference(project_state, path)
    ]
    if forbidden_paths:
        items.append(
            OperatorSummaryNoise(
                title="Access-controlled path context",
                reason="Keep 401/403 responses as access-control context only unless later evidence changes the signal.",
                endpoints=_dedupe(path.url for path in forbidden_paths),
                evidence_ids=_dedupe(
                    evidence_id
                    for path in forbidden_paths
                    for evidence_id in path.evidence_ids
                ),
            )
        )

    noisy_artifacts = [
        artifact
        for artifact in project_state.http_artifacts
        if artifact.artifact_type in {"encoded_like_artifact", "hidden_element"}
        and classify_encoded_artifact(artifact).category == LIKELY_NOISE
        and artifact.evidence_ids
    ]
    if noisy_artifacts:
        items.append(
            OperatorSummaryNoise(
                title="Encoded detector likely-noise matches",
                reason="Documentation, DTD, default-page, static, or low-diversity matches are classified as likely noise.",
                endpoints=_dedupe(artifact.url for artifact in noisy_artifacts if artifact.url),
                evidence_ids=_dedupe(
                    evidence_id
                    for artifact in noisy_artifacts
                    for evidence_id in artifact.evidence_ids
                ),
            )
        )
    return items


def _candidate_is_unconfirmed_default_service(
    candidate: Candidate,
    project_state: ProjectState,
) -> bool:
    candidate_origins = {
        origin
        for endpoint in candidate.affected_endpoints
        if (origin := http_origin_from_url(endpoint)) is not None
    }
    if not candidate_origins:
        return False
    matching_services = [
        service
        for service in project_state.http_services
        if http_origin_from_url(service.url) in candidate_origins
    ]
    return bool(matching_services) and all(
        classify_http_service_priority(project_state, service.url).priority == "low"
        for service in matching_services
    )


def _coverage_lines(project_state: ProjectState) -> list[str]:
    manifest = project_state.recon_manifest
    artifact_files = [
        artifact.file for artifact in manifest.artifacts
    ] if manifest else project_state.processed_files
    phases: list[str] = []
    phase_markers = (
        ("service discovery", ("nmap-services",)),
        ("HTTP metadata", ("curl-headers-", "robots-", "homepage-")),
        ("discovered-path follow-up", ("curl-headers-followup-",)),
        ("content discovery", ("gobuster-",)),
        ("content-result follow-up", ("curl-headers-content-followup-",)),
        ("selective body fetch", ("body-fetch-",)),
    )
    for label, prefixes in phase_markers:
        if any(Path(name).name.startswith(prefixes) for name in artifact_files):
            phases.append(label)
    open_ports = sum(
        service.state == "open" for service in project_state.port_services
    )
    profile = manifest.profile if manifest and manifest.profile else "not recorded"
    return [
        f"Open TCP ports recorded: {open_ports}",
        f"HTTP services recorded: {len(project_state.http_services)}",
        f"Recon profile: {profile}",
        f"Collected phases visible in evidence: {', '.join(phases) if phases else 'input ingestion only'}",
        "Remaining unknowns require manual validation; absence of evidence is not proof of safety.",
    ]


def _has_independent_endpoint_reference(project_state: ProjectState, path) -> bool:
    return bool(
        route_evidence_provenance(
            project_state,
            path.url,
        ).independent_reference_evidence_ids
    )


def _canonical_summary_url(value: str | None) -> str:
    return canonical_route_url(value)


def _interesting_path(path: str) -> bool:
    segments = {
        token
        for segment in path.strip("/").lower().split("/")
        for token in segment.replace("_", "-").split("-")
        if token
    }
    return bool(segments & INTERESTING_SEGMENTS)


def _dedupe(values) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result
