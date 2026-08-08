"""Deterministic evidence-backed operator summary construction."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from hashlib import sha256
import json
from pathlib import Path
from typing import Protocol, Sequence
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
from bugslyce.recon.deep_http_fingerprint_summary import (
    DeepHttpFingerprintSummary,
    DeepHttpResponseFingerprint,
)
from bugslyce.recon.deep_response_similarity_review import (
    DeepResponseSimilarityGroup,
    DeepResponseSimilarityReview,
)
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.deep_successful_content import (
    SuccessfulDeepContentReview,
    directory_listing_title,
)
from bugslyce.recon.route_provenance import (
    canonical_route_url,
    route_evidence_provenance,
)
from bugslyce.recon.robots_policy import robots_policy_review_eligible


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
    """One canonical ranked lead grounded in existing evidence IDs."""

    title: str
    why: str
    endpoints: list[str]
    evidence_ids: list[str]
    next_action: str
    signal: str
    score: int
    lead_type: str = "operator_summary_lead"
    lead_id: str = field(default="", compare=False)
    rank: int = field(default=0, compare=False)

    @property
    def rationale(self) -> str:
        """Return the canonical rationale without breaking the legacy field name."""

        return self.why

    @property
    def suggested_next_action(self) -> str:
        """Return the canonical action without breaking the legacy field name."""

        return self.next_action


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

    @property
    def ranked_leads(self) -> tuple[OperatorSummaryLead, ...]:
        """Return the immutable canonical ordered lead collection."""

        return tuple(self.review_first)


class DeepSummaryDisclosure(Protocol):
    """Structured Deep disclosure fields used by shared summary assembly."""

    category: str
    urls: Sequence[str]
    final_urls: Sequence[str]
    evidence_ids: Sequence[str]
    observed_values: Sequence[str]
    evidence_excerpt: Sequence[str]


def build_deep_operator_summary_leads(
    disclosures: Sequence[DeepSummaryDisclosure],
    successful_content_reviews: Sequence[SuccessfulDeepContentReview],
    *,
    http_fingerprint_summary: DeepHttpFingerprintSummary | None = None,
    response_similarity_review: DeepResponseSimilarityReview | None = None,
) -> tuple[OperatorSummaryLead, ...]:
    """Build the existing deterministic Deep additions to Operator Summary."""

    leads: list[OperatorSummaryLead] = []
    for disclosure in disclosures:
        source_urls = tuple(disclosure.urls)
        final_urls = tuple(disclosure.final_urls)
        differing_final_urls = tuple(url for url in final_urls if url not in source_urls)
        provenance = ""
        if differing_final_urls:
            provenance = (
                " The request began at "
                + ", ".join(f"`{url}`" for url in source_urls)
                + " and the retained body came from final response URL "
                + ", ".join(f"`{url}`" for url in differing_final_urls)
                + "."
            )
        if disclosure.category == "structured_configuration_body":
            excerpt = "; ".join(disclosure.evidence_excerpt[:3])
            why = (
                "Collected plaintext contains coherent operational configuration "
                f"structure. Bounded excerpt: `{excerpt}`.{provenance}"
            )
            title = "Structured operational configuration observed"
            score = 97
        elif disclosure.category == "structured_json_routes":
            routes = ", ".join(f"`{value}`" for value in disclosure.observed_values[:6])
            why = (
                "A valid collected JSON response directly discloses relative route "
                f"strings: {routes}. No request was generated from these values."
                f"{provenance}"
            )
            title = "Routes disclosed by structured JSON response"
            score = 94
        else:
            continue
        leads.append(
            OperatorSummaryLead(
                title=title,
                why=why,
                endpoints=list(differing_final_urls or source_urls),
                evidence_ids=list(disclosure.evidence_ids),
                next_action=(
                    "Inspect the saved response and correlate the direct values with "
                    "existing route and service evidence. Do not treat the disclosure "
                    "as a vulnerability or request uncollected routes automatically."
                ),
                signal="high",
                score=score,
                lead_type=disclosure.category,
            )
        )

    access_boundary_lead = _distinctive_access_boundary_lead(
        http_fingerprint_summary,
        response_similarity_review,
    )
    if access_boundary_lead is not None:
        leads.append(access_boundary_lead)

    listing_reviews: list[SuccessfulDeepContentReview] = []
    general_reviews: list[SuccessfulDeepContentReview] = []
    for review in successful_content_reviews:
        target = (
            listing_reviews
            if directory_listing_title(review) is not None
            else general_reviews
        )
        target.append(review)
    if listing_reviews:
        listing_count = len(listing_reviews)
        leads.append(
            OperatorSummaryLead(
                title=(
                    "Directory-listing-style response observed"
                    if listing_count == 1
                    else "Directory-listing-style responses observed"
                ),
                why=(
                    f"{listing_count} successful HTML "
                    f"response{'s' if listing_count != 1 else ''} used a "
                    "listing-specific page title that matched the retained response "
                    "path. This is direct response evidence, not a confirmed "
                    "vulnerability."
                ),
                endpoints=sorted(
                    {review.canonical_url for review in listing_reviews if review.canonical_url}
                ),
                evidence_ids=sorted(
                    {
                        evidence_id
                        for review in listing_reviews
                        for evidence_id in review.evidence_ids
                        if evidence_id
                    }
                ),
                next_action=(
                    "Review the retained response metadata and bounded preview offline to "
                    "confirm the listing-style behaviour and intended access. Do not "
                    "re-fetch child paths "
                    "or treat the directory-style response as a vulnerability."
                ),
                signal="direct listing response",
                score=88,
                lead_type="directory_listing_response",
            )
        )

    if general_reviews:
        endpoints = sorted(
            {review.canonical_url for review in general_reviews if review.canonical_url}
        )
        evidence_ids = sorted(
            {
                evidence_id
                for review in general_reviews
                for evidence_id in review.evidence_ids
                if evidence_id
            }
        )
        artefact_references = sorted(
            {
                reference
                for review in general_reviews
                for reference in review.artefact_references
                if reference
            }
        )
        response_count = len(general_reviews)
        verb = "was" if response_count == 1 else "were"
        leads.append(
            OperatorSummaryLead(
                title="Successfully collected Deep content available offline",
                why=(
                    f"{response_count} successful 2xx "
                    f"response{'s' if response_count != 1 else ''} {verb} promoted "
                    "for priority content review from "
                    + ", ".join(f"`{reference}`" for reference in artefact_references)
                    + "."
                ),
                endpoints=endpoints,
                evidence_ids=evidence_ids,
                next_action=(
                    "Use the detailed Human Triage and runbook entries for per-response "
                    "offline review. Do not re-fetch these URLs or treat successful "
                    "collection as a confirmed finding."
                ),
                signal="direct retained response",
                score=72,
                lead_type="successful_deep_content",
            )
        )
    return tuple(leads)


def _distinctive_access_boundary_lead(
    http_summary: DeepHttpFingerprintSummary | None,
    similarity_review: DeepResponseSimilarityReview | None,
) -> OperatorSummaryLead | None:
    if http_summary is None or similarity_review is None:
        return None

    grouped_fingerprint_ids = {
        fingerprint_id
        for group in similarity_review.groups
        for fingerprint_id in group.fingerprint_ids
    }
    candidates: list[tuple[DeepHttpResponseFingerprint, DeepResponseSimilarityGroup]] = []
    for fingerprint in http_summary.fingerprints:
        if (
            fingerprint.status_code not in {401, 403}
            or not fingerprint.evidence_ids
            or fingerprint.body_empty
            or fingerprint.fingerprint_id in grouped_fingerprint_ids
            or not _has_explicit_access_boundary_signal(fingerprint)
        ):
            continue
        contrast = _strongest_same_origin_contrast_group(
            fingerprint,
            similarity_review.groups,
        )
        if contrast is not None:
            candidates.append((fingerprint, contrast))

    if not candidates:
        return None

    ordered = sorted(
        candidates,
        key=lambda item: (
            _canonical_summary_url(item[0].requested_url),
            item[0].status_code,
            item[0].fingerprint_id,
        ),
    )
    endpoints = sorted(
        {
            _canonical_summary_url(fingerprint.requested_url)
            for fingerprint, _group in ordered
            if _canonical_summary_url(fingerprint.requested_url)
        }
    )
    evidence_ids = sorted(
        {
            evidence_id
            for fingerprint, _group in ordered
            for evidence_id in fingerprint.evidence_ids
            if evidence_id
        }
    )
    statuses = sorted({fingerprint.status_code for fingerprint, _group in ordered})
    family_sizes = sorted({group.member_count for _fingerprint, group in ordered})
    count = len(ordered)
    return OperatorSummaryLead(
        title=(
            "Distinctive access-boundary response observed"
            if count == 1
            else "Distinctive access-boundary responses observed"
        ),
        why=(
            f"{count} retained HTTP "
            f"{'/'.join(str(status) for status in statuses)} "
            f"response{'s' if count != 1 else ''} used explicit authentication or "
            "authorisation evidence, remained outside every retained repeated-response "
            "group, and contrasted with a same-origin response family containing at "
            f"least {min(family_sizes)} observations. This is access-boundary and "
            "response-contrast evidence, not evidence of weak access control or a "
            "vulnerability."
        ),
        endpoints=endpoints,
        evidence_ids=evidence_ids,
        next_action=(
            "Review the retained status, title or authentication header and compare it "
            "with the referenced same-origin response family offline. Do not attempt "
            "login, credential testing, access-control bypass, brute force, or form "
            "submission from this lead."
        ),
        signal="distinctive access-boundary response",
        score=86,
        lead_type="distinctive_access_boundary_response",
    )


def _strongest_same_origin_contrast_group(
    fingerprint: DeepHttpResponseFingerprint,
    groups: Sequence[DeepResponseSimilarityGroup],
) -> DeepResponseSimilarityGroup | None:
    origin = http_origin_from_url(fingerprint.requested_url)
    if origin is None:
        return None
    eligible_categories = {
        "exact_body_hash_group",
        "request_reflecting_template_group",
        "candidate_default_template_group",
        "client_error_signature_group",
        "response_signature_group",
    }
    eligible = []
    for group in groups:
        same_origin_urls = {
            url
            for url in group.requested_urls
            if http_origin_from_url(url) == origin
        }
        if (
            group.category in eligible_categories
            and group.member_count >= 3
            and len(same_origin_urls) >= 3
            and fingerprint.status_code not in group.status_codes
        ):
            eligible.append(group)
    if not eligible:
        return None
    return min(
        eligible,
        key=lambda group: (
            -group.member_count,
            group.category,
            group.group_id,
        ),
    )


def _has_explicit_access_boundary_signal(
    fingerprint: DeepHttpResponseFingerprint,
) -> bool:
    header_names = {
        header.name.casefold()
        for header in fingerprint.interesting_headers
        if header.name
    }
    if "www-authenticate" in header_names:
        return True

    title = (fingerprint.title_observed_in_bounded_preview or "").casefold()
    explicit_phrases = (
        "authorization header",
        "authorisation header",
        "authentication required",
        "authentication failed",
        "not authenticated",
        "credentials required",
        "credential required",
        "token required",
        "token missing",
        "missing token",
        "login required",
        "sign in required",
        "permission denied",
        "insufficient permission",
        "insufficient privilege",
        "not authorised",
        "not authorized",
    )
    return any(phrase in title for phrase in explicit_phrases)


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

    normalised = [_normalise_lead_membership(lead) for lead in leads]
    deduped: dict[tuple[str, tuple[str, ...]], OperatorSummaryLead] = {}
    for lead in normalised:
        key = (lead.title, tuple(lead.endpoints))
        current = deduped.get(key)
        if current is None:
            deduped[key] = lead
            continue
        preferred = min(
            (current, lead),
            key=lambda item: (
                -item.score,
                item.lead_type,
                item.why,
                item.next_action,
                item.signal,
            ),
        )
        deduped[key] = replace(
            preferred,
            evidence_ids=sorted(
                {*current.evidence_ids, *lead.evidence_ids},
            ),
        )
    ranked_unfinalised = sorted(
        deduped.values(),
        key=lambda item: (
            -item.score,
            item.title,
            tuple(item.endpoints),
            item.lead_type,
            item.why,
        ),
    )[:8]
    ranked = [
        _finalise_ranked_lead(lead, rank)
        for rank, lead in enumerate(ranked_unfinalised, start=1)
    ]
    promoted_access_boundary_urls = {
        _canonical_summary_url(endpoint)
        for lead in ranked
        if lead.lead_type == "distinctive_access_boundary_response"
        for endpoint in lead.endpoints
        if _canonical_summary_url(endpoint)
    }

    return OperatorSummary(
        review_first=ranked,
        low_signal=_low_signal_items(
            project_state,
            candidates,
            promoted_access_boundary_urls=promoted_access_boundary_urls,
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
            lead_type=candidate.candidate_type,
        )
    if candidate.candidate_type == "high_port_http_service":
        if _candidate_is_unconfirmed_default_service(
            candidate,
            project_state,
        ):
            return None
        candidate_hosts = {
            host
            for endpoint in candidate.affected_endpoints
            if (host := (urlparse(endpoint).hostname or "").lower())
        }
        candidate_origins = {
            origin
            for endpoint in candidate.affected_endpoints
            if (origin := http_origin_from_url(endpoint)) is not None
        }
        recorded_origins = {
            origin
            for service in project_state.http_services
            if (service_host := (urlparse(service.url).hostname or "").lower())
            and service_host in candidate_hosts
            and (origin := http_origin_from_url(service.url)) is not None
        }
        multiple_http_origins = len(recorded_origins | candidate_origins) > 1
        return OperatorSummaryLead(
            title=candidate.title,
            why=(
                "A separate HTTP service is recorded on a non-default high port."
                if multiple_http_origins
                else (
                    "The recorded HTTP service uses a non-default port. Port novelty "
                    "is contextual and does not by itself establish a separate application."
                )
            ),
            endpoints=candidate.affected_endpoints,
            evidence_ids=candidate.evidence_ids,
            next_action=(
                "Compare its metadata and functionality with other HTTP services before deeper manual review."
                if multiple_http_origins
                else (
                    "Review its retained metadata and functionality in context before "
                    "deciding whether it warrants deeper manual review."
                )
            ),
            signal="medium" if multiple_http_origins else "context",
            score=85 if multiple_http_origins else 60,
            lead_type=candidate.candidate_type,
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
            lead_type=candidate.candidate_type,
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
                lead_type="fetched_application_page",
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
        lead_type="encoded_or_hidden_artifact",
    )


def _unusual_robots_lead(project_state: ProjectState) -> OperatorSummaryLead | None:
    artifacts = [
        artifact
        for artifact in project_state.http_artifacts
        if artifact.artifact_type == "unusual_user_agent"
        and robots_policy_review_eligible(project_state, artifact.url)
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
        lead_type="unusual_robots_user_agent",
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
                lead_type="non_http_service_context",
            )
        )
    return leads


def _normalise_lead_membership(lead: OperatorSummaryLead) -> OperatorSummaryLead:
    return replace(
        lead,
        endpoints=sorted({value for value in lead.endpoints if value}),
        evidence_ids=sorted({value for value in lead.evidence_ids if value}),
        lead_id="",
        rank=0,
    )


def _finalise_ranked_lead(
    lead: OperatorSummaryLead,
    rank: int,
) -> OperatorSummaryLead:
    identity = {
        "lead_type": lead.lead_type,
        "title": lead.title,
        "rationale": lead.why,
        "signal": lead.signal,
        "score": lead.score,
        "endpoints": lead.endpoints,
        "evidence_ids": lead.evidence_ids,
        "suggested_next_action": lead.next_action,
    }
    digest = sha256(
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()[:16].upper()
    return replace(lead, lead_id=f"LEAD-{digest}", rank=rank)


def _low_signal_items(
    project_state: ProjectState,
    candidates: list[Candidate],
    *,
    promoted_access_boundary_urls: set[str] | None = None,
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

    promoted_urls = promoted_access_boundary_urls or set()
    forbidden_paths = [
        path
        for path in project_state.discovered_paths
        if path.status_code in {401, 403}
        and path.evidence_ids
        and _canonical_summary_url(path.url) not in promoted_urls
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
