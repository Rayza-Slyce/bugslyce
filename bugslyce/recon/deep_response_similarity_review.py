"""Offline response similarity review for Deep HTTP fingerprints.

This module groups already-redacted Deep HTTP fingerprint and redirect review
evidence using explicit deterministic signatures. It does not read files, write
files, fetch responses, follow redirects, invoke collectors, or enable Deep
Recon.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from html import escape, unescape
from html.parser import HTMLParser
from itertools import combinations
import json
import re
from urllib.parse import parse_qsl, quote, unquote, urlparse

from bugslyce.recon.deep_http_fingerprint_summary import (
    DeepHttpFingerprintSummary,
    DeepHttpResponseFingerprint,
)
from bugslyce.recon.deep_metadata_collector import (
    MAX_BODY_PREVIEW_CHARS as DEEP_METADATA_BODY_PREVIEW_CHARS,
)
from bugslyce.recon.deep_redirect_auth_flow_review import (
    DeepRedirectAuthFlowObservation,
    DeepRedirectAuthFlowReview,
)
from bugslyce.recon.deep_source_route_collector import (
    MAX_BODY_PREVIEW_CHARS as DEEP_SOURCE_ROUTE_BODY_PREVIEW_CHARS,
)


MAX_RENDERED_VALUES = 6
MAX_RENDERED_VALUE_CHARS = 120
MAX_UNIQUE_SUCCESS_RESPONSES = 12
MIN_REQUEST_REFLECTION_COMPARABLE_CHARS = 320
PERCENT_ESCAPE_RE = re.compile(r"%([0-9A-Fa-f]{2})")
URL_UNRESERVED_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
URL_TOKEN_CHARS = r"A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-"
HTML_REFERENCE_ATTRIBUTE_RE = re.compile(
    r"(?P<prefix>\b(?P<name>href|src|action|formaction)\s*=\s*)"
    r"(?:(?P<quote>['\"])(?P<quoted>.*?)(?P=quote)|"
    r"(?P<unquoted>[^\s'\"=<>`]+))",
    re.IGNORECASE | re.DOTALL,
)
BODY_SIZE_BAND_ORDER = (
    "empty",
    "1-255",
    "256-1023",
    "1024-4095",
    "4096-16383",
    "16384-65535",
    "65536+",
)
GROUP_CATEGORY_ORDER = {
    "exact_body_hash_group": 0,
    "redirect_pattern_group": 1,
    "request_reflecting_template_group": 2,
    "candidate_default_template_group": 3,
    "client_error_signature_group": 4,
    "response_signature_group": 5,
}
PAGE_REVIEW_WEAKENING_GROUP_CATEGORIES = frozenset(
    {
        "exact_body_hash_group",
        "request_reflecting_template_group",
        "candidate_default_template_group",
    }
)
SAFETY_NOTES = (
    "This is offline deterministic grouping of existing HTTP fingerprint evidence.",
    "No network requests were made.",
    "No responses were fetched.",
    "No redirects were followed.",
    "Groups represent shared bounded evidence signatures, not confirmed semantic identity.",
    "Request-reflecting families require sufficient retained HTML preview evidence and exact agreement across every member pair's complete mutually retained safely comparable region after request-specific replacement.",
    "Responses without demonstrated request-derived reflection remain ungrouped by the request-reflecting family rule.",
    "Candidate default/template groups are review hypotheses only.",
    "Unique 2xx responses are comparison context, not findings.",
    "This stage produces static manual-review context only.",
)


@dataclass(frozen=True)
class DeepResponseSimilarityGroup:
    """One conservative response similarity group."""

    group_id: str
    category: str
    title: str
    reason: str
    grouping_signature: tuple[str, ...]
    fingerprint_ids: tuple[str, ...]
    redirect_observation_ids: tuple[str, ...]
    source_repeated_body_group_ids: tuple[str, ...]
    requested_urls: tuple[str, ...]
    status_codes: tuple[int, ...]
    collection_sections: tuple[str, ...]
    body_hashes: tuple[str, ...]
    body_size_bands: tuple[str, ...]
    titles_observed_in_bounded_previews: tuple[str, ...]
    content_types: tuple[str, ...]
    server_families: tuple[str, ...]
    redirect_origin_relationships: tuple[str, ...]
    auth_path_transitions: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    interpretation: str
    representative_fingerprint_id: str | None = None
    representative_requested_url: str | None = None
    member_count: int = 0
    structural_signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeepUniqueSuccessResponse:
    """One ungrouped 2xx response retained for manual comparison."""

    unique_id: str
    fingerprint_id: str
    requested_url: str
    status_code: int
    title_observed_in_bounded_preview: str | None
    content_type: str | None
    server: str | None
    body_sha256: str
    body_bytes: int
    evidence_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class DeepResponseSimilaritySummaryCounts:
    """Immutable summary counts for response similarity review."""

    total_http_fingerprints_considered: int
    total_redirect_observations_considered: int
    exact_body_hash_groups: int
    redirect_pattern_groups: int
    repeated_auth_looking_redirect_groups: int
    candidate_default_template_groups: int
    client_error_signature_groups: int
    general_response_signature_groups: int
    total_grouped_fingerprints: int
    unique_ungrouped_2xx_responses: int
    responses_in_multiple_retained_groups: int
    request_reflecting_template_groups: int = 0


@dataclass(frozen=True)
class DeepResponseSimilarityReview:
    """Offline response similarity and noise-reduction review."""

    groups: tuple[DeepResponseSimilarityGroup, ...]
    unique_success_responses: tuple[DeepUniqueSuccessResponse, ...]
    summary_counts: DeepResponseSimilaritySummaryCounts
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class _PendingGroup:
    category: str
    title: str
    reason: str
    grouping_signature: tuple[str, ...]
    fingerprint_ids: tuple[str, ...]
    redirect_observation_ids: tuple[str, ...]
    source_repeated_body_group_ids: tuple[str, ...]
    requested_urls: tuple[str, ...]
    status_codes: tuple[int, ...]
    collection_sections: tuple[str, ...]
    body_hashes: tuple[str, ...]
    body_size_bands: tuple[str, ...]
    titles_observed_in_bounded_previews: tuple[str, ...]
    content_types: tuple[str, ...]
    server_families: tuple[str, ...]
    redirect_origin_relationships: tuple[str, ...]
    auth_path_transitions: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    interpretation: str
    representative_fingerprint_id: str
    representative_requested_url: str
    member_count: int
    structural_signals: tuple[str, ...]


@dataclass(frozen=True)
class _RequestReflectingEvidence:
    fingerprint: DeepHttpResponseFingerprint
    coarse_signature: tuple[str, ...]
    normalised_preview: str
    retained_preview_chars: int
    preview_truncated: bool
    reference_signature: tuple[str, ...]


def build_deep_response_similarity_review(
    http_summary: DeepHttpFingerprintSummary,
    redirect_review: DeepRedirectAuthFlowReview,
) -> DeepResponseSimilarityReview:
    """Build a deterministic response similarity review from 90A and 90B models."""

    fingerprints_by_id = {item.fingerprint_id: item for item in http_summary.fingerprints}
    pending = [
        *_exact_body_hash_groups(http_summary, fingerprints_by_id),
        *_redirect_pattern_groups(redirect_review, fingerprints_by_id),
        *_request_reflecting_template_groups(http_summary.fingerprints),
        *_response_signature_groups(http_summary.fingerprints),
        *_client_error_signature_groups(http_summary.fingerprints),
        *_candidate_default_template_groups(http_summary.fingerprints),
    ]
    groups = _assign_group_ids(_order_and_suppress_duplicates(pending))
    grouped_fingerprint_ids = {
        fingerprint_id
        for group in groups
        for fingerprint_id in group.fingerprint_ids
    }
    unique_successes = _unique_success_responses(
        http_summary.fingerprints,
        grouped_fingerprint_ids,
    )
    return DeepResponseSimilarityReview(
        groups=groups,
        unique_success_responses=unique_successes,
        summary_counts=_summary_counts(
            total_fingerprints=len(http_summary.fingerprints),
            total_redirect_observations=len(redirect_review.observations),
            groups=groups,
            unique_successes=unique_successes,
        ),
        safety_notes=SAFETY_NOTES,
    )


def render_deep_response_similarity_review_markdown(
    review: DeepResponseSimilarityReview,
) -> str:
    """Render response similarity review as terminal-friendly Markdown."""

    counts = review.summary_counts
    lines = [
        "## Deep Response Similarity Review",
        "",
        "This is offline deterministic grouping of existing HTTP fingerprint "
        "evidence. No network requests were made, no responses were fetched, "
        "and no redirects were followed.",
        "",
        "### Summary",
        "",
        f"- HTTP fingerprints considered: {counts.total_http_fingerprints_considered}",
        f"- Redirect observations considered: {counts.total_redirect_observations_considered}",
        f"- Exact body hash groups: {counts.exact_body_hash_groups}",
        f"- Redirect pattern groups: {counts.redirect_pattern_groups}",
        "- Request-reflecting template groups: "
        f"{counts.request_reflecting_template_groups}",
        "- Repeated auth-looking redirect groups: "
        f"{counts.repeated_auth_looking_redirect_groups}",
        "- Candidate default/template groups: "
        f"{counts.candidate_default_template_groups}",
        f"- Client-error signature groups: {counts.client_error_signature_groups}",
        "- General response signature groups: "
        f"{counts.general_response_signature_groups}",
        f"- Grouped fingerprints: {counts.total_grouped_fingerprints}",
        "- Unique ungrouped 2xx responses: "
        f"{counts.unique_ungrouped_2xx_responses}",
        "- Responses in multiple retained groups: "
        f"{counts.responses_in_multiple_retained_groups}",
        "",
        "### Response Similarity Groups",
        "",
    ]
    if review.groups:
        for group in review.groups:
            lines.extend(_render_group(group))
    else:
        lines.append("- None.")

    lines.extend(["", "### Unique Ungrouped 2xx Responses", ""])
    if review.unique_success_responses:
        for unique in review.unique_success_responses:
            lines.extend(_render_unique_success(unique))
    else:
        lines.append("- None.")

    lines.extend(
        [
            "",
            "### Grouping Interpretation Notes",
            "",
            "- Groups represent shared bounded evidence signatures, not confirmed semantic identity.",
            "- Request-reflecting families require sufficient retained HTML preview evidence and exact agreement across every member pair's complete mutually retained safely comparable region after request-specific replacement.",
            "- Responses without demonstrated request-derived reflection remain ungrouped by the request-reflecting family rule.",
            "- Candidate default/template groups are review hypotheses only.",
            "- Unique 2xx responses are comparison context, not findings.",
            "- Query values, fragments, URL credentials, and cookie values are not used.",
            "",
            "### Safety Notes",
            "",
        ]
    )
    lines.extend(f"- {note}" for note in review.safety_notes)
    lines.append("")
    return "\n".join(lines).rstrip()


def _exact_body_hash_groups(
    http_summary: DeepHttpFingerprintSummary,
    fingerprints_by_id: dict[str, DeepHttpResponseFingerprint],
) -> tuple[_PendingGroup, ...]:
    groups: list[_PendingGroup] = []
    for repeated in http_summary.repeated_body_groups:
        fingerprints = tuple(
            fingerprints_by_id[fingerprint_id]
            for fingerprint_id in repeated.fingerprint_ids
            if fingerprint_id in fingerprints_by_id
        )
        if len(fingerprints) < 2:
            continue
        groups.append(
            _group_from_fingerprints(
                category="exact_body_hash_group",
                title="Exact repeated non-empty body hash",
                reason="90A reported an exact repeated non-empty body hash.",
                signature=(f"body_sha256={repeated.body_sha256}",),
                fingerprints=fingerprints,
                source_repeated_body_group_ids=(repeated.repeated_body_id,),
                interpretation=(
                    "Exact body hash reuse is shared byte-level evidence, not "
                    "confirmed semantic identity."
                ),
            )
        )
    return tuple(groups)


def _redirect_pattern_groups(
    redirect_review: DeepRedirectAuthFlowReview,
    fingerprints_by_id: dict[str, DeepHttpResponseFingerprint],
) -> tuple[_PendingGroup, ...]:
    grouped: dict[tuple, list[DeepRedirectAuthFlowObservation]] = {}
    for observation in redirect_review.observations:
        key = _redirect_signature(observation)
        grouped.setdefault(key, []).append(observation)

    groups: list[_PendingGroup] = []
    for key, observations in grouped.items():
        if len(observations) < 2:
            continue
        fingerprints = tuple(
            fingerprints_by_id[observation.source_fingerprint_id]
            for observation in observations
            if observation.source_fingerprint_id is not None
            and observation.source_fingerprint_id in fingerprints_by_id
        )
        if len(fingerprints) < 2:
            continue
        groups.append(
            _group_from_fingerprints(
                category="redirect_pattern_group",
                title="Repeated redirect evidence pattern",
                reason="Redirect observations share the same safe one-hop signature.",
                signature=tuple(str(part) for part in key),
                fingerprints=fingerprints,
                redirect_observation_ids=tuple(
                    observation.observation_id for observation in observations
                ),
                redirect_origin_relationships=tuple(
                    _unique_sorted(
                        [
                            observation.origin_relationship
                            for observation in observations
                        ]
                    )
                ),
                auth_path_transitions=tuple(
                    _unique_sorted(
                        [
                            observation.auth_path_transition
                            for observation in observations
                        ]
                    )
                ),
                interpretation=(
                    "Repeated redirect pattern uses safe one-hop evidence only; "
                    "no redirect was followed."
                ),
            )
        )
    return tuple(groups)


def _response_signature_groups(
    fingerprints: tuple[DeepHttpResponseFingerprint, ...],
) -> tuple[_PendingGroup, ...]:
    grouped: dict[tuple, list[DeepHttpResponseFingerprint]] = {}
    for fingerprint in fingerprints:
        if 400 <= fingerprint.status_code <= 499:
            continue
        key = _response_signature(fingerprint)
        if not _has_meaningful_response_signature(key):
            continue
        grouped.setdefault(key, []).append(fingerprint)

    return tuple(
        _group_from_fingerprints(
            category="response_signature_group",
            title="Repeated response signature",
            reason="Responses share a conservative metadata-only response signature.",
            signature=tuple(str(part) for part in key),
            fingerprints=tuple(values),
            interpretation=(
                "Shared response signature is bounded metadata evidence only, "
                "not confirmed semantic identity."
            ),
        )
        for key, values in grouped.items()
        if len(values) >= 2
    )


def _client_error_signature_groups(
    fingerprints: tuple[DeepHttpResponseFingerprint, ...],
) -> tuple[_PendingGroup, ...]:
    grouped: dict[tuple, list[DeepHttpResponseFingerprint]] = {}
    for fingerprint in fingerprints:
        if not 400 <= fingerprint.status_code <= 499:
            continue
        key = _client_error_signature(fingerprint)
        if not _has_meaningful_client_error_signature(key):
            continue
        grouped.setdefault(key, []).append(fingerprint)

    return tuple(
        _group_from_fingerprints(
            category="client_error_signature_group",
            title="Repeated client-error response signature",
            reason="Repeated client-error response signature observed across multiple URLs.",
            signature=tuple(str(part) for part in key),
            fingerprints=tuple(values),
            interpretation=(
                "Repeated 4xx response signature is review context only; this "
                "is not a default-page conclusion."
            ),
        )
        for key, values in grouped.items()
        if len(values) >= 2
    )


def _candidate_default_template_groups(
    fingerprints: tuple[DeepHttpResponseFingerprint, ...],
) -> tuple[_PendingGroup, ...]:
    grouped: dict[tuple, list[DeepHttpResponseFingerprint]] = {}
    for fingerprint in fingerprints:
        if 400 <= fingerprint.status_code <= 499:
            continue
        key = _response_signature(fingerprint)
        if not _has_template_candidate_signature(fingerprint):
            continue
        grouped.setdefault(key, []).append(fingerprint)

    groups: list[_PendingGroup] = []
    for key, values in grouped.items():
        distinct_urls = {_safe_requested_url(fingerprint.requested_url) for fingerprint in values}
        if len(values) < 2 or len(distinct_urls) < 2:
            continue
        groups.append(
            _group_from_fingerprints(
                category="candidate_default_template_group",
                title="Candidate repeated response template",
                reason=(
                    "Multiple distinct URLs share a strong bounded response "
                    "signature; treat as a candidate repeated template/default "
                    "pattern only."
                ),
                signature=tuple(str(part) for part in key),
                fingerprints=tuple(values),
                interpretation=(
                    "Candidate default/template grouping is a review hypothesis, "
                    "not proof of a default page."
                ),
            )
        )
    return tuple(groups)


def _request_reflecting_template_groups(
    fingerprints: tuple[DeepHttpResponseFingerprint, ...],
) -> tuple[_PendingGroup, ...]:
    grouped: dict[tuple[str, ...], list[_RequestReflectingEvidence]] = {}
    for fingerprint in fingerprints:
        evidence = _request_reflecting_evidence(fingerprint)
        if evidence is None:
            continue
        key = (*evidence.coarse_signature, *evidence.reference_signature)
        grouped.setdefault(key, []).append(evidence)

    groups: list[_PendingGroup] = []
    for key in sorted(grouped):
        for family in _partition_request_reflecting_evidence(grouped[key]):
            comparison = _complete_comparable_signature(family)
            if comparison is None:
                continue
            signature, structural_signals = comparison
            fingerprints_in_family = tuple(item.fingerprint for item in family)
            distinct_urls = {
                _safe_requested_url(fingerprint.requested_url)
                for fingerprint in fingerprints_in_family
            }
            if len(fingerprints_in_family) < 2 or len(distinct_urls) < 2:
                continue
            groups.append(
                _group_from_fingerprints(
                    category="request_reflecting_template_group",
                    title="Repeated request-reflecting response template",
                    reason=(
                        f"{len(fingerprints_in_family)} collected response records "
                        "share one stable request-reflecting template across every "
                        "pairwise safely comparable bounded region."
                    ),
                    signature=signature,
                    fingerprints=fingerprints_in_family,
                    structural_signals=structural_signals,
                    interpretation=(
                        "Request-derived text was replaced only for this offline "
                        "comparison. Every member pair agrees exactly across its "
                        "complete mutually retained safely comparable region; "
                        "unavailable content beyond a truncated preview is not "
                        "assumed identical. The family is response-similarity "
                        "context, not a route-validity, soft-404, vulnerability, "
                        "or server-defect conclusion."
                    ),
                )
            )
    return tuple(groups)


def _partition_request_reflecting_evidence(
    values: list[_RequestReflectingEvidence],
) -> tuple[tuple[_RequestReflectingEvidence, ...], ...]:
    families: list[list[_RequestReflectingEvidence]] = []
    for candidate in sorted(values, key=_request_reflecting_evidence_sort_key):
        for family in families:
            if all(
                _pairwise_comparable_signature(candidate, member) is not None
                for member in family
            ):
                family.append(candidate)
                break
        else:
            families.append([candidate])
    return tuple(tuple(family) for family in families)


def _group_from_fingerprints(
    *,
    category: str,
    title: str,
    reason: str,
    signature: tuple[str, ...],
    fingerprints: tuple[DeepHttpResponseFingerprint, ...],
    interpretation: str,
    redirect_observation_ids: tuple[str, ...] = (),
    source_repeated_body_group_ids: tuple[str, ...] = (),
    redirect_origin_relationships: tuple[str, ...] = (),
    auth_path_transitions: tuple[str, ...] = (),
    structural_signals: tuple[str, ...] = (),
) -> _PendingGroup:
    representative = min(fingerprints, key=_representative_sort_key)
    return _PendingGroup(
        category=category,
        title=title,
        reason=reason,
        grouping_signature=signature,
        fingerprint_ids=tuple(
            _unique_sorted([item.fingerprint_id for item in fingerprints])
        ),
        redirect_observation_ids=tuple(_unique_sorted(list(redirect_observation_ids))),
        source_repeated_body_group_ids=tuple(
            _unique_sorted(list(source_repeated_body_group_ids))
        ),
        requested_urls=tuple(
            _unique_sorted(
                [_safe_requested_url(item.requested_url) for item in fingerprints]
            )
        ),
        status_codes=tuple(sorted({item.status_code for item in fingerprints})),
        collection_sections=tuple(
            _unique_sorted([item.collection_section for item in fingerprints])
        ),
        body_hashes=tuple(
            _unique_sorted(
                [item.body_sha256 for item in fingerprints if item.body_sha256]
            )
        ),
        body_size_bands=tuple(
            _sort_body_size_bands(
                [_body_size_band(item.body_bytes) for item in fingerprints]
            )
        ),
        titles_observed_in_bounded_previews=tuple(
            _unique_sorted_ci(
                [
                    item.title_observed_in_bounded_preview
                    for item in fingerprints
                    if item.title_observed_in_bounded_preview
                ]
            )
        ),
        content_types=tuple(
            _unique_sorted(
                [
                    _normalise_content_type(item.content_type)
                    for item in fingerprints
                    if item.content_type
                ]
            )
        ),
        server_families=tuple(
            _unique_sorted(
                [
                    _normalise_server_family(item.server)
                    for item in fingerprints
                    if item.server
                ]
            )
        ),
        redirect_origin_relationships=tuple(
            _unique_sorted(list(redirect_origin_relationships))
        ),
        auth_path_transitions=tuple(_unique_sorted(list(auth_path_transitions))),
        evidence_ids=tuple(
            _unique_sorted(
                [
                    evidence_id
                    for item in fingerprints
                    for evidence_id in item.evidence_ids
                ]
            )
        ),
        interpretation=interpretation,
        representative_fingerprint_id=representative.fingerprint_id,
        representative_requested_url=_safe_requested_url(
            representative.requested_url
        ),
        member_count=len(fingerprints),
        structural_signals=structural_signals,
    )


def _order_and_suppress_duplicates(
    pending: list[_PendingGroup],
) -> tuple[_PendingGroup, ...]:
    best_by_fingerprint_set: dict[frozenset[str], _PendingGroup] = {}
    redirects: list[_PendingGroup] = []
    for group in pending:
        if group.category == "redirect_pattern_group":
            redirects.append(group)
            continue
        key = frozenset(group.fingerprint_ids)
        existing = best_by_fingerprint_set.get(key)
        if existing is None or _duplicate_precedence(group) < _duplicate_precedence(existing):
            best_by_fingerprint_set[key] = group

    retained = [*redirects, *best_by_fingerprint_set.values()]
    return tuple(sorted(retained, key=_group_sort_key))


def _assign_group_ids(groups: tuple[_PendingGroup, ...]) -> tuple[DeepResponseSimilarityGroup, ...]:
    return tuple(
        DeepResponseSimilarityGroup(
            group_id=_group_id(group, index),
            category=group.category,
            title=group.title,
            reason=group.reason,
            grouping_signature=group.grouping_signature,
            fingerprint_ids=group.fingerprint_ids,
            redirect_observation_ids=group.redirect_observation_ids,
            source_repeated_body_group_ids=group.source_repeated_body_group_ids,
            requested_urls=group.requested_urls,
            status_codes=group.status_codes,
            collection_sections=group.collection_sections,
            body_hashes=group.body_hashes,
            body_size_bands=group.body_size_bands,
            titles_observed_in_bounded_previews=group.titles_observed_in_bounded_previews,
            content_types=group.content_types,
            server_families=group.server_families,
            redirect_origin_relationships=group.redirect_origin_relationships,
            auth_path_transitions=group.auth_path_transitions,
            evidence_ids=group.evidence_ids,
            interpretation=group.interpretation,
            representative_fingerprint_id=group.representative_fingerprint_id,
            representative_requested_url=group.representative_requested_url,
            member_count=group.member_count,
            structural_signals=group.structural_signals,
        )
        for index, group in enumerate(groups, start=1)
    )


def _unique_success_responses(
    fingerprints: tuple[DeepHttpResponseFingerprint, ...],
    grouped_fingerprint_ids: set[str],
) -> tuple[DeepUniqueSuccessResponse, ...]:
    candidates = sorted(
        (
            fingerprint
            for fingerprint in fingerprints
            if 200 <= fingerprint.status_code <= 299
            and fingerprint.fingerprint_id not in grouped_fingerprint_ids
        ),
        key=lambda item: (
            _safe_requested_url(item.requested_url),
            item.fingerprint_id,
            item.status_code,
            item.body_sha256,
        ),
    )[:MAX_UNIQUE_SUCCESS_RESPONSES]
    return tuple(
        DeepUniqueSuccessResponse(
            unique_id=f"DEEP-SIM-UNIQ-{index:04d}",
            fingerprint_id=fingerprint.fingerprint_id,
            requested_url=_safe_requested_url(fingerprint.requested_url),
            status_code=fingerprint.status_code,
            title_observed_in_bounded_preview=fingerprint.title_observed_in_bounded_preview,
            content_type=fingerprint.content_type,
            server=fingerprint.server,
            body_sha256=fingerprint.body_sha256,
            body_bytes=fingerprint.body_bytes,
            evidence_ids=tuple(_unique_sorted(list(fingerprint.evidence_ids))),
            reason="Unique collected 2xx response signature retained for manual comparison.",
        )
        for index, fingerprint in enumerate(candidates, start=1)
    )


def _summary_counts(
    *,
    total_fingerprints: int,
    total_redirect_observations: int,
    groups: tuple[DeepResponseSimilarityGroup, ...],
    unique_successes: tuple[DeepUniqueSuccessResponse, ...],
) -> DeepResponseSimilaritySummaryCounts:
    fingerprint_memberships: dict[str, int] = {}
    for group in groups:
        for fingerprint_id in group.fingerprint_ids:
            fingerprint_memberships[fingerprint_id] = fingerprint_memberships.get(fingerprint_id, 0) + 1
    return DeepResponseSimilaritySummaryCounts(
        total_http_fingerprints_considered=total_fingerprints,
        total_redirect_observations_considered=total_redirect_observations,
        exact_body_hash_groups=_count_category(groups, "exact_body_hash_group"),
        redirect_pattern_groups=_count_category(groups, "redirect_pattern_group"),
        repeated_auth_looking_redirect_groups=sum(
            1
            for group in groups
            if group.category == "redirect_pattern_group"
            and any(
                transition != "no_auth_path_signal"
                for transition in group.auth_path_transitions
            )
        ),
        candidate_default_template_groups=_count_category(
            groups,
            "candidate_default_template_group",
        ),
        client_error_signature_groups=_count_category(groups, "client_error_signature_group"),
        general_response_signature_groups=_count_category(groups, "response_signature_group"),
        total_grouped_fingerprints=len(fingerprint_memberships),
        unique_ungrouped_2xx_responses=len(unique_successes),
        responses_in_multiple_retained_groups=sum(
            1 for count in fingerprint_memberships.values() if count > 1
        ),
        request_reflecting_template_groups=_count_category(
            groups,
            "request_reflecting_template_group",
        ),
    )


def _request_reflecting_evidence(
    fingerprint: DeepHttpResponseFingerprint,
) -> _RequestReflectingEvidence | None:
    preview = fingerprint.bounded_body_preview
    media_type = _normalise_content_type(fingerprint.content_type)
    origin = _canonical_origin(fingerprint.requested_url)
    if (
        fingerprint.body_empty
        or len(preview) < MIN_REQUEST_REFLECTION_COMPARABLE_CHARS
        or media_type not in {"text/html", "application/xhtml+xml"}
        or origin is None
        or fingerprint.redirect_location is not None
        or _safe_requested_url(fingerprint.final_url)
        != _safe_requested_url(fingerprint.requested_url)
    ):
        return None

    variants = _request_reflection_variants(fingerprint.requested_url)
    if not variants:
        return None
    request_normalised_preview, preview_replacements = _replace_request_reflections(
        preview,
        variants,
    )
    title = fingerprint.title_observed_in_bounded_preview
    normalised_title, title_replacements = _replace_request_reflections(
        title or "",
        variants,
    )
    if preview_replacements == 0 or title_replacements == 0:
        return None

    reference_evidence = _safe_html_reference_evidence(
        request_normalised_preview,
        fingerprint.requested_url,
    )
    if reference_evidence is None:
        return None
    normalised_preview, retained_references = reference_evidence
    if len(normalised_preview) < MIN_REQUEST_REFLECTION_COMPARABLE_CHARS:
        return None
    html_structure = _html_structure_signature(normalised_preview)
    if len(html_structure) < 4 or not any(
        event.startswith("start:title[") for event in html_structure
    ):
        return None
    return _RequestReflectingEvidence(
        fingerprint=fingerprint,
        coarse_signature=(
            f"origin={origin}",
            f"method={fingerprint.method.upper()}",
            f"status={fingerprint.status_code}",
            f"content_type={media_type}",
            f"server_family={_normalise_server_family(fingerprint.server)}",
            f"body_size_band={_body_size_band(fingerprint.body_bytes)}",
            f"normalised_title={_normalise_title(normalised_title)}",
        ),
        normalised_preview=normalised_preview,
        retained_preview_chars=len(preview),
        preview_truncated=_preview_is_boundary_limited(fingerprint, preview),
        reference_signature=retained_references,
    )


def _preview_is_boundary_limited(
    fingerprint: DeepHttpResponseFingerprint,
    preview: str,
) -> bool:
    limits = {
        "metadata_collection": DEEP_METADATA_BODY_PREVIEW_CHARS,
        "source_route_collection": DEEP_SOURCE_ROUTE_BODY_PREVIEW_CHARS,
    }
    limit = limits.get(
        fingerprint.collection_section,
        min(DEEP_METADATA_BODY_PREVIEW_CHARS, DEEP_SOURCE_ROUTE_BODY_PREVIEW_CHARS),
    )
    return len(preview) >= limit


def _complete_comparable_signature(
    values: tuple[_RequestReflectingEvidence, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    if len(values) < 2:
        return None
    pairwise_proofs = tuple(
        proof
        for left, right in combinations(values, 2)
        if (proof := _pairwise_comparable_signature(left, right)) is not None
    )
    expected_pair_count = len(values) * (len(values) - 1) // 2
    if len(pairwise_proofs) != expected_pair_count:
        return None

    comparable_lengths = tuple(int(proof[0]) for proof in pairwise_proofs)
    truncated = values[0].preview_truncated
    retained_boundary_signature = (
        "truncated_chars=" + str(values[0].retained_preview_chars)
        if truncated
        else "complete"
    )
    retained_boundary_signal = (
        "equivalent raw retained preview boundary"
        if truncated
        else "complete retained previews"
    )
    canonical_pairwise_proofs = tuple(sorted(pairwise_proofs))
    pairwise_proof_digest = sha256(
        json.dumps(
            canonical_pairwise_proofs,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    signature = (
        *values[0].coarse_signature,
        "retained_preview_boundary=" + retained_boundary_signature,
        f"member_count={len(values)}",
        f"pairwise_comparisons={expected_pair_count}",
        "pairwise_comparable_chars="
        + f"{min(comparable_lengths)}-{max(comparable_lengths)}",
        "pairwise_proof_sha256=" + pairwise_proof_digest,
        "retained_html_references=" + json.dumps(
            values[0].reference_signature,
            ensure_ascii=True,
            separators=(",", ":"),
        ),
    )
    return signature, (
        "same canonical origin",
        "same request method",
        "same HTTP status",
        "compatible HTML content type",
        "same server-family observation",
        "same bounded body-size band",
        "direct response without retained redirect evidence",
        "request-derived reflection replaced",
        retained_boundary_signal,
        f"all {expected_pair_count} member pairs exactly match across each complete mutually retained normalised region",
        "same HTML structure across every pairwise comparable region",
        "same redacted structural HTML-reference signature",
    )


def _pairwise_comparable_signature(
    left: _RequestReflectingEvidence,
    right: _RequestReflectingEvidence,
) -> tuple[str, ...] | None:
    if (
        left.coarse_signature != right.coarse_signature
        or left.reference_signature != right.reference_signature
        or left.preview_truncated != right.preview_truncated
        or (
            left.preview_truncated
            and left.retained_preview_chars != right.retained_preview_chars
        )
    ):
        return None

    comparable_chars = min(
        len(left.normalised_preview),
        len(right.normalised_preview),
    )
    if comparable_chars < MIN_REQUEST_REFLECTION_COMPARABLE_CHARS:
        return None
    left_region = left.normalised_preview[:comparable_chars]
    right_region = right.normalised_preview[:comparable_chars]
    if left_region != right_region:
        return None
    if not left.preview_truncated and left.normalised_preview != right.normalised_preview:
        return None

    left_structure = _html_structure_signature(left_region)
    right_structure = _html_structure_signature(right_region)
    if len(left_structure) < 4 or left_structure != right_structure:
        return None
    return (
        str(comparable_chars),
        sha256(left_region.encode("utf-8")).hexdigest(),
        sha256(
            json.dumps(
                left_structure,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest(),
    )


def _request_reflecting_evidence_sort_key(
    evidence: _RequestReflectingEvidence,
) -> tuple[object, ...]:
    fingerprint = evidence.fingerprint
    return (
        _safe_requested_url(fingerprint.requested_url),
        fingerprint.method.upper(),
        fingerprint.status_code,
        fingerprint.fingerprint_id,
        fingerprint.body_sha256,
        tuple(sorted(fingerprint.evidence_ids)),
    )


def _canonical_origin(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        port = parsed.port
    except ValueError:
        return None
    effective_port = port or (443 if parsed.scheme.lower() == "https" else 80)
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{parsed.scheme.lower()}://{host}:{effective_port}"


def _request_reflection_variants(requested_url: str) -> tuple[str, ...]:
    try:
        parsed = urlparse(requested_url)
    except ValueError:
        return ()
    candidates = [requested_url, parsed.path]
    decoded_path = _unambiguous_percent_decoded_path(parsed.path)
    if decoded_path is not None:
        candidates.append(decoded_path)
    candidates.extend(escape(value, quote=False) for value in tuple(candidates))
    return tuple(
        sorted(
            {
                value
                for value in candidates
                if value and value != "/" and len(value) >= 2
            },
            key=lambda value: (-len(value), value),
        )
    )


def _unambiguous_percent_decoded_path(value: str) -> str | None:
    matches = tuple(PERCENT_ESCAPE_RE.finditer(value))
    if (
        not matches
        or re.search(r"%(?![0-9A-Fa-f]{2})", value)
        or any(
            chr(int(match.group(1), 16)) not in URL_UNRESERVED_CHARS
            for match in matches
        )
    ):
        return None
    decoded = unquote(value, errors="strict")
    if not decoded.startswith("/") or any(ord(character) < 32 for character in decoded):
        return None
    return decoded


def _replace_request_reflections(
    value: str,
    variants: tuple[str, ...],
) -> tuple[str, int]:
    rendered = value
    replacements = 0
    for variant in variants:
        pattern = re.compile(
            rf"(?<![{URL_TOKEN_CHARS}]){re.escape(variant)}(?![{URL_TOKEN_CHARS}])"
        )
        rendered, count = pattern.subn("{REQUEST}", rendered)
        replacements += count
    return rendered, replacements


class _HtmlStructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.events: list[str] = []
        self.references: list[tuple[str, str]] = []
        self.raw_start_tags: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        names = ",".join(sorted(name.lower() for name, _value in attrs))
        self.events.append(f"start:{tag.lower()}[{names}]")
        self.raw_start_tags.append(self.get_starttag_text())
        self.references.extend(
            (name.lower(), value)
            for name, value in attrs
            if name.lower() in {"action", "formaction", "href", "src"}
            and value is not None
        )

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        names = ",".join(sorted(name.lower() for name, _value in attrs))
        self.events.append(f"empty:{tag.lower()}[{names}]")
        self.raw_start_tags.append(self.get_starttag_text())
        self.references.extend(
            (name.lower(), value)
            for name, value in attrs
            if name.lower() in {"action", "formaction", "href", "src"}
            and value is not None
        )

    def handle_endtag(self, tag: str) -> None:
        self.events.append(f"end:{tag.lower()}")


def _html_structure_signature(value: str) -> tuple[str, ...]:
    parser = _HtmlStructureParser()
    try:
        parser.feed(value)
    except (AssertionError, ValueError):
        return ()
    return tuple(parser.events)


def _safe_html_reference_evidence(
    value: str,
    requested_url: str,
) -> tuple[str, tuple[str, ...]] | None:
    parser = _HtmlStructureParser()
    try:
        parser.feed(value)
    except (AssertionError, ValueError):
        return None
    safe_references: list[str] = []
    for attribute, reference in parser.references:
        safe = _safe_html_reference(attribute, reference, requested_url)
        if safe is None:
            return None
        safe_references.append(safe)
    normalised = _replace_html_reference_attributes(
        value,
        parser.raw_start_tags,
        requested_url,
        expected_reference_count=len(parser.references),
    )
    if normalised is None:
        return None
    return normalised, tuple(sorted(safe_references))


def _replace_html_reference_attributes(
    value: str,
    raw_start_tags: list[str],
    requested_url: str,
    *,
    expected_reference_count: int,
) -> str | None:
    parts: list[str] = []
    cursor = 0
    replaced_references = 0
    for raw_tag in raw_start_tags:
        position = value.find(raw_tag, cursor)
        if position < 0:
            return None
        invalid = False

        def replace_attribute(match: re.Match[str]) -> str:
            nonlocal invalid, replaced_references
            raw_reference = match.group("quoted")
            if raw_reference is None:
                raw_reference = match.group("unquoted") or ""
            safe = _safe_html_reference(
                match.group("name").lower(),
                unescape(raw_reference),
                requested_url,
            )
            if safe is None:
                invalid = True
                return match.group(0)
            replaced_references += 1
            digest = sha256(safe.encode("utf-8")).hexdigest()
            quote_character = match.group("quote") or "\""
            return (
                f"{match.group('prefix')}{quote_character}"
                f"{{HTML_REFERENCE:{digest}}}{quote_character}"
            )

        normalised_tag = HTML_REFERENCE_ATTRIBUTE_RE.sub(
            replace_attribute,
            raw_tag,
        )
        if invalid:
            return None
        parts.extend((value[cursor:position], normalised_tag))
        cursor = position + len(raw_tag)
    parts.append(value[cursor:])
    if replaced_references != expected_reference_count:
        return None
    return "".join(parts)


def _safe_html_reference(
    attribute: str,
    reference: str,
    requested_url: str,
) -> str | None:
    stripped = reference.strip()
    if any(ord(character) < 32 for character in stripped):
        return None
    if not stripped:
        return _canonical_reference_payload(
            {"attribute": attribute, "form": "empty"}
        )

    try:
        parsed = urlparse(stripped)
    except ValueError:
        return None
    if stripped.startswith("//"):
        form = "scheme_relative"
    elif stripped.startswith("/"):
        form = "root_relative"
    elif stripped.startswith("?"):
        form = "query_relative"
    elif stripped.startswith("#"):
        form = "fragment_relative"
    elif parsed.scheme:
        form = "absolute_http" if parsed.scheme.lower() == "http" else (
            "absolute_https" if parsed.scheme.lower() == "https" else "unsupported_scheme"
        )
    else:
        form = "path_relative"

    query_names = _safe_query_parameter_names(parsed.query)
    if query_names is None:
        return None
    payload: dict[str, object] = {
        "attribute": attribute,
        "form": form,
        "query_parameter_names": query_names,
    }
    if form == "fragment_relative":
        return _canonical_reference_payload(payload)
    if form in {"root_relative", "path_relative", "query_relative"}:
        path = parsed.path
        if any(ord(character) < 32 for character in path):
            return None
        payload["path"] = path
        return _canonical_reference_payload(payload)

    scheme = parsed.scheme.lower()
    if form == "scheme_relative":
        try:
            scheme = urlparse(requested_url).scheme.lower()
        except ValueError:
            return None
    if form == "unsupported_scheme" and parsed.hostname is None:
        payload.update(
            {
                "scheme": scheme,
                "opaque_path_sha256": sha256(parsed.path.encode("utf-8")).hexdigest(),
            }
        )
        return _canonical_reference_payload(payload)

    hostname = parsed.hostname.lower() if parsed.hostname else None
    if hostname is None:
        return None
    try:
        explicit_port = parsed.port
    except ValueError:
        return None
    effective_port = explicit_port
    if effective_port is None and scheme in {"http", "https"}:
        effective_port = 443 if scheme == "https" else 80
    path = parsed.path or "/"
    if any(ord(character) < 32 for character in path):
        return None
    payload.update(
        {
            "scheme": scheme,
            "hostname": hostname,
            "explicit_port": explicit_port,
            "effective_port": effective_port,
            "path": path,
            "userinfo_present_and_omitted": (
                parsed.username is not None or parsed.password is not None
            ),
        }
    )
    return _canonical_reference_payload(payload)


def _safe_query_parameter_names(query: str) -> tuple[str, ...] | None:
    if not query:
        return ()
    try:
        names = [
            name
            for name, _value in parse_qsl(query, keep_blank_values=True)
            if name
        ]
    except ValueError:
        return None
    if not names:
        names = [
            part.split("=", 1)[0]
            for part in query.split("&")
            if part.split("=", 1)[0]
        ]
    if any(
        len(name) > MAX_RENDERED_VALUE_CHARS
        or any(ord(character) < 32 for character in name)
        for name in names
    ):
        return None
    return tuple(sorted(set(names)))


def _canonical_reference_payload(payload: dict[str, object]) -> str:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def _representative_sort_key(
    fingerprint: DeepHttpResponseFingerprint,
) -> tuple[object, ...]:
    return (
        _safe_requested_url(fingerprint.requested_url),
        fingerprint.method.upper(),
        fingerprint.status_code,
        fingerprint.fingerprint_id,
        tuple(sorted(fingerprint.evidence_ids)),
    )


def _group_id(group: _PendingGroup, index: int) -> str:
    if group.category != "request_reflecting_template_group":
        return f"DEEP-SIM-GRP-{index:04d}"
    canonical = json.dumps(
        group.grouping_signature,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    digest = sha256(canonical.encode("ascii")).hexdigest()[:16].upper()
    return f"DEEP-RESP-FAM-{digest}"


def _redirect_signature(observation: DeepRedirectAuthFlowObservation) -> tuple:
    return (
        observation.redirect_status_code,
        observation.location_reference_form,
        observation.origin_relationship,
        observation.auth_path_transition,
        observation.set_cookie_present,
        _target_path_pattern(observation.safe_resolved_target_url),
        tuple(sorted(observation.target_query_parameter_names)),
        observation.fragment_present,
        observation.userinfo_present_and_omitted,
    )


def _response_signature(fingerprint: DeepHttpResponseFingerprint) -> tuple:
    return (
        fingerprint.status_code,
        _normalise_content_type(fingerprint.content_type),
        _normalise_server_family(fingerprint.server),
        _normalise_title(fingerprint.title_observed_in_bounded_preview),
        fingerprint.body_empty,
        _body_size_band(fingerprint.body_bytes),
        fingerprint.set_cookie_present,
        bool(fingerprint.redirect_location),
    )


def _client_error_signature(fingerprint: DeepHttpResponseFingerprint) -> tuple:
    return (
        fingerprint.status_code,
        _normalise_content_type(fingerprint.content_type),
        _normalise_server_family(fingerprint.server),
        _normalise_title(fingerprint.title_observed_in_bounded_preview),
        _body_size_band(fingerprint.body_bytes),
        fingerprint.body_empty,
    )


def _has_meaningful_response_signature(signature: tuple) -> bool:
    (
        _status,
        media_type,
        server_family,
        title,
        body_empty,
        body_band,
        set_cookie_present,
        redirect_location_present,
    ) = signature
    return bool(
        media_type
        or server_family
        or title
        or set_cookie_present
        or redirect_location_present
        or (not body_empty and body_band not in {"empty", "1-255"})
    )


def _has_meaningful_client_error_signature(signature: tuple) -> bool:
    _status, media_type, server_family, title, body_band, body_empty = signature
    return bool(media_type or server_family or title or (not body_empty and body_band != "empty"))


def _has_template_candidate_signature(fingerprint: DeepHttpResponseFingerprint) -> bool:
    if fingerprint.body_empty:
        return False
    media_type = _normalise_content_type(fingerprint.content_type)
    server_family = _normalise_server_family(fingerprint.server)
    title = _normalise_title(fingerprint.title_observed_in_bounded_preview)
    if title:
        return True
    return bool(media_type and server_family and _body_size_band(fingerprint.body_bytes) != "empty")


def _body_size_band(body_bytes: int) -> str:
    if body_bytes == 0:
        return "empty"
    if 1 <= body_bytes <= 255:
        return "1-255"
    if body_bytes <= 1023:
        return "256-1023"
    if body_bytes <= 4095:
        return "1024-4095"
    if body_bytes <= 16383:
        return "4096-16383"
    if body_bytes <= 65535:
        return "16384-65535"
    return "65536+"


def _normalise_content_type(content_type: str | None) -> str:
    if not content_type:
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def _normalise_server_family(server: str | None) -> str:
    if not server:
        return ""
    first_product = server.strip().split()[0].split("/", 1)[0].strip().lower()
    if not first_product:
        return ""
    if first_product.startswith("apache"):
        return "apache"
    if first_product.startswith("nginx"):
        return "nginx"
    if first_product.startswith("microsoft-iis"):
        return "microsoft-iis"
    if first_product.startswith("gunicorn"):
        return "gunicorn"
    return first_product[:80]


def _normalise_title(title: str | None) -> str:
    if not title:
        return ""
    return " ".join(title.casefold().split())[:120]


def _target_path_pattern(safe_url: str | None) -> str:
    if not safe_url:
        return ""
    try:
        return urlparse(safe_url).path or "/"
    except ValueError:
        return ""


def _duplicate_precedence(group: _PendingGroup) -> int:
    precedence = {
        "exact_body_hash_group": 0,
        "request_reflecting_template_group": 1,
        "candidate_default_template_group": 2,
        "client_error_signature_group": 3,
        "response_signature_group": 4,
    }
    return precedence.get(group.category, 10)


def _group_sort_key(group: _PendingGroup) -> tuple:
    auth_redirect_rank = 0
    if group.category == "redirect_pattern_group":
        auth_redirect_rank = 0 if any(
            transition != "no_auth_path_signal"
            for transition in group.auth_path_transitions
        ) else 1
    return (
        GROUP_CATEGORY_ORDER.get(group.category, 99),
        auth_redirect_rank,
        -len(group.fingerprint_ids),
        group.category,
        group.grouping_signature,
        group.requested_urls[0] if group.requested_urls else "",
        tuple(sorted(group.fingerprint_ids)),
    )


def _count_category(groups: tuple[DeepResponseSimilarityGroup, ...], category: str) -> int:
    return sum(1 for group in groups if group.category == category)


def _render_group(group: DeepResponseSimilarityGroup) -> list[str]:
    lines = [
        f"#### {group.group_id} - {group.title}",
        "",
        f"- Category: `{group.category}`",
        f"- Reason: {group.reason}",
        f"- Response count: {len(group.fingerprint_ids)}",
        "- Grouping signature: " + _format_compact_values(group.grouping_signature),
    ]
    if group.category == "request_reflecting_template_group":
        lines.extend(
            [
                "- Representative fingerprint: "
                f"`{group.representative_fingerprint_id or 'none'}`",
                "- Representative request: "
                f"`{_compact_single(group.representative_requested_url or 'none')}`",
                "- Structural signals: "
                + _format_compact_values(group.structural_signals),
                "- Member fingerprints:",
                *(f"  - `{value}`" for value in group.fingerprint_ids),
                "- Member requested URLs:",
                *(f"  - {_markdown_code(value)}" for value in group.requested_urls),
            ]
        )
        if group.evidence_ids:
            lines.extend(
                [
                    "- Member evidence IDs:",
                    *(f"  - `{value}`" for value in group.evidence_ids),
                ]
            )
    else:
        lines.append(
            "- Fingerprints: " + _format_compact_values(group.fingerprint_ids)
        )
    if group.redirect_observation_ids:
        lines.append(
            "- Redirect observations: "
            + _format_compact_values(group.redirect_observation_ids)
        )
    if group.source_repeated_body_group_ids:
        lines.append(
            "- Source repeated body groups: "
            + _format_compact_values(group.source_repeated_body_group_ids)
        )
    if group.category != "request_reflecting_template_group":
        lines.append("- URLs: " + _format_compact_values(group.requested_urls))
    lines.append(
        "- Status codes: "
        + _format_compact_values(tuple(str(value) for value in group.status_codes))
    )
    if group.titles_observed_in_bounded_previews:
        lines.append(
            "- Titles observed in bounded previews: "
            + _format_compact_values(group.titles_observed_in_bounded_previews)
        )
    if group.content_types:
        lines.append("- Content types: " + _format_compact_values(group.content_types))
    if group.server_families:
        lines.append("- Server families: " + _format_compact_values(group.server_families))
    if group.body_size_bands:
        lines.append("- Body size bands: " + _format_compact_values(group.body_size_bands))
    if group.body_hashes:
        lines.append("- Body hashes: " + _format_compact_values(group.body_hashes))
    if group.redirect_origin_relationships:
        lines.append(
            "- Origin relationships: "
            + _format_compact_values(group.redirect_origin_relationships)
        )
    if group.auth_path_transitions:
        lines.append(
            "- Auth path transitions: "
            + _format_compact_values(group.auth_path_transitions)
        )
    if group.evidence_ids and group.category != "request_reflecting_template_group":
        lines.append("- Evidence: " + _format_compact_values(group.evidence_ids))
    lines.extend([f"- Interpretation: {group.interpretation}", ""])
    return lines


def _render_unique_success(unique: DeepUniqueSuccessResponse) -> list[str]:
    lines = [
        f"#### {unique.unique_id} - Unique collected 2xx response",
        "",
        f"- Fingerprint: `{unique.fingerprint_id}`",
        f"- URL: `{_compact_single(unique.requested_url)}`",
        f"- Status: `{unique.status_code}`",
    ]
    if unique.title_observed_in_bounded_preview:
        lines.append(
            "- Title observed in bounded preview: "
            f"`{_compact_single(unique.title_observed_in_bounded_preview)}`"
        )
    if unique.content_type:
        lines.append(f"- Content-Type: `{_compact_single(unique.content_type)}`")
    if unique.server:
        lines.append(f"- Server: `{_compact_single(unique.server)}`")
    lines.extend(
        [
            f"- Body bytes: `{unique.body_bytes}`",
            f"- Body SHA-256: `{unique.body_sha256}`",
        ]
    )
    if unique.evidence_ids:
        lines.append("- Evidence: " + _format_compact_values(unique.evidence_ids))
    lines.extend([f"- Reason: {unique.reason}", ""])
    return lines


def _format_compact_values(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    rendered = ", ".join(f"`{_compact_single(value)}`" for value in values[:MAX_RENDERED_VALUES])
    remaining = len(values) - MAX_RENDERED_VALUES
    if remaining > 0:
        rendered += f", ... +{remaining} more"
    return rendered


def _compact_single(value: str, *, max_chars: int = MAX_RENDERED_VALUE_CHARS) -> str:
    compact = " ".join(str(value).strip().split())
    if len(compact) <= max_chars:
        return compact
    return compact[: max_chars - 24].rstrip() + " ... [truncated]"


def _markdown_code(value: str) -> str:
    longest_run = max(
        (len(match.group(0)) for match in re.finditer(r"`+", value)),
        default=0,
    )
    fence = "`" * (longest_run + 1)
    padding = " " if value.startswith("`") or value.endswith("`") else ""
    return f"{fence}{padding}{value}{padding}{fence}"


def _safe_requested_url(raw_url: str) -> str:
    try:
        parsed = urlparse(raw_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
    except (TypeError, ValueError):
        return "unresolved"
    if scheme not in {"http", "https"} or not hostname:
        return "unresolved"

    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        authority = f"{authority}:{port}"
    path = parsed.path or "/"
    query_names = _unique_sorted(
        [
            quote(name, safe="")
            for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
            if name
        ]
    )
    query = f"?{'&'.join(query_names)}" if query_names else ""
    return f"{scheme}://{authority}{path}{query}"


def _unique_sorted(values: list[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def _unique_sorted_ci(values: list[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values), key=lambda value: (value.casefold(), value)))


def _sort_body_size_bands(values: list[str]) -> tuple[str, ...]:
    order = {band: index for index, band in enumerate(BODY_SIZE_BAND_ORDER)}
    return tuple(sorted(set(values), key=lambda value: (order.get(value, 99), value)))


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
