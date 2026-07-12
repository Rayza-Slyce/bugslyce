"""Offline response similarity review for Deep HTTP fingerprints.

This module groups already-redacted Deep HTTP fingerprint and redirect review
evidence using explicit deterministic signatures. It does not read files, write
files, fetch responses, follow redirects, invoke collectors, or enable Deep
Recon.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlparse

from bugslyce.recon.deep_http_fingerprint_summary import (
    DeepHttpFingerprintSummary,
    DeepHttpResponseFingerprint,
)
from bugslyce.recon.deep_redirect_auth_flow_review import (
    DeepRedirectAuthFlowObservation,
    DeepRedirectAuthFlowReview,
)


MAX_RENDERED_VALUES = 6
MAX_RENDERED_VALUE_CHARS = 120
MAX_UNIQUE_SUCCESS_RESPONSES = 12
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
    "candidate_default_template_group": 3,
    "client_error_signature_group": 4,
    "response_signature_group": 5,
}
SAFETY_NOTES = (
    "This is offline deterministic grouping of existing HTTP fingerprint evidence.",
    "No network requests were made.",
    "No responses were fetched.",
    "No redirects were followed.",
    "Groups represent shared bounded evidence signatures, not confirmed semantic identity.",
    "Candidate default/template groups are review hypotheses only.",
    "Unique 2xx responses are comparison context, not findings.",
    "Deep Recon full mode was not enabled.",
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


def build_deep_response_similarity_review(
    http_summary: DeepHttpFingerprintSummary,
    redirect_review: DeepRedirectAuthFlowReview,
) -> DeepResponseSimilarityReview:
    """Build a deterministic response similarity review from 90A and 90B models."""

    fingerprints_by_id = {item.fingerprint_id: item for item in http_summary.fingerprints}
    pending = [
        *_exact_body_hash_groups(http_summary, fingerprints_by_id),
        *_redirect_pattern_groups(redirect_review, fingerprints_by_id),
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
            if observation.source_fingerprint_id in fingerprints_by_id
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
) -> _PendingGroup:
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
            group_id=f"DEEP-SIM-GRP-{index:04d}",
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
    )


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
        "candidate_default_template_group": 1,
        "client_error_signature_group": 2,
        "response_signature_group": 3,
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
        "- Fingerprints: " + _format_compact_values(group.fingerprint_ids),
    ]
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
    lines.extend(
        [
            "- URLs: " + _format_compact_values(group.requested_urls),
            "- Status codes: "
            + _format_compact_values(tuple(str(value) for value in group.status_codes)),
        ]
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
    if group.evidence_ids:
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
