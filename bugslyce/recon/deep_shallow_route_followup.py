"""Bounded shallow follow-up for extracted Deep static routes.

This module plans and collects one shallow same-origin GET pass from existing
91A/91B extraction results. It does not expose a CLI command, write files,
create directories, crawl, recurse, manually follow redirects, execute
JavaScript, submit forms, mutate parameters, or enable Deep Recon.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from hashlib import sha256
import math
from urllib.parse import parse_qsl, quote, urljoin, urlparse

from bugslyce.recon.deep_collection_policy import (
    DeepCollectionBounds,
    DeepCollectionRequest,
    default_deep_collection_bounds,
)
from bugslyce.recon.deep_html_route_extraction import DeepHtmlRouteExtractionResult
from bugslyce.recon.deep_javascript_route_extraction import (
    DeepJavaScriptRouteExtractionResult,
)
from bugslyce.recon.deep_metadata_collector import DeepHTTPResponse
from bugslyce.recon.deep_source_route_collector import MAX_BODY_PREVIEW_CHARS
from bugslyce.recon.http_origin import same_http_origin


DEFAULT_MAX_REQUESTS = 12
MAX_RENDERED_VALUES = 6
MAX_RENDERED_VALUE_CHARS = 120
LOW_VALUE_STATIC_SUFFIXES = (
    ".css",
    ".bmp",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".png",
    ".svg",
    ".webp",
    ".avif",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".mp3",
    ".wav",
    ".ogg",
    ".mp4",
    ".webm",
    ".avi",
    ".mov",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".exe",
    ".dll",
    ".bin",
    ".iso",
    ".dmg",
    ".apk",
)
DYNAMIC_SUFFIXES = (".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".html", ".htm", ".txt", ".map")
JAVASCRIPT_SUFFIXES = (".js", ".mjs", ".cjs")
PLAN_SAFETY_NOTES = (
    "This is one bounded shallow same-origin follow-up planning pass.",
    "Only path-only GET requests were planned.",
    "Observed query parameter names were retained as metadata, but query values were not replayed or invented.",
    "No route was followed recursively.",
    "No crawling occurred.",
    "No JavaScript was executed.",
    "No forms were submitted.",
    "No parameters were mutated.",
    "Redirects were not manually followed by this phase.",
    "No vulnerability was confirmed.",
    "No network request was made by this planning/rendering step.",
    "This stage produces static manual-review context only.",
)
RESULT_SAFETY_NOTES = (
    "This is one bounded shallow same-origin follow-up collection pass.",
    "Only path-only GET requests were selected.",
    "Observed query parameter names were retained as metadata, but query values were not replayed or invented.",
    "No route was followed recursively.",
    "No crawling occurred.",
    "No JavaScript was executed.",
    "No forms were submitted.",
    "No parameters were mutated.",
    "Redirects were not manually followed by this phase.",
    "No vulnerability was confirmed.",
    "Network access was limited to the supplied bounded fetcher and the selected plan requests.",
    "This stage produces static manual-review context only.",
)


@dataclass(frozen=True)
class DeepShallowRouteFollowupRequest:
    """One bounded same-origin shallow follow-up request."""

    request_id: str
    request_url: str
    method: str
    query_parameter_names: tuple[str, ...]
    source_model_kinds: tuple[str, ...]
    source_route_candidate_ids: tuple[str, ...]
    source_response_ids: tuple[str, ...]
    source_request_urls: tuple[str, ...]
    source_collection_sections: tuple[str, ...]
    source_selection_reasons: tuple[str, ...]
    html_tag_attribute_sources: tuple[str, ...]
    javascript_candidate_forms: tuple[str, ...]
    javascript_resolution_contexts: tuple[str, ...]
    javascript_script_types: tuple[str, ...]
    occurrence_count: int
    evidence_ids: tuple[str, ...]
    selection_reason: str
    interpretation: str


@dataclass(frozen=True)
class DeepShallowRouteFollowupSkippedItem:
    """Planning input skipped before shallow follow-up collection."""

    source_model_kind: str
    source_id: str
    safe_url: str
    reason: str
    source_response_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class DeepShallowRouteFollowupPlanSummaryCounts:
    """Immutable summary counts for shallow follow-up planning."""

    html_routes_considered: int
    javascript_candidates_considered: int
    eligible_same_origin_occurrences: int
    unique_path_only_targets_before_bound: int
    requests_selected: int
    total_skipped: int
    cross_origin_skipped: int
    not_comparable_skipped: int
    unresolved_skipped: int
    invalid_url_skipped: int
    invalid_origin_relationship_skipped: int
    low_value_static_skipped: int
    duplicates_aggregated: int
    request_bound_overflow_skipped: int
    html_supported_requests: int
    javascript_supported_requests: int
    requests_supported_by_both: int
    requests_with_observed_query_parameter_names: int


@dataclass(frozen=True)
class DeepShallowRouteFollowupPlan:
    """Bounded same-origin shallow follow-up plan."""

    requests: tuple[DeepShallowRouteFollowupRequest, ...]
    skipped: tuple[DeepShallowRouteFollowupSkippedItem, ...]
    summary_counts: DeepShallowRouteFollowupPlanSummaryCounts
    max_requests: int
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class DeepShallowRouteFollowupCollectedItem:
    """Collected shallow follow-up response summary with in-memory full body."""

    request_id: str
    requested_url: str
    method: str
    status_code: int
    final_url: str
    headers: tuple[tuple[str, str], ...]
    body_preview: str
    body_sha256: str
    body_bytes: int
    elapsed_seconds: float
    source_model_kinds: tuple[str, ...]
    source_route_candidate_ids: tuple[str, ...]
    query_parameter_names: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    interpretation: str
    body: bytes = field(default=b"", repr=False)


@dataclass(frozen=True)
class DeepShallowRouteFollowupCollectionSkippedItem:
    """Shallow follow-up request skipped or failed during collection."""

    request_id: str
    requested_url: str
    reason: str
    source_route_candidate_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    error_category: str | None = None


@dataclass(frozen=True)
class DeepShallowRouteFollowupResultSummaryCounts:
    """Immutable summary counts for shallow follow-up collection."""

    requests_planned: int
    responses_collected: int
    requests_skipped_or_failed: int
    fetch_errors: int
    invalid_fetch_responses: int
    responses_too_large: int


@dataclass(frozen=True)
class DeepShallowRouteFollowupResult:
    """Bounded shallow follow-up collection result."""

    collected: tuple[DeepShallowRouteFollowupCollectedItem, ...]
    skipped: tuple[DeepShallowRouteFollowupCollectionSkippedItem, ...]
    summary_counts: DeepShallowRouteFollowupResultSummaryCounts
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class _PendingEvidence:
    request_url: str
    query_parameter_names: tuple[str, ...]
    source_model_kind: str
    source_id: str
    source_response_ids: tuple[str, ...]
    source_request_urls: tuple[str, ...]
    source_collection_sections: tuple[str, ...]
    source_selection_reasons: tuple[str, ...]
    html_tag_attribute_sources: tuple[str, ...]
    javascript_candidate_forms: tuple[str, ...]
    javascript_resolution_contexts: tuple[str, ...]
    javascript_script_types: tuple[str, ...]
    occurrence_count: int
    evidence_ids: tuple[str, ...]


def build_deep_shallow_route_followup_plan(
    html_extraction: DeepHtmlRouteExtractionResult,
    javascript_extraction: DeepJavaScriptRouteExtractionResult,
    *,
    max_requests: int = DEFAULT_MAX_REQUESTS,
) -> DeepShallowRouteFollowupPlan:
    """Build a deterministic one-pass same-origin shallow follow-up plan."""

    active_max = _validate_max_requests(max_requests)
    pending: dict[str, list[_PendingEvidence]] = {}
    skipped: list[DeepShallowRouteFollowupSkippedItem] = []
    eligible_occurrences = 0
    duplicate_occurrences = 0

    for route in html_extraction.routes:
        safe_url = route.safe_resolved_url
        if route.origin_relationship == "cross_origin":
            skipped.append(_skip("html_route", route.route_id, safe_url, "cross_origin", route.source_response_ids, route.evidence_ids))
            continue
        if route.origin_relationship == "not_comparable":
            skipped.append(_skip("html_route", route.route_id, safe_url, "not_comparable", route.source_response_ids, route.evidence_ids))
            continue
        if route.origin_relationship != "same_origin":
            skipped.append(_skip("html_route", route.route_id, safe_url, "invalid_origin_relationship", route.source_response_ids, route.evidence_ids))
            continue
        request_url, query_names, reason = _path_only_request_url(safe_url)
        if reason is not None:
            skipped.append(_skip("html_route", route.route_id, safe_url, reason, route.source_response_ids, route.evidence_ids))
            continue
        if _has_low_value_suffix(request_url):
            skipped.append(_skip("html_route", route.route_id, request_url, "low_value_static_suffix", route.source_response_ids, route.evidence_ids))
            continue
        eligible_occurrences += 1
        if request_url in pending:
            duplicate_occurrences += 1
        pending.setdefault(request_url, []).append(
            _PendingEvidence(
                request_url=request_url,
                query_parameter_names=tuple(_merge_sorted([*route.query_parameter_names, *query_names])),
                source_model_kind="html_route",
                source_id=route.route_id,
                source_response_ids=route.source_response_ids,
                source_request_urls=_valid_safe_urls(route.source_request_urls),
                source_collection_sections=route.source_collection_sections,
                source_selection_reasons=route.source_selection_reasons,
                html_tag_attribute_sources=route.tag_attribute_sources,
                javascript_candidate_forms=(),
                javascript_resolution_contexts=(),
                javascript_script_types=(),
                occurrence_count=route.occurrence_count,
                evidence_ids=route.evidence_ids,
            )
        )

    for candidate in javascript_extraction.candidates:
        if candidate.safe_resolved_url is None:
            skipped.append(_skip("javascript_route", candidate.candidate_id, candidate.safe_candidate, "unresolved_relative", candidate.source_response_ids, candidate.evidence_ids))
            continue
        request_url, query_names, reason = _path_only_request_url(candidate.safe_resolved_url)
        if reason is not None:
            skipped.append(_skip("javascript_route", candidate.candidate_id, candidate.safe_resolved_url, reason, candidate.source_response_ids, candidate.evidence_ids))
            continue
        source_urls = _valid_safe_urls(candidate.source_request_urls)
        if not source_urls:
            skipped.append(_skip("javascript_route", candidate.candidate_id, request_url, "invalid_url", candidate.source_response_ids, candidate.evidence_ids))
            continue
        if not any(_same_origin(url, request_url) for url in source_urls):
            skipped.append(_skip("javascript_route", candidate.candidate_id, request_url, "cross_origin", candidate.source_response_ids, candidate.evidence_ids))
            continue
        if _has_low_value_suffix(request_url):
            skipped.append(_skip("javascript_route", candidate.candidate_id, request_url, "low_value_static_suffix", candidate.source_response_ids, candidate.evidence_ids))
            continue
        eligible_occurrences += 1
        if request_url in pending:
            duplicate_occurrences += 1
        pending.setdefault(request_url, []).append(
            _PendingEvidence(
                request_url=request_url,
                query_parameter_names=tuple(_merge_sorted([*candidate.query_parameter_names, *query_names])),
                source_model_kind="javascript_route",
                source_id=candidate.candidate_id,
                source_response_ids=candidate.source_response_ids,
                source_request_urls=source_urls,
                source_collection_sections=candidate.source_collection_sections,
                source_selection_reasons=candidate.source_selection_reasons,
                html_tag_attribute_sources=(),
                javascript_candidate_forms=candidate.candidate_forms,
                javascript_resolution_contexts=candidate.resolution_contexts,
                javascript_script_types=candidate.script_types,
                occurrence_count=candidate.occurrence_count,
                evidence_ids=candidate.evidence_ids,
            )
        )

    pending_requests = tuple(_pending_to_request(items) for items in pending.values())
    ordered_pending = tuple(sorted(pending_requests, key=_request_priority_key))
    selected = ordered_pending[:active_max]
    overflow = ordered_pending[active_max:]
    skipped.extend(_overflow_skips(overflow))
    requests = _assign_request_ids(selected)
    final_skipped = tuple(sorted(skipped, key=_skip_sort_key))
    counts = _plan_counts(
        html_extraction,
        javascript_extraction,
        requests,
        final_skipped,
        eligible_occurrences,
        len(pending),
        duplicate_occurrences,
    )
    return DeepShallowRouteFollowupPlan(
        requests=requests,
        skipped=final_skipped,
        summary_counts=counts,
        max_requests=active_max,
        safety_notes=PLAN_SAFETY_NOTES,
    )


def collect_deep_shallow_route_followups(
    plan: DeepShallowRouteFollowupPlan,
    *,
    fetcher: Callable[[DeepCollectionRequest, DeepCollectionBounds], DeepHTTPResponse],
) -> DeepShallowRouteFollowupResult:
    """Collect the selected shallow follow-up requests through an injected fetcher."""

    _validate_plan_for_collection(plan)
    bounds = _collection_bounds(plan.max_requests)
    collected: list[DeepShallowRouteFollowupCollectedItem] = []
    skipped: list[DeepShallowRouteFollowupCollectionSkippedItem] = []
    for request in plan.requests:
        deep_request = _to_deep_collection_request(request)
        try:
            response = fetcher(deep_request, bounds)
        except OSError as exc:
            skipped.append(_collection_skip(request, "fetch_error", type(exc).__name__))
            continue
        try:
            body, status_code, elapsed, final_url, headers = _validate_fetch_response(
                response,
                bounds=bounds,
            )
        except (AttributeError, TypeError, ValueError):
            skipped.append(_collection_skip(request, "invalid_fetch_response", "invalid_fetch_response"))
            continue
        if len(body) > bounds.max_response_bytes:
            skipped.append(_collection_skip(request, "response_too_large", "response_too_large"))
            continue
        collected.append(
            DeepShallowRouteFollowupCollectedItem(
                request_id=request.request_id,
                requested_url=request.request_url,
                method="GET",
                status_code=status_code,
                final_url=final_url,
                headers=headers,
                body_preview=_body_preview(body),
                body_sha256=sha256(body).hexdigest(),
                body_bytes=len(body),
                elapsed_seconds=elapsed,
                source_model_kinds=request.source_model_kinds,
                source_route_candidate_ids=request.source_route_candidate_ids,
                query_parameter_names=request.query_parameter_names,
                evidence_ids=request.evidence_ids,
                interpretation="Collected response from one bounded shallow same-origin GET follow-up.",
                body=body,
            )
        )
    counts = DeepShallowRouteFollowupResultSummaryCounts(
        requests_planned=len(plan.requests),
        responses_collected=len(collected),
        requests_skipped_or_failed=len(skipped),
        fetch_errors=sum(1 for item in skipped if item.reason == "fetch_error"),
        invalid_fetch_responses=sum(1 for item in skipped if item.reason == "invalid_fetch_response"),
        responses_too_large=sum(1 for item in skipped if item.reason == "response_too_large"),
    )
    return DeepShallowRouteFollowupResult(
        collected=tuple(collected),
        skipped=tuple(skipped),
        summary_counts=counts,
        safety_notes=RESULT_SAFETY_NOTES,
    )


def render_deep_shallow_route_followup_plan_markdown(
    plan: DeepShallowRouteFollowupPlan,
) -> str:
    """Render a shallow route follow-up plan as terminal-friendly Markdown."""

    counts = plan.summary_counts
    lines = [
        "## Deep Shallow Route Follow-up Plan",
        "",
        "This is one bounded shallow same-origin follow-up planning pass.",
        "",
        "### Summary",
        "",
        f"- HTML routes considered: {counts.html_routes_considered}",
        f"- JavaScript candidates considered: {counts.javascript_candidates_considered}",
        f"- Eligible same-origin occurrences: {counts.eligible_same_origin_occurrences}",
        f"- Unique path-only targets before bound: {counts.unique_path_only_targets_before_bound}",
        f"- Requests selected: {counts.requests_selected}",
        f"- Total skipped: {counts.total_skipped}",
        f"- Duplicates aggregated: {counts.duplicates_aggregated}",
        f"- Request-bound overflow skipped: {counts.request_bound_overflow_skipped}",
        "",
        "### Planned Requests",
        "",
    ]
    if plan.requests:
        for request in plan.requests:
            lines.extend(_render_plan_request(request))
    else:
        lines.append("- None.")
    lines.extend(["", "### Skipped Inputs", ""])
    if plan.skipped:
        for item in plan.skipped:
            lines.append(
                f"- `{item.source_model_kind}` `{item.source_id}` - `{item.reason}` - `{_compact_single(item.safe_url)}`"
            )
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "### Planning Interpretation Notes",
            "",
            "- Same-origin static route selected for one bounded shallow GET follow-up.",
            "- Query strings are removed from request URLs because query values were deliberately not retained.",
            "",
            "### Safety Notes",
            "",
        ]
    )
    lines.extend(f"- {note}" for note in plan.safety_notes)
    return "\n".join(lines).rstrip()


def render_deep_shallow_route_followup_result_markdown(
    result: DeepShallowRouteFollowupResult,
) -> str:
    """Render shallow route follow-up collection results as Markdown."""

    counts = result.summary_counts
    lines = [
        "## Deep Shallow Route Follow-up Results",
        "",
        "This is one bounded shallow same-origin follow-up collection result.",
        "",
        "### Summary",
        "",
        f"- Requests planned: {counts.requests_planned}",
        f"- Responses collected: {counts.responses_collected}",
        f"- Skipped or failed requests: {counts.requests_skipped_or_failed}",
        f"- Fetch errors: {counts.fetch_errors}",
        f"- Invalid fetch responses: {counts.invalid_fetch_responses}",
        f"- Responses too large: {counts.responses_too_large}",
        "",
        "### Collected Responses",
        "",
    ]
    if result.collected:
        for item in result.collected:
            lines.extend(_render_collected(item))
    else:
        lines.append("- None.")
    lines.extend(["", "### Skipped or Failed Requests", ""])
    if result.skipped:
        for item in result.skipped:
            suffix = f" - error: `{item.error_category}`" if item.error_category else ""
            lines.append(
                f"- `{item.request_id}` `{_compact_single(item.requested_url)}` - `{item.reason}`{suffix}"
            )
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "### Collection Interpretation Notes",
            "",
            "- Responses are bounded summaries from selected plan requests only.",
            "- Redirect metadata may be retained, but redirects were not manually followed by this phase.",
            "",
            "### Safety Notes",
            "",
        ]
    )
    lines.extend(f"- {note}" for note in result.safety_notes)
    return "\n".join(lines).rstrip()


def _validate_max_requests(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("max_requests must be an integer")
    if value < 1:
        raise ValueError("max_requests must be at least 1")
    if value > DEFAULT_MAX_REQUESTS:
        raise ValueError("max_requests must not exceed DEFAULT_MAX_REQUESTS")
    return value


def _path_only_request_url(url: str) -> tuple[str, tuple[str, ...], str | None]:
    safe = _safe_url(url)
    if safe == "unresolved":
        return ("", (), "invalid_url")
    try:
        parsed = urlparse(safe)
    except ValueError:
        return ("", (), "invalid_url")
    if parsed.scheme not in {"http", "https"}:
        return ("", (), "unsupported_scheme")
    if not parsed.hostname:
        return ("", (), "invalid_url")
    path = parsed.path or "/"
    authority = _authority(parsed)
    query_names = _query_names(parsed.query)
    return (f"{parsed.scheme.lower()}://{authority}{path}", query_names, None)


def _safe_url(raw_url: str) -> str:
    try:
        parsed = urlparse(raw_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
    except (TypeError, ValueError):
        return "unresolved"
    if scheme not in {"http", "https"} or not hostname:
        return "unresolved"
    names = _query_names(parsed.query)
    query = f"?{'&'.join(names)}" if names else ""
    return f"{scheme}://{_authority(parsed)}{parsed.path or '/'}{query}"


def _authority(parsed) -> str:
    hostname = (parsed.hostname or "").lower()
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if parsed.port is not None:
        authority = f"{authority}:{parsed.port}"
    return authority


def _query_names(query: str) -> tuple[str, ...]:
    return tuple(sorted({quote(name, safe="") for name, _value in parse_qsl(query, keep_blank_values=True) if name}))


def _same_origin(source_url: str, target_url: str) -> bool:
    return same_http_origin(source_url, target_url)


def _has_low_value_suffix(url: str) -> bool:
    try:
        suffix_path = urlparse(url).path.lower()
    except ValueError:
        return False
    return suffix_path.endswith(LOW_VALUE_STATIC_SUFFIXES)


def _pending_to_request(values: list[_PendingEvidence]) -> DeepShallowRouteFollowupRequest:
    ordered = sorted(values, key=_pending_sort_key)
    request_url = ordered[0].request_url
    kinds = _merge_sorted([item.source_model_kind for item in ordered], order=("html_route", "javascript_route"))
    query_names = _merge_sorted([name for item in ordered for name in item.query_parameter_names])
    source_ids = _merge_sorted([item.source_id for item in ordered])
    evidence = _merge_sorted([evidence_id for item in ordered for evidence_id in item.evidence_ids])
    return DeepShallowRouteFollowupRequest(
        request_id="",
        request_url=request_url,
        method="GET",
        query_parameter_names=query_names,
        source_model_kinds=kinds,
        source_route_candidate_ids=source_ids,
        source_response_ids=_merge_sorted([value for item in ordered for value in item.source_response_ids]),
        source_request_urls=_merge_sorted([value for item in ordered for value in item.source_request_urls]),
        source_collection_sections=_merge_sorted([value for item in ordered for value in item.source_collection_sections]),
        source_selection_reasons=_merge_sorted([value for item in ordered for value in item.source_selection_reasons]),
        html_tag_attribute_sources=_merge_sorted([value for item in ordered for value in item.html_tag_attribute_sources]),
        javascript_candidate_forms=_merge_sorted([value for item in ordered for value in item.javascript_candidate_forms]),
        javascript_resolution_contexts=_merge_sorted([value for item in ordered for value in item.javascript_resolution_contexts]),
        javascript_script_types=_merge_sorted([value for item in ordered for value in item.javascript_script_types]),
        occurrence_count=sum(item.occurrence_count for item in ordered),
        evidence_ids=evidence,
        selection_reason="same_origin_static_route",
        interpretation="Same-origin static route selected for one bounded shallow GET follow-up.",
    )


def _assign_request_ids(
    requests: tuple[DeepShallowRouteFollowupRequest, ...],
) -> tuple[DeepShallowRouteFollowupRequest, ...]:
    return tuple(
        DeepShallowRouteFollowupRequest(
            request_id=f"DEEP-SHALLOW-REQ-{index:04d}",
            request_url=request.request_url,
            method=request.method,
            query_parameter_names=request.query_parameter_names,
            source_model_kinds=request.source_model_kinds,
            source_route_candidate_ids=request.source_route_candidate_ids,
            source_response_ids=request.source_response_ids,
            source_request_urls=request.source_request_urls,
            source_collection_sections=request.source_collection_sections,
            source_selection_reasons=request.source_selection_reasons,
            html_tag_attribute_sources=request.html_tag_attribute_sources,
            javascript_candidate_forms=request.javascript_candidate_forms,
            javascript_resolution_contexts=request.javascript_resolution_contexts,
            javascript_script_types=request.javascript_script_types,
            occurrence_count=request.occurrence_count,
            evidence_ids=request.evidence_ids,
            selection_reason=request.selection_reason,
            interpretation=request.interpretation,
        )
        for index, request in enumerate(requests, start=1)
    )


def _overflow_skips(
    requests: tuple[DeepShallowRouteFollowupRequest, ...],
) -> tuple[DeepShallowRouteFollowupSkippedItem, ...]:
    return tuple(
        DeepShallowRouteFollowupSkippedItem(
            source_model_kind="+".join(request.source_model_kinds),
            source_id="+".join(request.source_route_candidate_ids),
            safe_url=request.request_url,
            reason="request_bound_exceeded",
            source_response_ids=request.source_response_ids,
            evidence_ids=request.evidence_ids,
        )
        for request in requests
    )


def _request_priority_key(request: DeepShallowRouteFollowupRequest) -> tuple:
    suffix_rank = _suffix_rank(request.request_url)
    path_depth = _path_depth(request.request_url)
    kinds = set(request.source_model_kinds)
    both_rank = 0 if kinds == {"html_route", "javascript_route"} else 1
    html_rank = 0 if "html_route" in kinds else 1
    js_rank = 0 if "javascript_route" in kinds else 1
    return (
        both_rank,
        html_rank,
        js_rank,
        suffix_rank,
        path_depth,
        request.request_url,
        request.source_route_candidate_ids,
        request.evidence_ids,
    )


def _suffix_rank(url: str) -> int:
    path = urlparse(url).path.lower()
    if "." not in path.rsplit("/", 1)[-1]:
        return 0
    if path.endswith(DYNAMIC_SUFFIXES):
        return 1
    if path.endswith(JAVASCRIPT_SUFFIXES):
        return 2
    return 3


def _path_depth(url: str) -> int:
    return len([part for part in urlparse(url).path.split("/") if part])


def _pending_sort_key(item: _PendingEvidence) -> tuple:
    return (
        item.request_url,
        item.source_model_kind,
        item.source_id,
        item.source_response_ids,
        item.evidence_ids,
    )


def _skip(
    source_model_kind: str,
    source_id: str,
    safe_url: str,
    reason: str,
    source_response_ids: tuple[str, ...],
    evidence_ids: tuple[str, ...],
) -> DeepShallowRouteFollowupSkippedItem:
    safe = _safe_url(safe_url)
    return DeepShallowRouteFollowupSkippedItem(
        source_model_kind=source_model_kind,
        source_id=source_id,
        safe_url=safe if safe != "unresolved" else "unresolved",
        reason=reason,
        source_response_ids=_merge_sorted(source_response_ids),
        evidence_ids=_merge_sorted(evidence_ids),
    )


def _skip_sort_key(item: DeepShallowRouteFollowupSkippedItem) -> tuple:
    return (item.reason, item.source_model_kind, item.safe_url, item.source_id)


def _plan_counts(
    html_extraction: DeepHtmlRouteExtractionResult,
    javascript_extraction: DeepJavaScriptRouteExtractionResult,
    requests: tuple[DeepShallowRouteFollowupRequest, ...],
    skipped: tuple[DeepShallowRouteFollowupSkippedItem, ...],
    eligible_occurrences: int,
    unique_targets_before_bound: int,
    duplicates_aggregated: int,
) -> DeepShallowRouteFollowupPlanSummaryCounts:
    return DeepShallowRouteFollowupPlanSummaryCounts(
        html_routes_considered=len(html_extraction.routes),
        javascript_candidates_considered=len(javascript_extraction.candidates),
        eligible_same_origin_occurrences=eligible_occurrences,
        unique_path_only_targets_before_bound=unique_targets_before_bound,
        requests_selected=len(requests),
        total_skipped=len(skipped),
        cross_origin_skipped=_count_skips(skipped, "cross_origin"),
        not_comparable_skipped=_count_skips(skipped, "not_comparable"),
        unresolved_skipped=_count_skips(skipped, "unresolved_relative"),
        invalid_url_skipped=_count_skips(skipped, "invalid_url"),
        invalid_origin_relationship_skipped=_count_skips(skipped, "invalid_origin_relationship"),
        low_value_static_skipped=_count_skips(skipped, "low_value_static_suffix"),
        duplicates_aggregated=duplicates_aggregated,
        request_bound_overflow_skipped=_count_skips(skipped, "request_bound_exceeded"),
        html_supported_requests=sum(1 for request in requests if "html_route" in request.source_model_kinds),
        javascript_supported_requests=sum(1 for request in requests if "javascript_route" in request.source_model_kinds),
        requests_supported_by_both=sum(1 for request in requests if set(request.source_model_kinds) == {"html_route", "javascript_route"}),
        requests_with_observed_query_parameter_names=sum(1 for request in requests if request.query_parameter_names),
    )


def _count_skips(skipped: tuple[DeepShallowRouteFollowupSkippedItem, ...], reason: str) -> int:
    return sum(1 for item in skipped if item.reason == reason)


def _to_deep_collection_request(
    request: DeepShallowRouteFollowupRequest,
) -> DeepCollectionRequest:
    parsed = urlparse(request.request_url)
    return DeepCollectionRequest(
        url=request.request_url,
        method="GET",
        source="shallow_route_followup",
        reason="same_origin_static_route",
        origin=f"{parsed.scheme.lower()}://{_authority(parsed)}",
        path=parsed.path or "/",
        evidence_ids=request.evidence_ids,
        tags=("shallow_route_followup",),
    )


def _validate_plan_for_collection(plan: DeepShallowRouteFollowupPlan) -> None:
    max_requests = _validate_max_requests(plan.max_requests)
    if len(plan.requests) > max_requests:
        raise ValueError("plan request count exceeds max_requests")
    if len(plan.requests) > DEFAULT_MAX_REQUESTS:
        raise ValueError("plan request count exceeds DEFAULT_MAX_REQUESTS")
    seen_ids: set[str] = set()
    for request in plan.requests:
        if request.method != "GET":
            raise ValueError("plan request method must be GET")
        if not request.request_id:
            raise ValueError("plan request ID must be non-empty")
        if request.request_id in seen_ids:
            raise ValueError("plan request IDs must be unique")
        seen_ids.add(request.request_id)
        canonical, _query_names_value, reason = _path_only_request_url(request.request_url)
        if reason is not None:
            raise ValueError("plan request URL must be valid path-only HTTP/HTTPS")
        try:
            parsed = urlparse(request.request_url)
        except ValueError as exc:
            raise ValueError("plan request URL must be parseable") from exc
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("plan request URL must not contain userinfo, query, or fragment")
        if request.request_url != canonical:
            raise ValueError("plan request URL must equal canonical path-only URL")
        if not request.source_request_urls or not any(
            _same_origin(source_url, request.request_url)
            for source_url in request.source_request_urls
        ):
            raise ValueError("plan request URL must have same-origin source provenance")


def _collection_bounds(max_requests: int) -> DeepCollectionBounds:
    return replace(
        default_deep_collection_bounds(),
        max_total_requests=max_requests,
        max_requests_per_origin=max_requests,
        allowed_methods=("GET",),
        allow_query_strings=False,
        allow_cross_origin=False,
    )


def _validate_fetch_response(
    response: DeepHTTPResponse,
    *,
    bounds: DeepCollectionBounds,
) -> tuple[bytes, int, float, str, tuple[tuple[str, str], ...]]:
    body = response.body
    if type(body) is not bytes:
        raise TypeError("response body must be bytes")
    status = response.status_code
    if type(status) is not int or status < 100 or status > 599:
        raise ValueError("response status must be an integer HTTP status")
    elapsed = response.elapsed_seconds
    if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)):
        raise ValueError("response elapsed_seconds must be a number")
    elapsed_float = float(elapsed)
    if not math.isfinite(elapsed_float) or elapsed_float < 0:
        raise ValueError("response elapsed_seconds must be finite and non-negative")
    final_url_raw = response.final_url
    if type(final_url_raw) is not str or not final_url_raw:
        raise ValueError("response final_url must be a non-empty string")
    final_url = _safe_url(final_url_raw)
    if final_url == "unresolved":
        raise ValueError("response final_url must be valid HTTP/HTTPS")
    headers = _canonical_headers(response.headers, final_url)
    return body, status, elapsed_float, final_url, headers


def _collection_skip(
    request: DeepShallowRouteFollowupRequest,
    reason: str,
    error_category: str,
) -> DeepShallowRouteFollowupCollectionSkippedItem:
    return DeepShallowRouteFollowupCollectionSkippedItem(
        request_id=request.request_id,
        requested_url=request.request_url,
        reason=reason,
        source_route_candidate_ids=request.source_route_candidate_ids,
        evidence_ids=request.evidence_ids,
        error_category=error_category,
    )


def _canonical_headers(headers, final_url: str) -> tuple[tuple[str, str], ...]:
    canonical: list[tuple[str, str]] = []
    try:
        iterator = iter(headers)
    except TypeError as exc:
        raise TypeError("response headers must be iterable") from exc
    for pair in iterator:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise TypeError("response headers must be two-item tuple pairs")
        name, value = pair
        if type(name) is not str or type(value) is not str:
            raise TypeError("response header names and values must be strings")
        header_name = name.lower()
        header_value = value
        if header_name.lower() == "location":
            header_value = _safe_location_header(final_url, header_value)
        canonical.append((header_name, header_value))
    return tuple(sorted(canonical, key=lambda item: (item[0], item[1])))


def _safe_location_header(requested_url: str, value: str) -> str:
    try:
        safe = _safe_url(urljoin(requested_url, value.strip()))
    except (TypeError, ValueError):
        return "unresolved"
    return safe if safe != "unresolved" else "unresolved"


def _valid_safe_urls(urls: tuple[str, ...]) -> tuple[str, ...]:
    return _merge_sorted([safe for safe in (_safe_url(url) for url in urls) if safe != "unresolved"])


def _body_preview(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")[:MAX_BODY_PREVIEW_CHARS]


def _render_plan_request(request: DeepShallowRouteFollowupRequest) -> list[str]:
    lines = [
        f"#### {request.request_id} - Shallow GET follow-up",
        "",
        f"- Request: `GET {_compact_single(request.request_url)}`",
        "- Query parameter names observed: " + _format_compact_values(request.query_parameter_names),
        "- Source models: " + _format_compact_values(request.source_model_kinds),
        "- Source IDs: " + _format_compact_values(request.source_route_candidate_ids),
        "- Source responses: " + _format_compact_values(request.source_response_ids),
        "- Source request URLs: " + _format_compact_values(request.source_request_urls),
        f"- Occurrences represented: `{request.occurrence_count}`",
        "- Evidence: " + _format_compact_values(request.evidence_ids),
        f"- Interpretation: {request.interpretation}",
        "",
    ]
    return lines


def _render_collected(item: DeepShallowRouteFollowupCollectedItem) -> list[str]:
    lines = [
        f"#### {item.request_id} - Collected shallow response",
        "",
        f"- Request: `GET {_compact_single(item.requested_url)}`",
        f"- Status: `{item.status_code}`",
        f"- Final URL: `{_compact_single(item.final_url)}`",
        f"- Body bytes: `{item.body_bytes}`",
        f"- Body SHA-256: `{item.body_sha256}`",
        "- Query parameter names observed: " + _format_compact_values(item.query_parameter_names),
        "- Source models: " + _format_compact_values(item.source_model_kinds),
        "- Source IDs: " + _format_compact_values(item.source_route_candidate_ids),
        "- Evidence: " + _format_compact_values(item.evidence_ids),
    ]
    if item.body_preview:
        lines.append(f"- Body preview: `{_compact_single(item.body_preview)}`")
    if item.headers:
        lines.append(
            "- Headers: "
            + _format_compact_values(tuple(f"{name}: {value}" for name, value in item.headers))
        )
    lines.extend([f"- Interpretation: {item.interpretation}", ""])
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


def _merge_sorted(values, *, order: tuple[str, ...] = ()) -> tuple[str, ...]:
    unique = {str(value) for value in values if str(value)}
    if not order:
        return tuple(sorted(unique))
    rank = {value: index for index, value in enumerate(order)}
    return tuple(sorted(unique, key=lambda value: (rank.get(value, len(rank)), value)))
