"""Offline HTTP fingerprint summary for Deep collection results.

This module classifies already-collected bounded Deep HTTP evidence. It does
not read files, write files, fetch URLs, invoke collectors, analyse redirect
flows, perform fuzzy similarity, or make Deep Recon available.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from html import unescape
import re
from urllib.parse import urlparse

from bugslyce.recon.deep_metadata_collector import (
    DeepMetadataCollectedItem,
    DeepMetadataCollectionResult,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.http_header_display import summarise_set_cookie


MAX_RENDERED_VALUES = 6
MAX_RENDERED_VALUE_CHARS = 120
MAX_TITLE_CHARS = 120
EMPTY_BODY_SHA256 = sha256(b"").hexdigest()
HTML_NOT_OBSERVED_HEADERS = (
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)
HTTPS_NOT_OBSERVED_HEADERS = ("Strict-Transport-Security",)
INTERESTING_HEADERS = (
    "Cache-Control",
    "Pragma",
    "Expires",
    "ETag",
    "Last-Modified",
    "Allow",
    "WWW-Authenticate",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Access-Control-Allow-Origin",
    "Vary",
)
SAFETY_NOTES = (
    "This is offline classification of existing collected HTTP evidence.",
    "No collection or network activity is performed by this summary.",
    "Titles are extracted only when visible in bounded previews.",
    "Not observed headers are evidence notes, not vulnerability findings.",
    "Raw collection evidence may retain complete Set-Cookie headers and cookie values.",
    "This derived human summary omits cookie values and shows only cookie names and relevant attributes.",
    "This stage produces static manual-review context only.",
)
TITLE_RE = re.compile(r"<title(?:\s[^>]*)?>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass(frozen=True)
class DeepHttpHeaderObservation:
    """One selected response header observation with a bounded value."""

    name: str
    value: str


@dataclass(frozen=True)
class DeepHttpResponseFingerprint:
    """Neutral fingerprint for one collected bounded HTTP response."""

    fingerprint_id: str
    collection_section: str
    requested_url: str
    final_url: str
    method: str
    status_code: int
    status_bucket: str
    title_observed_in_bounded_preview: str | None
    content_type: str | None
    server: str | None
    redirect_location: str | None
    set_cookie_present: bool
    set_cookie_count: int
    cookie_names: tuple[str, ...]
    body_sha256: str
    body_bytes: int
    body_empty: bool
    interesting_headers: tuple[DeepHttpHeaderObservation, ...]
    headers_not_observed: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    cookie_summaries: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeepHttpRepeatedBodyGroup:
    """Exact repeated non-empty body hash across collected responses."""

    repeated_body_id: str
    body_sha256: str
    count: int
    fingerprint_ids: tuple[str, ...]
    urls: tuple[str, ...]
    collection_sections: tuple[str, ...]
    body_bytes: tuple[int, ...]
    status_codes: tuple[int, ...]


@dataclass(frozen=True)
class DeepHttpFingerprintSummaryCounts:
    """Immutable count summary for Deep HTTP fingerprints."""

    total_collected_responses: int
    metadata_responses: int
    source_route_responses: int
    responses_2xx: int
    responses_3xx: int
    responses_4xx: int
    responses_5xx: int
    responses_other_status: int
    responses_with_title_observed_in_bounded_preview: int
    responses_setting_cookies: int
    exact_repeated_non_empty_body_groups: int


@dataclass(frozen=True)
class DeepHttpFingerprintSummary:
    """Combined HTTP fingerprint summary for bounded Deep collection results."""

    fingerprints: tuple[DeepHttpResponseFingerprint, ...]
    repeated_body_groups: tuple[DeepHttpRepeatedBodyGroup, ...]
    summary_counts: DeepHttpFingerprintSummaryCounts
    safety_notes: tuple[str, ...]


def build_deep_http_fingerprint_summary(
    metadata_result: DeepMetadataCollectionResult,
    source_route_result: DeepSourceRouteCollectionResult,
) -> DeepHttpFingerprintSummary:
    """Build a deterministic HTTP fingerprint summary from collection results."""

    pending = [
        *(
            _fingerprint_from_collected_item("metadata_collection", item)
            for item in metadata_result.collected
        ),
        *(
            _fingerprint_from_collected_item("source_route_collection", item)
            for item in source_route_result.collected
        ),
    ]
    ordered = sorted(pending, key=_fingerprint_sort_key)
    fingerprints = tuple(
        DeepHttpResponseFingerprint(
            fingerprint_id=f"DEEP-HTTP-FP-{index:04d}",
            collection_section=fingerprint.collection_section,
            requested_url=fingerprint.requested_url,
            final_url=fingerprint.final_url,
            method=fingerprint.method,
            status_code=fingerprint.status_code,
            status_bucket=fingerprint.status_bucket,
            title_observed_in_bounded_preview=(
                fingerprint.title_observed_in_bounded_preview
            ),
            content_type=fingerprint.content_type,
            server=fingerprint.server,
            redirect_location=fingerprint.redirect_location,
            set_cookie_present=fingerprint.set_cookie_present,
            set_cookie_count=fingerprint.set_cookie_count,
            cookie_names=fingerprint.cookie_names,
            cookie_summaries=fingerprint.cookie_summaries,
            body_sha256=fingerprint.body_sha256,
            body_bytes=fingerprint.body_bytes,
            body_empty=fingerprint.body_empty,
            interesting_headers=fingerprint.interesting_headers,
            headers_not_observed=fingerprint.headers_not_observed,
            evidence_ids=fingerprint.evidence_ids,
        )
        for index, fingerprint in enumerate(ordered, start=1)
    )
    repeated_groups = _build_repeated_body_groups(fingerprints)
    return DeepHttpFingerprintSummary(
        fingerprints=fingerprints,
        repeated_body_groups=repeated_groups,
        summary_counts=_summary_counts(
            fingerprints,
            repeated_groups,
            metadata_count=len(metadata_result.collected),
            source_route_count=len(source_route_result.collected),
        ),
        safety_notes=SAFETY_NOTES,
    )


def render_deep_http_fingerprint_summary_markdown(
    summary: DeepHttpFingerprintSummary,
) -> str:
    """Render a Deep HTTP fingerprint summary as terminal-friendly Markdown."""

    counts = summary.summary_counts
    lines = [
        "## Deep HTTP Fingerprint Summary",
        "",
        "This is offline classification of existing collected evidence. No "
        "collection or network activity is performed by this summary.",
        "",
        "### Summary",
        "",
        f"- Total collected responses: {counts.total_collected_responses}",
        f"- Metadata responses: {counts.metadata_responses}",
        f"- Source/route responses: {counts.source_route_responses}",
        f"- 2xx responses: {counts.responses_2xx}",
        f"- 3xx responses: {counts.responses_3xx}",
        f"- 4xx responses: {counts.responses_4xx}",
        f"- 5xx responses: {counts.responses_5xx}",
        f"- Other status responses: {counts.responses_other_status}",
        "- Responses with title observed in bounded preview: "
        f"{counts.responses_with_title_observed_in_bounded_preview}",
        f"- Responses setting cookies: {counts.responses_setting_cookies}",
        "- Exact repeated non-empty body groups: "
        f"{counts.exact_repeated_non_empty_body_groups}",
        "",
        "### Response Fingerprints",
        "",
    ]
    if summary.fingerprints:
        for fingerprint in summary.fingerprints:
            lines.extend(_render_fingerprint(fingerprint))
    else:
        lines.append("- None.")

    lines.extend(["", "### Exact Repeated Body Hashes", ""])
    if summary.repeated_body_groups:
        for group in summary.repeated_body_groups:
            lines.extend(_render_repeated_group(group))
    else:
        lines.append("- None.")

    lines.extend(
        [
            "",
            "### Header Interpretation Notes",
            "",
            "- Header names are matched case-insensitively.",
            "- Headers listed as not observed were not present in the collected "
            "response header set; this is not a vulnerability finding.",
            "- Browser-oriented header notes are only attached to HTML-like "
            "responses.",
            "- Strict-Transport-Security is only checked for HTTPS responses.",
            "- Raw collection artefacts may retain complete Set-Cookie headers. "
            "This derived summary renders cookie names and relevant attributes, "
            "but omits cookie values.",
            "",
            "### Safety Notes",
            "",
        ]
    )
    lines.extend(f"- {note}" for note in summary.safety_notes)
    lines.append("")
    return "\n".join(lines).rstrip()


@dataclass(frozen=True)
class _PendingFingerprint:
    collection_section: str
    requested_url: str
    final_url: str
    method: str
    status_code: int
    status_bucket: str
    title_observed_in_bounded_preview: str | None
    content_type: str | None
    server: str | None
    redirect_location: str | None
    set_cookie_present: bool
    set_cookie_count: int
    cookie_names: tuple[str, ...]
    cookie_summaries: tuple[str, ...]
    body_sha256: str
    body_bytes: int
    body_empty: bool
    interesting_headers: tuple[DeepHttpHeaderObservation, ...]
    headers_not_observed: tuple[str, ...]
    evidence_ids: tuple[str, ...]


def _fingerprint_from_collected_item(
    collection_section: str,
    item: DeepMetadataCollectedItem | DeepSourceRouteCollectedItem,
) -> _PendingFingerprint:
    headers = _normalised_headers(item.headers)
    content_type = _first_header(headers, "content-type")
    server = _first_header(headers, "server")
    redirect_location = _first_header(headers, "location")
    set_cookie_headers = _all_headers(headers, "set-cookie")
    cookie_names = _cookie_names(set_cookie_headers)
    cookie_summaries = _cookie_summaries(set_cookie_headers)
    title = _title_from_preview(item.body_preview)
    return _PendingFingerprint(
        collection_section=collection_section,
        requested_url=item.url,
        final_url=item.final_url,
        method=item.method.upper(),
        status_code=item.status_code,
        status_bucket=_status_bucket(item.status_code),
        title_observed_in_bounded_preview=title,
        content_type=_bounded_value(content_type) if content_type else None,
        server=_bounded_value(server) if server else None,
        redirect_location=_bounded_value(redirect_location) if redirect_location else None,
        set_cookie_present=bool(set_cookie_headers),
        set_cookie_count=len(set_cookie_headers),
        cookie_names=cookie_names,
        cookie_summaries=cookie_summaries,
        body_sha256=item.body_sha256,
        body_bytes=item.body_bytes,
        body_empty=item.body_bytes == 0,
        interesting_headers=_interesting_header_observations(headers),
        headers_not_observed=_headers_not_observed(
            headers,
            item.url,
            item.final_url,
            item.body_preview,
            content_type,
        ),
        evidence_ids=tuple(_dedupe(list(item.evidence_ids))),
    )


def _normalised_headers(
    headers: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str, str], ...]:
    return tuple((name.lower(), name, value) for name, value in headers)


def _first_header(headers: tuple[tuple[str, str, str], ...], name: str) -> str | None:
    wanted = name.lower()
    for lower_name, _original_name, value in headers:
        if lower_name == wanted:
            return _normalise_whitespace(value)
    return None


def _all_headers(headers: tuple[tuple[str, str, str], ...], name: str) -> tuple[str, ...]:
    wanted = name.lower()
    return tuple(
        _normalise_whitespace(value)
        for lower_name, _original_name, value in headers
        if lower_name == wanted
    )


def _cookie_summaries(values: tuple[str, ...]) -> tuple[str, ...]:
    summaries = [
        summary.compact
        for value in values
        if (summary := summarise_set_cookie(value)) is not None
    ]
    return tuple(_dedupe(summaries))


def _interesting_header_observations(
    headers: tuple[tuple[str, str, str], ...],
) -> tuple[DeepHttpHeaderObservation, ...]:
    allowed = {name.lower(): name for name in INTERESTING_HEADERS}
    observations: list[DeepHttpHeaderObservation] = []
    for lower_name, _original_name, value in headers:
        canonical = allowed.get(lower_name)
        if canonical is None:
            continue
        observations.append(
            DeepHttpHeaderObservation(
                name=canonical,
                value=_bounded_value(value),
            )
        )
    return tuple(observations)


def _headers_not_observed(
    headers: tuple[tuple[str, str, str], ...],
    requested_url: str,
    final_url: str,
    body_preview: str,
    content_type: str | None,
) -> tuple[str, ...]:
    observed = {lower_name for lower_name, _original_name, _value in headers}
    missing: list[str] = []
    if _is_html_like(content_type, body_preview):
        missing.extend(
            header
            for header in HTML_NOT_OBSERVED_HEADERS
            if header.lower() not in observed
        )
    if _is_https_url(final_url) or _is_https_url(requested_url):
        missing.extend(
            header
            for header in HTTPS_NOT_OBSERVED_HEADERS
            if header.lower() not in observed
        )
    return tuple(missing)


def _is_html_like(content_type: str | None, body_preview: str) -> bool:
    if content_type and "text/html" in content_type.lower():
        return True
    prefix = body_preview.lstrip().lower()
    return prefix.startswith("<!doctype html") or prefix.startswith("<html")


def _is_https_url(url: str) -> bool:
    try:
        return urlparse(url).scheme.lower() == "https"
    except ValueError:
        return False


def _cookie_names(set_cookie_headers: tuple[str, ...]) -> tuple[str, ...]:
    names: list[str] = []
    for header in set_cookie_headers:
        first_part = header.split(";", 1)[0]
        if "=" not in first_part:
            continue
        name = first_part.split("=", 1)[0].strip()
        if name:
            names.append(name)
    return tuple(_dedupe(names))


def _title_from_preview(preview: str) -> str | None:
    match = TITLE_RE.search(preview)
    if not match:
        return None
    title = _normalise_whitespace(unescape(match.group(1)))
    if not title:
        return None
    return _bounded_value(title, max_chars=MAX_TITLE_CHARS)


def _status_bucket(status_code: int) -> str:
    if 200 <= status_code <= 299:
        return "2xx_success"
    if 300 <= status_code <= 399:
        return "3xx_redirect"
    if 400 <= status_code <= 499:
        return "4xx_client_error"
    if 500 <= status_code <= 599:
        return "5xx_server_error"
    return "other_status"


def _fingerprint_sort_key(
    fingerprint: _PendingFingerprint | DeepHttpResponseFingerprint,
) -> tuple:
    return (
        fingerprint.requested_url,
        fingerprint.collection_section,
        fingerprint.method,
        fingerprint.status_code,
        fingerprint.final_url,
        fingerprint.body_sha256,
        fingerprint.title_observed_in_bounded_preview or "",
        fingerprint.content_type or "",
        fingerprint.server or "",
        fingerprint.redirect_location or "",
        fingerprint.set_cookie_present,
        fingerprint.set_cookie_count,
        tuple(sorted(fingerprint.cookie_names)),
        fingerprint.body_bytes,
        tuple(
            sorted(
                (header.name.lower(), header.value)
                for header in fingerprint.interesting_headers
            )
        ),
        tuple(sorted(fingerprint.headers_not_observed)),
        tuple(sorted(fingerprint.evidence_ids)),
    )


def _build_repeated_body_groups(
    fingerprints: tuple[DeepHttpResponseFingerprint, ...],
) -> tuple[DeepHttpRepeatedBodyGroup, ...]:
    grouped: dict[str, list[DeepHttpResponseFingerprint]] = {}
    for fingerprint in fingerprints:
        if fingerprint.body_empty or fingerprint.body_sha256 == EMPTY_BODY_SHA256:
            continue
        grouped.setdefault(fingerprint.body_sha256, []).append(fingerprint)

    pending: list[tuple[str, list[DeepHttpResponseFingerprint]]] = [
        (body_sha, values)
        for body_sha, values in grouped.items()
        if len(values) > 1
    ]
    pending.sort(key=lambda item: (-len(item[1]), item[0]))
    return tuple(
        DeepHttpRepeatedBodyGroup(
            repeated_body_id=f"DEEP-HTTP-REP-{index:04d}",
            body_sha256=body_sha,
            count=len(values),
            fingerprint_ids=tuple(value.fingerprint_id for value in values),
            urls=tuple(_dedupe([value.requested_url for value in values])),
            collection_sections=tuple(
                _dedupe([value.collection_section for value in values])
            ),
            body_bytes=tuple(sorted({value.body_bytes for value in values})),
            status_codes=tuple(sorted({value.status_code for value in values})),
        )
        for index, (body_sha, values) in enumerate(pending, start=1)
    )


def _summary_counts(
    fingerprints: tuple[DeepHttpResponseFingerprint, ...],
    repeated_groups: tuple[DeepHttpRepeatedBodyGroup, ...],
    *,
    metadata_count: int,
    source_route_count: int,
) -> DeepHttpFingerprintSummaryCounts:
    buckets = [fingerprint.status_bucket for fingerprint in fingerprints]
    return DeepHttpFingerprintSummaryCounts(
        total_collected_responses=len(fingerprints),
        metadata_responses=metadata_count,
        source_route_responses=source_route_count,
        responses_2xx=buckets.count("2xx_success"),
        responses_3xx=buckets.count("3xx_redirect"),
        responses_4xx=buckets.count("4xx_client_error"),
        responses_5xx=buckets.count("5xx_server_error"),
        responses_other_status=buckets.count("other_status"),
        responses_with_title_observed_in_bounded_preview=sum(
            1
            for fingerprint in fingerprints
            if fingerprint.title_observed_in_bounded_preview is not None
        ),
        responses_setting_cookies=sum(
            1 for fingerprint in fingerprints if fingerprint.set_cookie_present
        ),
        exact_repeated_non_empty_body_groups=len(repeated_groups),
    )


def _render_fingerprint(fingerprint: DeepHttpResponseFingerprint) -> list[str]:
    lines = [
        f"#### {fingerprint.fingerprint_id} - `{fingerprint.method} "
        f"{_compact_single(fingerprint.requested_url)}`",
        "",
        f"- Collection section: `{fingerprint.collection_section}`",
        f"- Status: `{fingerprint.status_code}` (`{fingerprint.status_bucket}`)",
    ]
    if fingerprint.final_url != fingerprint.requested_url:
        lines.append(f"- Final URL: `{_compact_single(fingerprint.final_url)}`")
    if fingerprint.title_observed_in_bounded_preview:
        lines.append(
            "- Title observed in bounded preview: "
            f"`{_compact_single(fingerprint.title_observed_in_bounded_preview)}`"
        )
    if fingerprint.content_type:
        lines.append(f"- Content-Type: `{fingerprint.content_type}`")
    if fingerprint.server:
        lines.append(f"- Server: `{fingerprint.server}`")
    if fingerprint.redirect_location:
        lines.append(
            f"- Redirect Location evidence: `{_compact_single(fingerprint.redirect_location)}`"
        )
    if fingerprint.set_cookie_present:
        lines.append(f"- Set-Cookie present: yes ({fingerprint.set_cookie_count} line(s))")
        if (
            fingerprint.cookie_summaries
            and fingerprint.cookie_summaries != fingerprint.cookie_names
        ):
            lines.append(
                "- Cookie names and relevant attributes: "
                + _format_compact_values(fingerprint.cookie_summaries)
            )
        elif fingerprint.cookie_names:
            lines.append(
                "- Cookie names: " + _format_compact_values(fingerprint.cookie_names)
            )
    else:
        lines.append("- Set-Cookie present: no")
    lines.extend(
        [
            f"- Body bytes: `{fingerprint.body_bytes}`",
            f"- Body SHA-256: `{fingerprint.body_sha256}`",
            f"- Body empty: {'yes' if fingerprint.body_empty else 'no'}",
        ]
    )
    if fingerprint.interesting_headers:
        rendered_headers = tuple(
            f"{header.name}: {header.value}" for header in fingerprint.interesting_headers
        )
        lines.append(
            "- Selected interesting headers: "
            + _format_compact_values(rendered_headers)
        )
    if fingerprint.headers_not_observed:
        rendered_missing = tuple(
            f"{header} not observed in collected response headers"
            for header in fingerprint.headers_not_observed
        )
        lines.append(
            "- Relevant headers not observed: "
            + _format_compact_values(rendered_missing)
        )
    if fingerprint.evidence_ids:
        lines.append("- Evidence: " + _format_compact_values(fingerprint.evidence_ids))
    lines.append("")
    return lines


def _render_repeated_group(group: DeepHttpRepeatedBodyGroup) -> list[str]:
    return [
        f"#### {group.repeated_body_id} - Exact repeated body hash",
        "",
        f"- Body SHA-256: `{group.body_sha256}`",
        f"- Response count: {group.count}",
        "- Fingerprints: " + _format_compact_values(group.fingerprint_ids),
        "- URLs: " + _format_compact_values(group.urls),
        "- Collection sections: " + _format_compact_values(group.collection_sections),
        "- Body byte counts: "
        + _format_compact_values(tuple(str(value) for value in group.body_bytes)),
        "- Status codes: "
        + _format_compact_values(tuple(str(value) for value in group.status_codes)),
        "",
    ]


def _format_compact_values(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    rendered = ", ".join(f"`{_compact_single(value)}`" for value in values[:MAX_RENDERED_VALUES])
    remaining = len(values) - MAX_RENDERED_VALUES
    if remaining > 0:
        rendered += f", ... +{remaining} more"
    return rendered


def _compact_single(value: str, *, max_chars: int = MAX_RENDERED_VALUE_CHARS) -> str:
    normalised = _normalise_whitespace(value)
    if len(normalised) <= max_chars:
        return normalised
    return normalised[: max_chars - 24].rstrip() + " ... [truncated]"


def _bounded_value(value: str, *, max_chars: int = MAX_RENDERED_VALUE_CHARS) -> str:
    return _compact_single(value, max_chars=max_chars)


def _normalise_whitespace(value: str) -> str:
    return " ".join(value.strip().split())


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
