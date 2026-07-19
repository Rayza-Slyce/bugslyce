"""Offline review summary for Deep source/route collection results."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from urllib.parse import urlparse

from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.deep_structured_body_review import (
    DeepStructuredBodyDisclosure,
    analyse_deep_structured_body,
    render_configuration_excerpt_line,
)
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.deep_shallow_route_followup import (
    DeepShallowRouteFollowupCollectedItem,
)


STATUS_BUCKET_ORDER = (
    "2xx_success",
    "3xx_redirect",
    "403_forbidden",
    "4xx_client_error",
    "5xx_server_error",
    "other_status",
)
MAX_RENDERED_URLS = 6
SAFETY_NOTES = (
    "Offline review only.",
    "No network requests were made by this review.",
    "No crawling was performed.",
    "No forms were submitted.",
    "No authentication was attempted.",
    "No payloads were injected.",
    "This stage produces static manual-review context only.",
)
CATEGORY_PRIORITY = {
    "structured_configuration_body": 0,
    "structured_json_routes": 1,
    "redirect_to_login": 2,
    "cookie_set_on_redirect": 3,
    "auth_route_response": 4,
    "forbidden_admin_or_status_route": 5,
    "admin_status_route_response": 6,
    "route_redirect": 7,
    "route_success": 8,
    "empty_body_response": 9,
    "repeated_body_signature": 10,
    "query_string_route_skipped": 11,
    "metadata_request_skipped": 12,
    "policy_blocked_skipped": 13,
    "fetch_error_skipped": 14,
}


@dataclass(frozen=True)
class DeepSourceRouteStatusBucket:
    """Status-code grouping for collected source/route responses."""

    name: str
    status_codes: tuple[int, ...]
    urls: tuple[str, ...]
    count: int


@dataclass(frozen=True)
class DeepSourceRouteBodySignature:
    """Repeated non-empty body hash across source/route responses."""

    body_sha256: str
    urls: tuple[str, ...]
    status_codes: tuple[int, ...]
    count: int


@dataclass(frozen=True)
class DeepSourceRouteReviewLead:
    """Human-facing source/route collection review prompt."""

    lead_id: str
    category: str
    title: str
    urls: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    reason: str
    signals: tuple[str, ...] = ()
    observed_values: tuple[str, ...] = ()
    evidence_excerpt: tuple[str, ...] = ()
    source_body_sha256: str | None = None
    final_urls: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeepSourceRouteCollectionReviewSummary:
    """Offline review summary for a source/route collection result."""

    total_collected: int
    total_skipped: int
    status_buckets: tuple[DeepSourceRouteStatusBucket, ...]
    body_signatures: tuple[DeepSourceRouteBodySignature, ...]
    skip_reasons: tuple[tuple[str, int], ...]
    review_leads: tuple[DeepSourceRouteReviewLead, ...]
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class _PendingLead:
    category: str
    title: str
    urls: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    reason: str
    signals: tuple[str, ...] = ()
    observed_values: tuple[str, ...] = ()
    evidence_excerpt: tuple[str, ...] = ()
    source_body_sha256: str | None = None
    final_urls: tuple[str, ...] = ()


def build_deep_source_route_collection_review(
    result: DeepSourceRouteCollectionResult,
    *,
    additional_collected: tuple[DeepShallowRouteFollowupCollectedItem, ...] = (),
) -> DeepSourceRouteCollectionReviewSummary:
    """Build a deterministic offline review summary from source/route output."""

    status_buckets = _build_status_buckets(result.collected)
    body_signatures = _build_body_signatures(result.collected)
    skip_reasons = _build_skip_reasons(result)
    review_leads = _build_review_leads(
        result,
        body_signatures,
        skip_reasons,
        additional_collected=additional_collected,
    )
    return DeepSourceRouteCollectionReviewSummary(
        total_collected=result.total_collected,
        total_skipped=result.total_skipped,
        status_buckets=status_buckets,
        body_signatures=body_signatures,
        skip_reasons=skip_reasons,
        review_leads=review_leads,
        safety_notes=SAFETY_NOTES,
    )


def render_deep_source_route_collection_review_markdown(
    summary: DeepSourceRouteCollectionReviewSummary,
) -> str:
    """Render a Deep source/route collection review as Markdown."""

    lines = [
        "## Deep Source/Route Collection Review",
        "",
        "This is an offline review of bounded Deep source/route collection evidence.",
        "",
        "### Summary",
        "",
        f"- Source/route responses collected: {summary.total_collected}",
        f"- Requests skipped: {summary.total_skipped}",
        "",
        "### Status Buckets",
        "",
    ]
    if summary.status_buckets:
        for bucket in summary.status_buckets:
            lines.append(
                f"- `{bucket.name}`: {bucket.count} - status codes: {_format_values(tuple(str(code) for code in bucket.status_codes))} - URLs: {_format_urls(bucket.urls)}"
            )
    else:
        lines.append("- None.")

    lines.extend(["", "### Review Leads", ""])
    if summary.review_leads:
        for lead in summary.review_leads:
            lines.extend(
                [
                    f"- **{lead.lead_id}: {lead.title}**",
                    f"  - Category: `{lead.category}`",
                    f"  - Reason: {lead.reason}",
                    f"  - URLs: {_format_urls(lead.urls)}",
                ]
            )
            if lead.signals:
                lines.append(f"  - Signals: {_format_values(lead.signals)}")
            differing_final_urls = tuple(
                final_url for final_url in lead.final_urls if final_url not in lead.urls
            )
            if differing_final_urls:
                lines.append(
                    "  - Final response URLs: " + _format_urls(differing_final_urls)
                )
            if lead.observed_values:
                lines.append(
                    f"  - Directly observed values: {_format_values(lead.observed_values)}"
                )
            if lead.evidence_excerpt:
                lines.append(
                    f"  - Bounded evidence excerpt: {_format_values(lead.evidence_excerpt)}"
                )
            if lead.source_body_sha256:
                lines.append(f"  - Source body SHA-256: `{lead.source_body_sha256}`")
            if lead.evidence_ids:
                lines.append(f"  - Evidence: {_format_values(lead.evidence_ids)}")
    else:
        lines.append("- None.")

    lines.extend(["", "### Repeated Body Signatures", ""])
    if summary.body_signatures:
        for signature in summary.body_signatures:
            lines.extend(
                [
                    f"- `{signature.body_sha256}`",
                    f"  - Count: {signature.count}",
                    f"  - Status codes: {_format_values(tuple(str(code) for code in signature.status_codes))}",
                    f"  - URLs: {_format_urls(signature.urls)}",
                ]
            )
    else:
        lines.append("- None.")

    lines.extend(["", "### Skip Reasons", ""])
    if summary.skip_reasons:
        for reason, count in summary.skip_reasons:
            lines.append(f"- `{reason}`: {count}")
    else:
        lines.append("- None.")

    lines.extend(["", "### Safety Notes", ""])
    lines.extend(f"- {note}" for note in summary.safety_notes)
    lines.append("")
    return "\n".join(lines).rstrip()


def _build_status_buckets(
    collected: tuple[DeepSourceRouteCollectedItem, ...],
) -> tuple[DeepSourceRouteStatusBucket, ...]:
    items_by_bucket: dict[str, list[DeepSourceRouteCollectedItem]] = {
        bucket: [] for bucket in STATUS_BUCKET_ORDER
    }
    for item in collected:
        items_by_bucket[_status_bucket(item.status_code)].append(item)

    buckets: list[DeepSourceRouteStatusBucket] = []
    for bucket in STATUS_BUCKET_ORDER:
        items = items_by_bucket[bucket]
        if not items:
            continue
        buckets.append(
            DeepSourceRouteStatusBucket(
                name=bucket,
                status_codes=tuple(sorted({item.status_code for item in items})),
                urls=tuple(_dedupe([item.url for item in items])),
                count=len(items),
            )
        )
    return tuple(buckets)


def _build_body_signatures(
    collected: tuple[DeepSourceRouteCollectedItem, ...],
) -> tuple[DeepSourceRouteBodySignature, ...]:
    items_by_hash: dict[str, list[DeepSourceRouteCollectedItem]] = defaultdict(list)
    for item in collected:
        if item.body_bytes == 0:
            continue
        items_by_hash[item.body_sha256].append(item)

    signatures: list[DeepSourceRouteBodySignature] = []
    for body_sha256, items in items_by_hash.items():
        if len(items) <= 1:
            continue
        signatures.append(
            DeepSourceRouteBodySignature(
                body_sha256=body_sha256,
                urls=tuple(_dedupe([item.url for item in items])),
                status_codes=tuple(sorted({item.status_code for item in items})),
                count=len(items),
            )
        )
    return tuple(
        sorted(
            signatures,
            key=lambda signature: (-signature.count, signature.body_sha256),
        )
    )


def _build_skip_reasons(
    result: DeepSourceRouteCollectionResult,
) -> tuple[tuple[str, int], ...]:
    counts = Counter(item.reason for item in result.skipped)
    return tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _build_review_leads(
    result: DeepSourceRouteCollectionResult,
    body_signatures: tuple[DeepSourceRouteBodySignature, ...],
    skip_reasons: tuple[tuple[str, int], ...],
    *,
    additional_collected: tuple[DeepShallowRouteFollowupCollectedItem, ...],
) -> tuple[DeepSourceRouteReviewLead, ...]:
    pending: list[_PendingLead] = []
    collected = result.collected

    structured_items = (
        *((item, item.url) for item in collected),
        *((item, item.requested_url) for item in additional_collected),
    )
    known_urls = tuple(
        url
        for collected_item, source_url in structured_items
        for url in (source_url, collected_item.final_url)
    )
    for item, source_url in structured_items:
        source_origin = http_origin_from_url(item.final_url) or http_origin_from_url(
            source_url
        )
        known_routes = frozenset(
            urlparse(url).path or "/"
            for url in known_urls
            if source_origin is not None and http_origin_from_url(url) == source_origin
        )
        for disclosure in analyse_deep_structured_body(
            item,
            source_url=source_url,
            known_routes=known_routes,
        ):
            pending.append(_lead_from_structured_disclosure(disclosure))

    success_items = [item for item in collected if 200 <= item.status_code <= 299]
    if success_items:
        pending.append(
            _lead_from_items(
                "route_success",
                "Collected route returned a success response",
                success_items,
                "Collected source/route response returned a 2xx status for manual review.",
            )
        )

    redirect_items = [item for item in collected if 300 <= item.status_code <= 399]
    if redirect_items:
        pending.append(
            _lead_from_items(
                "route_redirect",
                "Collected route returned a redirect",
                redirect_items,
                "Collected source/route response returned a 3xx redirect for manual review.",
            )
        )

    login_redirect_items = [
        item for item in redirect_items if _looks_login_redirect(_header_value(item, "location"))
    ]
    if login_redirect_items:
        pending.append(
            _lead_from_items(
                "redirect_to_login",
                "Collected route redirects toward a login path",
                login_redirect_items,
                "Redirect target looks auth-related; review as route context only.",
            )
        )

    cookie_redirect_items = [
        item for item in redirect_items if _has_header(item, "set-cookie")
    ]
    if cookie_redirect_items:
        pending.append(
            _lead_from_items(
                "cookie_set_on_redirect",
                "Redirect response sets a cookie",
                cookie_redirect_items,
                "Redirect response includes Set-Cookie presence; review as response context only.",
            )
        )

    forbidden_admin_items = [
        item
        for item in collected
        if item.status_code == 403 and _route_kind(item.url) == "admin_status_route"
    ]
    if forbidden_admin_items:
        pending.append(
            _lead_from_items(
                "forbidden_admin_or_status_route",
                "Admin/status-looking route returned forbidden",
                forbidden_admin_items,
                "Collected admin/status-looking route returned 403; review as access-boundary context only.",
            )
        )

    auth_items = [item for item in collected if _route_kind(item.url) == "auth_route"]
    if auth_items:
        pending.append(
            _lead_from_items(
                "auth_route_response",
                "Auth-looking route returned a response",
                auth_items,
                "Collected auth-looking route response deserves scoped manual review.",
            )
        )

    admin_items = [
        item for item in collected if _route_kind(item.url) == "admin_status_route"
    ]
    if admin_items:
        pending.append(
            _lead_from_items(
                "admin_status_route_response",
                "Admin/status-looking route returned a response",
                admin_items,
                "Collected admin/status-looking route response deserves scoped manual review.",
            )
        )

    empty_body_items = [item for item in collected if item.body_bytes == 0]
    if empty_body_items:
        pending.append(
            _lead_from_items(
                "empty_body_response",
                "Collected route returned an empty body",
                empty_body_items,
                "Collected response had no body bytes; review alongside status and headers.",
            )
        )

    for signature in body_signatures:
        items = tuple(
            item for item in collected if item.body_sha256 == signature.body_sha256
        )
        pending.append(
            _PendingLead(
                category="repeated_body_signature",
                title="Multiple source/routes returned the same body",
                urls=signature.urls,
                evidence_ids=_evidence_ids(items),
                reason="Repeated non-empty body hashes can indicate shared templates or default responses.",
                signals=(f"body sha256 {signature.body_sha256}",),
            )
        )

    reason_counts = dict(skip_reasons)
    skip_specs = (
        (
            "query_string_not_allowed",
            "query_string_route_skipped",
            "Query-string source/route requests were skipped",
            "Query-string URLs are not collected by this source/route collector.",
        ),
        (
            "metadata_request",
            "metadata_request_skipped",
            "Metadata requests were skipped by source/route collection",
            "These metadata requests were intentionally skipped by source/route collection because metadata is handled by the Deep metadata collection path.",
        ),
        (
            "policy_blocked",
            "policy_blocked_skipped",
            "Requests were blocked by Deep collection policy",
            "The restrictive Deep collection policy blocked these requests before collection.",
        ),
        (
            "fetch_error",
            "fetch_error_skipped",
            "Some source/route requests hit fetch errors",
            "The injected fetcher returned errors for these source/route attempts.",
        ),
    )
    for skip_reason, category, title, reason in skip_specs:
        if reason_counts.get(skip_reason):
            items = tuple(item for item in result.skipped if item.reason == skip_reason)
            pending.append(
                _PendingLead(
                    category=category,
                    title=title,
                    urls=tuple(_dedupe([item.url for item in items])),
                    evidence_ids=_skipped_evidence_ids(result, skip_reason),
                    reason=reason,
                    signals=(f"{skip_reason}: {reason_counts[skip_reason]}",),
                )
            )

    return _assign_lead_ids(tuple(pending))


def _lead_from_items(
    category: str,
    title: str,
    items,
    reason: str,
) -> _PendingLead:
    return _PendingLead(
        category=category,
        title=title,
        urls=tuple(_dedupe([item.url for item in items])),
        evidence_ids=_evidence_ids(items),
        reason=reason,
        signals=_signals_for_items(items),
    )


def _lead_from_structured_disclosure(
    disclosure: DeepStructuredBodyDisclosure,
) -> _PendingLead:
    if disclosure.kind == "structured_json_routes":
        title = "Relative routes disclosed by structured JSON"
        evidence_excerpt = disclosure.excerpt_lines
    else:
        title = "Structured operational configuration observed in response body"
        evidence_excerpt = tuple(
            render_configuration_excerpt_line(value)
            for value in disclosure.excerpt_lines
        )
    return _PendingLead(
        category=disclosure.kind,
        title=title,
        urls=(disclosure.source_url,),
        final_urls=(disclosure.source_final_url,),
        evidence_ids=disclosure.evidence_ids,
        reason=disclosure.reason,
        signals=(),
        observed_values=disclosure.observed_values,
        evidence_excerpt=evidence_excerpt,
        source_body_sha256=disclosure.source_body_sha256,
    )


def _signals_for_items(items) -> tuple[str, ...]:
    signals: list[str] = []
    for item in items:
        signals.extend(_signals_for_item(item))
    return tuple(_dedupe(signals))


def _signals_for_item(item: DeepSourceRouteCollectedItem) -> tuple[str, ...]:
    signals = [f"status {item.status_code}"]
    route_kind = _route_kind(item.url)
    if route_kind != "other_route":
        signals.append(route_kind.replace("_", "-"))

    location = _header_value(item, "location")
    if location:
        signals.append(f"location {_compact_value(location)}")
    if _has_header(item, "set-cookie"):
        signals.append("set-cookie present")
    content_type = _header_value(item, "content-type")
    if content_type:
        signals.append(f"content-type {_compact_value(content_type)}")
    server = _header_value(item, "server")
    if server:
        signals.append(f"server {_compact_value(server)}")
    if item.body_bytes == 0:
        signals.append("empty body")
    return tuple(signals)


def _assign_lead_ids(
    pending: tuple[_PendingLead, ...],
) -> tuple[DeepSourceRouteReviewLead, ...]:
    ordered = tuple(sorted(pending, key=_lead_sort_key))
    return tuple(
        DeepSourceRouteReviewLead(
            lead_id=f"DEEP-SRC-REV-{index:04d}",
            category=lead.category,
            title=lead.title,
            urls=lead.urls,
            evidence_ids=lead.evidence_ids,
            reason=lead.reason,
            signals=lead.signals,
            observed_values=lead.observed_values,
            evidence_excerpt=lead.evidence_excerpt,
            source_body_sha256=lead.source_body_sha256,
            final_urls=lead.final_urls,
        )
        for index, lead in enumerate(ordered, start=1)
    )


def _lead_sort_key(lead: _PendingLead) -> tuple[int, str, str, str]:
    priority = CATEGORY_PRIORITY.get(lead.category, len(CATEGORY_PRIORITY))
    first_url = lead.urls[0] if lead.urls else ""
    return (priority, lead.category, lead.title, first_url)


def _status_bucket(status_code: int) -> str:
    if 200 <= status_code <= 299:
        return "2xx_success"
    if 300 <= status_code <= 399:
        return "3xx_redirect"
    if status_code == 403:
        return "403_forbidden"
    if 400 <= status_code <= 499:
        return "4xx_client_error"
    if 500 <= status_code <= 599:
        return "5xx_server_error"
    return "other_status"


def _has_header(item: DeepSourceRouteCollectedItem, header_name: str) -> bool:
    return _header_value(item, header_name) != ""


def _header_value(item: DeepSourceRouteCollectedItem, header_name: str) -> str:
    lowered = header_name.lower()
    for name, value in item.headers:
        if name.lower() == lowered:
            return value
    return ""


def _looks_login_redirect(location: str) -> bool:
    if not location:
        return False
    return _route_kind(location) == "auth_route"


def _route_kind(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or url
    lowered = path.lower()
    terms = {
        part
        for part in lowered.strip("/").replace(".", "/").replace("-", "/").replace("_", "/").split("/")
        if part
    }
    if terms & {
        "account",
        "auth",
        "login",
        "password",
        "portal",
        "session",
        "signin",
        "sign",
    }:
        return "auth_route"
    if "sign-in" in lowered:
        return "auth_route"
    if terms & {
        "admin",
        "console",
        "dashboard",
        "debug",
        "manage",
        "management",
        "server",
        "status",
    }:
        return "admin_status_route"
    if "server-status" in lowered:
        return "admin_status_route"
    if terms & {"api", "graphql", "rest", "v1", "v2"}:
        return "api_route"
    return "other_route"


def _evidence_ids(items) -> tuple[str, ...]:
    evidence_ids: list[str] = []
    for item in items:
        evidence_ids.extend(item.evidence_ids)
    return tuple(_dedupe(evidence_ids))


def _skipped_evidence_ids(
    result: DeepSourceRouteCollectionResult,
    reason: str,
) -> tuple[str, ...]:
    evidence_ids: list[str] = []
    for item in result.skipped:
        if item.reason == reason:
            evidence_ids.extend(item.evidence_ids)
    return tuple(_dedupe(evidence_ids))


def _format_urls(urls: tuple[str, ...]) -> str:
    return _format_values(urls)


def _format_values(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    visible = values[:MAX_RENDERED_URLS]
    rendered = ", ".join(f"`{value}`" for value in visible)
    remaining = len(values) - len(visible)
    if remaining > 0:
        rendered += f", ... {remaining} more"
    return rendered


def _compact_value(value: str, max_length: int = 80) -> str:
    compact = " ".join(value.strip().split())
    if len(compact) <= max_length:
        return compact
    return compact[: max_length - 3].rstrip() + "..."


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
