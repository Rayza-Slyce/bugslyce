"""Offline Deep collection policy model.

This module validates proposed future Deep collection requests only. It does
not fetch URLs, read files, write files, run recon, execute commands, or make
Deep Recon available.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse


DEFAULT_MAX_TOTAL_REQUESTS = 100
DEFAULT_MAX_REQUESTS_PER_ORIGIN = 25
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_RESPONSE_BYTES = 1_000_000
UNSAFE_INTENT_TERMS = (
    "form_submission",
    "submit_form",
    "authentication",
    "login_attempt",
    "brute_force",
    "payload",
    "injection",
    "exploit",
    "browser_execution",
    "javascript_execution",
    "post",
    "put",
    "delete",
)
ALLOW_NOTES = (
    "method_allowed",
    "scheme_allowed",
    "origin_allowed",
    "within_request_bounds",
    "read_only_request",
)
INTRO_TEXT = (
    "This summary validates proposed Deep collection requests only. It does "
    "not fetch URLs, run live recon, or execute Deep Recon."
)
SAFETY_NOTES = (
    "This is a policy validation view, not a collection result.",
    "Allowed means policy-permitted for future collection, not fetched.",
    "Blocked means the request should not be collected by Deep under the current policy.",
    (
        "Do not submit forms, authenticate, brute force, inject payloads, "
        "execute browser JavaScript, or test routes from this policy summary."
    ),
    "Deep Recon was not executed.",
)


@dataclass(frozen=True)
class DeepCollectionBounds:
    """Restrictive default bounds for future Deep collection requests."""

    max_total_requests: int
    max_requests_per_origin: int
    timeout_seconds: int
    max_response_bytes: int
    allowed_methods: tuple[str, ...]
    allowed_schemes: tuple[str, ...]
    allow_query_strings: bool
    allow_cross_origin: bool
    allow_form_submission: bool
    allow_authentication: bool
    allow_payloads: bool
    allow_browser_execution: bool


@dataclass(frozen=True)
class DeepCollectionRequest:
    """One proposed future Deep collection request."""

    url: str
    method: str
    source: str
    reason: str
    origin: str
    path: str
    evidence_ids: tuple[str, ...]
    tags: tuple[str, ...]


@dataclass(frozen=True)
class DeepCollectionDecision:
    """Policy decision for one proposed future collection request."""

    url: str
    method: str
    allowed: bool
    reason: str
    policy_notes: tuple[str, ...]
    origin: str
    path: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class DeepCollectionPolicySummary:
    """Policy evaluation summary for proposed future collection requests."""

    bounds: DeepCollectionBounds
    decisions: tuple[DeepCollectionDecision, ...]
    allowed_count: int
    blocked_count: int
    blocked_reasons: tuple[tuple[str, int], ...]


def default_deep_collection_bounds() -> DeepCollectionBounds:
    """Return restrictive default Deep collection policy bounds."""

    return DeepCollectionBounds(
        max_total_requests=DEFAULT_MAX_TOTAL_REQUESTS,
        max_requests_per_origin=DEFAULT_MAX_REQUESTS_PER_ORIGIN,
        timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes=DEFAULT_MAX_RESPONSE_BYTES,
        allowed_methods=("GET", "HEAD"),
        allowed_schemes=("http", "https"),
        allow_query_strings=False,
        allow_cross_origin=False,
        allow_form_submission=False,
        allow_authentication=False,
        allow_payloads=False,
        allow_browser_execution=False,
    )


def evaluate_deep_collection_request(
    request: DeepCollectionRequest,
    *,
    bounds: DeepCollectionBounds | None = None,
    allowed_origins: tuple[str, ...] = (),
    already_seen_counts_by_origin: dict[str, int] | None = None,
    already_seen_total: int = 0,
) -> DeepCollectionDecision:
    """Evaluate one proposed request against the offline Deep policy."""

    active_bounds = bounds or default_deep_collection_bounds()
    counts_by_origin = already_seen_counts_by_origin or {}
    method = request.method.upper().strip()
    normalised = _normalise_url(request.url)
    if normalised is None:
        return _blocked(request, method, "invalid_url")
    normalised_url, origin, path, parsed = normalised

    if parsed.scheme not in active_bounds.allowed_schemes:
        return _blocked(request, method, "unsupported_scheme", origin=origin, path=path, url=normalised_url)
    if not parsed.hostname:
        return _blocked(request, method, "missing_hostname", origin=origin, path=path, url=normalised_url)
    if method not in active_bounds.allowed_methods:
        return _blocked(request, method, "method_not_allowed", origin=origin, path=path, url=normalised_url)
    if parsed.username or parsed.password:
        return _blocked(request, method, "url_userinfo_not_allowed", origin=origin, path=path, url=normalised_url)
    if parsed.fragment:
        return _blocked(request, method, "url_fragment_not_allowed", origin=origin, path=path, url=normalised_url)
    if parsed.query and not active_bounds.allow_query_strings:
        return _blocked(request, method, "query_string_not_allowed", origin=origin, path=path, url=normalised_url)
    if not active_bounds.allow_cross_origin and origin not in _normalised_origins(allowed_origins):
        return _blocked(request, method, "cross_origin_not_allowed", origin=origin, path=path, url=normalised_url)
    if _has_unsafe_intent(request):
        return _blocked(request, method, "unsafe_request_intent_blocked", origin=origin, path=path, url=normalised_url)
    if already_seen_total >= active_bounds.max_total_requests:
        return _blocked(request, method, "total_request_limit_exceeded", origin=origin, path=path, url=normalised_url)
    if counts_by_origin.get(origin, 0) >= active_bounds.max_requests_per_origin:
        return _blocked(request, method, "per_origin_limit_exceeded", origin=origin, path=path, url=normalised_url)

    return DeepCollectionDecision(
        url=normalised_url,
        method=method,
        allowed=True,
        reason="policy_allowed",
        policy_notes=ALLOW_NOTES,
        origin=origin,
        path=path,
        evidence_ids=tuple(_dedupe(list(request.evidence_ids))),
    )


def evaluate_deep_collection_requests(
    requests: tuple[DeepCollectionRequest, ...],
    *,
    bounds: DeepCollectionBounds | None = None,
    allowed_origins: tuple[str, ...] = (),
) -> DeepCollectionPolicySummary:
    """Evaluate proposed requests sequentially against the offline Deep policy."""

    active_bounds = bounds or default_deep_collection_bounds()
    counts_by_origin: dict[str, int] = {}
    total_seen = 0
    decisions: list[DeepCollectionDecision] = []
    for request in requests:
        decision = evaluate_deep_collection_request(
            request,
            bounds=active_bounds,
            allowed_origins=allowed_origins,
            already_seen_counts_by_origin=counts_by_origin,
            already_seen_total=total_seen,
        )
        decisions.append(decision)
        if decision.allowed:
            counts_by_origin[decision.origin] = counts_by_origin.get(decision.origin, 0) + 1
            total_seen += 1

    blocked_counter = Counter(decision.reason for decision in decisions if not decision.allowed)
    return DeepCollectionPolicySummary(
        bounds=active_bounds,
        decisions=tuple(decisions),
        allowed_count=sum(1 for decision in decisions if decision.allowed),
        blocked_count=sum(1 for decision in decisions if not decision.allowed),
        blocked_reasons=tuple(sorted(blocked_counter.items())),
    )


def render_deep_collection_policy_summary_markdown(
    summary: DeepCollectionPolicySummary,
) -> str:
    """Render a Deep collection policy summary as terminal-friendly Markdown."""

    bounds = summary.bounds
    lines = [
        "## Deep Collection Policy Summary",
        "",
        INTRO_TEXT,
        "",
        "### Bounds",
        "",
        "- Allowed methods: " + ", ".join(f"`{method}`" for method in bounds.allowed_methods),
        "- Allowed schemes: " + ", ".join(f"`{scheme}`" for scheme in bounds.allowed_schemes),
        f"- Max total requests: {bounds.max_total_requests}",
        f"- Max requests per origin: {bounds.max_requests_per_origin}",
        f"- Timeout seconds: {bounds.timeout_seconds}",
        f"- Max response bytes: {bounds.max_response_bytes}",
        f"- Query strings allowed: {_yes_no(bounds.allow_query_strings)}",
        f"- Cross-origin allowed: {_yes_no(bounds.allow_cross_origin)}",
        f"- Form submission allowed: {_yes_no(bounds.allow_form_submission)}",
        f"- Authentication allowed: {_yes_no(bounds.allow_authentication)}",
        f"- Payloads allowed: {_yes_no(bounds.allow_payloads)}",
        f"- Browser execution allowed: {_yes_no(bounds.allow_browser_execution)}",
        "",
        "### Summary",
        "",
        f"- Proposed requests: {len(summary.decisions)}",
        f"- Allowed requests: {summary.allowed_count}",
        f"- Blocked requests: {summary.blocked_count}",
        "",
    ]

    allowed = tuple(decision for decision in summary.decisions if decision.allowed)
    blocked = tuple(decision for decision in summary.decisions if not decision.allowed)
    if allowed:
        lines.extend(["### Allowed Requests", ""])
        lines.extend(_render_decisions(allowed))
        lines.append("")
    if blocked:
        lines.extend(["### Blocked Requests", ""])
        lines.extend(_render_decisions(blocked))
        lines.append("")
    if summary.blocked_reasons:
        lines.extend(["### Blocked Reasons", ""])
        lines.extend(
            f"- `{reason}`: {count}"
            for reason, count in summary.blocked_reasons
        )
        lines.append("")

    lines.extend(["### Safety Notes", ""])
    lines.extend(f"- {note}" for note in SAFETY_NOTES)
    lines.append("")
    return "\n".join(lines).rstrip()


def _render_decisions(decisions: tuple[DeepCollectionDecision, ...]) -> list[str]:
    lines: list[str] = []
    for decision in decisions:
        line = f"- `{decision.method} {decision.url}` - reason: {decision.reason}"
        if decision.policy_notes:
            line += " - notes: " + ", ".join(f"`{note}`" for note in decision.policy_notes)
        lines.append(line)
    return lines


def _blocked(
    request: DeepCollectionRequest,
    method: str,
    reason: str,
    *,
    origin: str = "",
    path: str = "",
    url: str | None = None,
) -> DeepCollectionDecision:
    return DeepCollectionDecision(
        url=url or request.url,
        method=method,
        allowed=False,
        reason=reason,
        policy_notes=(),
        origin=origin,
        path=path,
        evidence_ids=tuple(_dedupe(list(request.evidence_ids))),
    )


def _normalise_url(raw_url: str):
    value = raw_url.strip() if isinstance(raw_url, str) else ""
    if not value:
        return None
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if not scheme:
        return None
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    default_port = 443 if scheme == "https" else 80
    netloc = hostname if port in (None, default_port) else f"{hostname}:{port}"
    if parsed.username or parsed.password:
        auth = parsed.username or ""
        if parsed.password:
            auth += ":***"
        netloc = f"{auth}@{netloc}"
    path = parsed.path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    normalised_url = urlunparse((scheme, netloc, path, "", parsed.query, parsed.fragment))
    origin = urlunparse((scheme, netloc.split("@")[-1], "", "", "", ""))
    normalised_parsed = urlparse(normalised_url)
    return normalised_url, origin, path, normalised_parsed


def _normalised_origins(origins: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    for origin in origins:
        normalised = _normalise_url(origin)
        if normalised is None:
            continue
        result.append(normalised[1])
    return tuple(_dedupe(result))


def _has_unsafe_intent(request: DeepCollectionRequest) -> bool:
    values = [request.source, request.reason, *request.tags]
    lowered = " ".join(value.lower() for value in values if isinstance(value, str))
    return any(term in lowered for term in UNSAFE_INTENT_TERMS)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
