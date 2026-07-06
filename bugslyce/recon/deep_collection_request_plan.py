"""Offline Deep collection request planner.

This module proposes future Deep collection requests from already-loaded local
project state and validates them through the Deep collection policy. It does
not read files, write files, fetch URLs, run recon, execute commands, or make
Deep Recon available.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

from bugslyce.core.models import ProjectState
from bugslyce.recon.deep_collection_policy import (
    DeepCollectionBounds,
    DeepCollectionPolicySummary,
    DeepCollectionRequest,
    evaluate_deep_collection_requests,
)
from bugslyce.recon.deep_metadata_coverage import (
    build_deep_metadata_coverage_from_project_state,
)
from bugslyce.recon.deep_source_route_coverage import (
    build_deep_source_route_coverage_from_project_state,
)


ROUTE_REQUEST_CATEGORIES = {
    "auth_route",
    "admin_or_status_route",
    "api_route",
    "application_route",
}
ROUTE_CATEGORY_REASON_PARTS = {
    "auth_route": "auth_route",
    "admin_or_status_route": "admin_or_status_route",
    "api_route": "api_route",
    "application_route": "application_route",
}
INTRO_TEXT = (
    "This plan proposes future requests from existing local evidence. It does "
    "not fetch URLs, does not run live recon, and does not execute Deep Recon."
)
SAFETY_NOTES = (
    "This is a request planning view, not a collection result.",
    "Policy-allowed means allowed for a future bounded collector, not fetched.",
    "Policy-blocked means the future collector should not request that URL under the current policy.",
    "Do not submit forms, authenticate, brute force, inject payloads, execute browser JavaScript, or test routes from this plan.",
    "Deep Recon was not executed.",
)


@dataclass(frozen=True)
class DeepCollectionRequestSourceCount:
    """Count of proposed future collection requests by source section."""

    source: str
    count: int


@dataclass(frozen=True)
class DeepCollectionRequestPlan:
    """In-memory Deep collection request plan and policy evaluation."""

    allowed_origins: tuple[str, ...]
    proposed_requests: tuple[DeepCollectionRequest, ...]
    policy_summary: DeepCollectionPolicySummary
    source_counts: tuple[DeepCollectionRequestSourceCount, ...]


@dataclass(frozen=True)
class _PendingRequest:
    url: str
    method: str
    source: str
    reason: str
    evidence_ids: tuple[str, ...]
    tags: tuple[str, ...]


def build_deep_collection_request_plan_from_project_state(
    project_state: ProjectState,
    *,
    bounds: DeepCollectionBounds | None = None,
) -> DeepCollectionRequestPlan:
    """Build an offline future Deep collection request plan from ProjectState."""

    allowed_origins = _derive_allowed_origins(project_state)
    safe_local_urls = set(_derive_safe_local_urls(project_state))
    metadata_coverage = build_deep_metadata_coverage_from_project_state(project_state)
    source_route_coverage = build_deep_source_route_coverage_from_project_state(project_state)

    pending: list[_PendingRequest] = []
    for status, categories in (
        ("discovered_unfetched", ("auth_route",)),
        ("discovered_unfetched", ("admin_or_status_route",)),
        ("discovered_unfetched", ("api_route",)),
        ("discovered_unfetched", ("application_route",)),
        ("referenced_only", ("auth_route",)),
        ("referenced_only", ("admin_or_status_route",)),
        ("referenced_only", ("api_route",)),
        ("referenced_only", ("application_route",)),
    ):
        for item in source_route_coverage.items:
            if item.status != status or item.category not in categories:
                continue
            if item.url not in safe_local_urls:
                continue
            pending.append(_pending_route_request(item.url, item.status, item.category, item.evidence_ids))

    pending.extend(_pending_query_endpoint_requests(project_state))

    for item in metadata_coverage.items:
        if item.status != "planned_uncollected":
            continue
        item_origin = _origin_for_url(item.url)
        if item_origin is None or item_origin not in allowed_origins:
            continue
        pending.append(
            _PendingRequest(
                url=item.url,
                method="GET",
                source="metadata_coverage",
                reason="planned_uncollected_metadata",
                evidence_ids=item.evidence_ids,
                tags=("metadata", "coverage_gap"),
            )
        )

    proposed_requests = tuple(_to_collection_requests(_dedupe_pending_requests(pending)))
    policy_summary = evaluate_deep_collection_requests(
        proposed_requests,
        bounds=bounds,
        allowed_origins=allowed_origins,
    )
    source_counts = tuple(
        DeepCollectionRequestSourceCount(source=source, count=count)
        for source, count in sorted(Counter(request.source for request in proposed_requests).items())
    )
    return DeepCollectionRequestPlan(
        allowed_origins=allowed_origins,
        proposed_requests=proposed_requests,
        policy_summary=policy_summary,
        source_counts=source_counts,
    )


def render_deep_collection_request_plan_markdown(
    plan: DeepCollectionRequestPlan,
) -> str:
    """Render a Deep collection request plan as terminal-friendly Markdown."""

    lines = [
        "## Deep Collection Request Plan",
        "",
        INTRO_TEXT,
        "",
        "### Origin Allowlist",
        "",
    ]
    if plan.allowed_origins:
        lines.extend(f"- `{origin}`" for origin in plan.allowed_origins)
    else:
        lines.append("- No origins were derived from local evidence; policy evaluation fails closed.")
    lines.extend(["", "### Source Counts", ""])
    if plan.source_counts:
        lines.extend(f"- `{item.source}`: {item.count}" for item in plan.source_counts)
    else:
        lines.append("- No proposed request sources.")

    summary = plan.policy_summary
    lines.extend(
        [
            "",
            "### Summary",
            "",
            f"- Proposed requests: {len(plan.proposed_requests)}",
            f"- Policy-allowed requests: {summary.allowed_count}",
            f"- Policy-blocked requests: {summary.blocked_count}",
            "",
        ]
    )

    allowed = tuple(decision for decision in summary.decisions if decision.allowed)
    blocked = tuple(decision for decision in summary.decisions if not decision.allowed)
    lines.extend(["### Policy-Allowed Future Requests", ""])
    lines.extend(_render_policy_decisions(allowed) if allowed else ["- None."])
    lines.extend(["", "### Policy-Blocked Requests", ""])
    lines.extend(_render_policy_decisions(blocked) if blocked else ["- None."])
    if summary.blocked_reasons:
        lines.extend(["", "### Blocked Reasons", ""])
        lines.extend(f"- `{reason}`: {count}" for reason, count in summary.blocked_reasons)

    lines.extend(["", "### Safety Notes", ""])
    lines.extend(f"- {note}" for note in SAFETY_NOTES)
    lines.append("")
    return "\n".join(lines).rstrip()


def _pending_route_request(
    url: str,
    status: str,
    category: str,
    evidence_ids: tuple[str, ...],
) -> _PendingRequest:
    reason_part = ROUTE_CATEGORY_REASON_PARTS.get(category, "route")
    reason = f"{status}_{reason_part}"
    return _PendingRequest(
        url=url,
        method="GET",
        source="source_route_coverage",
        reason=reason,
        evidence_ids=evidence_ids,
        tags=("route", category) if status == "discovered_unfetched" else ("route", "referenced_only", category),
    )


def _pending_query_endpoint_requests(project_state: ProjectState) -> tuple[_PendingRequest, ...]:
    pending: list[_PendingRequest] = []
    for endpoint in project_state.endpoints:
        normalised = _normalise_url(endpoint.url, keep_query=True)
        if normalised is None or "?" not in normalised[0]:
            continue
        category = _category_for_path(endpoint.path)
        if category not in ROUTE_REQUEST_CATEGORIES:
            continue
        pending.append(
            _PendingRequest(
                url=normalised[0],
                method="GET",
                source="source_route_coverage",
                reason=f"referenced_only_{ROUTE_CATEGORY_REASON_PARTS.get(category, 'route')}",
                evidence_ids=tuple(_dedupe(endpoint.evidence_ids)),
                tags=("route", "referenced_only", category),
            )
        )
    return tuple(pending)


def _to_collection_requests(
    pending_requests: tuple[_PendingRequest, ...],
) -> tuple[DeepCollectionRequest, ...]:
    collection_items: list[DeepCollectionRequest] = []
    for pending in pending_requests:
        normalised = _normalise_url(pending.url, keep_query=True)
        if normalised is None:
            origin = ""
            path = ""
            url = pending.url
        else:
            url, origin, path = normalised
        collection_items.append(
            DeepCollectionRequest(
                url=url,
                method=pending.method,
                source=pending.source,
                reason=pending.reason,
                origin=origin,
                path=path,
                evidence_ids=pending.evidence_ids,
                tags=pending.tags,
            )
        )
    return tuple(collection_items)


def _derive_allowed_origins(project_state: ProjectState) -> tuple[str, ...]:
    origins: list[str] = []
    for url in _project_state_urls(project_state):
        normalised = _normalise_url(url, keep_query=False)
        if normalised is None:
            continue
        origins.append(normalised[1])
    return tuple(_dedupe(origins))


def _derive_safe_local_urls(project_state: ProjectState) -> tuple[str, ...]:
    urls: list[str] = []
    for url in _project_state_urls(project_state):
        normalised = _normalise_url(url, keep_query=False)
        if normalised is None:
            continue
        urls.append(normalised[0])
    return tuple(_dedupe(urls))


def _project_state_urls(project_state: ProjectState) -> tuple[str, ...]:
    urls: list[str] = []
    urls.extend(service.url for service in project_state.http_services)
    urls.extend(endpoint.url for endpoint in project_state.endpoints)
    urls.extend(artifact.url for artifact in project_state.http_artifacts)
    urls.extend(path.url for path in project_state.discovered_paths)
    return tuple(urls)


def _origin_for_url(raw_url: str) -> str | None:
    normalised = _normalise_url(raw_url, keep_query=False)
    if normalised is None:
        return None
    return normalised[1]


def _dedupe_pending_requests(
    pending_requests: list[_PendingRequest],
) -> tuple[_PendingRequest, ...]:
    seen: set[tuple[str, str]] = set()
    result: list[_PendingRequest] = []
    for pending in pending_requests:
        normalised = _normalise_url(pending.url, keep_query=True)
        key_url = normalised[0] if normalised is not None else pending.url
        key = (pending.method.upper(), key_url)
        if key in seen:
            continue
        seen.add(key)
        result.append(pending)
    return tuple(result)


def _render_policy_decisions(decisions) -> list[str]:
    lines: list[str] = []
    for decision in decisions:
        line = f"- `{decision.method} {decision.url}` - reason: {decision.reason}"
        if decision.evidence_ids:
            line += " - evidence: " + _format_compact_values(decision.evidence_ids)
        lines.append(line)
    return lines


def _format_compact_values(values: tuple[str, ...], limit: int = 6) -> str:
    rendered = ", ".join(f"`{value}`" for value in values[:limit])
    remaining = len(values) - limit
    if remaining > 0:
        rendered += f", ... +{remaining} more"
    return rendered


def _normalise_url(raw_url: str, *, keep_query: bool) -> tuple[str, str, str] | None:
    value = raw_url.strip() if isinstance(raw_url, str) else ""
    if not value:
        return None
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    if parsed.fragment:
        return None
    hostname = parsed.hostname.lower()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    default_port = 443 if scheme == "https" else 80
    netloc = hostname if port in (None, default_port) else f"{hostname}:{port}"
    path = parsed.path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    query = parsed.query if keep_query else ""
    url = urlunparse((scheme, netloc, path, "", query, ""))
    origin = urlunparse((scheme, netloc, "", "", "", ""))
    return url, origin, path


def _category_for_path(path: str) -> str:
    lowered = path.lower()
    terms = {part for part in lowered.strip("/").replace(".", "/").replace("-", "/").replace("_", "/").split("/") if part}
    if terms & {"account", "auth", "callback", "dashboard", "forgot", "login", "logout", "mfa", "oauth", "password", "portal", "register", "reset", "session", "signin", "signup", "sso", "token", "verify", "2fa"}:
        return "auth_route"
    if terms & {"actuator", "admin", "backoffice", "console", "control", "cpanel", "debug", "dev", "health", "internal", "manage", "management", "manager", "metrics", "monitor", "ops", "private", "server", "status", "staff", "test"}:
        return "admin_or_status_route"
    if terms & {"api", "docs", "graphql", "openapi", "swagger"} or "api-docs" in lowered:
        return "api_route"
    return "application_route"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
