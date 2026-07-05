"""Offline Deep source/route evidence coverage summary.

This module summarises already-loaded project state only. It does not read
files, write files, fetch URLs, execute commands, or make Deep Recon available.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlparse, urlunparse

from bugslyce.core.models import ProjectState


BODY_SOURCE_ARTIFACT_TYPES = {
    "page_title",
    "html_comment",
    "keyword_hit",
    "form",
    "input",
    "link",
    "script_or_asset",
    "encoded_like_artifact",
    "hidden_element",
}
SOURCE_ROUTE_STATUSES = (
    "body_collected",
    "headers_collected",
    "discovered_unfetched",
    "referenced_only",
    "static_noise",
    "metadata_context",
)
SOURCE_ROUTE_CATEGORIES = (
    "auth_route",
    "admin_or_status_route",
    "application_route",
    "source_context",
    "form_context",
    "api_route",
    "script_or_asset",
    "static_asset",
    "metadata_route",
    "other_route",
)
METADATA_PATHS = {
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/humans.txt",
    "/favicon.ico",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
}
STATIC_SUFFIXES = (
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".png",
    ".svg",
    ".ttf",
    ".woff",
    ".woff2",
)
STATIC_SEGMENTS = {"/assets/", "/static/", "/images/", "/icons/", "/img/", "/css/", "/js/"}
STATIC_DIRECTORIES = {
    "/assets",
    "/static",
    "/images",
    "/icons",
    "/img",
    "/css",
    "/js",
}
AUTH_TERMS = {
    "account",
    "auth",
    "callback",
    "dashboard",
    "forgot",
    "login",
    "logout",
    "mfa",
    "oauth",
    "password",
    "portal",
    "register",
    "reset",
    "session",
    "signin",
    "signup",
    "sso",
    "token",
    "verify",
    "2fa",
}
ADMIN_TERMS = {
    "actuator",
    "admin",
    "backoffice",
    "console",
    "control",
    "cpanel",
    "debug",
    "dev",
    "health",
    "internal",
    "manage",
    "management",
    "manager",
    "metrics",
    "monitor",
    "ops",
    "private",
    "server-info",
    "server-status",
    "staff",
    "status",
    "test",
}
API_TERMS = {
    "api",
    "api-docs",
    "docs",
    "graphql",
    "openapi",
    "swagger",
}
MAX_RENDERED_VALUES = 6
INTRO_TEXT = (
    "This summary describes already-collected local source and route evidence. "
    "It does not fetch URLs and does not execute Deep Recon."
)
NOTES = (
    "This is a coverage view, not a finding list.",
    "Missing body/source evidence does not imply the route is absent or safe.",
    (
        "Do not fetch, submit forms, authenticate, brute force, or test routes "
        "from this summary unless explicitly authorised and in scope."
    ),
)


@dataclass(frozen=True)
class DeepSourceRouteCoverageItem:
    """One source/route coverage item from already-loaded local evidence."""

    url: str
    path: str
    status: str
    category: str
    source: str
    evidence_ids: tuple[str, ...]
    signals: tuple[str, ...]
    planned: bool
    collected: bool
    reason: str
    suggested_manual_review: str


@dataclass(frozen=True)
class DeepSourceRouteCoverageSummary:
    """Deterministic Deep source/route coverage summary."""

    items: tuple[DeepSourceRouteCoverageItem, ...]
    body_collected_count: int
    headers_collected_count: int
    discovered_unfetched_count: int
    referenced_only_count: int
    static_noise_count: int
    metadata_context_count: int


@dataclass(frozen=True)
class _PendingCoverage:
    url: str
    path: str
    status: str
    category: str
    source: str
    evidence_ids: tuple[str, ...]
    signals: tuple[str, ...]
    reason: str


def build_deep_source_route_coverage_from_project_state(
    project_state: ProjectState,
) -> DeepSourceRouteCoverageSummary:
    """Build source/route coverage from already-loaded ProjectState evidence."""

    pending: dict[str, _PendingCoverage] = {}

    for artifact in project_state.http_artifacts:
        normalised_url = _normalise_url(artifact.url)
        if normalised_url is None:
            continue
        path = _normalised_path(normalised_url)
        status, category = _status_category_for_path(path)
        if status not in {"static_noise", "metadata_context"}:
            if artifact.artifact_type in BODY_SOURCE_ARTIFACT_TYPES:
                status = "body_collected"
            else:
                status = "referenced_only"
            category = _category_for_path_and_signal(path, artifact.artifact_type)
        _merge_pending(
            pending,
            _PendingCoverage(
                url=normalised_url,
                path=path,
                status=status,
                category=category,
                source=f"http_artifact:{artifact.artifact_type}",
                evidence_ids=tuple(_dedupe(artifact.evidence_ids)),
                signals=(artifact.artifact_type,),
                reason=_reason_for_status(status),
            ),
        )

    for path_record in project_state.discovered_paths:
        normalised_url = _normalise_url(path_record.url)
        if normalised_url is None:
            continue
        path = _normalised_path(normalised_url)
        status, category = _status_category_for_path(path)
        if status not in {"static_noise", "metadata_context"}:
            status = "discovered_unfetched"
            category = _category_for_path_and_signal(path, "discovered_path")
        _merge_pending(
            pending,
            _PendingCoverage(
                url=normalised_url,
                path=path,
                status=status,
                category=category,
                source="project-state:discovered-path",
                evidence_ids=tuple(_dedupe(path_record.evidence_ids)),
                signals=("discovered_path",),
                reason=_reason_for_status(status),
            ),
        )

    for endpoint in project_state.endpoints:
        normalised_url = _normalise_url(endpoint.url)
        if normalised_url is None:
            continue
        path = _normalised_path(normalised_url)
        status, category = _status_category_for_path(path)
        if status not in {"static_noise", "metadata_context"}:
            status = "referenced_only"
            category = _category_for_path_and_signal(path, "endpoint")
        _merge_pending(
            pending,
            _PendingCoverage(
                url=normalised_url,
                path=path,
                status=status,
                category=category,
                source="project-state:endpoint",
                evidence_ids=tuple(_dedupe(endpoint.evidence_ids)),
                signals=("endpoint",),
                reason=_reason_for_status(status),
            ),
        )

    for service in project_state.http_services:
        normalised_url = _normalise_url(service.url)
        if normalised_url is None:
            continue
        path = _normalised_path(normalised_url)
        status, category = _status_category_for_path(path)
        if status not in {"static_noise", "metadata_context"}:
            status = "headers_collected"
            category = _category_for_path_and_signal(path, "http_service")
        signals = ["http_service"]
        if service.status_code is not None:
            signals.append(f"status:{service.status_code}")
        if service.title:
            signals.append("title")
        _merge_pending(
            pending,
            _PendingCoverage(
                url=normalised_url,
                path=path,
                status=status,
                category=category,
                source="project-state:http-service",
                evidence_ids=tuple(_dedupe(service.evidence_ids)),
                signals=tuple(signals),
                reason=_reason_for_status(status),
            ),
        )

    items = tuple(
        DeepSourceRouteCoverageItem(
            url=item.url,
            path=item.path,
            status=item.status,
            category=item.category,
            source=item.source,
            evidence_ids=item.evidence_ids,
            signals=item.signals,
            planned=False,
            collected=item.status in {"body_collected", "headers_collected"},
            reason=item.reason,
            suggested_manual_review=_suggested_manual_review(item.status, item.category),
        )
        for item in sorted(pending.values(), key=_coverage_sort_key)
    )
    return DeepSourceRouteCoverageSummary(
        items=items,
        body_collected_count=sum(1 for item in items if item.status == "body_collected"),
        headers_collected_count=sum(1 for item in items if item.status == "headers_collected"),
        discovered_unfetched_count=sum(
            1 for item in items if item.status == "discovered_unfetched"
        ),
        referenced_only_count=sum(1 for item in items if item.status == "referenced_only"),
        static_noise_count=sum(1 for item in items if item.status == "static_noise"),
        metadata_context_count=sum(1 for item in items if item.status == "metadata_context"),
    )


def render_deep_source_route_coverage_markdown(
    summary: DeepSourceRouteCoverageSummary,
) -> str:
    """Render Deep source/route coverage as terminal-friendly Markdown."""

    lines = [
        "## Deep Source/Route Coverage",
        "",
        INTRO_TEXT,
        "",
        "### Summary",
        "",
        f"- Body/source collected: {summary.body_collected_count}",
        f"- Headers collected: {summary.headers_collected_count}",
        f"- Discovered but unfetched: {summary.discovered_unfetched_count}",
        f"- Referenced only: {summary.referenced_only_count}",
        f"- Static noise: {summary.static_noise_count}",
        f"- Metadata context: {summary.metadata_context_count}",
        "",
    ]

    sections = (
        (
            "Reviewable Application Routes",
            lambda item: item.status in {"body_collected", "headers_collected"}
            and item.status not in {"static_noise", "metadata_context"}
            and item.category not in {"static_asset", "metadata_route"},
        ),
        ("Discovered But Not Body-Fetched", lambda item: item.status == "discovered_unfetched"),
        ("Referenced Only", lambda item: item.status == "referenced_only"),
        ("Static / Directory Context", lambda item: item.status == "static_noise"),
        ("Metadata Context", lambda item: item.status == "metadata_context"),
    )
    for title, predicate in sections:
        section_items = tuple(item for item in summary.items if predicate(item))
        if not section_items:
            continue
        lines.extend([f"### {title}", ""])
        lines.extend(_render_items(section_items))
        lines.append("")

    lines.extend(["### Notes", ""])
    lines.extend(f"- {note}" for note in NOTES)
    lines.append("")
    return "\n".join(lines).rstrip()


def _render_items(items: tuple[DeepSourceRouteCoverageItem, ...]) -> list[str]:
    lines: list[str] = []
    for item in items:
        line = f"- `{item.url}` - {item.category} - {item.status}"
        if item.signals:
            line += " - signals: " + _format_compact_values(item.signals)
        if item.evidence_ids:
            line += " - evidence: " + _format_compact_values(item.evidence_ids)
        lines.append(line)
        lines.append(f"  - Suggested manual review: {item.suggested_manual_review}")
    return lines


def _merge_pending(
    pending: dict[str, _PendingCoverage],
    candidate: _PendingCoverage,
) -> None:
    existing = pending.get(candidate.url)
    if existing is None:
        pending[candidate.url] = candidate
        return
    status = _stronger_status(existing.status, candidate.status)
    primary = existing if status == existing.status else candidate
    pending[candidate.url] = _PendingCoverage(
        url=primary.url,
        path=primary.path,
        status=status,
        category=_stronger_category(existing.category, candidate.category),
        source=", ".join(_dedupe([existing.source, candidate.source])),
        evidence_ids=tuple(_dedupe([*existing.evidence_ids, *candidate.evidence_ids])),
        signals=tuple(_dedupe([*existing.signals, *candidate.signals])),
        reason=_reason_for_status(status),
    )


def _status_category_for_path(path: str) -> tuple[str, str]:
    if path in METADATA_PATHS:
        return "metadata_context", "metadata_route"
    if _is_static_path(path):
        return "static_noise", "static_asset"
    return "referenced_only", "other_route"


def _category_for_path_and_signal(path: str, signal: str) -> str:
    lowered_path = path.lower()
    names = _path_terms(lowered_path)
    if names & AUTH_TERMS:
        return "auth_route"
    if names & ADMIN_TERMS:
        return "admin_or_status_route"
    if names & API_TERMS:
        return "api_route"
    if signal in {"form", "input"}:
        return "form_context"
    if signal in {"html_comment", "keyword_hit", "encoded_like_artifact", "hidden_element"}:
        return "source_context"
    if signal == "script_or_asset":
        return "script_or_asset"
    if lowered_path == "/":
        return "application_route"
    return "application_route"


def _is_static_path(path: str) -> bool:
    lowered = path.lower()
    return lowered in STATIC_DIRECTORIES or lowered.endswith(STATIC_SUFFIXES) or any(
        segment in lowered for segment in STATIC_SEGMENTS
    )


def _path_terms(lowered_path: str) -> set[str]:
    segments = [segment for segment in lowered_path.strip("/").split("/") if segment]
    terms = set(segments)
    for segment in segments:
        if "." in segment:
            terms.add(segment.rsplit(".", 1)[0])
        terms.update(part for part in re.split(r"[._-]+", segment) if part)
    return terms


def _stronger_status(first: str, second: str) -> str:
    order = {
        "body_collected": 0,
        "headers_collected": 1,
        "discovered_unfetched": 2,
        "referenced_only": 3,
        "static_noise": 4,
        "metadata_context": 5,
    }
    return first if order[first] <= order[second] else second


def _stronger_category(first: str, second: str) -> str:
    order = {
        "auth_route": 0,
        "admin_or_status_route": 1,
        "application_route": 2,
        "source_context": 3,
        "form_context": 4,
        "api_route": 5,
        "script_or_asset": 6,
        "other_route": 7,
        "static_asset": 8,
        "metadata_route": 9,
    }
    return first if order[first] <= order[second] else second


def _coverage_sort_key(item: _PendingCoverage) -> tuple[int, int, str]:
    category_order = {
        "auth_route": 0,
        "admin_or_status_route": 1,
        "application_route": 2,
        "source_context": 3,
        "form_context": 4,
        "api_route": 5,
        "script_or_asset": 6,
        "other_route": 7,
        "metadata_route": 8,
        "static_asset": 9,
    }
    status_order = {
        "body_collected": 0,
        "headers_collected": 1,
        "discovered_unfetched": 2,
        "referenced_only": 3,
        "metadata_context": 4,
        "static_noise": 5,
    }
    return (
        category_order.get(item.category, 99),
        status_order.get(item.status, 99),
        item.url,
    )


def _reason_for_status(status: str) -> str:
    return {
        "body_collected": "local_body_or_source_artifact_collected",
        "headers_collected": "local_http_service_or_header_context_collected",
        "discovered_unfetched": "local_discovered_path_without_body_source_evidence",
        "referenced_only": "local_endpoint_or_source_reference_only",
        "static_noise": "static_or_library_asset_context",
        "metadata_context": "metadata_route_context",
    }[status]


def _suggested_manual_review(status: str, category: str) -> str:
    if category == "auth_route":
        return (
            "Review the collected route context manually; do not submit forms or "
            "attempt authentication from this summary."
        )
    if category == "admin_or_status_route":
        return "Review the route purpose and exposure context manually before escalating."
    if status == "discovered_unfetched":
        return "Treat this as a discovered route gap unless authorised follow-up collection exists."
    if status == "referenced_only":
        return "Treat this as a source or endpoint reference until response evidence exists."
    if status == "static_noise":
        return "Keep as low-signal static context unless it supports a stronger route lead."
    if status == "metadata_context":
        return "Use metadata route context alongside dedicated metadata coverage and review output."
    return "Review the local source and route evidence in context before escalating."


def _format_compact_values(values: tuple[str, ...]) -> str:
    rendered = ", ".join(f"`{value}`" for value in values[:MAX_RENDERED_VALUES])
    remaining = len(values) - MAX_RENDERED_VALUES
    if remaining > 0:
        rendered += f", ... +{remaining} more"
    return rendered


def _normalise_url(raw_url: str) -> str | None:
    value = raw_url.strip() if isinstance(raw_url, str) else ""
    if not value:
        return None
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    hostname = parsed.hostname.lower()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    netloc = hostname if port in (None, default_port) else f"{hostname}:{port}"
    path = _normalise_path_value(parsed.path)
    return urlunparse((parsed.scheme.lower(), netloc, path, "", "", ""))


def _normalised_path(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    return _normalise_path_value(parsed.path)


def _normalise_path_value(path: str) -> str:
    if not path:
        return "/"
    if len(path) > 1:
        return path.rstrip("/")
    return path


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
