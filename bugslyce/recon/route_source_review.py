"""Offline route/source review for already-collected Standard evidence."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
import re
from urllib.parse import urlparse

from bugslyce.core.engagement_context import engagement_context_review_guidance
from bugslyce.core.models import ProjectState
from bugslyce.recon.artefact_analysis import ArtefactSource


MAX_ROUTE_LENGTH = 160
MAX_ROUTES_PER_SOURCE = 80
MAX_ROUTES_PER_LEAD = 25
STATIC_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".css",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
)
ABSOLUTE_URL_RE = re.compile(r"https?://[^\s\"'<>)]{1,240}", re.IGNORECASE)
ROUTE_RE = re.compile(
    r"(?<![:/<])/[A-Za-z0-9._~!$&()*+,;=:@/%-]{1,180}"
    r"(?:\?[A-Za-z0-9._~!$&()*+,;=:@/?%-]{1,120})?"
)
CATEGORY_ORDER = {
    "authentication/account/session": 0,
    "admin/debug/status/dev": 1,
    "api/graphql/webhook": 2,
    "file/data transfer": 3,
    "object/reference-looking": 4,
    "general route references": 5,
}
CATEGORY_TITLES = {
    "authentication/account/session": "Authentication/account/session routes",
    "admin/debug/status/dev": "Admin/debug/status/dev routes",
    "api/graphql/webhook": "API/GraphQL/webhook routes",
    "file/data transfer": "Upload/download/import/export/file routes",
    "object/reference-looking": "User/account/tenant/object-reference-looking routes",
    "general route references": "General route references",
}
CATEGORY_MANUAL_REVIEW = {
    "authentication/account/session": (
        "Review authentication, account, and session route context manually.",
        "Confirm whether account boundaries or session behaviour are in scope before manual testing.",
    ),
    "admin/debug/status/dev": (
        "Review admin, debug, status, and development route context manually.",
        "Confirm expected service purpose and exposure before escalating.",
    ),
    "api/graphql/webhook": (
        "Review API, GraphQL, webhook, and callback route context manually.",
        "Correlate with observed HTTP services and any documented scope boundaries.",
    ),
    "file/data transfer": (
        "Review upload, download, import, export, backup, and file route context manually.",
        "Confirm whether any data transfer behaviour is in scope before manual testing.",
    ),
    "object/reference-looking": (
        "Review object-reference-looking routes and parameters manually.",
        "Check whether user, account, tenant, organisation, or project context is present before escalating.",
    ),
    "general route references": (
        "Review route references in their collected source context.",
        "Prioritise routes that correlate with stronger service, robots, or source evidence.",
    ),
}
COMMON_MANUAL_REVIEW = (
    "Review the already-collected source context.",
    "Correlate with discovered paths, robots entries, and HTTP service context.",
    "Confirm whether the route is in scope before manual testing.",
    "Record request/response evidence before escalating.",
    (
        "Do not submit forms, brute force, attempt authentication, or treat "
        "route names as confirmed exposure."
    ),
)


@dataclass(frozen=True)
class RouteSourceLead:
    """Grouped offline route/source review lead."""

    lead_id: str
    category: str
    title: str
    priority: str
    route_references: tuple[str, ...]
    source_kinds: tuple[str, ...]
    source_ids: tuple[str, ...]
    rationale: str
    manual_review: tuple[str, ...]


@dataclass(frozen=True)
class _RouteObservation:
    route: str
    source_kind: str
    source_id: str | None
    source_order: int


def build_route_source_review(
    project_state: ProjectState,
    sources: Sequence[ArtefactSource],
) -> tuple[RouteSourceLead, ...]:
    """Build deterministic route/source leads from local ProjectState and sources."""

    allowed_hosts = _allowed_hosts(project_state)
    allowed_hosts.update(_source_hosts(sources))
    observations: list[_RouteObservation] = []
    source_order = 0

    for endpoint in project_state.endpoints:
        source_order += 1
        observations.extend(
            _observations_from_route(
                endpoint.url,
                "endpoint",
                endpoint.evidence_ids[0] if endpoint.evidence_ids else None,
                source_order,
                allowed_hosts,
            )
        )
    for path in project_state.discovered_paths:
        source_order += 1
        observations.extend(
            _observations_from_route(
                path.url,
                "discovered_path",
                path.evidence_ids[0] if path.evidence_ids else None,
                source_order,
                allowed_hosts,
            )
        )
    for source in sources:
        source_order += 1
        observations.extend(_observations_from_source(source, source_order, allowed_hosts))

    grouped: dict[str, list[_RouteObservation]] = defaultdict(list)
    seen_by_category: dict[str, set[tuple[str, str | None]]] = defaultdict(set)
    for observation in observations:
        category = _route_category(observation.route)
        key = (observation.route, observation.source_id)
        if key in seen_by_category[category]:
            continue
        seen_by_category[category].add(key)
        grouped[category].append(observation)

    drafts = [
        _lead_for_category(category, items)
        for category, items in grouped.items()
        if items
    ]
    drafts.sort(key=_lead_sort_key)
    return tuple(
        RouteSourceLead(
            lead_id=f"ROUTE-{index:04d}",
            category=lead.category,
            title=lead.title,
            priority=lead.priority,
            route_references=lead.route_references,
            source_kinds=lead.source_kinds,
            source_ids=lead.source_ids,
            rationale=lead.rationale,
            manual_review=lead.manual_review,
        )
        for index, lead in enumerate(drafts, start=1)
    )


def render_route_source_review_markdown(
    leads: Sequence[RouteSourceLead],
    *,
    engagement_context: str | None = None,
) -> str:
    """Render Standard offline route/source review leads as Markdown."""

    lines = [
        "## Offline Route/Source Review",
        "",
        (
            "These route/source hints were extracted from already-collected local "
            "evidence. They are manual review prompts only and are not validated issues."
        ),
        "",
        engagement_context_review_guidance(engagement_context),
        "",
    ]
    if not leads:
        lines.extend(
            [
                "No offline route/source review leads were generated from the collected evidence.",
                "",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    for lead in leads:
        lines.extend(
            [
                f"### {lead.lead_id}: {lead.title}",
                "",
                f"- Priority: {lead.priority}",
                f"- Category: {lead.category}",
                f"- Rationale: {lead.rationale}",
                "- Observed route references:",
            ]
        )
        lines.extend(f"  - `{route}`" for route in lead.route_references)
        if lead.source_kinds:
            lines.append(
                "- Source kinds: "
                + ", ".join(f"`{source_kind}`" for source_kind in lead.source_kinds)
            )
        if lead.source_ids:
            lines.append(
                "- Source IDs: "
                + ", ".join(f"`{source_id}`" for source_id in lead.source_ids)
            )
        lines.append("- Safe manual review:")
        lines.extend(f"  - {step}" for step in lead.manual_review)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _observations_from_source(
    source: ArtefactSource,
    source_order: int,
    allowed_hosts: set[str],
) -> list[_RouteObservation]:
    routes: list[str] = []
    routes.extend(_extract_absolute_url_routes(source.text, allowed_hosts))
    routes.extend(_extract_relative_routes(source.text))
    routes = _dedupe_preserve_order(routes)[:MAX_ROUTES_PER_SOURCE]
    return [
        _RouteObservation(
            route=route,
            source_kind=source.source_kind,
            source_id=source.source_id or None,
            source_order=source_order,
        )
        for route in routes
    ]


def _observations_from_route(
    value: str,
    source_kind: str,
    source_id: str | None,
    source_order: int,
    allowed_hosts: set[str],
) -> list[_RouteObservation]:
    routes = _extract_absolute_url_routes(value, allowed_hosts)
    routes.extend(_extract_relative_routes(value))
    return [
        _RouteObservation(route=route, source_kind=source_kind, source_id=source_id, source_order=source_order)
        for route in _dedupe_preserve_order(routes)[:MAX_ROUTES_PER_SOURCE]
    ]


def _extract_absolute_url_routes(text: str, allowed_hosts: set[str]) -> list[str]:
    routes: list[str] = []
    for match in ABSOLUTE_URL_RE.finditer(text):
        parsed = urlparse(_strip_route_punctuation(match.group(0)))
        host = (parsed.hostname or "").lower()
        if not host or host not in allowed_hosts:
            continue
        route = _normalise_route(parsed.path or "/", parsed.query)
        if route:
            routes.append(route)
    return routes


def _extract_relative_routes(text: str) -> list[str]:
    routes: list[str] = []
    relative_text = ABSOLUTE_URL_RE.sub(" ", text)
    for match in ROUTE_RE.finditer(relative_text):
        raw = _strip_route_punctuation(match.group(0))
        if raw.startswith("//"):
            continue
        parsed = urlparse(raw)
        route = _normalise_route(parsed.path or raw, parsed.query)
        if route:
            routes.append(route)
    return routes


def _normalise_route(path: str, query: str = "") -> str | None:
    route = _strip_route_punctuation(path.strip())
    if not route.startswith("/") or route == "/":
        return None
    if len(route) > MAX_ROUTE_LENGTH:
        return None
    lowered_path = route.lower()
    if lowered_path.endswith(STATIC_EXTENSIONS):
        return None
    if query:
        route = f"{route}?{_strip_route_punctuation(query)}"
        if len(route) > MAX_ROUTE_LENGTH:
            return None
    return route


def _strip_route_punctuation(value: str) -> str:
    return value.strip().rstrip(".,;:!?'\"`)]}")


def _route_category(route: str) -> str:
    lowered = route.lower()
    if _has_any(lowered, ("/login", "/logout", "/register", "/signup", "/reset", "/password", "/session", "/auth", "/oauth", "/account", "/profile")):
        return "authentication/account/session"
    if _has_any(lowered, ("/admin", "/debug", "/dev", "/test", "/status", "/health", "/internal", "/staging", "/console")):
        return "admin/debug/status/dev"
    if _has_any(lowered, ("/api", "/v1", "/v2", "/graphql", "/webhook", "/callback")):
        return "api/graphql/webhook"
    if _has_any(lowered, ("/upload", "/download", "/import", "/export", "/backup", "/file", "/files", "/attachment", "/attachments")):
        return "file/data transfer"
    if _looks_object_reference(lowered):
        return "object/reference-looking"
    return "general route references"


def _has_any(value: str, needles: tuple[str, ...]) -> bool:
    return any(needle in value for needle in needles)


def _looks_object_reference(value: str) -> bool:
    if any(token in value for token in ("user_id", "account_id", "tenant_id", "org_id", "organisation_id", "project_id", "id=")):
        return True
    object_terms = ("/user", "/users", "/account", "/accounts", "/tenant", "/tenants", "/org", "/organisation", "/project", "/projects")
    return any(term in value for term in object_terms) and any(segment.isdigit() for segment in value.replace("?", "/").replace("&", "/").split("/"))


def _lead_for_category(category: str, observations: list[_RouteObservation]) -> RouteSourceLead:
    ordered = sorted(observations, key=lambda item: item.source_order)
    routes = tuple(_dedupe_preserve_order(item.route for item in ordered)[:MAX_ROUTES_PER_LEAD])
    source_kinds = tuple(sorted({item.source_kind for item in ordered if item.source_kind}))
    source_ids = tuple(sorted({item.source_id for item in ordered if item.source_id}))
    priority = _priority_for_observations(ordered)
    return RouteSourceLead(
        lead_id="",
        category=category,
        title=CATEGORY_TITLES[category],
        priority=priority,
        route_references=routes,
        source_kinds=source_kinds,
        source_ids=source_ids,
        rationale=_rationale(category, ordered),
        manual_review=(*CATEGORY_MANUAL_REVIEW[category], *COMMON_MANUAL_REVIEW),
    )


def _priority_for_observations(observations: list[_RouteObservation]) -> str:
    routes = {item.route for item in observations}
    source_kinds = {item.source_kind for item in observations}
    return "medium" if len(routes) > 1 or len(source_kinds) > 1 else "low"


def _rationale(category: str, observations: list[_RouteObservation]) -> str:
    route_count = len({item.route for item in observations})
    source_count = len({item.source_kind for item in observations})
    return (
        f"Already-collected local evidence contains {route_count} route-shaped "
        f"reference(s) in the {category} bucket across {source_count} source kind(s)."
    )


def _lead_sort_key(lead: RouteSourceLead) -> tuple[object, ...]:
    first_route = lead.route_references[0] if lead.route_references else ""
    first_source = lead.source_ids[0] if lead.source_ids else ""
    return (CATEGORY_ORDER.get(lead.category, 99), first_route, first_source)


def _allowed_hosts(project_state: ProjectState) -> set[str]:
    hosts: set[str] = set()
    manifest = project_state.recon_manifest
    if manifest and manifest.target:
        hosts.add(manifest.target.lower())
    for service in project_state.http_services:
        hosts.add(service.hostname.lower())
    for endpoint in project_state.endpoints:
        hosts.add(endpoint.hostname.lower())
    for artifact in project_state.http_artifacts:
        parsed = urlparse(artifact.url)
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    return hosts


def _source_hosts(sources: Sequence[ArtefactSource]) -> set[str]:
    hosts: set[str] = set()
    for source in sources:
        parsed = urlparse(source.url or "")
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    return hosts


def _dedupe_preserve_order(values) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
