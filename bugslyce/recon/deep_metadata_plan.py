"""Pure Deep Recon common metadata request planning.

This module builds planned request queues only. It does not inspect projects,
read files, write files, create outputs, run commands, resolve DNS, or make
network requests.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from urllib.parse import urlparse, urlunparse

from bugslyce.core.models import ProjectState


MAX_DEEP_METADATA_SERVICES = 50
DEEP_METADATA_PATHS: tuple[tuple[str, str, str], ...] = (
    ("/robots.txt", "robots", "Common robots.txt policy and clue source."),
    ("/sitemap.xml", "sitemap", "Common sitemap index for already authorised services."),
    ("/security.txt", "security", "Common security contact metadata path."),
    ("/.well-known/security.txt", "security", "Well-known security contact metadata path."),
    ("/humans.txt", "humans", "Common humans.txt metadata path."),
    ("/crossdomain.xml", "crossdomain", "Legacy cross-domain policy metadata path."),
    ("/clientaccesspolicy.xml", "client_access_policy", "Legacy client access policy metadata path."),
    ("/favicon.ico", "favicon", "Common favicon metadata for service correlation."),
)
DEEP_METADATA_GUARANTEES = (
    "This is a planned request queue only.",
    "No network requests are performed.",
    "No project files are read or written.",
    "No commands are executed.",
    "No output files are created.",
    "Deep Recon is available only through the bounded deep-bounded profile.",
    "`deep-bounded` remains bounded and scope-conscious.",
)


@dataclass(frozen=True)
class DeepMetadataService:
    """One explicit in-scope HTTP service URL supplied by a future caller."""

    url: str
    source: str


@dataclass(frozen=True)
class DeepMetadataRequest:
    """One planned common metadata request."""

    request_id: str
    service_url: str
    method: str
    url: str
    path: str
    category: str
    reason: str
    source: str


@dataclass(frozen=True)
class DeepMetadataSkippedService:
    """One service input skipped by the planner."""

    url: str
    source: str
    reason: str


@dataclass(frozen=True)
class DeepMetadataPlan:
    """Deterministic common metadata request plan."""

    requests: tuple[DeepMetadataRequest, ...]
    skipped_services: tuple[DeepMetadataSkippedService, ...]
    bounds: dict[str, int]
    non_executable_guarantees: tuple[str, ...]


def build_deep_metadata_request_plan(
    services: Iterable[DeepMetadataService],
    *,
    max_services: int | None = None,
) -> DeepMetadataPlan:
    """Build a deterministic Deep common metadata request plan."""

    service_limit = MAX_DEEP_METADATA_SERVICES if max_services is None else max(0, max_services)
    request_queue: list[DeepMetadataRequest] = []
    skipped: list[DeepMetadataSkippedService] = []
    origins: list[tuple[str, DeepMetadataService]] = []
    seen_origins: set[str] = set()

    for service in services:
        if not isinstance(service, DeepMetadataService):
            continue
        origin, reason = _normalise_http_origin(service.url)
        if origin is None:
            skipped.append(
                DeepMetadataSkippedService(
                    url=service.url,
                    source=service.source,
                    reason=reason,
                )
            )
            continue
        if origin in seen_origins:
            skipped.append(
                DeepMetadataSkippedService(
                    url=service.url,
                    source=service.source,
                    reason="duplicate_origin",
                )
            )
            continue
        if len(origins) >= service_limit:
            skipped.append(
                DeepMetadataSkippedService(
                    url=service.url,
                    source=service.source,
                    reason="service_limit_exceeded",
                )
            )
            continue
        seen_origins.add(origin)
        origins.append((origin, service))

    request_number = 1
    for origin, service in origins:
        for path, category, reason in DEEP_METADATA_PATHS:
            request_queue.append(
                DeepMetadataRequest(
                    request_id=f"deep-meta-{request_number:04d}",
                    service_url=origin,
                    method="GET",
                    url=_join_origin_path(origin, path),
                    path=path,
                    category=category,
                    reason=reason,
                    source=service.source,
                )
            )
            request_number += 1

    return DeepMetadataPlan(
        requests=tuple(request_queue),
        skipped_services=tuple(skipped),
        bounds={
            "max_services": service_limit,
            "metadata_paths_per_service": len(DEEP_METADATA_PATHS),
        },
        non_executable_guarantees=DEEP_METADATA_GUARANTEES,
    )


def build_deep_metadata_services_from_project_state(
    project_state: ProjectState,
) -> tuple[DeepMetadataService, ...]:
    """Build metadata planner service inputs from loaded project state only."""

    services: list[DeepMetadataService] = []
    for service in project_state.http_services:
        _append_project_state_service(
            services,
            service.url,
            "project-state:http-service",
        )
    for endpoint in project_state.endpoints:
        _append_project_state_service(
            services,
            endpoint.url,
            "project-state:endpoint",
        )
    for artifact in project_state.http_artifacts:
        _append_project_state_service(
            services,
            artifact.url,
            "project-state:http-artifact",
        )
    for path in project_state.discovered_paths:
        _append_project_state_service(
            services,
            path.url,
            "project-state:discovered-path",
        )
    return tuple(services)


def build_deep_metadata_plan_from_project_state(
    project_state: ProjectState,
    *,
    max_services: int | None = None,
) -> DeepMetadataPlan:
    """Build a metadata plan from loaded project state without execution."""

    return build_deep_metadata_request_plan(
        build_deep_metadata_services_from_project_state(project_state),
        max_services=max_services,
    )


def export_deep_metadata_plan_json(plan: DeepMetadataPlan) -> dict[str, object]:
    """Return a deterministic JSON-serialisable metadata plan payload."""

    return {
        "schema_version": 1,
        "request_count": len(plan.requests),
        "skipped_service_count": len(plan.skipped_services),
        "bounds": dict(plan.bounds),
        "requests": [asdict(request) for request in plan.requests],
        "skipped_services": [asdict(service) for service in plan.skipped_services],
        "non_executable_guarantees": list(plan.non_executable_guarantees),
    }


def render_deep_metadata_plan_markdown(plan: DeepMetadataPlan) -> str:
    """Render a deterministic Markdown summary for a metadata request plan."""

    lines = [
        "# Deep Common Metadata Request Plan",
        "",
        f"- Planned requests: {len(plan.requests)}",
        f"- Skipped services: {len(plan.skipped_services)}",
        f"- Max services: {plan.bounds['max_services']}",
        f"- Metadata paths per service: {plan.bounds['metadata_paths_per_service']}",
        "",
        "## Planned Requests",
        "",
    ]
    if not plan.requests:
        lines.append("- None.")
    else:
        lines.extend(
            f"- `{request.request_id}` `{request.method}` {request.url} ({request.category})"
            for request in plan.requests
        )

    lines.extend(["", "## Skipped Services", ""])
    if not plan.skipped_services:
        lines.append("- None.")
    else:
        lines.extend(
            f"- `{service.url}` from `{service.source}`: {service.reason}"
            for service in plan.skipped_services
        )

    lines.extend(["", "## Non-Executable Guarantees", ""])
    lines.extend(f"- {guarantee}" for guarantee in plan.non_executable_guarantees)
    lines.append("")
    return "\n".join(lines)


def _normalise_http_origin(raw_url: str) -> tuple[str | None, str]:
    value = raw_url.strip() if isinstance(raw_url, str) else ""
    if not value:
        return None, "empty_url"
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None, "malformed_url"
    if parsed.scheme not in {"http", "https"}:
        return None, "unsupported_scheme"
    if not parsed.hostname:
        return None, "malformed_url"
    hostname = parsed.hostname.lower()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    default_port = 443 if parsed.scheme == "https" else 80
    netloc = hostname if port in (None, default_port) else f"{hostname}:{port}"
    return urlunparse((parsed.scheme, netloc, "/", "", "", "")), ""


def _join_origin_path(origin: str, path: str) -> str:
    return origin.rstrip("/") + path


def _append_project_state_service(
    services: list[DeepMetadataService],
    url: str,
    source: str,
) -> None:
    if _normalise_http_origin(url)[0] is None:
        return
    services.append(DeepMetadataService(url=url, source=source))
