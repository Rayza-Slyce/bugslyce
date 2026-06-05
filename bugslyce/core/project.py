"""Deterministic project assembly for parsed passive recon inputs."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import warnings as warnings_module

from bugslyce.core.models import (
    Asset,
    Endpoint,
    Evidence,
    HTTPService,
    ParsedHTTPXRecord,
    ParsedNotes,
    ParsedScope,
    ParsedSubdomain,
    ParsedURL,
    ProjectState,
)
from bugslyce.core.normalise import dedupe_preserve_order, normalise_hostname, normalise_url
from bugslyce.core.scope import parse_scope
from bugslyce.parsers.httpx import parse_httpx_jsonl
from bugslyce.parsers.notes import parse_notes
from bugslyce.parsers.subdomains import parse_subdomains
from bugslyce.parsers.urls import parse_urls


InputParser = Callable[[Path], object]


def build_project_state(input_dir: Path) -> ProjectState:
    """Build an in-memory project state from MVP passive recon files."""

    warnings: list[str] = []
    processed_files: list[str] = []

    scope = _parse_optional(input_dir / "scope.md", parse_scope, processed_files, warnings)
    subdomains = _parse_optional(input_dir / "subdomains.txt", parse_subdomains, processed_files, warnings)
    httpx_records = _parse_optional(input_dir / "httpx.jsonl", parse_httpx_jsonl, processed_files, warnings)
    urls = _parse_optional(input_dir / "urls.txt", parse_urls, processed_files, warnings)
    notes = _parse_optional(input_dir / "notes.md", parse_notes, processed_files, warnings)

    evidence: list[Evidence] = []
    asset_evidence: dict[str, list[str]] = defaultdict(list)
    asset_sources: dict[str, list[str]] = defaultdict(list)
    service_records: dict[str, HTTPService] = {}
    endpoint_records: dict[str, Endpoint] = {}
    service_order: list[str] = []
    endpoint_order: list[str] = []

    scope_entries = _scope_entries(scope)
    for entry_type, value in scope_entries:
        evidence_id = _append_evidence(
            evidence,
            "SCOPE",
            scope.source_path,
            entry_type,
            value,
            {"scope_type": entry_type},
        )
        host = _simple_scope_host(value)
        if host:
            _link_asset(asset_evidence, asset_sources, host, evidence_id, scope.source_path)

    for record in subdomains:
        host = normalise_hostname(record.hostname)
        evidence_id = _append_evidence(
            evidence,
            "HOST",
            record.source_path,
            "subdomain",
            host,
            {"line_number": record.line_number},
        )
        _link_asset(asset_evidence, asset_sources, host, evidence_id, record.source_path)

    for record in httpx_records:
        service_url = normalise_url(record.url or "")
        host = _record_hostname(record)
        evidence_id = _append_evidence(
            evidence,
            "HTTP",
            record.source_path,
            "http_service",
            service_url or host,
            {
                "line_number": record.line_number,
                "status_code": record.status_code,
                "title": record.title,
                "technologies": record.tech,
                "content_length": record.content_length,
            },
        )
        if host:
            _link_asset(asset_evidence, asset_sources, host, evidence_id, record.source_path)
        if service_url and host and service_url not in service_records:
            service_order.append(service_url)
            service_records[service_url] = HTTPService(
                url=service_url,
                hostname=host,
                status_code=record.status_code,
                title=record.title,
                technologies=dedupe_preserve_order(record.tech),
                content_length=record.content_length,
                evidence_ids=[evidence_id],
                tags=_host_tags(host),
            )
        elif service_url and service_url in service_records:
            _append_unique(service_records[service_url].evidence_ids, evidence_id)

    for record in urls:
        endpoint_url = normalise_url(record.original_url)
        host = normalise_hostname(record.hostname)
        evidence_id = _append_evidence(
            evidence,
            "URL",
            record.source_path,
            "endpoint",
            endpoint_url,
            {
                "line_number": record.line_number,
                "path": record.path,
                "query_params": record.query_param_names,
            },
        )
        _link_asset(asset_evidence, asset_sources, host, evidence_id, record.source_path)
        if endpoint_url not in endpoint_records:
            endpoint_order.append(endpoint_url)
            endpoint_records[endpoint_url] = Endpoint(
                url=endpoint_url,
                hostname=host,
                path=record.path,
                query_params=dedupe_preserve_order(record.query_param_names),
                evidence_ids=[evidence_id],
                tags=_endpoint_tags(record.path, record.query_param_names),
            )
        else:
            _append_unique(endpoint_records[endpoint_url].evidence_ids, evidence_id)

    for index, item in enumerate(notes.note_items, start=1):
        _append_evidence(
            evidence,
            "NOTE",
            notes.source_path,
            "note",
            item,
            {"item_number": index},
        )

    assets = [
        Asset(
            hostname=host,
            in_scope=_scope_status(host, scope),
            sources=dedupe_preserve_order(asset_sources[host]),
            evidence_ids=dedupe_preserve_order(asset_evidence[host]),
            tags=_host_tags(host),
        )
        for host in asset_evidence
    ]

    return ProjectState(
        project_name=input_dir.name,
        input_dir=str(input_dir),
        processed_files=processed_files,
        scope_summary=_scope_summary(scope),
        assets=assets,
        http_services=[service_records[url] for url in service_order],
        endpoints=[endpoint_records[url] for url in endpoint_order],
        evidence=evidence,
        warnings=warnings,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def _parse_optional(
    path: Path,
    parser: InputParser,
    processed_files: list[str],
    warnings: list[str],
) -> object:
    if not path.exists():
        warnings.append(f"Optional input file missing: {path}")
        return _empty_parse_result(path.name, path)

    with warnings_module.catch_warnings(record=True) as captured:
        warnings_module.simplefilter("always", RuntimeWarning)
        result = parser(path)

    processed_files.append(str(path))
    warnings.extend(str(item.message) for item in captured)
    return result


def _empty_parse_result(name: str, path: Path) -> object:
    source_path = str(path)
    if name == "scope.md":
        return ParsedScope([], [], "", source_path)
    if name == "notes.md":
        return ParsedNotes("", [], source_path)
    return []


def _scope_entries(scope: object) -> list[tuple[str, str]]:
    if not isinstance(scope, ParsedScope):
        return []
    return [("scope_in", value) for value in scope.in_scope] + [
        ("scope_out", value) for value in scope.out_of_scope
    ]


def _append_evidence(
    evidence: list[Evidence],
    prefix: str,
    source_file: str,
    evidence_type: str,
    value: str,
    context: dict[str, object],
) -> str:
    evidence_id = f"EVID-{prefix}-{_next_evidence_number(evidence, prefix):04d}"
    evidence.append(
        Evidence(
            id=evidence_id,
            source_file=source_file,
            evidence_type=evidence_type,
            value=value,
            context=context,
        )
    )
    return evidence_id


def _next_evidence_number(evidence: list[Evidence], prefix: str) -> int:
    starts_with = f"EVID-{prefix}-"
    return sum(1 for item in evidence if item.id.startswith(starts_with)) + 1


def _record_hostname(record: ParsedHTTPXRecord) -> str:
    if record.host:
        return normalise_hostname(record.host)
    if record.url:
        parsed = urlparse(record.url)
        if parsed.hostname:
            return normalise_hostname(parsed.hostname)
    return ""


def _link_asset(
    asset_evidence: dict[str, list[str]],
    asset_sources: dict[str, list[str]],
    hostname: str,
    evidence_id: str,
    source_file: str,
) -> None:
    if not hostname:
        return
    _append_unique(asset_evidence[hostname], evidence_id)
    _append_unique(asset_sources[hostname], source_file)


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _scope_summary(scope: object) -> str:
    if not isinstance(scope, ParsedScope):
        return "Scope file not processed."
    return f"{len(scope.in_scope)} in-scope entries; {len(scope.out_of_scope)} out-of-scope entries"


def _scope_status(hostname: str, scope: object) -> bool | None:
    if not isinstance(scope, ParsedScope):
        return None
    host = normalise_hostname(hostname)
    in_hosts = [_simple_scope_host(value) for value in scope.in_scope]
    out_hosts = [_simple_scope_host(value) for value in scope.out_of_scope]

    if any(_host_matches_scope(host, scope_host) for scope_host in out_hosts if scope_host):
        return False
    if any(_host_matches_scope(host, scope_host) for scope_host in in_hosts if scope_host):
        return True
    return None


def _simple_scope_host(value: str) -> str | None:
    stripped = value.strip().strip("`").strip()
    if not stripped:
        return None
    if " " in stripped or "/" in stripped:
        return None
    if stripped.startswith("*."):
        stripped = stripped[2:]
    return normalise_hostname(stripped)


def _host_matches_scope(hostname: str, scope_host: str) -> bool:
    return hostname == scope_host or hostname.endswith(f".{scope_host}")


def _host_tags(hostname: str) -> list[str]:
    host = hostname.lower()
    tags: list[str] = []
    if "api" in host:
        tags.append("api")
    if "admin" in host:
        tags.append("admin")
    if any(marker in host for marker in ("staging", "stage", "dev", "test")):
        tags.append("environment")
    if any(marker in host for marker in ("cdn", "static", "assets")):
        tags.append("static_or_cdn")
    return tags


def _endpoint_tags(path: str, query_params: list[str]) -> list[str]:
    lower_path = path.lower()
    lower_params = [param.lower() for param in query_params]
    combined_params = " ".join(lower_params)
    tags: list[str] = []

    if any(marker in lower_path for marker in ("login", "auth", "reset", "account", "session")):
        tags.append("auth_surface")
    if "admin" in lower_path:
        tags.append("admin_surface")
    if any(marker in lower_path for marker in ("/api/", "/v1/", "/v2/", "/graphql")):
        tags.append("api_surface")
    if any(marker in lower_path for marker in ("upload", "import", "export", "download", "file", "content")) or any(
        marker in combined_params for marker in ("upload", "import", "export", "download", "file", "content")
    ):
        tags.append("file_or_content_surface")
    if any(marker in combined_params for marker in ("id", "user_id", "account_id", "org_id", "tenant_id", "order_id")):
        tags.append("object_reference")
    if any(marker in combined_params for marker in ("next", "url", "redirect", "return", "return_to")):
        tags.append("redirect_parameter")
    if lower_path.endswith((".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff", ".woff2")):
        tags.append("static_asset")

    return tags
