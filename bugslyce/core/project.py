"""Deterministic project assembly for parsed passive recon inputs."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
import re
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse
import warnings as warnings_module

from bugslyce.core.models import (
    Asset,
    DiscoveredPath,
    Endpoint,
    Evidence,
    HTTPArtifact,
    HTTPService,
    ParsedHTTPXRecord,
    ParsedHTTPHeaders,
    ParsedNotes,
    ParsedScope,
    ParsedSubdomain,
    ParsedURL,
    PortService,
    ProjectState,
    ReconPackSummary,
)
from bugslyce.core.normalise import dedupe_preserve_order, normalise_hostname, normalise_url
from bugslyce.core.scope import parse_scope
from bugslyce.parsers.gobuster import parse_gobuster
from bugslyce.parsers.html import parse_html
from bugslyce.parsers.http_headers import parse_http_headers
from bugslyce.parsers.httpx import parse_httpx_jsonl
from bugslyce.parsers.nmap import parse_nmap_normal
from bugslyce.parsers.notes import parse_notes
from bugslyce.parsers.robots import parse_robots
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
    port_services: list[PortService] = []
    port_service_keys: dict[tuple[str, int, str], PortService] = {}
    http_artifacts: list[HTTPArtifact] = []
    discovered_paths: list[DiscoveredPath] = []

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

    default_host = _default_raw_host(scope, subdomains)
    for raw_path in sorted(input_dir.glob("nmap*.txt")):
        records = _parse_present(raw_path, lambda path: parse_nmap_normal(path, default_host), processed_files, warnings)
        for record in records:
            host = normalise_hostname(record.host or default_host or "")
            evidence_id = _append_evidence(
                evidence,
                "PORT",
                record.source_file,
                "port_service",
                f"{host}:{record.port}/{record.protocol} {record.state} {record.service or 'unknown'}",
                {
                    "port": record.port,
                    "protocol": record.protocol,
                    "state": record.state,
                    "service": record.service,
                    "product": record.product,
                    "version": record.version,
                },
            )
            if host:
                _link_asset(asset_evidence, asset_sources, host, evidence_id, record.source_file)
            key = (host, record.port, record.protocol)
            if key not in port_service_keys:
                record.host = host
                record.evidence_ids = [evidence_id]
                record.tags = _port_service_tags(record)
                port_service_keys[key] = record
                port_services.append(record)
            else:
                existing = port_service_keys[key]
                _append_unique(existing.evidence_ids, evidence_id)
                existing.tags = dedupe_preserve_order([*existing.tags, *_port_service_tags(record)])
                if not existing.product and record.product:
                    existing.product = record.product
                if not existing.version and record.version:
                    existing.version = record.version
            if record.state == "open" and _is_http_service_name(record.service):
                service_url = _service_url(host, record.port, record.service)
                _merge_http_service(
                    service_records,
                    service_order,
                    service_url,
                    host,
                    None,
                    None,
                    [value for value in (record.product, record.version) if value],
                    None,
                    evidence_id,
                )

    for raw_path in sorted(input_dir.glob("curl-headers-*.txt")):
        header = _parse_present(raw_path, parse_http_headers, processed_files, warnings)
        if not isinstance(header, ParsedHTTPHeaders):
            continue
        url = _infer_artifact_url(raw_path, default_host, "headers")
        evidence_id = _append_evidence(
            evidence,
            "HEADER",
            header.source_file,
            "http_headers",
            url or raw_path.name,
            {
                "status_code": header.status_code,
                "server": header.server,
                "content_type": header.content_type,
                "content_length": header.content_length,
                "location": header.location,
            },
        )
        if url:
            host = normalise_hostname(urlparse(url).hostname or "")
            _link_asset(asset_evidence, asset_sources, host, evidence_id, header.source_file)
            origin = _origin_url(url)
            _merge_http_service(
                service_records,
                service_order,
                origin,
                host,
                header.status_code if url == origin else None,
                None,
                [header.server] if header.server else [],
                header.content_length if url == origin else None,
                evidence_id,
            )
            if url != origin or header.status_code == 404 or header.location:
                discovered = DiscoveredPath(
                    url=url,
                    status_code=header.status_code,
                    content_length=header.content_length,
                    redirect_location=header.location,
                    source=header.source_file,
                    evidence_ids=[evidence_id],
                    tags=_discovered_path_tags(url, header.status_code),
                )
                discovered_paths.append(discovered)
                _merge_endpoint_from_url(
                    endpoint_records,
                    endpoint_order,
                    url,
                    evidence_id,
                    extra_tags=discovered.tags,
                )

    for raw_path in sorted(input_dir.glob("gobuster-*.txt")):
        base_url = _infer_artifact_url(raw_path, default_host, "gobuster")
        records = _parse_present(
            raw_path,
            lambda path: parse_gobuster(path, base_url),
            processed_files,
            warnings,
        )
        for record in records:
            evidence_id = _append_evidence(
                evidence,
                "PATH",
                record.source,
                "discovered_path",
                record.url,
                {
                    "status_code": record.status_code,
                    "content_length": record.content_length,
                    "redirect_location": record.redirect_location,
                },
            )
            record.evidence_ids = [evidence_id]
            record.tags = _discovered_path_tags(record.url, record.status_code)
            discovered_paths.append(record)
            if urlparse(record.url).hostname:
                host = normalise_hostname(urlparse(record.url).hostname or "")
                _link_asset(asset_evidence, asset_sources, host, evidence_id, record.source)
                _merge_endpoint_from_url(
                    endpoint_records,
                    endpoint_order,
                    record.url,
                    evidence_id,
                    extra_tags=record.tags,
                )

    for raw_path in sorted(input_dir.glob("robots-*.txt")):
        url = _infer_artifact_url(raw_path, default_host, "robots")
        artifacts = _parse_present(
            raw_path,
            lambda path: parse_robots(path, url),
            processed_files,
            warnings,
        )
        for artifact in artifacts:
            evidence_id = _record_http_artifact(
                artifact,
                evidence,
                http_artifacts,
                asset_evidence,
                asset_sources,
            )
            if artifact.artifact_type == "robots" and artifact.url:
                _merge_endpoint_from_url(
                    endpoint_records,
                    endpoint_order,
                    artifact.url,
                    evidence_id,
                    extra_tags=["robots_artifact"],
                )

    for raw_path in sorted(input_dir.glob("*.html")):
        url = _infer_artifact_url(raw_path, default_host, "html")
        artifacts = _parse_present(
            raw_path,
            lambda path: parse_html(path, url),
            processed_files,
            warnings,
        )
        for artifact in artifacts:
            evidence_id = _record_http_artifact(
                artifact,
                evidence,
                http_artifacts,
                asset_evidence,
                asset_sources,
            )
            if artifact.artifact_type in {"link", "script_or_asset", "form"}:
                linked_url = urljoin(url, artifact.value) if url else artifact.value
                if urlparse(linked_url).scheme in {"http", "https"} and urlparse(linked_url).hostname:
                    _merge_endpoint_from_url(
                        endpoint_records,
                        endpoint_order,
                        normalise_url(linked_url),
                        evidence_id,
                    )
            if artifact.artifact_type == "page_title" and url:
                origin = _origin_url(url)
                service = service_records.get(origin)
                if service and normalise_url(url) == origin and not service.title:
                    service.title = artifact.value

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

    services = [service_records[url] for url in service_order]
    endpoints = [endpoint_records[url] for url in endpoint_order]
    interesting_artifacts = [
        artifact
        for artifact in http_artifacts
        if artifact.artifact_type not in {"page_title", "link", "script_or_asset", "user_agent"}
    ]

    return ProjectState(
        project_name=input_dir.name,
        input_dir=str(input_dir),
        processed_files=processed_files,
        scope_summary=_scope_summary(scope),
        assets=assets,
        http_services=services,
        endpoints=endpoints,
        port_services=port_services,
        http_artifacts=http_artifacts,
        discovered_paths=discovered_paths,
        recon_summary=ReconPackSummary(
            open_port_count=sum(1 for service in port_services if service.state == "open"),
            http_service_count=len(services),
            interesting_artifact_count=len(interesting_artifacts),
            candidate_count=0,
        ),
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


def _parse_present(
    path: Path,
    parser: InputParser,
    processed_files: list[str],
    warnings: list[str],
) -> object:
    with warnings_module.catch_warnings(record=True) as captured:
        warnings_module.simplefilter("always", RuntimeWarning)
        result = parser(path)
    if str(path) not in processed_files:
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


def _default_raw_host(scope: ParsedScope, subdomains: list[ParsedSubdomain]) -> str | None:
    for value in scope.in_scope:
        host = _simple_scope_host(value)
        if host:
            return host
    if subdomains:
        return normalise_hostname(subdomains[0].hostname)
    return None


def _port_service_tags(record: PortService) -> list[str]:
    tags: list[str] = []
    if record.state == "open":
        tags.append("open_service")
    if _is_http_service_name(record.service):
        tags.append("http_service")
        if record.port not in {80, 443}:
            tags.append("non_default_http_port")
    return tags


def _is_http_service_name(service: str | None) -> bool:
    value = (service or "").lower()
    return value in {"http", "https", "http-proxy", "https-alt"} or "http" in value


def _service_url(host: str, port: int, service: str | None) -> str:
    scheme = "https" if "https" in (service or "").lower() or port == 443 else "http"
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    return f"{scheme}://{netloc}/"


def _merge_http_service(
    records: dict[str, HTTPService],
    order: list[str],
    url: str,
    hostname: str,
    status_code: int | None,
    title: str | None,
    technologies: list[str],
    content_length: int | None,
    evidence_id: str,
) -> None:
    url = normalise_url(url)
    if url not in records:
        order.append(url)
        records[url] = HTTPService(
            url=url,
            hostname=hostname,
            status_code=status_code,
            title=title,
            technologies=dedupe_preserve_order(technologies),
            content_length=content_length,
            evidence_ids=[evidence_id],
            tags=_host_tags(hostname),
        )
        return
    service = records[url]
    _append_unique(service.evidence_ids, evidence_id)
    service.technologies = dedupe_preserve_order([*service.technologies, *technologies])
    if service.status_code is None:
        service.status_code = status_code
    if service.title is None:
        service.title = title
    if service.content_length is None:
        service.content_length = content_length


def _merge_endpoint_from_url(
    records: dict[str, Endpoint],
    order: list[str],
    url: str,
    evidence_id: str,
    extra_tags: list[str] | None = None,
) -> None:
    normalised = normalise_url(url)
    parsed = urlparse(normalised)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return
    query_params = dedupe_preserve_order(name for name, _value in parse_qsl(parsed.query, keep_blank_values=True))
    tags = dedupe_preserve_order([*_endpoint_tags(parsed.path or "/", query_params), *(extra_tags or [])])
    if normalised not in records:
        order.append(normalised)
        records[normalised] = Endpoint(
            url=normalised,
            hostname=normalise_hostname(parsed.hostname),
            path=parsed.path or "/",
            query_params=query_params,
            evidence_ids=[evidence_id],
            tags=tags,
        )
        return
    endpoint = records[normalised]
    _append_unique(endpoint.evidence_ids, evidence_id)
    endpoint.tags = dedupe_preserve_order([*endpoint.tags, *tags])


def _record_http_artifact(
    artifact: HTTPArtifact,
    evidence: list[Evidence],
    artifacts: list[HTTPArtifact],
    asset_evidence: dict[str, list[str]],
    asset_sources: dict[str, list[str]],
) -> str:
    evidence_id = _append_evidence(
        evidence,
        "ART",
        artifact.source_file,
        artifact.artifact_type,
        artifact.value,
        {"url": artifact.url, "tags": artifact.tags},
    )
    artifact.evidence_ids = [evidence_id]
    artifact.tags = _artifact_tags(artifact)
    artifacts.append(artifact)
    host = normalise_hostname(urlparse(artifact.url).hostname or "")
    if host:
        _link_asset(asset_evidence, asset_sources, host, evidence_id, artifact.source_file)
    return evidence_id


def _artifact_tags(artifact: HTTPArtifact) -> list[str]:
    tags: list[str] = []
    if artifact.artifact_type in {"robots", "allow_rule", "disallow_rule", "unusual_user_agent"}:
        tags.append("robots_artifact")
    if artifact.artifact_type in {"encoded_like_artifact", "hidden_element"}:
        tags.append("encoded_or_hidden_artifact")
    if artifact.artifact_type == "script_or_asset":
        tags.append("static_asset")
    return tags


def _discovered_path_tags(url: str, status_code: int | None) -> list[str]:
    parsed = urlparse(url)
    tags = _endpoint_tags(parsed.path or "/", [name for name, _value in parse_qsl(parsed.query)])
    if status_code == 404:
        tags.append("dead_path")
    if status_code is not None and 300 <= status_code < 400:
        tags.append("redirecting_path")
    return dedupe_preserve_order(tags)


def _origin_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def _infer_artifact_url(path: Path, host: str | None, artifact_kind: str) -> str:
    if not host:
        return ""
    stem = path.stem.lower()
    port = _filename_port(stem)
    scheme = "https" if port == 443 else "http"
    netloc = host
    if port and port not in {80, 443}:
        netloc = f"{host}:{port}"
    base = f"{scheme}://{netloc}/"

    if artifact_kind == "robots":
        return urljoin(base, "robots.txt")
    tokens = stem.split("-")
    path_tokens = [
        token
        for token in tokens
        if token
        not in {
            "curl",
            "headers",
            "gobuster",
            "homepage",
            "robots",
            "root",
            "manual",
            str(port) if port else "",
        }
        and not token.isdigit()
    ]
    if artifact_kind == "headers" and "manual" in tokens:
        path_tokens.append("manual")
    if not path_tokens:
        return base
    return urljoin(base, "/".join(path_tokens) + "/")


def _filename_port(stem: str) -> int | None:
    for token in re.findall(r"(?<!\d)(\d{1,5})(?!\d)", stem):
        port = int(token)
        if 1 <= port <= 65535:
            return port
    return None


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
    non_tld_labels = host.split(".")[:-1]
    tags: list[str] = []
    if "api" in host:
        tags.append("api")
    if "admin" in host:
        tags.append("admin")
    if any(
        label == "test" or any(marker in label for marker in ("staging", "stage", "dev"))
        for label in non_tld_labels
    ):
        tags.append("environment")
    if any(marker in host for marker in ("cdn", "static", "assets")):
        tags.append("static_or_cdn")
    return tags


def _endpoint_tags(path: str, query_params: list[str]) -> list[str]:
    lower_path = path.lower()
    lower_params = [param.lower() for param in query_params]
    combined_params = " ".join(lower_params)
    tags: list[str] = []

    if _is_auth_surface_path(lower_path):
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


def _is_auth_surface_path(path: str) -> bool:
    segments = [segment for segment in path.strip("/").split("/") if segment]
    first_segment = segments[0] if segments else ""
    auth_segments = {
        "login",
        "logout",
        "signin",
        "signup",
        "register",
        "reset",
        "password",
        "forgot-password",
        "auth",
        "session",
        "sessions",
        "oauth",
        "sso",
    }
    user_account_segments = {"account", "profile", "me"}

    if any(segment in auth_segments for segment in segments):
        return True
    return first_segment in user_account_segments
