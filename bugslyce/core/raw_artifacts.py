"""Raw recon artifact discovery, context resolution, and project-state assembly."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse
import warnings as warnings_module

from bugslyce.core.models import (
    DiscoveredPath,
    Endpoint,
    Evidence,
    HTTPArtifact,
    HTTPService,
    ParsedHTTPHeaders,
    PortService,
    ReconManifest,
    ReconManifestArtifact,
)
from bugslyce.core.normalise import dedupe_preserve_order, normalise_hostname, normalise_url
from bugslyce.parsers.gobuster import parse_gobuster
from bugslyce.parsers.html import parse_html
from bugslyce.parsers.http_headers import parse_http_headers
from bugslyce.parsers.nmap import parse_nmap_normal
from bugslyce.parsers.robots import parse_robots


@dataclass
class RawAssemblyResult:
    """Structured records assembled from saved raw recon artifacts."""

    port_services: list[PortService]
    http_artifacts: list[HTTPArtifact]
    discovered_paths: list[DiscoveredPath]


@dataclass(frozen=True)
class _ArtifactContext:
    type: str
    path: Path
    metadata: ReconManifestArtifact | None = None
    manifest_target: str | None = None


def assemble_raw_artifacts(
    input_dir: Path,
    manifest: ReconManifest | None,
    default_host: str | None,
    evidence: list[Evidence],
    asset_evidence: dict[str, list[str]],
    asset_sources: dict[str, list[str]],
    service_records: dict[str, HTTPService],
    service_order: list[str],
    endpoint_records: dict[str, Endpoint],
    endpoint_order: list[str],
    processed_files: list[str],
    warnings: list[str],
    host_tags: Callable[[str], list[str]],
    endpoint_tags: Callable[[str, list[str]], list[str]],
) -> RawAssemblyResult:
    """Parse manifest-described and filename-discovered raw artifacts."""

    port_services: list[PortService] = []
    port_service_keys: dict[tuple[str, int, str], PortService] = {}
    http_artifacts: list[HTTPArtifact] = []
    discovered_paths: list[DiscoveredPath] = []

    for context in _artifact_contexts(input_dir, manifest):
        if context.type == "nmap":
            _assemble_nmap(
                context,
                default_host,
                evidence,
                asset_evidence,
                asset_sources,
                service_records,
                service_order,
                port_services,
                port_service_keys,
                processed_files,
                warnings,
                host_tags,
            )
        elif context.type == "http_headers":
            _assemble_headers(
                context,
                default_host,
                evidence,
                asset_evidence,
                asset_sources,
                service_records,
                service_order,
                endpoint_records,
                endpoint_order,
                discovered_paths,
                processed_files,
                warnings,
                host_tags,
                endpoint_tags,
            )
        elif context.type == "gobuster":
            _assemble_gobuster(
                context,
                default_host,
                evidence,
                asset_evidence,
                asset_sources,
                endpoint_records,
                endpoint_order,
                discovered_paths,
                processed_files,
                warnings,
                endpoint_tags,
            )
        elif context.type == "robots":
            _assemble_robots(
                context,
                default_host,
                evidence,
                asset_evidence,
                asset_sources,
                endpoint_records,
                endpoint_order,
                http_artifacts,
                processed_files,
                warnings,
                endpoint_tags,
            )
        elif context.type == "html":
            _assemble_html(
                context,
                default_host,
                evidence,
                asset_evidence,
                asset_sources,
                service_records,
                endpoint_records,
                endpoint_order,
                http_artifacts,
                processed_files,
                warnings,
                endpoint_tags,
            )

    return RawAssemblyResult(port_services, http_artifacts, discovered_paths)


def _artifact_contexts(input_dir: Path, manifest: ReconManifest | None) -> list[_ArtifactContext]:
    if manifest:
        return [
            _ArtifactContext(artifact.type, input_dir / artifact.file, artifact, manifest.target)
            for artifact in manifest.artifacts
        ]

    contexts: list[_ArtifactContext] = []
    patterns = (
        ("nmap", "nmap*.txt"),
        ("http_headers", "curl-headers-*.txt"),
        ("gobuster", "gobuster-*.txt"),
        ("robots", "robots-*.txt"),
        ("html", "*.html"),
    )
    for artifact_type, pattern in patterns:
        for path in sorted(input_dir.glob(pattern)):
            contexts.append(_ArtifactContext(artifact_type, path))
    return contexts


def _assemble_nmap(
    context: _ArtifactContext,
    default_host: str | None,
    evidence: list[Evidence],
    asset_evidence: dict[str, list[str]],
    asset_sources: dict[str, list[str]],
    service_records: dict[str, HTTPService],
    service_order: list[str],
    port_services: list[PortService],
    port_service_keys: dict[tuple[str, int, str], PortService],
    processed_files: list[str],
    warnings: list[str],
    host_tags: Callable[[str], list[str]],
) -> None:
    metadata = context.metadata
    context_host = _context_host(metadata, context.manifest_target, default_host)
    records = _parse_present(
        context.path,
        lambda path: parse_nmap_normal(path, context_host),
        processed_files,
        warnings,
    )
    for record in records:
        host = normalise_hostname(
            context_host if metadata and metadata.host else record.host or context_host or ""
        )
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
                **_manifest_context(metadata),
            },
        )
        if host:
            _link_asset(asset_evidence, asset_sources, host, evidence_id, record.source_file)
        key = (host, record.port, record.protocol)
        tags = dedupe_preserve_order([*_port_service_tags(record), *_metadata_tags(metadata)])
        if key not in port_service_keys:
            record.host = host
            record.evidence_ids = [evidence_id]
            record.tags = tags
            port_service_keys[key] = record
            port_services.append(record)
        else:
            existing = port_service_keys[key]
            _append_unique(existing.evidence_ids, evidence_id)
            existing.tags = dedupe_preserve_order([*existing.tags, *tags])
            if existing.service in {None, "unknown"} and record.service not in {None, "unknown"}:
                existing.service = record.service
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
                host_tags,
            )


def _assemble_headers(
    context: _ArtifactContext,
    default_host: str | None,
    evidence: list[Evidence],
    asset_evidence: dict[str, list[str]],
    asset_sources: dict[str, list[str]],
    service_records: dict[str, HTTPService],
    service_order: list[str],
    endpoint_records: dict[str, Endpoint],
    endpoint_order: list[str],
    discovered_paths: list[DiscoveredPath],
    processed_files: list[str],
    warnings: list[str],
    host_tags: Callable[[str], list[str]],
    endpoint_tags: Callable[[str, list[str]], list[str]],
) -> None:
    header = _parse_present(context.path, parse_http_headers, processed_files, warnings)
    if not isinstance(header, ParsedHTTPHeaders):
        return
    url = _context_url(context, default_host, "headers")
    evidence_id = _append_evidence(
        evidence,
        "HEADER",
        header.source_file,
        "http_headers",
        url or context.path.name,
        {
            "status_code": header.status_code,
            "server": header.server,
            "content_type": header.content_type,
            "content_length": header.content_length,
            "location": header.location,
            **_manifest_context(context.metadata),
        },
    )
    if not url:
        return
    host = normalise_hostname(urlparse(url).hostname or "")
    _link_asset(asset_evidence, asset_sources, host, evidence_id, header.source_file)
    origin = _origin_url(url)
    _merge_http_service(
        service_records,
        service_order,
        origin,
        host,
        header.status_code if normalise_url(url) == origin else None,
        None,
        [header.server] if header.server else [],
        header.content_length if normalise_url(url) == origin else None,
        evidence_id,
        host_tags,
    )
    if normalise_url(url) != origin or header.status_code == 404 or header.location:
        tags = dedupe_preserve_order(
            [*_discovered_path_tags(url, header.status_code, endpoint_tags), *_metadata_tags(context.metadata)]
        )
        discovered_paths.append(
            DiscoveredPath(
                url=normalise_url(url),
                status_code=header.status_code,
                content_length=header.content_length,
                redirect_location=header.location,
                source=header.source_file,
                evidence_ids=[evidence_id],
                tags=tags,
            )
        )
        _merge_endpoint_from_url(
            endpoint_records,
            endpoint_order,
            url,
            evidence_id,
            endpoint_tags,
            tags,
        )


def _assemble_gobuster(
    context: _ArtifactContext,
    default_host: str | None,
    evidence: list[Evidence],
    asset_evidence: dict[str, list[str]],
    asset_sources: dict[str, list[str]],
    endpoint_records: dict[str, Endpoint],
    endpoint_order: list[str],
    discovered_paths: list[DiscoveredPath],
    processed_files: list[str],
    warnings: list[str],
    endpoint_tags: Callable[[str, list[str]], list[str]],
) -> None:
    base_url = _context_url(context, default_host, "gobuster")
    records = _parse_present(
        context.path,
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
                **_manifest_context(context.metadata),
            },
        )
        record.evidence_ids = [evidence_id]
        record.tags = dedupe_preserve_order(
            [
                *_discovered_path_tags(record.url, record.status_code, endpoint_tags),
                *_metadata_tags(context.metadata),
            ]
        )
        discovered_paths.append(record)
        host = normalise_hostname(urlparse(record.url).hostname or "")
        if host:
            _link_asset(asset_evidence, asset_sources, host, evidence_id, record.source)
            _merge_endpoint_from_url(
                endpoint_records,
                endpoint_order,
                record.url,
                evidence_id,
                endpoint_tags,
                record.tags,
            )


def _assemble_robots(
    context: _ArtifactContext,
    default_host: str | None,
    evidence: list[Evidence],
    asset_evidence: dict[str, list[str]],
    asset_sources: dict[str, list[str]],
    endpoint_records: dict[str, Endpoint],
    endpoint_order: list[str],
    http_artifacts: list[HTTPArtifact],
    processed_files: list[str],
    warnings: list[str],
    endpoint_tags: Callable[[str, list[str]], list[str]],
) -> None:
    url = _context_url(context, default_host, "robots")
    artifacts = _parse_present(
        context.path,
        lambda path: parse_robots(path, url),
        processed_files,
        warnings,
    )
    for artifact in artifacts:
        evidence_id = _record_http_artifact(
            artifact,
            context.metadata,
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
                endpoint_tags,
                ["robots_artifact"],
            )


def _assemble_html(
    context: _ArtifactContext,
    default_host: str | None,
    evidence: list[Evidence],
    asset_evidence: dict[str, list[str]],
    asset_sources: dict[str, list[str]],
    service_records: dict[str, HTTPService],
    endpoint_records: dict[str, Endpoint],
    endpoint_order: list[str],
    http_artifacts: list[HTTPArtifact],
    processed_files: list[str],
    warnings: list[str],
    endpoint_tags: Callable[[str, list[str]], list[str]],
) -> None:
    url = _context_url(context, default_host, "html")
    artifacts = _parse_present(
        context.path,
        lambda path: parse_html(path, url),
        processed_files,
        warnings,
    )
    for artifact in artifacts:
        evidence_id = _record_http_artifact(
            artifact,
            context.metadata,
            evidence,
            http_artifacts,
            asset_evidence,
            asset_sources,
        )
        if artifact.artifact_type in {"link", "script_or_asset", "form"}:
            linked_url = urljoin(url, artifact.value) if url else artifact.value
            parsed = urlparse(linked_url)
            if parsed.scheme in {"http", "https"} and parsed.hostname:
                _merge_endpoint_from_url(
                    endpoint_records,
                    endpoint_order,
                    normalise_url(linked_url),
                    evidence_id,
                    endpoint_tags,
                )
        if artifact.artifact_type == "page_title" and url:
            origin = _origin_url(url)
            service = service_records.get(origin)
            if service and normalise_url(url) == origin and not service.title:
                service.title = artifact.value


def _context_url(context: _ArtifactContext, default_host: str | None, artifact_kind: str) -> str:
    metadata = context.metadata
    if metadata:
        if artifact_kind == "gobuster" and metadata.base_url:
            return normalise_url(metadata.base_url)
        if metadata.url:
            return normalise_url(metadata.url)
        if metadata.base_url:
            base_url = normalise_url(metadata.base_url)
            return urljoin(base_url, "robots.txt") if artifact_kind == "robots" else base_url
        host = _context_host(metadata, context.manifest_target, default_host)
        if host:
            base = _metadata_base_url(metadata, host)
            return urljoin(base, "robots.txt") if artifact_kind == "robots" else base
    return _infer_artifact_url(context.path, default_host, artifact_kind)


def _context_host(
    metadata: ReconManifestArtifact | None,
    manifest_target: str | None,
    default_host: str | None,
) -> str | None:
    if metadata and metadata.host:
        return normalise_hostname(metadata.host)
    if manifest_target:
        parsed = urlparse(manifest_target if "://" in manifest_target else f"//{manifest_target}")
        target_host = parsed.hostname or manifest_target
        return normalise_hostname(target_host)
    return default_host


def _metadata_base_url(metadata: ReconManifestArtifact, host: str) -> str:
    protocol = (metadata.protocol or "").lower()
    scheme = protocol if protocol in {"http", "https"} else ("https" if metadata.port == 443 else "http")
    default_port = 443 if scheme == "https" else 80
    netloc = host if metadata.port in {None, default_port} else f"{host}:{metadata.port}"
    return f"{scheme}://{netloc}/"


def _manifest_context(metadata: ReconManifestArtifact | None) -> dict[str, object]:
    if metadata is None:
        return {}
    context: dict[str, object] = {
        "manifest_description": metadata.description,
        "manifest_tags": metadata.tags,
    }
    if metadata.status_code is not None:
        context["status_code"] = metadata.status_code
    return context


def _metadata_tags(metadata: ReconManifestArtifact | None) -> list[str]:
    return metadata.tags if metadata else []


def _parse_present(
    path: Path,
    parser: Callable[[Path], object],
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


def _append_evidence(
    evidence: list[Evidence],
    prefix: str,
    source_file: str,
    evidence_type: str,
    value: str,
    context: dict[str, object],
) -> str:
    number = sum(1 for item in evidence if item.id.startswith(f"EVID-{prefix}-")) + 1
    evidence_id = f"EVID-{prefix}-{number:04d}"
    evidence.append(Evidence(evidence_id, source_file, evidence_type, value, context))
    return evidence_id


def _record_http_artifact(
    artifact: HTTPArtifact,
    metadata: ReconManifestArtifact | None,
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
        {"url": artifact.url, "tags": artifact.tags, **_manifest_context(metadata)},
    )
    artifact.evidence_ids = [evidence_id]
    artifact.tags = dedupe_preserve_order([*_artifact_tags(artifact), *_metadata_tags(metadata)])
    artifacts.append(artifact)
    host = normalise_hostname(urlparse(artifact.url).hostname or "")
    if host:
        _link_asset(asset_evidence, asset_sources, host, evidence_id, artifact.source_file)
    return evidence_id


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
    host_tags: Callable[[str], list[str]],
) -> None:
    url = normalise_url(url)
    if url not in records:
        order.append(url)
        records[url] = HTTPService(
            url,
            hostname,
            status_code,
            title,
            dedupe_preserve_order(technologies),
            content_length,
            [evidence_id],
            host_tags(hostname),
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
    endpoint_tags: Callable[[str, list[str]], list[str]],
    extra_tags: list[str] | None = None,
) -> None:
    normalised = normalise_url(url)
    parsed = urlparse(normalised)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return
    query_params = dedupe_preserve_order(name for name, _value in parse_qsl(parsed.query, keep_blank_values=True))
    tags = dedupe_preserve_order([*endpoint_tags(parsed.path or "/", query_params), *(extra_tags or [])])
    if normalised not in records:
        order.append(normalised)
        records[normalised] = Endpoint(
            normalised,
            normalise_hostname(parsed.hostname),
            parsed.path or "/",
            query_params,
            [evidence_id],
            tags,
        )
        return
    endpoint = records[normalised]
    _append_unique(endpoint.evidence_ids, evidence_id)
    endpoint.tags = dedupe_preserve_order([*endpoint.tags, *tags])


def _link_asset(
    asset_evidence: dict[str, list[str]],
    asset_sources: dict[str, list[str]],
    hostname: str,
    evidence_id: str,
    source_file: str,
) -> None:
    if hostname:
        _append_unique(asset_evidence[hostname], evidence_id)
        _append_unique(asset_sources[hostname], source_file)


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


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


def _artifact_tags(artifact: HTTPArtifact) -> list[str]:
    tags: list[str] = []
    if artifact.artifact_type in {
        "robots",
        "allow_rule",
        "disallow_rule",
        "robots_value",
        "sitemap_rule",
        "unusual_user_agent",
    }:
        tags.append("robots_artifact")
    if artifact.artifact_type in {"encoded_like_artifact", "hidden_element"}:
        tags.append("encoded_or_hidden_artifact")
    if artifact.artifact_type == "script_or_asset":
        tags.append("static_asset")
    return tags


def _discovered_path_tags(
    url: str,
    status_code: int | None,
    endpoint_tags: Callable[[str, list[str]], list[str]],
) -> list[str]:
    parsed = urlparse(url)
    tags = endpoint_tags(parsed.path or "/", [name for name, _value in parse_qsl(parsed.query)])
    if status_code == 404:
        tags.append("dead_path")
    if status_code is not None and 300 <= status_code < 400:
        tags.append("redirecting_path")
    return dedupe_preserve_order(tags)


def _origin_url(url: str) -> str:
    parsed = urlparse(normalise_url(url))
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
    ports: list[int] = []
    for token in re.findall(r"(?<!\d)(\d{1,5})(?!\d)", stem):
        port = int(token)
        if 1 <= port <= 65535:
            ports.append(port)
    return ports[-1] if ports else None
