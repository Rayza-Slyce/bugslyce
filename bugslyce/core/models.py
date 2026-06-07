"""Simple parsed record models for BugSlyce input files."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ParserWarning:
    """Non-fatal parser warning captured for result-style parsers."""

    message: str
    source_path: str
    line_number: int | None = None


@dataclass(frozen=True)
class ParsedScope:
    """Parsed Markdown scope document."""

    in_scope: list[str]
    out_of_scope: list[str]
    raw_text: str
    source_path: str
    warnings: list[ParserWarning] = field(default_factory=list)


@dataclass(frozen=True)
class ParsedSubdomain:
    """Parsed hostname from a subdomain list."""

    hostname: str
    source_path: str
    line_number: int


@dataclass(frozen=True)
class ParsedHTTPXRecord:
    """Parsed passive HTTP metadata record from httpx-style JSONL."""

    url: str | None
    host: str | None
    status_code: int | None
    title: str | None
    tech: list[str]
    content_length: int | None
    source_path: str
    line_number: int


@dataclass(frozen=True)
class ParsedURL:
    """Parsed URL record with extracted standard-library URL components."""

    original_url: str
    scheme: str
    hostname: str
    path: str
    query: str
    query_param_names: list[str]
    source_path: str
    line_number: int


@dataclass(frozen=True)
class ParsedNotes:
    """Parsed Markdown notes document."""

    raw_text: str
    note_items: list[str]
    source_path: str
    warnings: list[ParserWarning] = field(default_factory=list)


@dataclass(frozen=True)
class Evidence:
    """Source-backed evidence item created during project assembly."""

    id: str
    source_file: str
    evidence_type: str
    value: str
    context: dict[str, Any]


@dataclass
class Asset:
    """Host-level asset assembled from parsed passive inputs."""

    hostname: str
    in_scope: bool | None
    sources: list[str]
    evidence_ids: list[str]
    tags: list[str]


@dataclass
class HTTPService:
    """HTTP service assembled from passive HTTP metadata."""

    url: str
    hostname: str
    status_code: int | None
    title: str | None
    technologies: list[str]
    content_length: int | None
    evidence_ids: list[str]
    tags: list[str]


@dataclass
class Endpoint:
    """URL endpoint assembled from parsed URL records."""

    url: str
    hostname: str
    path: str
    query_params: list[str]
    evidence_ids: list[str]
    tags: list[str]


@dataclass
class PortService:
    """Structured port/service evidence foundation for future recon ingestion."""

    host: str
    port: int
    protocol: str
    state: str
    service: str | None
    product: str | None
    version: str | None
    source_file: str
    evidence_ids: list[str]
    tags: list[str]


@dataclass
class HTTPArtifact:
    """Structured HTTP artifact foundation for future recon ingestion."""

    url: str
    artifact_type: str
    value: str
    source_file: str
    evidence_ids: list[str]
    tags: list[str]


@dataclass
class DiscoveredPath:
    """Structured discovered-path foundation for future recon ingestion."""

    url: str
    status_code: int | None
    content_length: int | None
    redirect_location: str | None
    source: str
    evidence_ids: list[str]
    tags: list[str]


@dataclass(frozen=True)
class ParsedHTTPHeaders:
    """Parsed response header block from saved curl output."""

    status_code: int | None
    server: str | None
    content_type: str | None
    content_length: int | None
    location: str | None
    source_file: str


@dataclass
class ReconPackSummary:
    """Compact recon pack counts for future structured exports."""

    open_port_count: int
    http_service_count: int
    interesting_artifact_count: int
    candidate_count: int


@dataclass(frozen=True)
class ProjectState:
    """In-memory project state assembled from MVP input files."""

    project_name: str
    input_dir: str
    processed_files: list[str]
    scope_summary: str
    assets: list[Asset]
    http_services: list[HTTPService]
    endpoints: list[Endpoint]
    port_services: list[PortService]
    http_artifacts: list[HTTPArtifact]
    discovered_paths: list[DiscoveredPath]
    recon_summary: ReconPackSummary | None
    evidence: list[Evidence]
    warnings: list[str]
    generated_at: str


@dataclass(frozen=True)
class Candidate:
    """Evidence-backed manual review lead generated from deterministic signals."""

    id: str
    candidate_type: str
    title: str
    priority: str
    rationale: str
    affected_assets: list[str]
    affected_endpoints: list[str]
    evidence_ids: list[str]
    suggested_manual_validation: list[str]
    kill_switch_guidance: str | None
