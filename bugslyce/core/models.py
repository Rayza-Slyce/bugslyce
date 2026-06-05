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
    evidence: list[Evidence]
    warnings: list[str]
    generated_at: str
