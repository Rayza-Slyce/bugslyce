"""Simple parsed record models for BugSlyce input files."""

from __future__ import annotations

from dataclasses import dataclass, field


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
