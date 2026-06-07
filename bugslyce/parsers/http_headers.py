"""Parser for saved curl response headers."""

from __future__ import annotations

from pathlib import Path
import re
import warnings

from bugslyce.core.models import ParsedHTTPHeaders


def parse_http_headers(path: Path) -> ParsedHTTPHeaders:
    """Parse the final HTTP response header block from saved curl output."""

    source_file = str(path)
    if not path.exists():
        warnings.warn(f"HTTP header file does not exist: {path}", RuntimeWarning, stacklevel=2)
        return ParsedHTTPHeaders(None, None, None, None, None, source_file)

    blocks = _header_blocks(path.read_text(encoding="utf-8").splitlines())
    if not blocks:
        warnings.warn(f"No HTTP response header block found in {path}", RuntimeWarning, stacklevel=2)
        return ParsedHTTPHeaders(None, None, None, None, None, source_file)

    status_line, header_lines = blocks[-1]
    status_match = re.match(r"^HTTP/\S+\s+(\d{3})", status_line, re.IGNORECASE)
    status_code = int(status_match.group(1)) if status_match else None
    headers: dict[str, str] = {}
    for line in header_lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    return ParsedHTTPHeaders(
        status_code=status_code,
        server=headers.get("server"),
        content_type=headers.get("content-type"),
        content_length=_optional_int(headers.get("content-length")),
        location=headers.get("location"),
        source_file=source_file,
    )


def _header_blocks(lines: list[str]) -> list[tuple[str, list[str]]]:
    blocks: list[tuple[str, list[str]]] = []
    status_line: str | None = None
    headers: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.upper().startswith("HTTP/"):
            if status_line is not None:
                blocks.append((status_line, headers))
            status_line = stripped
            headers = []
        elif status_line is not None:
            if not stripped:
                blocks.append((status_line, headers))
                status_line = None
                headers = []
            else:
                headers.append(stripped)
    if status_line is not None:
        blocks.append((status_line, headers))
    return blocks


def _optional_int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None
