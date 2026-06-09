"""Lightweight parsing for Markdown scope files."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import re
from urllib.parse import urlparse
import warnings

from bugslyce.core.models import ParsedScope, ParserWarning


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def parse_scope(path: Path) -> ParsedScope:
    """Parse a simple Markdown scope file into in-scope and out-of-scope entries."""

    source_path = str(path)
    if not path.exists():
        warning = ParserWarning("Scope file does not exist.", source_path)
        warnings.warn(warning.message, RuntimeWarning, stacklevel=2)
        return ParsedScope([], [], "", source_path, [warning])

    raw_text = path.read_text(encoding="utf-8")
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    section: str | None = None

    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        heading = stripped.lstrip("#").strip().lower()
        if stripped.startswith("#"):
            if "out of scope" in heading:
                section = "out"
            elif "in scope" in heading:
                section = "in"
            else:
                section = None
            continue

        if section not in {"in", "out"}:
            continue

        item = _extract_markdown_list_item(stripped)
        if not item:
            continue

        if section == "in":
            in_scope.append(item)
        else:
            out_of_scope.append(item)

    return ParsedScope(in_scope, out_of_scope, raw_text, source_path)


def is_target_like_scope_entry(value: str) -> bool:
    """Return whether a scope bullet clearly identifies a network target."""

    return scope_entry_target(value) is not None


def scope_entry_target(value: str) -> str | None:
    """Extract a normalized host or network from a target-like scope entry."""

    stripped = value.strip().strip("`").strip()
    if not stripped or any(character.isspace() for character in stripped):
        return None

    if stripped.lower().startswith(("http://", "https://")):
        try:
            parsed = urlparse(stripped)
            return parsed.hostname.lower().rstrip(".") if parsed.hostname else None
        except ValueError:
            return None

    candidate = stripped[2:] if stripped.startswith("*.") else stripped
    candidate = candidate.rstrip(".")
    if not candidate:
        return None

    try:
        if "/" in candidate:
            return str(ipaddress.ip_network(candidate, strict=False))
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    if len(candidate) > 253 or "." not in candidate:
        return None
    labels = candidate.split(".")
    if all(_HOST_LABEL.fullmatch(label) for label in labels):
        return candidate.lower()
    return None


def _extract_markdown_list_item(line: str) -> str | None:
    if not line.startswith(("-", "*")):
        return None

    item = line[1:].strip()
    if not item:
        return None

    backtick_match = re.fullmatch(r"`([^`]+)`", item)
    if backtick_match:
        return backtick_match.group(1).strip()

    return item
