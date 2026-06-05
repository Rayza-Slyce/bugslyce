"""Parser for passive httpx-style JSONL metadata files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import warnings

from bugslyce.core.models import ParsedHTTPXRecord


def parse_httpx_jsonl(path: Path) -> list[ParsedHTTPXRecord]:
    """Parse valid JSON object lines and warn on malformed lines."""

    if not path.exists():
        warnings.warn(f"HTTPX JSONL file does not exist: {path}", RuntimeWarning, stacklevel=2)
        return []

    records: list[ParsedHTTPXRecord] = []

    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue

        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            warnings.warn(
                f"Skipping malformed JSONL line {line_number} in {path}: {exc.msg}",
                RuntimeWarning,
                stacklevel=2,
            )
            continue

        if not isinstance(parsed, dict):
            warnings.warn(
                f"Skipping non-object JSONL line {line_number} in {path}",
                RuntimeWarning,
                stacklevel=2,
            )
            continue

        records.append(
            ParsedHTTPXRecord(
                url=_optional_str(parsed.get("url")),
                host=_lower_optional_str(parsed.get("host")),
                status_code=_optional_int(parsed.get("status_code")),
                title=_optional_str(parsed.get("title")),
                tech=_tech_list(parsed.get("tech")),
                content_length=_optional_int(parsed.get("content_length")),
                source_path=str(path),
                line_number=line_number,
            )
        )

    return records


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _lower_optional_str(value: Any) -> str | None:
    value_as_str = _optional_str(value)
    if value_as_str is None:
        return None
    return value_as_str.lower()


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _tech_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]
