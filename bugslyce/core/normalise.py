"""Small normalisation helpers for passive recon records."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlparse, urlunparse


def normalise_hostname(value: str) -> str:
    """Return a lowercase hostname with surrounding punctuation trimmed."""

    return value.strip().strip(".").lower()


def normalise_url(value: str) -> str:
    """Return a URL with lowercase scheme and hostname where parseable."""

    stripped = value.strip()
    parsed = urlparse(stripped)
    if not parsed.scheme or not parsed.netloc:
        return stripped

    hostname = (parsed.hostname or "").lower()
    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo = f"{userinfo}:{parsed.password}"
        netloc = f"{userinfo}@{netloc}"

    return urlunparse(
        (
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    """Deduplicate strings while preserving first-seen order."""

    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
