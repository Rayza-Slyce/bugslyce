"""Parser for BugSlyce-native bounded content-discovery output."""

from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urljoin, urlparse
import warnings

from bugslyce.core.models import DiscoveredPath


_NO_DESTINATION_REDIRECT_REFUSAL_REASONS = frozenset(
    {"malformed_location", "unsupported_redirect"}
)
_REDIRECT_FOLLOWUP_FAILURE_CATEGORIES = frozenset(
    {
        "connect_error",
        "dns_error",
        "no_usable_ipv4",
        "timeout",
        "tls_error",
        "transport_error",
    }
)
_NATIVE_CONTENT_DISCOVERY_LINE = re.compile(
    r"^\s*(?P<path>/[^\s\[\]]*)\s+"
    r"\(Status:\s*(?P<status>\d{3})\)\s+"
    r"\[Size:\s*(?P<size>\d+)\]"
    r"(?:\s+\[-->\s*(?P<redirect>https?://[^\s\]]+)\]"
    r"|\s+\[redirect refused:\s*(?P<refusal>malformed_location|unsupported_redirect)\]"
    r"|\s+\[redirect follow-up failed:\s*"
    r"(?P<followup>connect_error|dns_error|no_usable_ipv4|timeout|tls_error|transport_error)\s+"
    r"-->\s*(?P<followup_destination>https?://[^\s\]]+)\])?\s*$"
)


def parse_content_discovery(path: Path, base_url: str | None = None) -> list[DiscoveredPath]:
    """Parse current BugSlyce-native path records and safe redirect metadata."""

    if not path.exists():
        warnings.warn(
            f"Native content-discovery output file does not exist: {path}",
            RuntimeWarning,
            stacklevel=2,
        )
        return []

    records: list[DiscoveredPath] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        match = _NATIVE_CONTENT_DISCOVERY_LINE.match(line)
        if not match or not _valid_native_redirect(match.group("redirect")) or not _valid_native_redirect(
            match.group("followup_destination")
        ):
            warnings.warn(
                f"Skipping malformed native content-discovery line {line_number} in {path}",
                RuntimeWarning,
                stacklevel=2,
            )
            continue

        discovered = match.group("path").lstrip("/")
        url = urljoin(_ensure_trailing_slash(base_url), discovered) if base_url else discovered
        redirect = match.group("redirect") or match.group("followup_destination")
        tags = _native_outcome_tags(
            refusal_reason=match.group("refusal"),
            followup_failure_category=match.group("followup"),
        )
        records.append(
            DiscoveredPath(
                url=url,
                status_code=int(match.group("status")),
                content_length=int(match.group("size")),
                redirect_location=redirect,
                source=str(path),
                evidence_ids=[],
                tags=tags,
            )
        )

    return records


def _valid_native_redirect(value: str | None) -> bool:
    if value is None:
        return True
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname)


def native_content_discovery_outcome_context(tags: list[str]) -> dict[str, str]:
    """Return controlled native outcome provenance carried by parser-owned tags."""

    tag_set = set(tags)
    refusal_reasons = [
        reason
        for reason in _NO_DESTINATION_REDIRECT_REFUSAL_REASONS
        if f"native_redirect_refused_{reason}" in tag_set
    ]
    followup_categories = [
        category
        for category in _REDIRECT_FOLLOWUP_FAILURE_CATEGORIES
        if f"native_redirect_followup_failed_{category}" in tag_set
    ]
    if (
        "native_redirect_refused" in tag_set
        and len(refusal_reasons) == 1
        and not followup_categories
        and "native_redirect_followup_failed" not in tag_set
    ):
        return {"native_redirect_refusal_reason": refusal_reasons[0]}
    if (
        "native_redirect_followup_failed" in tag_set
        and len(followup_categories) == 1
        and not refusal_reasons
        and "native_redirect_refused" not in tag_set
    ):
        return {
            "native_redirect_followup_failure_category": followup_categories[0]
        }
    return {}


def _native_outcome_tags(
    *,
    refusal_reason: str | None,
    followup_failure_category: str | None,
) -> list[str]:
    if refusal_reason in _NO_DESTINATION_REDIRECT_REFUSAL_REASONS:
        return [
            "native_redirect_refused",
            f"native_redirect_refused_{refusal_reason}",
        ]
    if followup_failure_category in _REDIRECT_FOLLOWUP_FAILURE_CATEGORIES:
        return [
            "native_redirect_followup_failed",
            f"native_redirect_followup_failed_{followup_failure_category}",
        ]
    return []


def _ensure_trailing_slash(value: str | None) -> str:
    if not value:
        return ""
    return value if value.endswith("/") else f"{value}/"
