"""Human-safe rendering for retained HTTP response headers."""

from __future__ import annotations

from dataclasses import dataclass
import re


MAX_ATTRIBUTE_CHARS = 96
COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
COOKIE_ATTRIBUTES = {
    "domain": "Domain",
    "expires": "Expires",
    "httponly": "HttpOnly",
    "max-age": "Max-Age",
    "partitioned": "Partitioned",
    "path": "Path",
    "samesite": "SameSite",
    "secure": "Secure",
}


@dataclass(frozen=True)
class CookieHeaderSummary:
    """Cookie name and non-value attributes suitable for human output."""

    name: str
    attributes: tuple[str, ...]

    @property
    def compact(self) -> str:
        if not self.attributes:
            return self.name
        return f"{self.name} ({'; '.join(self.attributes)})"

    @property
    def redacted_header_value(self) -> str:
        suffix = f"; {'; '.join(self.attributes)}" if self.attributes else ""
        return f"{self.name}=<redacted>{suffix}"


def summarise_set_cookie(value: str) -> CookieHeaderSummary | None:
    """Return a deterministic cookie summary without retaining its value."""

    parts = [" ".join(part.strip().split()) for part in value.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, _cookie_value = parts[0].split("=", 1)
    name = name.strip()
    if not name or not COOKIE_NAME.fullmatch(name):
        return None

    attributes: list[str] = []
    for raw_attribute in parts[1:]:
        if not raw_attribute:
            continue
        raw_name, separator, raw_value = raw_attribute.partition("=")
        canonical = COOKIE_ATTRIBUTES.get(raw_name.strip().lower())
        if canonical is None:
            continue
        if separator:
            bounded = raw_value.strip()[:MAX_ATTRIBUTE_CHARS]
            if bounded:
                attributes.append(f"{canonical}={bounded}")
        else:
            attributes.append(canonical)
    return CookieHeaderSummary(name=name, attributes=tuple(_dedupe(attributes)))


def render_response_headers_for_humans(
    headers: tuple[tuple[str, str], ...],
) -> tuple[str, ...]:
    """Render response headers while redacting retained Set-Cookie values."""

    rendered: list[str] = []
    for name, value in headers:
        if name.lower() != "set-cookie":
            rendered.append(f"{name}: {value}")
            continue
        summary = summarise_set_cookie(value)
        if summary is None:
            rendered.append(f"{name}: <cookie value redacted>")
        else:
            rendered.append(f"{name}: {summary.redacted_header_value}")
    return tuple(rendered)


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
