"""Small HTTP origin normalisation helpers for bounded recon planning."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True, order=True)
class HttpOrigin:
    """Canonical HTTP(S) origin used for executable request boundaries."""

    scheme: str
    hostname: str
    effective_port: int

    @property
    def authority(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        default_port = 443 if self.scheme == "https" else 80
        return host if self.effective_port == default_port else f"{host}:{self.effective_port}"

    @property
    def origin_url(self) -> str:
        return f"{self.scheme}://{self.authority}"


def http_origin_from_url(raw_url: str) -> HttpOrigin | None:
    """Return a canonical HTTP(S) origin or None for unsafe/non-HTTP input."""

    value = raw_url.strip() if isinstance(raw_url, str) else ""
    if not value:
        return None
    try:
        parsed = urlparse(value)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    hostname = parsed.hostname.lower().rstrip(".")
    if not hostname:
        return None
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    return HttpOrigin(scheme=scheme, hostname=hostname, effective_port=effective_port)


def canonical_http_origin_url(raw_url: str) -> str | None:
    origin = http_origin_from_url(raw_url)
    return None if origin is None else origin.origin_url


def same_http_origin(first_url: str, second_url: str) -> bool:
    first = http_origin_from_url(first_url)
    second = http_origin_from_url(second_url)
    return first is not None and second is not None and first == second
