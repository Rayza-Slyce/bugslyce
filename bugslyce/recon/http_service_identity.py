"""Evidence-backed logical HTTP origin resolution for retained project state."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

from bugslyce.core.models import ProjectState
from bugslyce.core.normalise import normalise_hostname
from bugslyce.parsers.nmap import http_scheme_for_port_service


@dataclass(frozen=True)
class HTTPOriginBinding:
    """Observed service origin projected to one evidence-authorised logical origin."""

    observed_origin: str
    logical_origin: str
    nmap_discovered: bool


def resolve_target_http_origins(
    project_state: ProjectState,
    target: str,
) -> tuple[HTTPOriginBinding, ...]:
    """Resolve retained HTTP origins belonging to a logical target without live lookup."""

    logical_target = normalise_hostname(target)
    authorised_hosts = {logical_target}
    authorised_hosts.update(
        relationship.peer_host
        for relationship in getattr(project_state, "nmap_reported_host_peers", ())
        if relationship.reported_host == logical_target
    )

    origins: dict[str, bool] = {}
    for service in getattr(project_state, "http_services", ()):
        observed_origin = _root_origin(service.url)
        if observed_origin is not None:
            origins.setdefault(observed_origin, False)

    for service in project_state.port_services:
        scheme = http_scheme_for_port_service(service)
        if (
            service.state != "open"
            or service.protocol != "tcp"
            or scheme is None
        ):
            continue
        observed_origin = _origin_for_host(scheme, service.host, service.port)
        origins[observed_origin] = True

    bindings: list[HTTPOriginBinding] = []
    for observed_origin, nmap_discovered in origins.items():
        parsed = urlparse(observed_origin)
        observed_host = normalise_hostname(parsed.hostname or "")
        if observed_host not in authorised_hosts:
            continue
        port = _parsed_port(parsed)
        if port is None:
            continue
        bindings.append(
            HTTPOriginBinding(
                observed_origin=observed_origin,
                logical_origin=_origin_for_host(parsed.scheme, logical_target, port),
                nmap_discovered=nmap_discovered,
            )
        )
    return tuple(sorted(bindings, key=_binding_sort_key))


def _root_origin(value: str) -> str | None:
    try:
        parsed = urlparse(value)
        port = _parsed_port(parsed)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or port is None:
        return None
    return _origin_for_host(parsed.scheme, parsed.hostname, port)


def _parsed_port(parsed) -> int | None:
    if parsed.scheme == "https":
        return parsed.port or 443
    if parsed.scheme == "http":
        return parsed.port or 80
    return None


def _origin_for_host(scheme: str, host: str, port: int) -> str:
    hostname = normalise_hostname(host)
    authority = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    netloc = authority if port == default_port else f"{authority}:{port}"
    return urlunparse((scheme, netloc, "/", "", "", ""))


def _binding_sort_key(binding: HTTPOriginBinding) -> tuple[str, int, str, str]:
    parsed = urlparse(binding.logical_origin)
    return (
        parsed.scheme,
        _parsed_port(parsed) or 0,
        binding.logical_origin,
        binding.observed_origin,
    )
