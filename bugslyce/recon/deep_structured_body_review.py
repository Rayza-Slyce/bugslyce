"""Bounded offline recognition of structured Deep response bodies."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import re
from typing import Protocol
from urllib.parse import urlsplit

MAX_ANALYSED_BODY_BYTES = 262_144
MAX_JSON_DEPTH = 8
MAX_JSON_NODES = 512
MAX_JSON_LIST_ITEMS = 128
MAX_JSON_ROUTES_PER_BODY = 32
MAX_ROUTE_CHARS = 256
MAX_CONFIG_LINES = 256
MAX_CONFIG_LINE_CHARS = 320
MAX_CONFIG_EXCERPT_LINES = 4

_ROUTE_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_ASSIGNMENT = re.compile(
    r"^(?P<key>[A-Za-z_][A-Za-z0-9_.-]{1,63})\s*[:=]\s*(?P<value>\S(?:.*\S)?)$"
)
_DIRECTIVE = re.compile(
    r"^(?P<key>[A-Za-z_][A-Za-z0-9_.-]{1,63})\s+(?P<value>\S(?:.*\S)?)$"
)
_SECTION = re.compile(r"^\[[A-Za-z0-9_. -]{1,80}\]$")
_BLOCK = re.compile(r"^</?[A-Za-z][A-Za-z0-9_.-]*(?:\s+[^<>]{1,240})?>$")
_POSIX_PATH = re.compile(r"(?<![A-Za-z0-9._-])/(?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]*")
_HOST_PORT = re.compile(
    r"^(?P<host>\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):(?P<port>\d{1,5})$"
)
_LABELLED_VALUE = re.compile(
    r"^(?P<key>[A-Za-z_][A-Za-z0-9_. -]{1,63}?)(?P<separator>\s*[:=]\s*)(?P<value>\S(?:.*\S)?)$"
)
_HTML_MARKUP = re.compile(r"<\s*(?:!doctype|html|head|body|script|style)\b", re.IGNORECASE)
_SECRET_KEY_CONCEPTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "privatekey",
    "authorization",
    "authorisation",
    "cookie",
    "session",
)
_OPERATIONAL_KEY_CONCEPTS = (
    "address",
    "bind",
    "directory",
    "documentroot",
    "environment",
    "handler",
    "host",
    "listen",
    "location",
    "log",
    "module",
    "path",
    "port",
    "process",
    "protocol",
    "proxy",
    "root",
    "route",
    "runtime",
    "server",
    "service",
    "socket",
    "timeout",
    "upstream",
    "worker",
)
_FILESYSTEM_ROOTS = frozenset(
    {
        "bin",
        "boot",
        "dev",
        "etc",
        "home",
        "lib",
        "lib64",
        "opt",
        "proc",
        "root",
        "run",
        "sbin",
        "srv",
        "sys",
        "tmp",
        "usr",
        "var",
    }
)


@dataclass(frozen=True)
class DeepStructuredBodyDisclosure:
    """One direct, bounded observation from a collected response body."""

    kind: str
    source_url: str
    source_final_url: str
    source_body_sha256: str
    evidence_ids: tuple[str, ...]
    observed_values: tuple[str, ...]
    excerpt_lines: tuple[str, ...]
    reason: str


class _StructuredBodyItem(Protocol):
    final_url: str
    headers: tuple[tuple[str, str], ...]
    body_preview: str
    body_sha256: str
    evidence_ids: tuple[str, ...]


def analyse_deep_structured_body(
    item: _StructuredBodyItem,
    *,
    source_url: str,
    known_routes: frozenset[str] = frozenset(),
) -> tuple[DeepStructuredBodyDisclosure, ...]:
    """Recognise bounded JSON routes and coherent configuration-like plaintext."""

    # The bounded preview is part of the persisted collection contract. Full
    # bodies are deliberately in-memory only and cannot ground reproducible
    # offline review findings.
    if not item.body_preview:
        return ()
    text = item.body_preview
    if len(text.encode("utf-8")) > MAX_ANALYSED_BODY_BYTES:
        return ()
    if "\x00" in text:
        return ()

    disclosures: list[DeepStructuredBodyDisclosure] = []
    json_value, json_supported = _parse_json_body(text, item.headers)
    if json_value is not None:
        routes = _extract_json_routes(json_value, known_routes)
        if routes:
            disclosures.append(
                DeepStructuredBodyDisclosure(
                    kind="structured_json_routes",
                    source_url=source_url,
                    source_final_url=item.final_url,
                    source_body_sha256=item.body_sha256,
                    evidence_ids=tuple(_dedupe(item.evidence_ids)),
                    observed_values=routes,
                    excerpt_lines=(),
                    reason=(
                        "A valid structured JSON response directly contains relative "
                        "web-route strings. These are disclosure evidence only and were "
                        "not requested by this review."
                    ),
                )
            )
    elif not json_supported:
        config_excerpt = _configuration_excerpt(text, item.headers)
        if config_excerpt:
            disclosures.append(
                DeepStructuredBodyDisclosure(
                    kind="structured_configuration_body",
                    source_url=source_url,
                    source_final_url=item.final_url,
                    source_body_sha256=item.body_sha256,
                    evidence_ids=tuple(_dedupe(item.evidence_ids)),
                    observed_values=(),
                    excerpt_lines=config_excerpt,
                    reason=(
                        "The collected plaintext body contains multiple coherent "
                        "directive, assignment, and operational-value structures. "
                        "This is direct configuration-like evidence for manual review, "
                        "not a vulnerability or exploitability conclusion."
                    ),
                )
            )
    return tuple(disclosures)


def _parse_json_body(
    text: str,
    headers: tuple[tuple[str, str], ...],
) -> tuple[object | None, bool]:
    compact = text.lstrip()
    content_type = _header_value(headers, "content-type").lower()
    media_type = content_type.split(";", 1)[0].strip()
    supported = media_type == "application/json" or media_type.endswith("+json")
    json_shaped = _looks_json_shaped(compact)
    if not (supported or json_shaped):
        return None, False
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return None, True
    if not isinstance(value, (dict, list)):
        return None, True
    return value, True


def _looks_json_shaped(compact: str) -> bool:
    if compact.startswith("{"):
        return True
    if not compact.startswith("["):
        return False
    first_line = compact.splitlines()[0].strip()
    return _SECTION.fullmatch(first_line) is None


def _extract_json_routes(
    value: object,
    known_routes: frozenset[str],
) -> tuple[str, ...]:
    routes: list[str] = []
    seen = {_canonical_route(route) for route in known_routes}
    nodes_seen = 0

    def visit(current: object, depth: int) -> None:
        nonlocal nodes_seen
        if (
            depth > MAX_JSON_DEPTH
            or nodes_seen >= MAX_JSON_NODES
            or len(routes) >= MAX_JSON_ROUTES_PER_BODY
        ):
            return
        nodes_seen += 1
        if isinstance(current, str):
            route = _validated_route(current)
            canonical = _canonical_route(route) if route else ""
            if route and canonical not in seen:
                seen.add(canonical)
                routes.append(route)
            return
        if isinstance(current, dict):
            for key in sorted(current, key=lambda candidate: str(candidate)):
                if len(routes) >= MAX_JSON_ROUTES_PER_BODY or nodes_seen >= MAX_JSON_NODES:
                    break
                visit(current[key], depth + 1)
            return
        if isinstance(current, list):
            for child in current[:MAX_JSON_LIST_ITEMS]:
                if len(routes) >= MAX_JSON_ROUTES_PER_BODY or nodes_seen >= MAX_JSON_NODES:
                    break
                visit(child, depth + 1)

    visit(value, 0)
    return tuple(routes)


def _validated_route(value: str) -> str | None:
    if not value or len(value) > MAX_ROUTE_CHARS or value.startswith("//"):
        return None
    if any(ord(character) < 32 or character.isspace() for character in value):
        return None
    if "\\" in value or not _ROUTE_PATH.fullmatch(value):
        return None
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    segments = [segment for segment in parsed.path.split("/") if segment]
    if not segments or any(segment in {".", ".."} for segment in segments):
        return None
    if segments[0].lower() in _FILESYSTEM_ROOTS:
        return None
    if any(_UUID.fullmatch(segment) for segment in segments):
        return None
    if not any(any(character.isalpha() for character in segment) for segment in segments):
        return None
    if any(_looks_opaque_identifier(segment) for segment in segments):
        return None
    return parsed.path


def _looks_opaque_identifier(value: str) -> bool:
    if len(value) < 48 or not value.isalnum():
        return False
    classes = sum(
        (
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
        )
    )
    return classes >= 2


def _canonical_route(value: str) -> str:
    if not value:
        return ""
    parsed = urlsplit(value)
    path = parsed.path or "/"
    return path if path == "/" else path.rstrip("/")


def _configuration_excerpt(
    text: str,
    headers: tuple[tuple[str, str], ...],
) -> tuple[str, ...]:
    content_type = _header_value(headers, "content-type").lower()
    media_type = content_type.split(";", 1)[0].strip()
    if any(
        marker in media_type
        for marker in ("html", "css", "javascript", "ecmascript", "xml", "json", "image/")
    ):
        return ()
    if _HTML_MARKUP.search(text):
        return ()

    structured: list[tuple[str, frozenset[str]]] = []
    for raw_line in text.splitlines()[:MAX_CONFIG_LINES]:
        line = " ".join(raw_line.strip().split())[:MAX_CONFIG_LINE_CHARS]
        if not line or line.startswith(("#", ";", "//")):
            continue
        kinds = _configuration_line_kinds(line)
        if kinds:
            structured.append((line, kinds))

    if len(structured) < 3:
        return ()
    all_kinds = set().union(*(kinds for _line, kinds in structured))
    structural_kinds = all_kinds & {"assignment", "directive", "section", "block"}
    operational_kinds = all_kinds & {
        "filesystem_path",
        "network_value",
        "operational_key",
        "section",
        "block",
    }
    assignment_or_directive_count = sum(
        bool(kinds & {"assignment", "directive"}) for _line, kinds in structured
    )
    assignment_count = sum("assignment" in kinds for _line, kinds in structured)
    directive_count = sum("directive" in kinds for _line, kinds in structured)
    operational_line_count = sum(
        bool(kinds & {"filesystem_path", "network_value", "operational_key"})
        for _line, kinds in structured
    )
    coherent_single_syntax = (
        (assignment_count >= 3 or directive_count >= 3)
        and operational_line_count >= 2
    )
    coherent_mixed_syntax = (
        len(structural_kinds) >= 2
        and operational_kinds
        and assignment_or_directive_count >= 2
    )
    if not (coherent_single_syntax or coherent_mixed_syntax):
        return ()
    return tuple(line for line, _kinds in structured[:MAX_CONFIG_EXCERPT_LINES])


def _configuration_line_kinds(line: str) -> frozenset[str]:
    kinds: set[str] = set()
    assignment = _ASSIGNMENT.fullmatch(line)
    if assignment:
        kinds.add("assignment")
    if _SECTION.fullmatch(line):
        kinds.add("section")
    if _BLOCK.fullmatch(line) and not line.lower().startswith(("<meta", "<link", "<img")):
        kinds.add("block")
    directive = _DIRECTIVE.fullmatch(line)
    if directive and _looks_directive_like(directive.group("key"), directive.group("value")):
        kinds.add("directive")
    key_value = assignment or directive
    if key_value and _is_operational_key(key_value.group("key")):
        kinds.add("operational_key")
    if _POSIX_PATH.search(line):
        kinds.add("filesystem_path")
    if key_value and _looks_network_value(
        key_value.group("key"),
        key_value.group("value"),
    ):
        kinds.add("network_value")
    return frozenset(kinds)


def _looks_directive_like(key: str, value: str) -> bool:
    if value.endswith((".", "!", "?")) or len(value.split()) > 8:
        return False
    shaped_key = (
        "_" in key
        or "-" in key
        or "." in key
        or key.isupper()
        or (any(character.isupper() for character in key[1:]) and key[0].isupper())
    )
    shaped_value = bool(
        _POSIX_PATH.search(value)
        or _looks_network_value(key, value)
        or _is_operational_key(key)
    )
    return shaped_key or shaped_value


def render_configuration_excerpt_line(line: str) -> str:
    """Return one Markdown-safe configuration line with secret values redacted."""

    compact = " ".join(line.strip().split())[:MAX_CONFIG_LINE_CHARS]
    match = _LABELLED_VALUE.fullmatch(compact)
    separator = match.group("separator") if match is not None else " "
    if match is None:
        match = _DIRECTIVE.fullmatch(compact)
    if match is not None and _is_secret_key(match.group("key")):
        compact = f"{match.group('key')}{separator}[REDACTED]"
    return "".join(
        "'" if character == "`" else " " if ord(character) < 32 else character
        for character in compact
    )


def _is_secret_key(key: str) -> bool:
    normalised = re.sub(r"[^a-z0-9]", "", key.lower())
    return any(concept in normalised for concept in _SECRET_KEY_CONCEPTS)


def _is_operational_key(key: str) -> bool:
    normalised = re.sub(r"[^a-z0-9]", "", key.lower())
    return any(concept in normalised for concept in _OPERATIONAL_KEY_CONCEPTS)


def _looks_network_value(key: str, value: str) -> bool:
    compact = value.strip().strip("'\"")
    normalised_key = re.sub(r"[^a-z0-9]", "", key.lower())
    host_port = _HOST_PORT.fullmatch(compact)
    if host_port is not None:
        return _valid_port(host_port.group("port")) and _valid_host_address(
            host_port.group("host"),
            allow_single_label=True,
        )
    if normalised_key.endswith("port") or normalised_key in {"listen", "port"}:
        return _valid_port(compact)
    if not any(
        concept in normalised_key
        for concept in ("address", "bind", "host", "listen", "server")
    ):
        return False
    return _valid_host_address(compact, allow_single_label=True)


def _valid_host_address(value: str, *, allow_single_label: bool) -> bool:
    host = value.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if host.lower() == "localhost":
        return True
    if len(host) > 253 or (not allow_single_label and "." not in host):
        return False
    labels = host.rstrip(".").split(".")
    return all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    )


def _valid_port(value: str) -> bool:
    return value.isdigit() and 1 <= int(value) <= 65_535


def _header_value(headers: tuple[tuple[str, str], ...], name: str) -> str:
    wanted = name.lower()
    return next((value for key, value in headers if key.lower() == wanted), "")


def _dedupe(values) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result
