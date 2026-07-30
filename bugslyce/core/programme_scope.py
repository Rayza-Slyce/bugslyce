"""Canonical, deterministic programme target-scope modelling.

This module is intentionally pure. It validates operator-provided scope facts
and evaluates already-canonical destinations without filesystem, DNS, socket,
HTTP, subprocess, or project integration. The initial dependency-free model
supports ordinary ASCII DNS labels only; internationalised U-labels and A-labels
are deliberately refused until modern IDNA handling is available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import re
from typing import Any, TypeAlias
from urllib.parse import SplitResult, urlsplit
import unicodedata

from bugslyce.core.engagement_context import BUG_BOUNTY_CONTEXT
from bugslyce.time_utils import Clock, format_utc_iso, utc_now_iso


PROGRAMME_SCOPE_SCHEMA_VERSION = "1.0"

ACTION_INCLUDE = "include"
ACTION_EXCLUDE = "exclude"
SUPPORTED_SCOPE_ACTIONS = frozenset({ACTION_INCLUDE, ACTION_EXCLUDE})

RULE_EXACT_HOSTNAME = "exact_hostname"
RULE_WILDCARD_SUBDOMAIN = "wildcard_subdomain"
RULE_EXACT_HTTP_URL = "exact_http_url"
RULE_HTTP_PATH_PREFIX = "http_path_prefix"
RULE_EXACT_IPV4 = "exact_ipv4"
RULE_IPV4_CIDR = "ipv4_cidr"
SUPPORTED_SCOPE_RULE_KINDS = frozenset(
    {
        RULE_EXACT_HOSTNAME,
        RULE_WILDCARD_SUBDOMAIN,
        RULE_EXACT_HTTP_URL,
        RULE_HTTP_PATH_PREFIX,
        RULE_EXACT_IPV4,
        RULE_IPV4_CIDR,
    }
)

DESTINATION_HOSTNAME = "hostname"
DESTINATION_IPV4 = "ipv4"
DESTINATION_HTTP_URL = "http_url"
SUPPORTED_RAW_DESTINATION_KINDS = frozenset(
    {DESTINATION_HOSTNAME, DESTINATION_IPV4, DESTINATION_HTTP_URL}
)

OUTCOME_ALLOWED = "allowed"
OUTCOME_BLOCKED = "blocked"
OUTCOME_UNKNOWN = "unknown"
SUPPORTED_SCOPE_OUTCOMES = frozenset(
    {OUTCOME_ALLOWED, OUTCOME_BLOCKED, OUTCOME_UNKNOWN}
)

REASON_INCLUDED = "included"
REASON_EXPLICIT_EXCLUSION = "explicit_exclusion"
REASON_NO_MATCHING_INCLUSION = "no_matching_inclusion"
REASON_UNSUPPORTED_DESTINATION = "unsupported_destination"
REASON_INVALID_DESTINATION = "invalid_destination"
REASON_RESOLVED_IP_EXCLUDED = "resolved_ip_excluded"
SUPPORTED_SCOPE_REASON_CODES = frozenset(
    {
        REASON_INCLUDED,
        REASON_EXPLICIT_EXCLUSION,
        REASON_NO_MATCHING_INCLUSION,
        REASON_UNSUPPORTED_DESTINATION,
        REASON_INVALID_DESTINATION,
        REASON_RESOLVED_IP_EXCLUDED,
    }
)

MAX_RULE_ID_LENGTH = 64
MAX_PRIVATE_TEXT_LENGTH = 4096
MAX_TIMESTAMP_LENGTH = 64
MAX_HOSTNAME_LENGTH = 253
MAX_HOSTNAME_LABEL_LENGTH = 63
MAX_URL_LENGTH = 8192
MAX_PATH_LENGTH = 4096
MAX_QUERY_LENGTH = 4096
MAX_OPERATOR_SAFE_EXPLANATION_LENGTH = 4096

_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_LEGACY_IPV4_DECIMAL_COMPONENT = re.compile(r"^[0-9]+$")
_LEGACY_IPV4_HEXADECIMAL_COMPONENT = re.compile(r"^0[xX][0-9A-Fa-f]+$")
_HEX = frozenset("0123456789abcdefABCDEF")
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_PATH_LITERAL = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "-._~!$&'()*+,;=:@/"
)
_QUERY_LITERAL = _PATH_LITERAL | frozenset("?")
_NESTED_PATH_BOUNDARY_ESCAPE = re.compile(
    r"%25(?:25)*(?:2e|2f|5c)",
    re.IGNORECASE,
)


def _contains_unsafe_text(value: str) -> bool:
    return any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        or character in {"\u2028", "\u2029"}
        for character in value
    )


def validate_rule_id(value: object) -> str:
    """Validate one stable, report-safe rule identifier."""

    if not isinstance(value, str) or not _RULE_ID.fullmatch(value):
        raise ValueError(
            "Programme scope rule ID must contain 1-64 ASCII letters, digits, "
            "dot, underscore, or dash, and must begin with a letter or digit."
        )
    return value


def validate_private_scope_text(value: object, *, label: str) -> str | None:
    """Validate optional private policy text without rendering its value."""

    if value is None:
        return None
    if not isinstance(value, str) or not value or not value.strip():
        raise ValueError(f"{label} must be omitted or contain non-empty text.")
    if len(value) > MAX_PRIVATE_TEXT_LENGTH:
        raise ValueError(f"{label} exceeds the technical size limit.")
    if _contains_unsafe_text(value):
        raise ValueError(f"{label} contains an unsafe control character.")
    return value


def canonicalise_hostname(value: object) -> str:
    """Return an ordinary canonical ASCII hostname, never an IP or IDN."""

    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Hostname must be non-empty without surrounding whitespace.")
    if not value.isascii():
        raise ValueError(
            "Internationalised hostname scope is not supported in the current "
            "programme-scope model."
        )
    if _contains_unsafe_text(value):
        raise ValueError("Hostname must use safe ASCII DNS syntax.")
    if value.endswith(".."):
        raise ValueError("Hostname must not contain multiple terminal dots.")
    candidate = value[:-1] if value.endswith(".") else value
    if not candidate or len(candidate) > MAX_HOSTNAME_LENGTH:
        raise ValueError("Hostname length is invalid.")
    try:
        ipaddress.IPv4Address(candidate)
    except ValueError:
        pass
    else:
        raise ValueError("IPv4 literals must use the IPv4 destination type.")
    if all(character in "0123456789." for character in candidate) or (
        _is_legacy_numeric_ipv4_hostname(candidate)
    ):
        raise ValueError("Ambiguous numeric hostname syntax is not supported.")
    labels = candidate.split(".")
    if any(not label or len(label) > MAX_HOSTNAME_LABEL_LENGTH for label in labels):
        raise ValueError("Hostname labels are invalid.")
    for label in labels:
        if label.casefold().startswith("xn--"):
            raise ValueError(
                "Internationalised hostname scope is not supported in the current "
                "programme-scope model."
            )
        if not _HOST_LABEL.fullmatch(label):
            raise ValueError("Hostname labels must use ASCII letters, digits, or hyphens.")
    return candidate.lower()


def _is_legacy_numeric_ipv4_hostname(candidate: str) -> bool:
    """Recognise one to four decimal or 0x-prefixed numeric components."""

    components = candidate.split(".")
    return 1 <= len(components) <= 4 and all(
        _LEGACY_IPV4_DECIMAL_COMPONENT.fullmatch(component)
        or _LEGACY_IPV4_HEXADECIMAL_COMPONENT.fullmatch(component)
        for component in components
    )


def canonicalise_ipv4(value: object) -> str:
    """Return canonical dotted-decimal IPv4 without accepting ambiguous forms."""

    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("IPv4 address must be non-empty without surrounding whitespace.")
    if not value.isascii() or _contains_unsafe_text(value):
        raise ValueError("IPv4 address must use canonical ASCII syntax.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("IPv4 address is invalid.") from None
    if not isinstance(address, ipaddress.IPv4Address) or str(address) != value:
        raise ValueError("IPv4 address must use canonical dotted-decimal syntax.")
    return str(address)


def canonicalise_ipv4_cidr(value: object) -> str:
    """Return one strict, network-aligned canonical IPv4 CIDR."""

    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("IPv4 CIDR must be non-empty without surrounding whitespace.")
    if not value.isascii() or _contains_unsafe_text(value):
        raise ValueError("IPv4 CIDR must use canonical ASCII syntax.")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ValueError("IPv4 CIDR must be valid and network-aligned.") from None
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("IPv6 scope rules are not supported.")
    canonical = str(network)
    if canonical != value:
        raise ValueError("IPv4 CIDR must use canonical dotted-decimal syntax.")
    return canonical


@dataclass(frozen=True, order=True)
class CanonicalHTTPOrigin:
    """One strict HTTP(S) origin with an effective port."""

    scheme: str
    host_kind: str
    host: str
    effective_port: int

    def __post_init__(self) -> None:
        if self.scheme not in {"http", "https"}:
            raise ValueError("Canonical HTTP origin scheme is invalid.")
        if self.host_kind == DESTINATION_HOSTNAME:
            if canonicalise_hostname(self.host) != self.host:
                raise ValueError("Canonical HTTP hostname is not canonical.")
        elif self.host_kind == DESTINATION_IPV4:
            if canonicalise_ipv4(self.host) != self.host:
                raise ValueError("Canonical HTTP IPv4 address is not canonical.")
        else:
            raise ValueError("Canonical HTTP origin host kind is invalid.")
        if (
            isinstance(self.effective_port, bool)
            or not isinstance(self.effective_port, int)
            or not 1 <= self.effective_port <= 65535
        ):
            raise ValueError("Canonical HTTP origin port is invalid.")

    @property
    def authority(self) -> str:
        default_port = 80 if self.scheme == "http" else 443
        return (
            self.host
            if self.effective_port == default_port
            else f"{self.host}:{self.effective_port}"
        )

    @property
    def canonical_value(self) -> str:
        return f"{self.scheme}://{self.authority}"


@dataclass(frozen=True)
class CanonicalHostnameDestination:
    """One canonical logical hostname destination."""

    hostname: str
    kind: str = field(default=DESTINATION_HOSTNAME, init=False)

    def __post_init__(self) -> None:
        if canonicalise_hostname(self.hostname) != self.hostname:
            raise ValueError("Canonical hostname destination is not canonical.")

    @property
    def canonical_value(self) -> str:
        return self.hostname


@dataclass(frozen=True)
class CanonicalIPv4Destination:
    """One canonical logical or resolved IPv4 destination."""

    address: str
    kind: str = field(default=DESTINATION_IPV4, init=False)

    def __post_init__(self) -> None:
        if canonicalise_ipv4(self.address) != self.address:
            raise ValueError("Canonical IPv4 destination is not canonical.")

    @property
    def canonical_value(self) -> str:
        return self.address


@dataclass(frozen=True)
class CanonicalHTTPURLDestination:
    """One canonical HTTP URL with exact query-presence semantics."""

    origin: CanonicalHTTPOrigin
    path: str
    query: str | None
    kind: str = field(default=DESTINATION_HTTP_URL, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.origin, CanonicalHTTPOrigin):
            raise ValueError("Canonical HTTP URL origin is invalid.")
        if canonicalise_http_path(self.path) != self.path:
            raise ValueError("Canonical HTTP URL path is not canonical.")
        if self.query is not None:
            validate_http_query(self.query)

    @property
    def canonical_value(self) -> str:
        query = "" if self.query is None else f"?{self.query}"
        return f"{self.origin.canonical_value}{self.path}{query}"


CanonicalLogicalDestination: TypeAlias = (
    CanonicalHostnameDestination
    | CanonicalIPv4Destination
    | CanonicalHTTPURLDestination
)


@dataclass(frozen=True)
class CanonicalResolvedIPv4Peer:
    """One resolved peer tied to an already-canonical logical destination."""

    logical_destination: CanonicalHostnameDestination | CanonicalHTTPURLDestination
    peer: CanonicalIPv4Destination

    def __post_init__(self) -> None:
        if not isinstance(
            self.logical_destination,
            (CanonicalHostnameDestination, CanonicalHTTPURLDestination),
        ):
            raise ValueError("Resolved peer requires a hostname-based logical destination.")
        if (
            isinstance(self.logical_destination, CanonicalHTTPURLDestination)
            and self.logical_destination.origin.host_kind != DESTINATION_HOSTNAME
        ):
            raise ValueError("Resolved peer HTTP destination must use a hostname origin.")
        if not isinstance(self.peer, CanonicalIPv4Destination):
            raise ValueError("Resolved peer must use a canonical IPv4 destination.")


def canonicalise_hostname_destination(value: object) -> CanonicalHostnameDestination:
    return CanonicalHostnameDestination(canonicalise_hostname(value))


def canonicalise_ipv4_destination(value: object) -> CanonicalIPv4Destination:
    return CanonicalIPv4Destination(canonicalise_ipv4(value))


def canonicalise_http_path(value: object) -> str:
    """Canonicalise a strict ASCII HTTP path without collapsing literal slashes."""

    if not isinstance(value, str):
        raise ValueError("HTTP path is invalid.")
    if value == "":
        return "/"
    if len(value) > MAX_PATH_LENGTH:
        raise ValueError("HTTP path exceeds the technical size limit.")
    if not value.isascii() or _contains_unsafe_text(value) or "\\" in value:
        raise ValueError("HTTP path contains unsafe or unsupported characters.")
    if not value.startswith("/") or "?" in value or "#" in value:
        raise ValueError("HTTP path must be an absolute path without query or fragment.")
    if _NESTED_PATH_BOUNDARY_ESCAPE.search(value):
        raise ValueError("HTTP path contains an ambiguous nested boundary escape.")

    canonical: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character != "%":
            if character not in _PATH_LITERAL:
                raise ValueError("HTTP path contains an unsupported literal character.")
            canonical.append(character)
            index += 1
            continue
        byte = _percent_byte(value, index, label="HTTP path")
        if byte in {0x2F, 0x5C}:
            raise ValueError("HTTP path contains an encoded path separator.")
        if byte < 0x20 or byte == 0x7F or byte >= 0x80:
            raise ValueError("HTTP path contains an unsafe encoded byte.")
        decoded = chr(byte)
        canonical.append(decoded if decoded in _UNRESERVED else f"%{byte:02X}")
        index += 3
    canonical_path = "".join(canonical)
    if _NESTED_PATH_BOUNDARY_ESCAPE.search(canonical_path):
        raise ValueError("HTTP path contains an ambiguous nested boundary escape.")
    return _remove_dot_segments(canonical_path)


def _percent_byte(value: str, index: int, *, label: str) -> int:
    if index + 2 >= len(value) or value[index + 1] not in _HEX or value[index + 2] not in _HEX:
        raise ValueError(f"{label} contains a malformed percent escape.")
    return int(value[index + 1 : index + 3], 16)


def _remove_dot_segments(path: str) -> str:
    input_buffer = path
    output = ""
    while input_buffer:
        if input_buffer.startswith("../"):
            input_buffer = input_buffer[3:]
        elif input_buffer.startswith("./"):
            input_buffer = input_buffer[2:]
        elif input_buffer.startswith("/./"):
            input_buffer = "/" + input_buffer[3:]
        elif input_buffer == "/.":
            input_buffer = "/"
        elif input_buffer.startswith("/../"):
            input_buffer = "/" + input_buffer[4:]
            output = _remove_last_path_segment(output)
        elif input_buffer == "/..":
            input_buffer = "/"
            output = _remove_last_path_segment(output)
        elif input_buffer in {".", ".."}:
            input_buffer = ""
        else:
            boundary = input_buffer.find("/", 1 if input_buffer.startswith("/") else 0)
            if boundary == -1:
                output += input_buffer
                input_buffer = ""
            else:
                output += input_buffer[:boundary]
                input_buffer = input_buffer[boundary:]
    return output or "/"


def _remove_last_path_segment(path: str) -> str:
    boundary = path.rfind("/")
    return "" if boundary < 0 else path[:boundary]


def validate_http_query(value: object) -> str:
    """Validate an exact query representation without normalising its semantics."""

    if not isinstance(value, str):
        raise ValueError("HTTP query is invalid.")
    if len(value) > MAX_QUERY_LENGTH:
        raise ValueError("HTTP query exceeds the technical size limit.")
    if not value.isascii() or _contains_unsafe_text(value) or "\\" in value or "#" in value:
        raise ValueError("HTTP query contains unsafe or unsupported characters.")
    index = 0
    while index < len(value):
        character = value[index]
        if character == "%":
            byte = _percent_byte(value, index, label="HTTP query")
            if byte < 0x20 or byte == 0x7F:
                raise ValueError("HTTP query contains an unsafe encoded control byte.")
            index += 3
            continue
        if character not in _QUERY_LITERAL:
            raise ValueError("HTTP query contains an unsupported literal character.")
        index += 1
    return value


def canonicalise_http_url_destination(value: object) -> CanonicalHTTPURLDestination:
    """Canonicalise one absolute HTTP(S) URL with exact query state."""

    raw_value, parsed, port = _parse_http_url(value)
    return _canonicalise_parsed_http_url(raw_value, parsed, port)


def _parse_http_url(value: object) -> tuple[str, SplitResult, int | None]:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("HTTP URL must be non-empty without surrounding whitespace.")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError("HTTP URL exceeds the technical size limit.")
    if not value.isascii() or _contains_unsafe_text(value) or "\\" in value:
        raise ValueError("HTTP URL contains unsafe or unsupported characters.")
    if "#" in value:
        raise ValueError("HTTP URL fragments are not supported.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        raise ValueError("HTTP URL is malformed.") from None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        raise ValueError("HTTP URL must be an absolute HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("HTTP URL userinfo is not supported.")
    if parsed.netloc.endswith(":") and port is None:
        raise ValueError("HTTP URL port is malformed.")
    return value, parsed, port


def _canonicalise_parsed_http_url(
    raw_value: str,
    parsed: SplitResult,
    port: int | None,
) -> CanonicalHTTPURLDestination:
    scheme = parsed.scheme.lower()
    raw_host = parsed.hostname
    if raw_host is None:
        raise ValueError("HTTP URL must contain a hostname.")
    try:
        canonical_host = canonicalise_ipv4(raw_host)
    except ValueError:
        canonical_host = canonicalise_hostname(raw_host)
        host_kind = DESTINATION_HOSTNAME
    else:
        host_kind = DESTINATION_IPV4
    effective_port = port if port is not None else (80 if scheme == "http" else 443)
    origin = CanonicalHTTPOrigin(scheme, host_kind, canonical_host, effective_port)
    path = canonicalise_http_path(parsed.path)
    query = validate_http_query(parsed.query) if "?" in raw_value else None
    return CanonicalHTTPURLDestination(origin=origin, path=path, query=query)


def canonicalise_http_origin(value: object) -> CanonicalHTTPOrigin:
    """Canonicalise one root HTTP(S) origin without discarding URL components."""

    raw_value, parsed, port = _parse_http_url(value)
    if parsed.path not in {"", "/"}:
        raise ValueError(
            "HTTP origin raw path must be empty or literal '/' and must not "
            "contain a path or query."
        )
    if "?" in raw_value:
        raise ValueError("HTTP origin must not contain a path or query.")
    destination = _canonicalise_parsed_http_url(raw_value, parsed, port)
    return destination.origin


def canonicalise_resolved_ipv4_peer(
    logical_destination: CanonicalHostnameDestination | CanonicalHTTPURLDestination,
    peer: object,
) -> CanonicalResolvedIPv4Peer:
    return CanonicalResolvedIPv4Peer(
        logical_destination=logical_destination,
        peer=canonicalise_ipv4_destination(peer),
    )


@dataclass(frozen=True)
class ProgrammeScopeRule:
    """One canonical programme inclusion or exclusion rule."""

    rule_id: str
    action: str
    kind: str
    canonical_value: str
    private_note: str | None = field(default=None, repr=False)
    private_source_wording: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        validate_rule_id(self.rule_id)
        if self.action not in SUPPORTED_SCOPE_ACTIONS:
            raise ValueError("Programme scope rule action is unsupported.")
        if self.kind not in SUPPORTED_SCOPE_RULE_KINDS:
            raise ValueError("Programme scope rule kind is unsupported.")
        if _canonical_rule_value(self.kind, self.canonical_value) != self.canonical_value:
            raise ValueError("Programme scope rule value is not canonical.")
        validate_private_scope_text(self.private_note, label="Private scope note")
        validate_private_scope_text(
            self.private_source_wording,
            label="Private scope source wording",
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "canonical_value": self.canonical_value,
            "kind": self.kind,
            "private_note": self.private_note,
            "private_source_wording": self.private_source_wording,
            "rule_id": self.rule_id,
        }


def build_programme_scope_rule(
    *,
    rule_id: object,
    action: object,
    kind: object,
    value: object,
    private_note: object = None,
    private_source_wording: object = None,
) -> ProgrammeScopeRule:
    """Validate raw rule input and return its sole canonical representation."""

    validated_id = validate_rule_id(rule_id)
    if not isinstance(action, str) or action not in SUPPORTED_SCOPE_ACTIONS:
        raise ValueError("Programme scope rule action is unsupported.")
    if not isinstance(kind, str) or kind not in SUPPORTED_SCOPE_RULE_KINDS:
        raise ValueError("Programme scope rule kind is unsupported.")
    return ProgrammeScopeRule(
        rule_id=validated_id,
        action=action,
        kind=kind,
        canonical_value=_canonical_rule_value(kind, value),
        private_note=validate_private_scope_text(
            private_note,
            label="Private scope note",
        ),
        private_source_wording=validate_private_scope_text(
            private_source_wording,
            label="Private scope source wording",
        ),
    )


def _canonical_rule_value(kind: str, value: object) -> str:
    if kind == RULE_EXACT_HOSTNAME:
        return canonicalise_hostname(value)
    if kind == RULE_WILDCARD_SUBDOMAIN:
        if not isinstance(value, str) or not value.startswith("*.") or value.count("*") != 1:
            raise ValueError("Wildcard scope rule must use exactly '*.example.test' syntax.")
        suffix = canonicalise_hostname(value[2:])
        return f"*.{suffix}"
    if kind == RULE_EXACT_IPV4:
        return canonicalise_ipv4(value)
    if kind == RULE_IPV4_CIDR:
        return canonicalise_ipv4_cidr(value)
    if kind in {RULE_EXACT_HTTP_URL, RULE_HTTP_PATH_PREFIX}:
        destination = canonicalise_http_url_destination(value)
        if kind == RULE_HTTP_PATH_PREFIX and destination.query is not None:
            raise ValueError("HTTP path-prefix rule must not contain a query.")
        return destination.canonical_value
    raise ValueError("Programme scope rule kind is unsupported.")


@dataclass(frozen=True)
class ProgrammeScopePolicy:
    """Canonical programme target-authority facts for pure evaluation."""

    schema_version: str
    engagement_context: str
    updated_at: str
    rules: tuple[ProgrammeScopeRule, ...]

    def __post_init__(self) -> None:
        if self.schema_version != PROGRAMME_SCOPE_SCHEMA_VERSION:
            raise ValueError("Programme scope schema version is unsupported.")
        if self.engagement_context != BUG_BOUNTY_CONTEXT:
            raise ValueError("Programme scope context must be bug_bounty.")
        _validate_updated_at(self.updated_at)
        if not isinstance(self.rules, tuple) or any(
            not isinstance(rule, ProgrammeScopeRule) for rule in self.rules
        ):
            raise ValueError("Programme scope rules must be a tuple of canonical rules.")
        canonical_order = tuple(sorted(self.rules, key=_rule_order_key))
        if self.rules != canonical_order:
            raise ValueError("Programme scope rules are not in deterministic order.")
        folded_ids = [rule.rule_id.casefold() for rule in self.rules]
        if len(folded_ids) != len(set(folded_ids)):
            raise ValueError("Programme scope rule IDs must be unique case-insensitively.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_context": self.engagement_context,
            "rules": [rule.to_dict() for rule in self.rules],
            "schema_version": self.schema_version,
            "updated_at": self.updated_at,
        }


def build_programme_scope_policy(
    rules: tuple[ProgrammeScopeRule, ...] | list[ProgrammeScopeRule],
    *,
    schema_version: str = PROGRAMME_SCOPE_SCHEMA_VERSION,
    engagement_context: str = BUG_BOUNTY_CONTEXT,
    updated_at: str | None = None,
    clock: Clock | None = None,
) -> ProgrammeScopePolicy:
    """Build a deterministic policy without reading or writing local state."""

    if not isinstance(rules, (tuple, list)) or any(
        not isinstance(rule, ProgrammeScopeRule) for rule in rules
    ):
        raise ValueError("Programme scope rules must use canonical rule objects.")
    timestamp = utc_now_iso(clock) if updated_at is None else _validate_updated_at(updated_at)
    return ProgrammeScopePolicy(
        schema_version=schema_version,
        engagement_context=engagement_context,
        updated_at=timestamp,
        rules=tuple(sorted(rules, key=_rule_order_key)),
    )


def _validate_updated_at(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > MAX_TIMESTAMP_LENGTH
        or not value.endswith("Z")
    ):
        raise ValueError("Programme scope updated_at must be a canonical UTC timestamp.")
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError:
        raise ValueError("Programme scope updated_at must be a canonical UTC timestamp.") from None
    if format_utc_iso(parsed) != value:
        raise ValueError("Programme scope updated_at must be a canonical UTC timestamp.")
    return value


def _rule_order_key(rule: ProgrammeScopeRule) -> tuple[str, str]:
    return (rule.rule_id.casefold(), rule.rule_id)


def _canonical_scope_explanation(
    reason_code: str,
    *,
    primary_inclusion_rule_id: str | None,
    primary_exclusion_rule_id: str | None,
) -> str:
    if reason_code == REASON_INCLUDED:
        if primary_inclusion_rule_id is None:
            raise ValueError("Included scope decision requires a primary inclusion.")
        return (
            "Destination is included by programme scope rule "
            f"{primary_inclusion_rule_id}."
        )
    if reason_code == REASON_EXPLICIT_EXCLUSION:
        if primary_exclusion_rule_id is None:
            raise ValueError("Blocked scope decision requires a primary exclusion.")
        return (
            "Destination is blocked by explicit programme scope rule "
            f"{primary_exclusion_rule_id}."
        )
    if reason_code == REASON_RESOLVED_IP_EXCLUDED:
        if primary_exclusion_rule_id is None:
            raise ValueError("Resolved peer decision requires a primary exclusion.")
        return (
            "Resolved IPv4 peer is blocked by explicit programme scope rule "
            f"{primary_exclusion_rule_id}."
        )
    if reason_code == REASON_NO_MATCHING_INCLUSION:
        return "Destination has no matching programme scope inclusion."
    if reason_code == REASON_UNSUPPORTED_DESTINATION:
        return "Destination type is unsupported by programme scope evaluation."
    if reason_code == REASON_INVALID_DESTINATION:
        return "Destination is invalid and was not evaluated as authorised."
    raise ValueError("Scope decision reason is unsupported.")


@dataclass(frozen=True)
class ScopeDecision:
    """Complete deterministic decision without private policy wording."""

    outcome: str
    canonical_destination: CanonicalLogicalDestination | None
    reason_code: str
    matched_inclusion_rule_ids: tuple[str, ...]
    matched_exclusion_rule_ids: tuple[str, ...]
    primary_inclusion_rule_id: str | None
    primary_exclusion_rule_id: str | None
    operator_safe_explanation: str
    resolved_peer: CanonicalIPv4Destination | None = None

    def __post_init__(self) -> None:
        if self.outcome not in SUPPORTED_SCOPE_OUTCOMES:
            raise ValueError("Scope decision outcome is unsupported.")
        if self.reason_code not in SUPPORTED_SCOPE_REASON_CODES:
            raise ValueError("Scope decision reason is unsupported.")
        if self.canonical_destination is not None and not isinstance(
            self.canonical_destination,
            (
                CanonicalHostnameDestination,
                CanonicalIPv4Destination,
                CanonicalHTTPURLDestination,
            ),
        ):
            raise ValueError("Scope decision destination is invalid.")
        if self.resolved_peer is not None and not isinstance(
            self.resolved_peer, CanonicalIPv4Destination
        ):
            raise ValueError("Scope decision resolved peer is invalid.")
        if self.resolved_peer is not None and not _supports_resolved_peer(
            self.canonical_destination
        ):
            raise ValueError(
                "Scope decision resolved peer requires a hostname-based destination."
            )
        for values in (
            self.matched_inclusion_rule_ids,
            self.matched_exclusion_rule_ids,
        ):
            if not isinstance(values, tuple):
                raise ValueError("Scope decision matched rule IDs must be tuples.")
            if values != tuple(sorted(values, key=lambda item: (item.casefold(), item))):
                raise ValueError("Scope decision matched rule IDs are not deterministic.")
            for value in values:
                validate_rule_id(value)
            if len(values) != len({value.casefold() for value in values}):
                raise ValueError("Scope decision matched rule IDs must be unique.")
        if (
            self.primary_inclusion_rule_id is not None
            and self.primary_inclusion_rule_id not in self.matched_inclusion_rule_ids
        ):
            raise ValueError("Scope decision primary inclusion is not a matched rule.")
        if (
            self.primary_exclusion_rule_id is not None
            and self.primary_exclusion_rule_id not in self.matched_exclusion_rule_ids
        ):
            raise ValueError("Scope decision primary exclusion is not a matched rule.")
        if self.resolved_peer is None:
            if bool(self.matched_inclusion_rule_ids) != bool(
                self.primary_inclusion_rule_id
            ):
                raise ValueError(
                    "Non-resolved scope decision has inconsistent primary inclusion."
                )
            if bool(self.matched_exclusion_rule_ids) != bool(
                self.primary_exclusion_rule_id
            ):
                raise ValueError(
                    "Non-resolved scope decision has inconsistent primary exclusion."
                )
        if (
            not isinstance(self.operator_safe_explanation, str)
            or not self.operator_safe_explanation.strip()
            or len(self.operator_safe_explanation)
            > MAX_OPERATOR_SAFE_EXPLANATION_LENGTH
            or _contains_unsafe_text(self.operator_safe_explanation)
        ):
            raise ValueError("Scope decision explanation is invalid.")
        if self.reason_code in {
            REASON_UNSUPPORTED_DESTINATION,
            REASON_INVALID_DESTINATION,
        }:
            self._validate_unevaluated_unknown()
        else:
            if self.canonical_destination is None:
                raise ValueError(
                    "Evaluated scope decision requires a canonical destination."
                )
            if self.outcome == OUTCOME_ALLOWED:
                self._validate_allowed()
            elif self.outcome == OUTCOME_BLOCKED:
                self._validate_blocked()
            else:
                self._validate_evaluated_unknown()
        expected_explanation = _canonical_scope_explanation(
            self.reason_code,
            primary_inclusion_rule_id=self.primary_inclusion_rule_id,
            primary_exclusion_rule_id=self.primary_exclusion_rule_id,
        )
        if self.operator_safe_explanation != expected_explanation:
            raise ValueError("Scope decision explanation is not canonical.")

    def _validate_unevaluated_unknown(self) -> None:
        if (
            self.outcome != OUTCOME_UNKNOWN
            or self.canonical_destination is not None
            or self.resolved_peer is not None
            or self.matched_inclusion_rule_ids
            or self.matched_exclusion_rule_ids
            or self.primary_inclusion_rule_id is not None
            or self.primary_exclusion_rule_id is not None
        ):
            raise ValueError("Unevaluated scope decision state is inconsistent.")

    def _validate_allowed(self) -> None:
        if (
            self.reason_code != REASON_INCLUDED
            or not self.matched_inclusion_rule_ids
            or self.primary_inclusion_rule_id is None
            or self.matched_exclusion_rule_ids
            or self.primary_exclusion_rule_id is not None
        ):
            raise ValueError("Allowed scope decision state is inconsistent.")

    def _validate_blocked(self) -> None:
        if (
            self.reason_code
            not in {REASON_EXPLICIT_EXCLUSION, REASON_RESOLVED_IP_EXCLUDED}
            or not self.matched_exclusion_rule_ids
            or self.primary_exclusion_rule_id is None
            or (
                self.reason_code == REASON_RESOLVED_IP_EXCLUDED
                and self.resolved_peer is None
            )
        ):
            raise ValueError("Blocked scope decision state is inconsistent.")

    def _validate_evaluated_unknown(self) -> None:
        if (
            self.reason_code != REASON_NO_MATCHING_INCLUSION
            or self.matched_exclusion_rule_ids
            or self.primary_inclusion_rule_id is not None
            or self.primary_exclusion_rule_id is not None
            or (self.matched_inclusion_rule_ids and self.resolved_peer is None)
        ):
            raise ValueError("Unknown scope decision state is inconsistent.")


def _supports_resolved_peer(
    destination: CanonicalLogicalDestination | None,
) -> bool:
    if isinstance(destination, CanonicalHostnameDestination):
        return True
    return (
        isinstance(destination, CanonicalHTTPURLDestination)
        and destination.origin.host_kind == DESTINATION_HOSTNAME
    )


def evaluate_programme_scope(
    policy: ProgrammeScopePolicy,
    destination: object,
) -> ScopeDecision:
    """Evaluate one canonical destination using exclusion-first default deny."""

    if not isinstance(policy, ProgrammeScopePolicy):
        raise ValueError("A canonical programme scope policy is required.")
    if not isinstance(
        destination,
        (
            CanonicalHostnameDestination,
            CanonicalIPv4Destination,
            CanonicalHTTPURLDestination,
        ),
    ):
        return _unknown_decision(REASON_UNSUPPORTED_DESTINATION)
    matches = tuple(rule for rule in policy.rules if _rule_matches(rule, destination))
    return _decision_from_matches(policy, destination, matches)


def evaluate_raw_scope_destination(
    policy: ProgrammeScopePolicy,
    destination_kind: object,
    value: object,
) -> ScopeDecision:
    """Canonicalise raw input or return a deterministic fail-closed decision."""

    if not isinstance(policy, ProgrammeScopePolicy):
        raise ValueError("A canonical programme scope policy is required.")
    if not isinstance(destination_kind, str):
        return _unknown_decision(REASON_UNSUPPORTED_DESTINATION)
    if destination_kind not in SUPPORTED_RAW_DESTINATION_KINDS:
        return _unknown_decision(REASON_UNSUPPORTED_DESTINATION)
    try:
        if destination_kind == DESTINATION_HOSTNAME:
            destination: CanonicalLogicalDestination = canonicalise_hostname_destination(value)
        elif destination_kind == DESTINATION_IPV4:
            destination = canonicalise_ipv4_destination(value)
        else:
            destination = canonicalise_http_url_destination(value)
    except ValueError:
        return _unknown_decision(REASON_INVALID_DESTINATION)
    return evaluate_programme_scope(policy, destination)


def evaluate_resolved_ipv4_peer(
    policy: ProgrammeScopePolicy,
    logical_decision: ScopeDecision,
    resolved_peer: CanonicalResolvedIPv4Peer,
) -> ScopeDecision:
    """Combine a logical decision with pure exact-IP/CIDR peer evaluation."""

    if not isinstance(policy, ProgrammeScopePolicy):
        raise ValueError("A canonical programme scope policy is required.")
    if not isinstance(logical_decision, ScopeDecision):
        raise ValueError("Resolved peer evaluation requires a logical scope decision.")
    if not isinstance(resolved_peer, CanonicalResolvedIPv4Peer):
        raise ValueError("Resolved peer evaluation requires a canonical peer.")
    if logical_decision.canonical_destination != resolved_peer.logical_destination:
        raise ValueError("Resolved peer does not match the logical scope destination.")
    canonical_logical_decision = evaluate_programme_scope(
        policy,
        resolved_peer.logical_destination,
    )
    if logical_decision != canonical_logical_decision:
        raise ValueError(
            "Logical scope decision does not match the supplied policy's canonical "
            "logical scope decision."
        )

    peer_matches = tuple(
        rule
        for rule in policy.rules
        if rule.kind in {RULE_EXACT_IPV4, RULE_IPV4_CIDR}
        and _rule_matches(rule, resolved_peer.peer)
    )
    peer_inclusions = tuple(
        rule for rule in peer_matches if rule.action == ACTION_INCLUDE
    )
    peer_exclusions = tuple(
        rule for rule in peer_matches if rule.action == ACTION_EXCLUDE
    )
    inclusion_ids = _sorted_ids(
        (
            *logical_decision.matched_inclusion_rule_ids,
            *(rule.rule_id for rule in peer_inclusions),
        )
    )
    exclusion_ids = _sorted_ids(
        (
            *logical_decision.matched_exclusion_rule_ids,
            *(rule.rule_id for rule in peer_exclusions),
        )
    )

    if peer_exclusions:
        primary_exclusion = _primary_rule_id(peer_exclusions)
        outcome = OUTCOME_BLOCKED
        reason = REASON_RESOLVED_IP_EXCLUDED
        primary_inclusion = logical_decision.primary_inclusion_rule_id
    else:
        outcome = logical_decision.outcome
        reason = logical_decision.reason_code
        primary_inclusion = logical_decision.primary_inclusion_rule_id
        primary_exclusion = logical_decision.primary_exclusion_rule_id
    explanation = _canonical_scope_explanation(
        reason,
        primary_inclusion_rule_id=primary_inclusion,
        primary_exclusion_rule_id=primary_exclusion,
    )
    return ScopeDecision(
        outcome=outcome,
        canonical_destination=logical_decision.canonical_destination,
        reason_code=reason,
        matched_inclusion_rule_ids=inclusion_ids,
        matched_exclusion_rule_ids=exclusion_ids,
        primary_inclusion_rule_id=primary_inclusion,
        primary_exclusion_rule_id=primary_exclusion,
        operator_safe_explanation=explanation,
        resolved_peer=resolved_peer.peer,
    )


def _rule_matches(
    rule: ProgrammeScopeRule,
    destination: CanonicalLogicalDestination,
) -> bool:
    if isinstance(destination, CanonicalHostnameDestination):
        return _hostname_rule_matches(rule, destination.hostname)
    if isinstance(destination, CanonicalIPv4Destination):
        return _ipv4_rule_matches(rule, destination.address)
    if isinstance(destination, CanonicalHTTPURLDestination):
        if rule.kind == RULE_EXACT_HTTP_URL:
            return rule.canonical_value == destination.canonical_value
        if rule.kind == RULE_HTTP_PATH_PREFIX:
            rule_url = canonicalise_http_url_destination(rule.canonical_value)
            return rule_url.origin == destination.origin and _path_prefix_matches(
                rule_url.path,
                destination.path,
            )
        if destination.origin.host_kind == DESTINATION_HOSTNAME:
            return _hostname_rule_matches(rule, destination.origin.host)
        return _ipv4_rule_matches(rule, destination.origin.host)
    return False


def _hostname_rule_matches(rule: ProgrammeScopeRule, hostname: str) -> bool:
    if rule.kind == RULE_EXACT_HOSTNAME:
        return hostname == rule.canonical_value
    if rule.kind == RULE_WILDCARD_SUBDOMAIN:
        suffix = rule.canonical_value[2:]
        return hostname != suffix and hostname.endswith(f".{suffix}")
    return False


def _ipv4_rule_matches(rule: ProgrammeScopeRule, address: str) -> bool:
    if rule.kind == RULE_EXACT_IPV4:
        return address == rule.canonical_value
    if rule.kind == RULE_IPV4_CIDR:
        return ipaddress.IPv4Address(address) in ipaddress.IPv4Network(rule.canonical_value)
    return False


def _path_prefix_matches(prefix: str, path: str) -> bool:
    if prefix == "/":
        return True
    if prefix.endswith("/"):
        return path.startswith(prefix)
    return path == prefix or path.startswith(f"{prefix}/")


def _decision_from_matches(
    policy: ProgrammeScopePolicy,
    destination: CanonicalLogicalDestination,
    matches: tuple[ProgrammeScopeRule, ...],
) -> ScopeDecision:
    inclusions = tuple(rule for rule in matches if rule.action == ACTION_INCLUDE)
    exclusions = tuple(rule for rule in matches if rule.action == ACTION_EXCLUDE)
    inclusion_ids = _sorted_ids(rule.rule_id for rule in inclusions)
    exclusion_ids = _sorted_ids(rule.rule_id for rule in exclusions)
    primary_inclusion = _primary_rule_id(inclusions)
    primary_exclusion = _primary_rule_id(exclusions)
    if exclusions:
        outcome = OUTCOME_BLOCKED
        reason = REASON_EXPLICIT_EXCLUSION
    elif inclusions:
        outcome = OUTCOME_ALLOWED
        reason = REASON_INCLUDED
    else:
        outcome = OUTCOME_UNKNOWN
        reason = REASON_NO_MATCHING_INCLUSION
    explanation = _canonical_scope_explanation(
        reason,
        primary_inclusion_rule_id=primary_inclusion,
        primary_exclusion_rule_id=primary_exclusion,
    )
    return ScopeDecision(
        outcome=outcome,
        canonical_destination=destination,
        reason_code=reason,
        matched_inclusion_rule_ids=inclusion_ids,
        matched_exclusion_rule_ids=exclusion_ids,
        primary_inclusion_rule_id=primary_inclusion,
        primary_exclusion_rule_id=primary_exclusion,
        operator_safe_explanation=explanation,
    )


def _unknown_decision(reason: str) -> ScopeDecision:
    explanation = _canonical_scope_explanation(
        reason,
        primary_inclusion_rule_id=None,
        primary_exclusion_rule_id=None,
    )
    return ScopeDecision(
        outcome=OUTCOME_UNKNOWN,
        canonical_destination=None,
        reason_code=reason,
        matched_inclusion_rule_ids=(),
        matched_exclusion_rule_ids=(),
        primary_inclusion_rule_id=None,
        primary_exclusion_rule_id=None,
        operator_safe_explanation=explanation,
    )


def _sorted_ids(values: Any) -> tuple[str, ...]:
    return tuple(sorted(set(values), key=lambda item: (item.casefold(), item)))


def _primary_rule_id(rules: tuple[ProgrammeScopeRule, ...]) -> str | None:
    if not rules:
        return None
    return min(rules, key=_primary_rule_order_key).rule_id


def _primary_rule_order_key(rule: ProgrammeScopeRule) -> tuple[int, int, str, str]:
    rank, detail = _rule_specificity(rule)
    return (-rank, -detail, rule.rule_id.casefold(), rule.rule_id)


def _rule_specificity(rule: ProgrammeScopeRule) -> tuple[int, int]:
    if rule.kind == RULE_EXACT_HTTP_URL:
        return (5, 0)
    if rule.kind == RULE_HTTP_PATH_PREFIX:
        return (4, len(canonicalise_http_url_destination(rule.canonical_value).path))
    if rule.kind in {RULE_EXACT_HOSTNAME, RULE_EXACT_IPV4}:
        return (3, 0)
    if rule.kind == RULE_WILDCARD_SUBDOMAIN:
        return (2, len(rule.canonical_value[2:].split(".")))
    if rule.kind == RULE_IPV4_CIDR:
        return (1, ipaddress.IPv4Network(rule.canonical_value).prefixlen)
    raise ValueError("Programme scope rule kind is unsupported.")
