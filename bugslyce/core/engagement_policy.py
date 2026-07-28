"""Versioned engagement-policy validation, storage, and redacted presentation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import errno
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Mapping
import unicodedata

from bugslyce.core.engagement_context import BUG_BOUNTY_CONTEXT
from bugslyce.time_utils import Clock, format_utc_iso, utc_now_iso


ENGAGEMENT_POLICY_FILENAME = "engagement_policy.json"
ENGAGEMENT_POLICY_SCHEMA_VERSION = "1.0"
CONSERVATIVE_HTTP_RATE = Decimal("2")
CONSERVATIVE_HTTP_CONCURRENCY = 1

CONFIRMED = "confirmed"
NOT_CONFIRMED = "not_confirmed"
NOT_YET_CONFIRMED = "not_yet_confirmed"

AUTOMATION_PERMITTED = "explicitly_permitted"
AUTOMATION_NOT_PERMITTED = "not_permitted"

RATE_SOURCE_CONSERVATIVE = "bugslyce_conservative_default"
RATE_SOURCE_PROGRAMME = "programme_published_limit"

TCP_SKIP = "skip_tcp_discovery"
TCP_CONSERVATIVE = "conservative_common_web_ports"
TCP_CUSTOM = "programme_approved_custom_ports"
TCP_FULL = "full_tcp_explicitly_permitted"

IDENTIFICATION_NONE = "confirmed_none"
IDENTIFICATION_HEADERS = "custom_headers"
IDENTIFICATION_USER_AGENT = "custom_user_agent"
IDENTIFICATION_HEADERS_AND_USER_AGENT = "custom_headers_and_user_agent"
IDENTIFICATION_UNKNOWN = "not_yet_confirmed"

READINESS_INCOMPLETE = "policy_incomplete"
READINESS_FUTURE_ENFORCEMENT = "complete_for_future_enforcement"
ENFORCEMENT_UNAVAILABLE = "live_enforcement_unavailable_r0a"
LIVE_EXECUTION_BLOCKED = "blocked"

MAX_NUMERIC_INPUT_LENGTH = 128
MAX_DECIMAL_ADJUSTED_EXPONENT = 1000
MAX_TCP_SPECIFICATION_LENGTH = 4096
MAX_IDENTIFICATION_HEADERS = 64
MAX_IDENTIFICATION_NAME_LENGTH = 128
MAX_IDENTIFICATION_VALUE_LENGTH = 4096
MAX_POLICY_FILE_BYTES = 256 * 1024
MAX_TIMESTAMP_LENGTH = 64

_CONFIRMATION_STATES = {CONFIRMED, NOT_CONFIRMED, NOT_YET_CONFIRMED}
_AUTOMATION_STATES = {
    AUTOMATION_PERMITTED,
    AUTOMATION_NOT_PERMITTED,
    NOT_YET_CONFIRMED,
}
_RATE_SOURCES = {RATE_SOURCE_CONSERVATIVE, RATE_SOURCE_PROGRAMME}
_TCP_POLICIES = {TCP_SKIP, TCP_CONSERVATIVE, TCP_CUSTOM, TCP_FULL}
_IDENTIFICATION_STATES = {
    IDENTIFICATION_NONE,
    IDENTIFICATION_HEADERS,
    IDENTIFICATION_USER_AGENT,
    IDENTIFICATION_HEADERS_AND_USER_AGENT,
    IDENTIFICATION_UNKNOWN,
}
_HTTP_FIELD_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# Credential-bearing fields and RFC hop-by-hop or message-framing fields are not
# valid researcher-identification channels. User-Agent has its own policy field.
PROHIBITED_IDENTIFICATION_HEADERS = frozenset(
    name.casefold()
    for name in (
        "Host",
        "Content-Length",
        "Connection",
        "Keep-Alive",
        "Transfer-Encoding",
        "TE",
        "Trailer",
        "Upgrade",
        "Proxy-Connection",
        "Authorization",
        "Proxy-Authorization",
        "Proxy-Authenticate",
        "Cookie",
        "Set-Cookie",
        "WWW-Authenticate",
        "User-Agent",
        "X-API-Key",
        "API-Key",
        "X-Auth-Token",
        "X-Access-Token",
        "X-CSRF-Token",
        "X-XSRF-Token",
    )
)


@dataclass(frozen=True)
class IdentificationHeader:
    """One programme-required request identifier."""

    name: str
    value: str = field(repr=False)


@dataclass(frozen=True)
class EngagementPolicy:
    """Canonical operator-provided policy facts stored in the private file."""

    schema_version: str
    engagement_context: str
    updated_at: str
    programme_rules_reviewed: str
    automated_reconnaissance: str
    maximum_http_requests_per_second: str
    http_rate_source: str
    programme_rate_confirmed: str
    maximum_http_concurrency: int
    concurrent_automation_confirmed: str
    tcp_discovery_policy: str
    custom_tcp_ports: str | None
    tcp_policy_confirmed: str
    identification_requirement: str
    identification_headers: tuple[IdentificationHeader, ...] = field(
        default_factory=tuple,
        repr=False,
    )
    custom_user_agent: str | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Return deterministic JSON-compatible policy data."""

        return {
            "automated_reconnaissance": self.automated_reconnaissance,
            "concurrent_automation_confirmed": self.concurrent_automation_confirmed,
            "custom_tcp_ports": self.custom_tcp_ports,
            "custom_user_agent": self.custom_user_agent,
            "engagement_context": self.engagement_context,
            "http_rate_source": self.http_rate_source,
            "identification_headers": [
                {"name": header.name, "value": header.value}
                for header in self.identification_headers
            ],
            "identification_requirement": self.identification_requirement,
            "maximum_http_concurrency": self.maximum_http_concurrency,
            "maximum_http_requests_per_second": (
                self.maximum_http_requests_per_second
            ),
            "programme_rate_confirmed": self.programme_rate_confirmed,
            "programme_rules_reviewed": self.programme_rules_reviewed,
            "schema_version": self.schema_version,
            "tcp_discovery_policy": self.tcp_discovery_policy,
            "tcp_policy_confirmed": self.tcp_policy_confirmed,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class EngagementPolicyAssessment:
    """Derived policy readiness and current-build execution capability."""

    readiness_state: str
    not_ready_reasons: tuple[str, ...]
    enforcement_state: str
    live_execution_state: str


def validate_http_rate(value: object) -> str:
    """Validate and normalise a positive finite HTTP request rate."""

    if isinstance(value, bool):
        raise ValueError("HTTP request rate must be a positive finite number.")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("HTTP request rate must be a positive finite number.")
    if not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("HTTP request rate must be a positive finite number.")
    try:
        text = str(value).strip()
    except (ValueError, OverflowError):
        raise ValueError("HTTP request rate exceeds the technical size limit.") from None
    if len(text) > MAX_NUMERIC_INPUT_LENGTH:
        raise ValueError("HTTP request rate exceeds the technical size limit.")
    try:
        parsed = Decimal(text)
    except (InvalidOperation, ValueError):
        raise ValueError("HTTP request rate must be a positive finite number.") from None
    if not parsed.is_finite() or parsed <= 0:
        raise ValueError("HTTP request rate must be a positive finite number.")
    if (
        len(parsed.as_tuple().digits) > MAX_NUMERIC_INPUT_LENGTH
        or abs(parsed.adjusted()) > MAX_DECIMAL_ADJUSTED_EXPONENT
    ):
        raise ValueError("HTTP request rate exceeds the technical size limit.")
    return _normalise_decimal(parsed)


def validate_http_concurrency(value: object) -> int:
    """Validate a positive integral HTTP concurrency value."""

    if isinstance(value, bool):
        raise ValueError("HTTP concurrency must be a positive integer.")
    if isinstance(value, str):
        text = value.strip()
        if len(text) > MAX_NUMERIC_INPUT_LENGTH:
            raise ValueError("HTTP concurrency exceeds the technical size limit.")
        if not text or not text.isdecimal():
            raise ValueError("HTTP concurrency must be a positive integer.")
        parsed = int(text)
    elif isinstance(value, int):
        if value.bit_length() > MAX_NUMERIC_INPUT_LENGTH * 4:
            raise ValueError("HTTP concurrency exceeds the technical size limit.")
        parsed = value
    else:
        raise ValueError("HTTP concurrency must be a positive integer.")
    if parsed <= 0:
        raise ValueError("HTTP concurrency must be a positive integer.")
    return parsed


def normalise_tcp_port_specification(value: str) -> str:
    """Validate, deduplicate, sort, and compact a TCP port specification."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("Custom TCP ports must contain ports or ranges.")
    if len(value) > MAX_TCP_SPECIFICATION_LENGTH:
        raise ValueError("Custom TCP ports exceed the technical size limit.")
    ports: set[int] = set()
    for part in value.split(","):
        item = part.strip()
        if not item:
            raise ValueError("Custom TCP ports contain an empty item.")
        if "-" in item:
            if item.count("-") != 1:
                raise ValueError("Custom TCP port range is malformed.")
            start_text, end_text = (piece.strip() for piece in item.split("-", 1))
            if not start_text.isdecimal() or not end_text.isdecimal():
                raise ValueError("Custom TCP port range is malformed.")
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError("Custom TCP port range must be ascending.")
        else:
            if not item.isdecimal():
                raise ValueError("Custom TCP port is malformed.")
            start = end = int(item)
        if start < 1 or end > 65535:
            raise ValueError("Custom TCP ports must be within 1-65535.")
        ports.update(range(start, end + 1))
    return _compact_ports(sorted(ports))


def validate_identification_header_name(value: object) -> str:
    """Validate one HTTP field name for use as a traffic identifier."""

    if not isinstance(value, str):
        raise ValueError("Identification header name is invalid.")
    if len(value) > MAX_IDENTIFICATION_NAME_LENGTH:
        raise ValueError("Identification header name exceeds the technical size limit.")
    name = value.strip()
    if not name or name != value or not _HTTP_FIELD_NAME.fullmatch(name):
        raise ValueError("Identification header name is invalid.")
    if name.casefold() in PROHIBITED_IDENTIFICATION_HEADERS:
        raise ValueError(
            f"{name} cannot be used as a custom identification header."
        )
    return name


def validate_identification_value(value: object, *, label: str) -> str:
    """Validate a required header value or custom User-Agent without echoing it."""

    if not isinstance(value, str) or not value or not value.strip():
        raise ValueError(f"{label} must be configured.")
    if len(value) > MAX_IDENTIFICATION_VALUE_LENGTH:
        raise ValueError(f"{label} exceeds the technical size limit.")
    if any(
        unicodedata.category(character) == "Cc"
        or character in {"\u2028", "\u2029"}
        for character in value
    ):
        raise ValueError(f"{label} contains an unsafe control character.")
    if value != value.strip():
        raise ValueError(f"{label} must not contain leading or trailing whitespace.")
    return value


def validate_identification_headers(
    headers: tuple[IdentificationHeader, ...] | list[IdentificationHeader],
) -> tuple[IdentificationHeader, ...]:
    """Validate identifiers and reject case-insensitive duplicate field names."""

    validated: list[IdentificationHeader] = []
    if len(headers) > MAX_IDENTIFICATION_HEADERS:
        raise ValueError("Identification headers exceed the technical count limit.")
    seen: set[str] = set()
    for header in headers:
        if not isinstance(header, IdentificationHeader):
            raise ValueError("Identification headers must use structured entries.")
        name = validate_identification_header_name(header.name)
        folded = name.casefold()
        if folded in seen:
            raise ValueError("Identification header names must be unique.")
        seen.add(folded)
        validated.append(
            IdentificationHeader(
                name=name,
                value=validate_identification_value(
                    header.value,
                    label="Identification header value",
                ),
            )
        )
    return tuple(validated)


def build_bug_bounty_policy(
    *,
    programme_rules_reviewed: str = NOT_YET_CONFIRMED,
    automated_reconnaissance: str = NOT_YET_CONFIRMED,
    maximum_http_requests_per_second: object = CONSERVATIVE_HTTP_RATE,
    http_rate_source: str = RATE_SOURCE_CONSERVATIVE,
    programme_rate_confirmed: str = NOT_YET_CONFIRMED,
    maximum_http_concurrency: object = CONSERVATIVE_HTTP_CONCURRENCY,
    concurrent_automation_confirmed: str = NOT_YET_CONFIRMED,
    tcp_discovery_policy: str = TCP_CONSERVATIVE,
    custom_tcp_ports: str | None = None,
    tcp_policy_confirmed: str = NOT_YET_CONFIRMED,
    identification_requirement: str = IDENTIFICATION_UNKNOWN,
    identification_headers: tuple[IdentificationHeader, ...] = (),
    custom_user_agent: str | None = None,
    updated_at: str | None = None,
    clock: Clock | None = None,
) -> EngagementPolicy:
    """Build one validated set of canonical bug bounty policy facts."""

    _require_choice(
        programme_rules_reviewed,
        _CONFIRMATION_STATES,
        "Programme-rules review state",
    )
    _require_choice(
        automated_reconnaissance,
        _AUTOMATION_STATES,
        "Automated-reconnaissance permission",
    )
    _require_choice(http_rate_source, _RATE_SOURCES, "HTTP rate source")
    _require_choice(
        programme_rate_confirmed,
        _CONFIRMATION_STATES,
        "Programme-rate confirmation",
    )
    _require_choice(
        concurrent_automation_confirmed,
        _CONFIRMATION_STATES,
        "Concurrent-automation confirmation",
    )
    _require_choice(tcp_discovery_policy, _TCP_POLICIES, "TCP discovery policy")
    _require_choice(
        tcp_policy_confirmed,
        _CONFIRMATION_STATES,
        "TCP-policy confirmation",
    )
    _require_choice(
        identification_requirement,
        _IDENTIFICATION_STATES,
        "Identification requirement",
    )

    rate = validate_http_rate(maximum_http_requests_per_second)
    concurrency = validate_http_concurrency(maximum_http_concurrency)
    headers = validate_identification_headers(identification_headers)
    user_agent = (
        validate_identification_value(custom_user_agent, label="Custom User-Agent")
        if custom_user_agent is not None
        else None
    )
    ports = None
    if custom_tcp_ports is not None:
        ports = normalise_tcp_port_specification(custom_tcp_ports)

    timestamp = (
        utc_now_iso(clock)
        if updated_at is None
        else validate_policy_timestamp(updated_at)
    )
    return EngagementPolicy(
        schema_version=ENGAGEMENT_POLICY_SCHEMA_VERSION,
        engagement_context=BUG_BOUNTY_CONTEXT,
        updated_at=timestamp,
        programme_rules_reviewed=programme_rules_reviewed,
        automated_reconnaissance=automated_reconnaissance,
        maximum_http_requests_per_second=rate,
        http_rate_source=http_rate_source,
        programme_rate_confirmed=programme_rate_confirmed,
        maximum_http_concurrency=concurrency,
        concurrent_automation_confirmed=concurrent_automation_confirmed,
        tcp_discovery_policy=tcp_discovery_policy,
        custom_tcp_ports=ports,
        tcp_policy_confirmed=tcp_policy_confirmed,
        identification_requirement=identification_requirement,
        identification_headers=headers,
        custom_user_agent=user_agent,
    )


def assess_engagement_policy(
    policy: EngagementPolicy,
) -> EngagementPolicyAssessment:
    """Derive readiness and R0A capability without persisting either."""

    reasons = tuple(
        _readiness_reasons(
            programme_rules_reviewed=policy.programme_rules_reviewed,
            automated_reconnaissance=policy.automated_reconnaissance,
            rate=Decimal(policy.maximum_http_requests_per_second),
            http_rate_source=policy.http_rate_source,
            programme_rate_confirmed=policy.programme_rate_confirmed,
            concurrency=policy.maximum_http_concurrency,
            concurrent_automation_confirmed=policy.concurrent_automation_confirmed,
            tcp_discovery_policy=policy.tcp_discovery_policy,
            custom_tcp_ports=policy.custom_tcp_ports,
            tcp_policy_confirmed=policy.tcp_policy_confirmed,
            identification_requirement=policy.identification_requirement,
            headers=policy.identification_headers,
            user_agent=policy.custom_user_agent,
        )
    )
    ready = not reasons
    return EngagementPolicyAssessment(
        readiness_state=(
            READINESS_FUTURE_ENFORCEMENT if ready else READINESS_INCOMPLETE
        ),
        not_ready_reasons=reasons,
        enforcement_state=ENFORCEMENT_UNAVAILABLE,
        live_execution_state=LIVE_EXECUTION_BLOCKED,
    )


def policy_from_dict(payload: object) -> EngagementPolicy:
    """Load and independently validate one current policy payload."""

    if not isinstance(payload, Mapping):
        raise ValueError("Engagement policy must be a JSON object.")
    expected_fields = {
        "automated_reconnaissance",
        "concurrent_automation_confirmed",
        "custom_tcp_ports",
        "custom_user_agent",
        "engagement_context",
        "http_rate_source",
        "identification_headers",
        "identification_requirement",
        "maximum_http_concurrency",
        "maximum_http_requests_per_second",
        "programme_rate_confirmed",
        "programme_rules_reviewed",
        "schema_version",
        "tcp_discovery_policy",
        "tcp_policy_confirmed",
        "updated_at",
    }
    actual_fields = set(payload)
    if actual_fields != expected_fields:
        raise ValueError("Engagement policy fields do not match the canonical schema.")
    schema_version = payload.get("schema_version")
    if schema_version != ENGAGEMENT_POLICY_SCHEMA_VERSION:
        raise ValueError("Engagement policy schema version is unsupported.")
    headers_payload = payload.get("identification_headers")
    if not isinstance(headers_payload, list):
        raise ValueError("Engagement policy identification_headers must be a list.")
    headers: list[IdentificationHeader] = []
    for item in headers_payload:
        if not isinstance(item, Mapping) or set(item) != {"name", "value"}:
            raise ValueError("Engagement policy identification header schema is invalid.")
        name = item["name"]
        value = item["value"]
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("Engagement policy identification header schema is invalid.")
        headers.append(IdentificationHeader(name=name, value=value))

    required_strings = (
        "engagement_context",
        "updated_at",
        "programme_rules_reviewed",
        "automated_reconnaissance",
        "maximum_http_requests_per_second",
        "http_rate_source",
        "programme_rate_confirmed",
        "concurrent_automation_confirmed",
        "tcp_discovery_policy",
        "tcp_policy_confirmed",
        "identification_requirement",
    )
    for field_name in required_strings:
        if not isinstance(payload.get(field_name), str):
            raise ValueError(f"Engagement policy field is invalid: {field_name}")
    custom_ports = payload.get("custom_tcp_ports")
    custom_user_agent = payload.get("custom_user_agent")
    if custom_ports is not None and not isinstance(custom_ports, str):
        raise ValueError("Engagement policy field is invalid: custom_tcp_ports")
    if custom_user_agent is not None and not isinstance(custom_user_agent, str):
        raise ValueError("Engagement policy field is invalid: custom_user_agent")

    if payload["engagement_context"] != BUG_BOUNTY_CONTEXT:
        raise ValueError("Engagement policy context must be bug_bounty.")
    policy = build_bug_bounty_policy(
        programme_rules_reviewed=payload["programme_rules_reviewed"],
        automated_reconnaissance=payload["automated_reconnaissance"],
        maximum_http_requests_per_second=payload[
            "maximum_http_requests_per_second"
        ],
        http_rate_source=payload["http_rate_source"],
        programme_rate_confirmed=payload["programme_rate_confirmed"],
        maximum_http_concurrency=payload.get("maximum_http_concurrency"),
        concurrent_automation_confirmed=payload[
            "concurrent_automation_confirmed"
        ],
        tcp_discovery_policy=payload["tcp_discovery_policy"],
        custom_tcp_ports=custom_ports,
        tcp_policy_confirmed=payload["tcp_policy_confirmed"],
        identification_requirement=payload["identification_requirement"],
        identification_headers=tuple(headers),
        custom_user_agent=custom_user_agent,
        updated_at=payload["updated_at"],
    )
    return policy


def write_engagement_policy(project_dir: Path, policy: EngagementPolicy) -> Path:
    """Atomically write one private project-local policy without following links."""

    project_dir = project_dir.expanduser().resolve()
    if not project_dir.is_dir():
        raise ValueError("Engagement policy project directory does not exist.")
    if not isinstance(policy, EngagementPolicy):
        raise ValueError("Engagement policy must use the canonical policy model.")
    validated_policy = policy_from_dict(policy.to_dict())
    destination = project_dir / ENGAGEMENT_POLICY_FILENAME
    _refuse_unsafe_policy_path(destination)
    content = (
        json.dumps(validated_policy.to_dict(), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(content) > MAX_POLICY_FILE_BYTES:
        raise ValueError("Engagement policy exceeds the technical size limit.")
    fd, temporary_name = tempfile.mkstemp(
        prefix=".engagement_policy.",
        suffix=".tmp",
        dir=project_dir,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _refuse_unsafe_policy_path(destination)
        os.replace(temporary, destination)
    except Exception:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
        raise
    return destination


def load_engagement_policy(project_dir: Path) -> EngagementPolicy:
    """Load one private policy from the same no-follow descriptor that is checked."""

    project_dir = project_dir.expanduser().resolve()
    policy_path = project_dir / ENGAGEMENT_POLICY_FILENAME
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = -1
    try:
        fd = os.open(policy_path, flags)
    except FileNotFoundError:
        raise ValueError("Engagement policy file is missing.") from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(
                "Engagement policy path must be a regular file, not a link."
            ) from None
        raise ValueError("Engagement policy file could not be opened safely.") from None
    try:
        descriptor_stat = os.fstat(fd)
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise ValueError(
                "Engagement policy path must be a regular file, not a link."
            )
        if descriptor_stat.st_uid != os.geteuid():
            raise ValueError("Engagement policy file must be owned by the current user.")
        if stat.S_IMODE(descriptor_stat.st_mode) & 0o077:
            raise ValueError(
                "Engagement policy permissions are unsafe; set owner-only mode 0600."
            )
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            content = handle.read(MAX_POLICY_FILE_BYTES + 1)
        if len(content.encode("utf-8")) > MAX_POLICY_FILE_BYTES:
            raise ValueError("Engagement policy file exceeds the technical size limit.")
        try:
            payload = json.loads(content)
        except (UnicodeError, json.JSONDecodeError):
            raise ValueError(
                "Engagement policy file is malformed or unreadable."
            ) from None
    except ValueError:
        raise
    except (OSError, UnicodeError):
        raise ValueError("Engagement policy file is malformed or unreadable.") from None
    finally:
        if fd >= 0:
            os.close(fd)
    return policy_from_dict(payload)


def render_redacted_policy(policy: EngagementPolicy) -> str:
    """Render policy facts without identification values."""

    assessment = assess_engagement_policy(policy)
    lines = [
        "BugSlyce engagement policy",
        f"Policy schema: {policy.schema_version}",
        f"Programme rules reviewed: {_label(policy.programme_rules_reviewed)}",
        f"Automated reconnaissance: {_label(policy.automated_reconnaissance)}",
        (
            "Maximum aggregate HTTP rate: "
            f"{policy.maximum_http_requests_per_second} requests per second"
        ),
        f"Rate source: {_label(policy.http_rate_source)}",
        f"Maximum HTTP concurrency: {policy.maximum_http_concurrency}",
        f"TCP discovery: {_label(policy.tcp_discovery_policy)}",
        f"Identification requirement: {_label(policy.identification_requirement)}",
    ]
    if policy.custom_tcp_ports:
        lines.append(f"Custom TCP ports: {policy.custom_tcp_ports}")
    if policy.identification_headers:
        lines.append("Identification headers:")
        lines.extend(
            f"- {header.name}: configured" for header in policy.identification_headers
        )
    else:
        lines.append("Identification headers: not configured")
    lines.append(
        "Custom User-Agent: "
        + ("configured" if policy.custom_user_agent else "not configured")
    )
    lines.append(f"Policy readiness: {_label(assessment.readiness_state)}")
    if assessment.not_ready_reasons:
        lines.append("Reasons preventing readiness:")
        lines.extend(f"- {reason}" for reason in assessment.not_ready_reasons)
    else:
        lines.append("Reasons preventing readiness: none")
    lines.extend(
        (
            "Live enforcement: unavailable in R0A.",
            (
                "Policy configuration values are not yet enforced across every "
                "network component. Live bug bounty reconnaissance remains blocked."
            ),
        )
    )
    return "\n".join(lines)


def bug_bounty_live_refusal_reasons(policy: EngagementPolicy | None) -> tuple[str, ...]:
    """Return deterministic policy-specific reasons for central live refusal."""

    if policy is None:
        return ("Engagement policy is missing.",)
    return assess_engagement_policy(policy).not_ready_reasons


def validate_policy_timestamp(value: object) -> str:
    """Validate BugSlyce's seconds-precision UTC policy timestamp format."""

    if not isinstance(value, str) or not value or not value.strip():
        raise ValueError("Engagement policy timestamp is invalid.")
    if len(value) > MAX_TIMESTAMP_LENGTH:
        raise ValueError("Engagement policy timestamp exceeds the technical size limit.")
    if value != value.strip():
        raise ValueError("Engagement policy timestamp is invalid.")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise ValueError("Engagement policy timestamp is invalid.") from None
    if format_utc_iso(parsed) != value:
        raise ValueError("Engagement policy timestamp is invalid.")
    return value


def _readiness_reasons(
    *,
    programme_rules_reviewed: str,
    automated_reconnaissance: str,
    rate: Decimal,
    http_rate_source: str,
    programme_rate_confirmed: str,
    concurrency: int,
    concurrent_automation_confirmed: str,
    tcp_discovery_policy: str,
    custom_tcp_ports: str | None,
    tcp_policy_confirmed: str,
    identification_requirement: str,
    headers: tuple[IdentificationHeader, ...],
    user_agent: str | None,
) -> list[str]:
    reasons: list[str] = []
    if programme_rules_reviewed != CONFIRMED:
        reasons.append("Current programme rules have not been confirmed as reviewed.")
    if automated_reconnaissance == AUTOMATION_NOT_PERMITTED:
        reasons.append("The programme does not permit automated reconnaissance.")
    elif automated_reconnaissance != AUTOMATION_PERMITTED:
        reasons.append("Automated reconnaissance permission is not yet confirmed.")
    if rate > CONSERVATIVE_HTTP_RATE and http_rate_source != RATE_SOURCE_PROGRAMME:
        reasons.append("A rate above the conservative default must be programme-defined.")
    if http_rate_source == RATE_SOURCE_PROGRAMME and programme_rate_confirmed != CONFIRMED:
        reasons.append("The programme-published HTTP rate has not been confirmed.")
    if concurrency > 1 and concurrent_automation_confirmed != CONFIRMED:
        reasons.append("Concurrent automation above one request is not confirmed.")
    if tcp_discovery_policy == TCP_CUSTOM:
        if custom_tcp_ports is None:
            reasons.append("Programme-approved custom TCP ports are not configured.")
        if tcp_policy_confirmed != CONFIRMED:
            reasons.append("The programme-approved custom TCP policy is not confirmed.")
    elif custom_tcp_ports is not None:
        reasons.append("Custom TCP ports require the programme-approved custom policy.")
    if tcp_discovery_policy == TCP_FULL and tcp_policy_confirmed != CONFIRMED:
        reasons.append("Full TCP discovery permission is not confirmed.")
    needs_headers = identification_requirement in {
        IDENTIFICATION_HEADERS,
        IDENTIFICATION_HEADERS_AND_USER_AGENT,
    }
    needs_user_agent = identification_requirement in {
        IDENTIFICATION_USER_AGENT,
        IDENTIFICATION_HEADERS_AND_USER_AGENT,
    }
    if identification_requirement == IDENTIFICATION_UNKNOWN:
        reasons.append("Traffic-identification requirements are not yet confirmed.")
    if needs_headers and not headers:
        reasons.append("Required custom identification headers are not configured.")
    if not needs_headers and headers:
        reasons.append("Custom headers do not match the identification requirement.")
    if needs_user_agent and user_agent is None:
        reasons.append("Required custom User-Agent is not configured.")
    if not needs_user_agent and user_agent is not None:
        reasons.append("Custom User-Agent does not match the identification requirement.")
    return reasons


def _require_choice(value: object, allowed: set[str], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{label} is invalid.")
    return value


def _normalise_decimal(value: Decimal) -> str:
    text = format(value.normalize(), "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _compact_ports(ports: list[int]) -> str:
    ranges: list[tuple[int, int]] = []
    start = previous = ports[0]
    for port in ports[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append((start, previous))
        start = previous = port
    ranges.append((start, previous))
    return ",".join(
        str(start) if start == end else f"{start}-{end}"
        for start, end in ranges
    )


def _refuse_unsafe_policy_path(path: Path) -> None:
    try:
        path_stat = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
        raise ValueError("Engagement policy path must be a regular file, not a link.")


def _label(value: str) -> str:
    return value.replace("_", " ").capitalize()
