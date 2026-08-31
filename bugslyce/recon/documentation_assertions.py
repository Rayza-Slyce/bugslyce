"""Target-independent offline assertions from retained documentation HTML."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from hashlib import sha256
from html import unescape
from html.parser import HTMLParser
import re
from urllib.parse import urlsplit, urlunsplit

from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.http_origin import HttpOrigin, http_origin_from_url


MAXIMUM_MATCHED_EXCERPT_CHARS = 200
MAXIMUM_STRUCTURAL_LOCATOR_CHARS = 200
ELIGIBLE_MEDIA_TYPES = frozenset({"text/html", "application/xhtml+xml"})
HTTP_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
)
EXCLUDED_TAGS = frozenset(
    {"script", "style", "template", "noscript", "nav", "header", "footer", "aside"}
)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$")
_SCOPE_RE = re.compile(r"^[A-Za-z0-9._~:/-]{1,128}$")
_REQUEST_LINE_RE = re.compile(
    r"(?m)^[ \t]*(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)[ \t]+([^\s]+)[ \t]*$"
)
_HTTP_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_REALTIME_URL_RE = re.compile(r"wss?://[^\s<>\"']+", re.IGNORECASE)
_AFFIRMATIVE_REQUIRED = frozenset({"required", "yes", "true"})


class DocumentationAssertionKind(Enum):
    SERVICE_BASE_URL = "service_base_url"
    HTTP_OPERATION = "http_operation"
    REQUIRED_HEADER = "required_header"
    AUTHENTICATION_SCHEME = "authentication_scheme"
    OAUTH_SCOPE = "oauth_scope"
    REALTIME_ENDPOINT = "realtime_endpoint"


class DocumentationAuthenticationScheme(Enum):
    BEARER = "bearer"


class DocumentationSourceOwnerKind(Enum):
    DEEP_SOURCE_ROUTE_COLLECTED_ITEM = "deep_source_route_collected_item"


class DocumentationStructuralContext(Enum):
    LABELLED_CODE_BLOCK = "labelled_code_block"
    DEFINITION_PAIR = "definition_pair"
    TABLE_ROW = "table_row"


class DocumentationSourceSkipReason(Enum):
    MISSING_BODY = "missing_body"
    BODY_HASH_MISMATCH = "body_hash_mismatch"
    BODY_LENGTH_MISMATCH = "body_length_mismatch"
    MISSING_EVIDENCE = "missing_evidence"
    NON_SUCCESS_STATUS = "non_success_status"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"


def _require_non_blank(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-blank")
    return value.strip()


def _contains_control(value: str) -> bool:
    return _CONTROL_RE.search(value) is not None


def _semantic_id(prefix: str, *parts: object) -> str:
    digest = sha256()
    for part in parts:
        value = part.value if isinstance(part, Enum) else str(part)
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return f"{prefix}-{digest.hexdigest()}"


def _normalise_evidence_ids(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        return ()
    normalised: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            return ()
        normalised.add(value.strip())
    return tuple(sorted(normalised))


def _canonical_http_url(value: str) -> tuple[str, HttpOrigin] | None:
    if not isinstance(value, str) or value != value.strip() or _contains_control(value):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    if parsed.username or parsed.password or parsed.fragment:
        return None
    origin = http_origin_from_url(value)
    if origin is None:
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    return (
        urlunsplit(
            (
                origin.scheme,
                origin.authority,
                parsed.path or "/",
                parsed.query,
                "",
            )
        ),
        origin,
    )


@dataclass(frozen=True)
class DocumentedServiceBaseURL:
    canonical_url: str
    origin: HttpOrigin

    def __post_init__(self) -> None:
        canonical = _canonical_http_url(self.canonical_url)
        if canonical is None or canonical != (self.canonical_url, self.origin):
            raise ValueError("documented service base URL is not canonical")


@dataclass(frozen=True)
class DocumentedHttpOperation:
    method: str
    route: str

    def __post_init__(self) -> None:
        if self.method not in HTTP_METHODS:
            raise ValueError("documented HTTP operation method is unsupported")
        route = _require_non_blank(self.route, label="documented operation route")
        if route != self.route or _contains_control(route) or any(char.isspace() for char in route):
            raise ValueError("documented operation route is invalid")
        if route.startswith(("http://", "https://")):
            canonical = _canonical_http_url(route)
            if canonical is None or canonical[0] != route:
                raise ValueError("documented absolute operation route is invalid")
        elif not route.startswith("/") or "#" in route:
            raise ValueError("documented operation route must be root-relative or HTTP")


@dataclass(frozen=True)
class DocumentedRequiredHeader:
    header_name: str

    def __post_init__(self) -> None:
        if not isinstance(self.header_name, str) or not _HEADER_NAME_RE.fullmatch(
            self.header_name
        ):
            raise ValueError("documented required header name is invalid")
        if self.header_name != self.header_name.lower():
            raise ValueError("documented required header name must be canonical")


@dataclass(frozen=True)
class DocumentedAuthentication:
    scheme: DocumentationAuthenticationScheme

    def __post_init__(self) -> None:
        if not isinstance(self.scheme, DocumentationAuthenticationScheme):
            raise ValueError("documented authentication scheme must be typed")


@dataclass(frozen=True)
class DocumentedOAuthScope:
    scope: str

    def __post_init__(self) -> None:
        if not isinstance(self.scope, str) or not _SCOPE_RE.fullmatch(self.scope):
            raise ValueError("documented OAuth scope is invalid")


def _canonical_realtime_url(value: str) -> tuple[str, str, str, int, str, str] | None:
    if not isinstance(value, str) or value != value.strip() or _contains_control(value):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"ws", "wss"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password or parsed.fragment:
        return None
    hostname = parsed.hostname.lower().rstrip(".")
    if not hostname or (port is not None and not 1 <= port <= 65535):
        return None
    effective_port = port if port is not None else (443 if scheme == "wss" else 80)
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "wss" else 80
    authority = host if effective_port == default_port else f"{host}:{effective_port}"
    path = parsed.path or "/"
    canonical_url = urlunsplit((scheme, authority, path, parsed.query, ""))
    return canonical_url, scheme, hostname, effective_port, path, parsed.query


@dataclass(frozen=True)
class DocumentedRealtimeEndpoint:
    canonical_url: str
    scheme: str
    hostname: str
    effective_port: int
    path: str
    query: str

    def __post_init__(self) -> None:
        canonical = _canonical_realtime_url(self.canonical_url)
        expected = (
            self.canonical_url,
            self.scheme,
            self.hostname,
            self.effective_port,
            self.path,
            self.query,
        )
        if canonical != expected:
            raise ValueError("documented realtime endpoint is not canonical")


DocumentationAssertionValue = (
    DocumentedServiceBaseURL
    | DocumentedHttpOperation
    | DocumentedRequiredHeader
    | DocumentedAuthentication
    | DocumentedOAuthScope
    | DocumentedRealtimeEndpoint
)


@dataclass(frozen=True)
class DocumentationAssertionSourceReference:
    owner_kind: DocumentationSourceOwnerKind
    source_id: str
    request_url: str
    final_url: str
    method: str
    status_code: int
    body_sha256: str
    body_bytes: int
    evidence_ids: tuple[str, ...]
    media_type: str

    def __post_init__(self) -> None:
        if self.owner_kind is not DocumentationSourceOwnerKind.DEEP_SOURCE_ROUTE_COLLECTED_ITEM:
            raise ValueError("documentation source owner kind is invalid")
        _require_non_blank(self.source_id, label="documentation source id")
        _require_non_blank(self.request_url, label="documentation request URL")
        _require_non_blank(self.final_url, label="documentation final URL")
        if not isinstance(self.method, str) or self.method != self.method.upper() or not self.method:
            raise ValueError("documentation source method is invalid")
        if isinstance(self.status_code, bool) or not isinstance(self.status_code, int):
            raise ValueError("documentation source status is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.body_sha256):
            raise ValueError("documentation source body SHA-256 is invalid")
        if isinstance(self.body_bytes, bool) or not isinstance(self.body_bytes, int) or self.body_bytes <= 0:
            raise ValueError("documentation source body length is invalid")
        evidence_ids = _normalise_evidence_ids(self.evidence_ids)
        if not evidence_ids:
            raise ValueError("documentation source evidence is missing")
        object.__setattr__(self, "evidence_ids", evidence_ids)
        if self.media_type not in ELIGIBLE_MEDIA_TYPES:
            raise ValueError("documentation source media type is invalid")


@dataclass(frozen=True)
class DocumentationAssertionSupport:
    source_reference: DocumentationAssertionSourceReference
    structural_context: DocumentationStructuralContext
    start_offset: int
    end_offset: int
    line_number: int
    structural_locator: str
    matched_excerpt: str

    def __post_init__(self) -> None:
        if not isinstance(self.source_reference, DocumentationAssertionSourceReference):
            raise ValueError("documentation support source reference is invalid")
        if not isinstance(self.structural_context, DocumentationStructuralContext):
            raise ValueError("documentation support structural context is invalid")
        if (
            isinstance(self.start_offset, bool)
            or not isinstance(self.start_offset, int)
            or self.start_offset < 0
            or isinstance(self.end_offset, bool)
            or not isinstance(self.end_offset, int)
            or self.end_offset <= self.start_offset
        ):
            raise ValueError("documentation support offsets are invalid")
        if isinstance(self.line_number, bool) or not isinstance(self.line_number, int) or self.line_number < 1:
            raise ValueError("documentation support line number is invalid")
        if not isinstance(self.structural_locator, str) or not 1 <= len(self.structural_locator) <= MAXIMUM_STRUCTURAL_LOCATOR_CHARS:
            raise ValueError("documentation support structural locator is invalid")
        if not isinstance(self.matched_excerpt, str) or not 1 <= len(self.matched_excerpt) <= MAXIMUM_MATCHED_EXCERPT_CHARS:
            raise ValueError("documentation support excerpt is invalid")


_VALUE_TYPES = {
    DocumentationAssertionKind.SERVICE_BASE_URL: DocumentedServiceBaseURL,
    DocumentationAssertionKind.HTTP_OPERATION: DocumentedHttpOperation,
    DocumentationAssertionKind.REQUIRED_HEADER: DocumentedRequiredHeader,
    DocumentationAssertionKind.AUTHENTICATION_SCHEME: DocumentedAuthentication,
    DocumentationAssertionKind.OAUTH_SCOPE: DocumentedOAuthScope,
    DocumentationAssertionKind.REALTIME_ENDPOINT: DocumentedRealtimeEndpoint,
}


def _support_sort_key(support: DocumentationAssertionSupport) -> tuple[object, ...]:
    return (
        support.source_reference.source_id,
        support.start_offset,
        support.end_offset,
        support.structural_context.value,
        support.structural_locator,
    )


@dataclass(frozen=True)
class DocumentationAssertion:
    assertion_id: str
    kind: DocumentationAssertionKind
    value: DocumentationAssertionValue
    supports: tuple[DocumentationAssertionSupport, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.kind, DocumentationAssertionKind):
            raise ValueError("documentation assertion kind is invalid")
        if not isinstance(self.value, _VALUE_TYPES[self.kind]):
            raise ValueError("documentation assertion kind and value contradict")
        expected_id = _assertion_id(self.kind, self.value)
        if self.assertion_id != expected_id:
            raise ValueError("documentation assertion id does not match kind and value")
        supports = tuple(sorted(set(self.supports), key=_support_sort_key))
        if not supports:
            raise ValueError("documentation assertion requires support")
        object.__setattr__(self, "supports", supports)


@dataclass(frozen=True)
class DocumentationSourceSkip:
    source_id: str
    request_url: str
    body_sha256: str
    evidence_ids: tuple[str, ...]
    reason: DocumentationSourceSkipReason

    def __post_init__(self) -> None:
        _require_non_blank(self.source_id, label="skipped documentation source id")
        _require_non_blank(self.request_url, label="skipped documentation request URL")
        if not isinstance(self.reason, DocumentationSourceSkipReason):
            raise ValueError("documentation source skip reason is invalid")
        object.__setattr__(self, "evidence_ids", _normalise_evidence_ids(self.evidence_ids))


@dataclass(frozen=True)
class DocumentationAssertionExtractionResult:
    assertions: tuple[DocumentationAssertion, ...]
    skipped_sources: tuple[DocumentationSourceSkip, ...]
    sources_considered: int
    sources_eligible: int

    def __post_init__(self) -> None:
        if self.assertions != tuple(sorted(self.assertions, key=lambda item: item.assertion_id)):
            raise ValueError("documentation assertions are not deterministic")
        if self.skipped_sources != tuple(
            sorted(self.skipped_sources, key=lambda item: (item.source_id, item.reason.value))
        ):
            raise ValueError("documentation source skips are not deterministic")
        if (
            isinstance(self.sources_considered, bool)
            or not isinstance(self.sources_considered, int)
            or self.sources_considered < 0
            or isinstance(self.sources_eligible, bool)
            or not isinstance(self.sources_eligible, int)
            or not 0 <= self.sources_eligible <= self.sources_considered
        ):
            raise ValueError("documentation extraction counts are invalid")


def _value_identity(value: DocumentationAssertionValue) -> tuple[object, ...]:
    if isinstance(value, DocumentedServiceBaseURL):
        return (value.canonical_url,)
    if isinstance(value, DocumentedHttpOperation):
        return value.method, value.route
    if isinstance(value, DocumentedRequiredHeader):
        return (value.header_name,)
    if isinstance(value, DocumentedAuthentication):
        return (value.scheme.value,)
    if isinstance(value, DocumentedOAuthScope):
        return (value.scope,)
    if isinstance(value, DocumentedRealtimeEndpoint):
        return (value.canonical_url,)
    raise TypeError("unsupported documentation assertion value")


def _assertion_id(
    kind: DocumentationAssertionKind,
    value: DocumentationAssertionValue,
) -> str:
    return _semantic_id("DOC-ASSERTION", kind, *_value_identity(value))


@dataclass(frozen=True)
class _TextSpan:
    text: str
    start: int
    end: int


@dataclass
class _Element:
    element_id: int
    tag: str
    parent_id: int | None
    attrs: dict[str, str]
    excluded: bool
    children: list[int] = field(default_factory=list)
    text_spans: list[_TextSpan] = field(default_factory=list)


class _DocumentationHTMLParser(HTMLParser):
    def __init__(self, decoded_source: str) -> None:
        super().__init__(convert_charrefs=False)
        self.decoded_source = decoded_source
        self.line_starts = [0]
        self.line_starts.extend(
            index + 1 for index, char in enumerate(decoded_source) if char == "\n"
        )
        self.elements: list[_Element] = []
        self.stack: list[int] = []

    def _offset(self) -> int:
        line, column = self.getpos()
        if line < 1 or line > len(self.line_starts):
            raise ValueError("HTML parser position is outside decoded source")
        return self.line_starts[line - 1] + column

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, self_closing=False)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, self_closing=True)

    def _start(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
        *,
        self_closing: bool,
    ) -> None:
        tag_name = tag.lower()
        attributes = {
            name.lower(): value or ""
            for name, value in attrs
            if isinstance(name, str) and name
        }
        parent_id = self.stack[-1] if self.stack else None
        parent_excluded = (
            self.elements[parent_id].excluded if parent_id is not None else False
        )
        element = _Element(
            element_id=len(self.elements),
            tag=tag_name,
            parent_id=parent_id,
            attrs=attributes,
            excluded=parent_excluded
            or tag_name in EXCLUDED_TAGS
            or _attributes_hide(attributes),
        )
        self.elements.append(element)
        if parent_id is not None:
            self.elements[parent_id].children.append(element.element_id)
        if not self_closing:
            self.stack.append(element.element_id)

    def handle_endtag(self, tag: str) -> None:
        tag_name = tag.lower()
        for index in range(len(self.stack) - 1, -1, -1):
            if self.elements[self.stack[index]].tag == tag_name:
                del self.stack[index:]
                return

    def handle_data(self, data: str) -> None:
        if not self.stack or not data:
            return
        start = self._offset()
        end = start + len(data)
        if self.decoded_source[start:end] != data:
            return
        self.elements[self.stack[-1]].text_spans.append(
            _TextSpan(text=data, start=start, end=end)
        )


def _attributes_hide(attrs: dict[str, str]) -> bool:
    if "hidden" in attrs or attrs.get("aria-hidden", "").strip().lower() == "true":
        return True
    style = re.sub(r"\s+", "", attrs.get("style", "").lower())
    return "display:none" in style or "visibility:hidden" in style


def _normalised_text(element: _Element) -> str:
    return " ".join(
        unescape("".join(span.text for span in element.text_spans)).split()
    )


def _single_value_span(element: _Element) -> _TextSpan | None:
    non_blank = [span for span in element.text_spans if span.text.strip()]
    if len(non_blank) != 1:
        return None
    span = non_blank[0]
    stripped = span.text.strip()
    if not stripped or len(stripped) > MAXIMUM_MATCHED_EXCERPT_CHARS:
        return None
    leading = len(span.text) - len(span.text.lstrip())
    start = span.start + leading
    end = start + len(stripped)
    if span.text[leading : leading + len(stripped)] != stripped:
        return None
    return _TextSpan(stripped, start, end)


def _line_number(decoded: str, offset: int) -> int:
    return decoded.count("\n", 0, offset) + 1


def _source_id(item: DeepSourceRouteCollectedItem) -> str:
    return _semantic_id(
        "DOC-SOURCE",
        DocumentationSourceOwnerKind.DEEP_SOURCE_ROUTE_COLLECTED_ITEM,
        str(item.method).upper(),
        item.url,
        item.final_url,
        item.status_code,
        str(item.body_sha256).lower(),
    )


def _media_type(item: DeepSourceRouteCollectedItem) -> str:
    values = tuple(
        sorted(
            value.split(";", 1)[0].strip().lower()
            for name, value in item.headers
            if isinstance(name, str)
            and isinstance(value, str)
            and name.strip().lower() == "content-type"
        )
    )
    return values[0] if values else ""


def _eligibility_reason(
    item: DeepSourceRouteCollectedItem,
) -> tuple[DocumentationSourceSkipReason | None, tuple[str, ...], str]:
    if not isinstance(item.body, bytes) or not item.body:
        return DocumentationSourceSkipReason.MISSING_BODY, (), _media_type(item)
    if sha256(item.body).hexdigest() != str(item.body_sha256).lower():
        return DocumentationSourceSkipReason.BODY_HASH_MISMATCH, (), _media_type(item)
    if (
        isinstance(item.body_bytes, bool)
        or not isinstance(item.body_bytes, int)
        or len(item.body) != item.body_bytes
    ):
        return DocumentationSourceSkipReason.BODY_LENGTH_MISMATCH, (), _media_type(item)
    evidence_ids = _normalise_evidence_ids(item.evidence_ids)
    if not evidence_ids:
        return DocumentationSourceSkipReason.MISSING_EVIDENCE, (), _media_type(item)
    if (
        isinstance(item.status_code, bool)
        or not isinstance(item.status_code, int)
        or not 200 <= item.status_code <= 299
    ):
        return DocumentationSourceSkipReason.NON_SUCCESS_STATUS, evidence_ids, _media_type(item)
    media_type = _media_type(item)
    if media_type not in ELIGIBLE_MEDIA_TYPES:
        return DocumentationSourceSkipReason.UNSUPPORTED_MEDIA_TYPE, evidence_ids, media_type
    return None, evidence_ids, media_type


def _source_reference(
    item: DeepSourceRouteCollectedItem,
    evidence_ids: tuple[str, ...],
    media_type: str,
) -> DocumentationAssertionSourceReference:
    return DocumentationAssertionSourceReference(
        owner_kind=DocumentationSourceOwnerKind.DEEP_SOURCE_ROUTE_COLLECTED_ITEM,
        source_id=_source_id(item),
        request_url=item.url,
        final_url=item.final_url,
        method=item.method.upper(),
        status_code=item.status_code,
        body_sha256=item.body_sha256.lower(),
        body_bytes=item.body_bytes,
        evidence_ids=evidence_ids,
        media_type=media_type,
    )


def _skip(
    item: DeepSourceRouteCollectedItem,
    reason: DocumentationSourceSkipReason,
) -> DocumentationSourceSkip:
    return DocumentationSourceSkip(
        source_id=_source_id(item),
        request_url=str(item.url),
        body_sha256=str(item.body_sha256).lower(),
        evidence_ids=_normalise_evidence_ids(item.evidence_ids),
        reason=reason,
    )


@dataclass(frozen=True)
class _Contribution:
    kind: DocumentationAssertionKind
    value: DocumentationAssertionValue
    support: DocumentationAssertionSupport


def _support(
    source: DocumentationAssertionSourceReference,
    context: DocumentationStructuralContext,
    span: _TextSpan,
    decoded: str,
    locator: str,
) -> DocumentationAssertionSupport | None:
    if (
        not span.text
        or len(span.text) > MAXIMUM_MATCHED_EXCERPT_CHARS
        or decoded[span.start : span.end] != span.text
    ):
        return None
    locator = locator[:MAXIMUM_STRUCTURAL_LOCATOR_CHARS]
    if not locator:
        return None
    return DocumentationAssertionSupport(
        source_reference=source,
        structural_context=context,
        start_offset=span.start,
        end_offset=span.end,
        line_number=_line_number(decoded, span.start),
        structural_locator=locator,
        matched_excerpt=span.text,
    )


def _service_label(label: str) -> bool:
    words = set(re.findall(r"[a-z]+", label.lower()))
    return bool(words & {"api", "service"}) and bool(words & {"base", "root"}) and bool(
        words & {"url", "uri"}
    )


def _operation_label(label: str) -> bool:
    words = set(re.findall(r"[a-z]+", label.lower()))
    return bool(words & {"operation", "request"})


def _realtime_label(label: str) -> bool:
    words = set(re.findall(r"[a-z]+", label.lower()))
    return bool(words & {"websocket", "realtime"}) and bool(words & {"endpoint", "url"})


def _authentication_label(label: str) -> bool:
    words = set(re.findall(r"[a-z]+", label.lower()))
    return bool(words & {"authentication", "security"}) and bool(
        words & {"scheme", "required"}
    )


def _oauth_scope_label(label: str) -> bool:
    words = set(re.findall(r"[a-z]+", label.lower()))
    return "scope" in words and bool(words & {"oauth", "security"})


def _required_header_label(label: str) -> bool:
    words = set(re.findall(r"[a-z]+", label.lower()))
    return "header" in words and "required" in words


def _operation_value(text: str) -> tuple[DocumentedHttpOperation, tuple[int, int]] | None:
    matches = tuple(_REQUEST_LINE_RE.finditer(text))
    if len(matches) != 1:
        return None
    match = matches[0]
    method, route = match.group(1), match.group(2)
    try:
        value = DocumentedHttpOperation(method=method, route=route)
    except ValueError:
        return None
    return value, (match.start(1), match.end(2))


def _service_value(text: str) -> tuple[DocumentedServiceBaseURL, tuple[int, int]] | None:
    matches = tuple(_HTTP_URL_RE.finditer(text))
    if len(matches) != 1:
        return None
    match = matches[0]
    canonical = _canonical_http_url(match.group())
    if canonical is None:
        return None
    return DocumentedServiceBaseURL(canonical[0], canonical[1]), match.span()


def _realtime_value(text: str) -> tuple[DocumentedRealtimeEndpoint, tuple[int, int]] | None:
    matches = tuple(_REALTIME_URL_RE.finditer(text))
    if len(matches) != 1:
        return None
    match = matches[0]
    canonical = _canonical_realtime_url(match.group())
    if canonical is None:
        return None
    return DocumentedRealtimeEndpoint(*canonical), match.span()


def _span_slice(span: _TextSpan, relative: tuple[int, int]) -> _TextSpan:
    start, end = relative
    return _TextSpan(span.text[start:end], span.start + start, span.start + end)


def _contribution_for_label_value(
    *,
    label: str,
    value_span: _TextSpan,
    context: DocumentationStructuralContext,
    source: DocumentationAssertionSourceReference,
    decoded: str,
    locator: str,
) -> tuple[_Contribution, ...]:
    candidates: list[tuple[DocumentationAssertionKind, DocumentationAssertionValue, tuple[int, int]]] = []
    if _service_label(label):
        parsed = _service_value(value_span.text)
        if parsed is not None:
            candidates.append((DocumentationAssertionKind.SERVICE_BASE_URL, *parsed))
    if _operation_label(label):
        parsed = _operation_value(value_span.text)
        if parsed is not None:
            candidates.append((DocumentationAssertionKind.HTTP_OPERATION, *parsed))
    if _realtime_label(label):
        parsed = _realtime_value(value_span.text)
        if parsed is not None:
            candidates.append((DocumentationAssertionKind.REALTIME_ENDPOINT, *parsed))
    if context is not DocumentationStructuralContext.LABELLED_CODE_BLOCK:
        value_text = value_span.text.strip()
        relative_start = len(value_span.text) - len(value_span.text.lstrip())
        relative = (relative_start, relative_start + len(value_text))
        if _authentication_label(label) and value_text.lower() == "bearer":
            candidates.append(
                (
                    DocumentationAssertionKind.AUTHENTICATION_SCHEME,
                    DocumentedAuthentication(DocumentationAuthenticationScheme.BEARER),
                    relative,
                )
            )
        if _oauth_scope_label(label) and _SCOPE_RE.fullmatch(value_text):
            candidates.append(
                (
                    DocumentationAssertionKind.OAUTH_SCOPE,
                    DocumentedOAuthScope(value_text),
                    relative,
                )
            )
        if _required_header_label(label) and _HEADER_NAME_RE.fullmatch(value_text):
            candidates.append(
                (
                    DocumentationAssertionKind.REQUIRED_HEADER,
                    DocumentedRequiredHeader(value_text.lower()),
                    relative,
                )
            )
    contributions: list[_Contribution] = []
    for kind, value, relative in candidates:
        exact_span = _span_slice(value_span, relative)
        support = _support(source, context, exact_span, decoded, locator)
        if support is not None:
            contributions.append(_Contribution(kind, value, support))
    return tuple(contributions)


def _labelled_code_contributions(
    parser: _DocumentationHTMLParser,
    source: DocumentationAssertionSourceReference,
) -> tuple[_Contribution, ...]:
    contributions: list[_Contribution] = []
    headings = {"h1", "h2", "h3", "h4", "h5", "h6"}
    for parent in parser.elements:
        children = [parser.elements[item] for item in parent.children]
        for label_element, value_element in zip(children, children[1:]):
            if (
                label_element.excluded
                or value_element.excluded
                or label_element.tag not in headings
                or value_element.tag not in {"pre", "code"}
            ):
                continue
            label = _normalised_text(label_element)
            span = _single_value_span(value_element)
            if not label or span is None:
                continue
            contributions.extend(
                _contribution_for_label_value(
                    label=label,
                    value_span=span,
                    context=DocumentationStructuralContext.LABELLED_CODE_BLOCK,
                    source=source,
                    decoded=parser.decoded_source,
                    locator=(
                        f"html/{parent.tag}[{parent.element_id}]/"
                        f"{label_element.tag}[{label_element.element_id}]+"
                        f"{value_element.tag}[{value_element.element_id}]"
                    ),
                )
            )
    return tuple(contributions)


def _definition_contributions(
    parser: _DocumentationHTMLParser,
    source: DocumentationAssertionSourceReference,
) -> tuple[_Contribution, ...]:
    contributions: list[_Contribution] = []
    for definition_list in parser.elements:
        if definition_list.tag != "dl" or definition_list.excluded:
            continue
        children = [parser.elements[item] for item in definition_list.children]
        for label_element, value_element in zip(children, children[1:]):
            if (
                label_element.tag != "dt"
                or value_element.tag != "dd"
                or label_element.excluded
                or value_element.excluded
            ):
                continue
            label = _normalised_text(label_element)
            span = _single_value_span(value_element)
            if not label or span is None:
                continue
            contributions.extend(
                _contribution_for_label_value(
                    label=label,
                    value_span=span,
                    context=DocumentationStructuralContext.DEFINITION_PAIR,
                    source=source,
                    decoded=parser.decoded_source,
                    locator=(
                        f"html/dl[{definition_list.element_id}]/"
                        f"dt[{label_element.element_id}]+dd[{value_element.element_id}]"
                    ),
                )
            )
    return tuple(contributions)


def _row_cells(parser: _DocumentationHTMLParser, row: _Element) -> tuple[_Element, ...]:
    return tuple(
        parser.elements[item]
        for item in row.children
        if parser.elements[item].tag in {"th", "td"}
        and not parser.elements[item].excluded
    )


def _table_contributions(
    parser: _DocumentationHTMLParser,
    source: DocumentationAssertionSourceReference,
) -> tuple[_Contribution, ...]:
    contributions: list[_Contribution] = []
    for table in parser.elements:
        if table.tag != "table" or table.excluded:
            continue
        rows = [
            element
            for element in parser.elements
            if element.tag == "tr"
            and not element.excluded
            and _nearest_ancestor(parser, element, "table") == table.element_id
        ]
        if not rows:
            continue
        header_cells = _row_cells(parser, rows[0])
        if not header_cells or not all(cell.tag == "th" for cell in header_cells):
            continue
        headers = tuple(_normalised_text(cell).lower() for cell in header_cells)
        for row in rows[1:]:
            cells = _row_cells(parser, row)
            if not cells or len(cells) != len(headers):
                continue
            spans = tuple(_single_value_span(cell) for cell in cells)
            if any(span is None for span in spans):
                continue
            values = tuple(span.text.strip() for span in spans if span is not None)
            locator = f"html/table[{table.element_id}]/tr[{row.element_id}]"
            contributions.extend(
                _contributions_from_table_row(
                    headers,
                    values,
                    tuple(span for span in spans if span is not None),
                    source,
                    parser.decoded_source,
                    locator,
                )
            )
    return tuple(contributions)


def _nearest_ancestor(
    parser: _DocumentationHTMLParser,
    element: _Element,
    tag: str,
) -> int | None:
    parent_id = element.parent_id
    while parent_id is not None:
        parent = parser.elements[parent_id]
        if parent.tag == tag:
            return parent_id
        parent_id = parent.parent_id
    return None


def _header_index(headers: tuple[str, ...], predicate) -> int | None:
    for index, header in enumerate(headers):
        if predicate(header):
            return index
    return None


def _table_header_words(value: str) -> frozenset[str]:
    return frozenset(re.findall(r"[a-z]+", value.lower()))


def _contributions_from_table_row(
    headers: tuple[str, ...],
    values: tuple[str, ...],
    spans: tuple[_TextSpan, ...],
    source: DocumentationAssertionSourceReference,
    decoded: str,
    locator: str,
) -> tuple[_Contribution, ...]:
    contributions: list[_Contribution] = []
    context = DocumentationStructuralContext.TABLE_ROW

    def add_value(
        kind: DocumentationAssertionKind,
        value: DocumentationAssertionValue,
        span: _TextSpan,
    ) -> None:
        support = _support(source, context, span, decoded, locator)
        if support is not None:
            contributions.append(_Contribution(kind, value, support))

    if len(headers) == 1:
        contributions.extend(
            _contribution_for_label_value(
                label=headers[0],
                value_span=spans[0],
                context=context,
                source=source,
                decoded=decoded,
                locator=locator,
            )
        )

    method_index = _header_index(headers, lambda value: "method" in value)
    route_index = _header_index(
        headers,
        lambda value: any(token in value for token in ("route", "path", "endpoint")),
    )
    if method_index is not None and route_index is not None:
        method, route = values[method_index].upper(), values[route_index]
        if method in HTTP_METHODS:
            try:
                operation = DocumentedHttpOperation(method, route)
            except ValueError:
                pass
            else:
                start = spans[method_index].start
                end = spans[route_index].end
                if start <= end and end - start <= MAXIMUM_MATCHED_EXCERPT_CHARS:
                    exact = _TextSpan(decoded[start:end], start, end)
                    support = _support(source, context, exact, decoded, locator)
                    if support is not None:
                        contributions.append(
                            _Contribution(
                                DocumentationAssertionKind.HTTP_OPERATION,
                                operation,
                                support,
                            )
                        )

    header_index = _header_index(headers, lambda value: "header" in value)
    required_index = _header_index(headers, lambda value: "required" in value)
    if header_index is not None and required_index is not None:
        header_name = values[header_index]
        required = values[required_index].strip().lower()
        if _HEADER_NAME_RE.fullmatch(header_name) and required in _AFFIRMATIVE_REQUIRED:
            support = _support(
                source,
                context,
                spans[header_index],
                decoded,
                locator,
            )
            if support is not None:
                contributions.append(
                    _Contribution(
                        DocumentationAssertionKind.REQUIRED_HEADER,
                        DocumentedRequiredHeader(header_name.lower()),
                        support,
                    )
                )

    service_index = _header_index(
        headers,
        lambda value: bool(_table_header_words(value) & {"service", "api"}),
    )
    base_url_index = _header_index(
        headers,
        lambda value: bool(_table_header_words(value) & {"base", "root"})
        and bool(_table_header_words(value) & {"url", "uri"}),
    )
    if (
        service_index is not None
        and base_url_index is not None
        and service_index != base_url_index
    ):
        parsed = _service_value(values[base_url_index])
        if parsed is not None:
            service_base, relative = parsed
            add_value(
                DocumentationAssertionKind.SERVICE_BASE_URL,
                service_base,
                _span_slice(spans[base_url_index], relative),
            )

    authentication_index = _header_index(
        headers,
        lambda value: bool(
            _table_header_words(value) & {"authentication", "security"}
        ),
    )
    scheme_index = _header_index(
        headers,
        lambda value: "scheme" in _table_header_words(value),
    )
    if (
        authentication_index is not None
        and scheme_index is not None
        and authentication_index != scheme_index
        and values[authentication_index].strip().lower() in _AFFIRMATIVE_REQUIRED
        and values[scheme_index].strip().lower()
        == DocumentationAuthenticationScheme.BEARER.value
    ):
        add_value(
            DocumentationAssertionKind.AUTHENTICATION_SCHEME,
            DocumentedAuthentication(DocumentationAuthenticationScheme.BEARER),
            spans[scheme_index],
        )

    oauth_scope_index = _header_index(
        headers,
        lambda value: {"oauth", "scope"}.issubset(_table_header_words(value)),
    )
    if (
        authentication_index is not None
        and oauth_scope_index is not None
        and authentication_index != oauth_scope_index
        and values[authentication_index].strip().lower() in _AFFIRMATIVE_REQUIRED
        and _SCOPE_RE.fullmatch(values[oauth_scope_index])
    ):
        add_value(
            DocumentationAssertionKind.OAUTH_SCOPE,
            DocumentedOAuthScope(values[oauth_scope_index]),
            spans[oauth_scope_index],
        )

    protocol_index = _header_index(
        headers,
        lambda value: "protocol" in _table_header_words(value),
    )
    realtime_endpoint_index = _header_index(
        headers,
        lambda value: bool(
            _table_header_words(value) & {"websocket", "realtime"}
        )
        and bool(_table_header_words(value) & {"endpoint", "url"}),
    )
    if (
        protocol_index is not None
        and realtime_endpoint_index is not None
        and protocol_index != realtime_endpoint_index
        and " ".join(values[protocol_index].strip().lower().split())
        in {"websocket", "web socket", "realtime"}
    ):
        parsed = _realtime_value(values[realtime_endpoint_index])
        if parsed is not None:
            realtime_endpoint, relative = parsed
            add_value(
                DocumentationAssertionKind.REALTIME_ENDPOINT,
                realtime_endpoint,
                _span_slice(spans[realtime_endpoint_index], relative),
            )

    return tuple(contributions)


def _parse_contributions(
    item: DeepSourceRouteCollectedItem,
    source: DocumentationAssertionSourceReference,
) -> tuple[_Contribution, ...]:
    decoded = item.body.decode("utf-8", errors="replace")
    parser = _DocumentationHTMLParser(decoded)
    try:
        parser.feed(decoded)
        parser.close()
    except Exception:
        return ()
    return (
        *_labelled_code_contributions(parser, source),
        *_definition_contributions(parser, source),
        *_table_contributions(parser, source),
    )


def build_documentation_assertions(
    source_collection: DeepSourceRouteCollectionResult,
) -> DocumentationAssertionExtractionResult:
    """Extract bounded direct-documentation assertions without performing I/O."""

    if not isinstance(source_collection, DeepSourceRouteCollectionResult):
        raise ValueError("documentation assertions require a typed source collection")

    contributions: dict[
        str,
        tuple[DocumentationAssertionKind, DocumentationAssertionValue, set[DocumentationAssertionSupport]],
    ] = {}
    skipped: list[DocumentationSourceSkip] = []
    eligible = 0
    ordered_items = tuple(sorted(source_collection.collected, key=_source_id))
    for item in ordered_items:
        if not isinstance(item, DeepSourceRouteCollectedItem):
            raise ValueError("documentation source collection contains an invalid item")
        reason, evidence_ids, media_type = _eligibility_reason(item)
        if reason is not None:
            skipped.append(_skip(item, reason))
            continue
        eligible += 1
        source = _source_reference(item, evidence_ids, media_type)
        for contribution in _parse_contributions(item, source):
            assertion_id = _assertion_id(contribution.kind, contribution.value)
            existing = contributions.get(assertion_id)
            if existing is None:
                contributions[assertion_id] = (
                    contribution.kind,
                    contribution.value,
                    {contribution.support},
                )
                continue
            kind, value, supports = existing
            if kind is not contribution.kind or value != contribution.value:
                raise ValueError("documentation assertion identity collision")
            supports.add(contribution.support)

    assertions = tuple(
        DocumentationAssertion(
            assertion_id=assertion_id,
            kind=kind,
            value=value,
            supports=tuple(supports),
        )
        for assertion_id, (kind, value, supports) in sorted(contributions.items())
    )
    return DocumentationAssertionExtractionResult(
        assertions=assertions,
        skipped_sources=tuple(
            sorted(skipped, key=lambda item: (item.source_id, item.reason.value))
        ),
        sources_considered=len(source_collection.collected),
        sources_eligible=eligible,
    )
