"""Bounded lexical context classification for retained JavaScript strings.

This module does not execute JavaScript, evaluate expressions, perform IO, or
claim that rejected strings identify nonexistent routes.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import re


REQUEST_CALL = "request_call"
ROUTE_CONFIGURATION = "route_configuration"
ORDINARY_LEXICAL_STRING = "ordinary_lexical_string"
FRAMEWORK_SERIALISED_STATE = "framework_serialised_state"
ACCEPTED_ROUTE_CONTEXTS = frozenset({REQUEST_CALL, ROUTE_CONFIGURATION})

_CONFIGURATION_IDENTIFIERS = frozenset(
    {
        "route",
        "routes",
        "path",
        "paths",
        "url",
        "urls",
        "uri",
        "uris",
        "endpoint",
        "endpoints",
        "apiurl",
        "baseurl",
        "endpointurl",
    }
)
_FRAMEWORK_CALL_RE = re.compile(
    r"\b(?:self|window|globalThis)\s*\.\s*__next_f\s*\.\s*push\s*\("
)
_FETCH_PREFIX_RE = re.compile(
    r"(?:"
    r"(?<![\w$.])fetch"
    r"|(?<![\w$.])(?:window|globalThis)\s*\.\s*fetch"
    r")\s*\(\s*$"
)
_XHR_OPEN_PREFIX_RE = re.compile(
    r"(?<![\w$.])(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*open\s*\(\s*$"
)
_DIRECT_ASSIGNMENT_RE = re.compile(
    r"(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*$"
)
_PROPERTY_ASSIGNMENT_RE = re.compile(
    r"(?:^|[{,])\s*(?:([A-Za-z_$][\w$]*)|[\"']([A-Za-z_$][\w$]*)[\"'])\s*:\s*$"
)
_CONFIGURATION_CONTAINER_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([\[{])"
)


@dataclass(frozen=True)
class JavaScriptSemanticLiteral:
    """One complete lexical string and its deterministic source context."""

    value: str
    start_offset: int
    end_offset: int
    semantic_context: str = ORDINARY_LEXICAL_STRING
    dynamic_template: bool = False
    malformed: bool = False
    dynamic_concatenation: bool = False


def scan_javascript_semantic_literals(
    source: str,
) -> tuple[JavaScriptSemanticLiteral, ...]:
    """Scan complete literals and classify their bounded syntactic context."""

    literals = _scan_literals(source)
    code_view = _executable_code_view(source, literals)
    literals = tuple(
        replace(
            literal,
            dynamic_concatenation=_is_concatenated(
                code_view,
                literal.start_offset,
                literal.end_offset,
            ),
        )
        for literal in literals
    )
    framework_ranges = _framework_call_ranges(code_view)
    configuration_ranges = _configuration_container_ranges(code_view)
    return tuple(
        replace(
            literal,
            semantic_context=_semantic_context(
                code_view,
                literal,
                framework_ranges,
                configuration_ranges,
                literals,
            ),
        )
        for literal in literals
    )


def _semantic_context(
    code_view: str,
    literal: JavaScriptSemanticLiteral,
    framework_ranges: tuple[tuple[int, int], ...],
    configuration_ranges: tuple[tuple[int, int], ...],
    literals: tuple[JavaScriptSemanticLiteral, ...],
) -> str:
    if any(start < literal.start_offset < end for start, end in framework_ranges):
        return FRAMEWORK_SERIALISED_STATE
    prefix = code_view[max(0, literal.start_offset - 320) : literal.start_offset]
    if _FETCH_PREFIX_RE.search(prefix) or _is_xml_http_request_open_argument(
        code_view,
        literal,
        literals,
    ):
        return REQUEST_CALL
    if any(start < literal.start_offset < end for start, end in configuration_ranges):
        return ROUTE_CONFIGURATION
    identifier = _direct_configuration_identifier(code_view, literal, literals)
    if identifier is not None and _normalise_identifier(identifier) in _CONFIGURATION_IDENTIFIERS:
        return ROUTE_CONFIGURATION
    return ORDINARY_LEXICAL_STRING


def _direct_configuration_identifier(
    code_view: str,
    literal: JavaScriptSemanticLiteral,
    literals: tuple[JavaScriptSemanticLiteral, ...],
) -> str | None:
    prefix = code_view[max(0, literal.start_offset - 320) : literal.start_offset]
    assignment = _DIRECT_ASSIGNMENT_RE.search(prefix)
    if assignment is not None:
        return assignment.group(1)
    property_assignment = _PROPERTY_ASSIGNMENT_RE.search(prefix)
    if property_assignment is not None:
        return property_assignment.group(1) or property_assignment.group(2)
    literal_index = _literal_index(literal, literals)
    if literal_index == 0:
        return None
    property_key = literals[literal_index - 1]
    between = code_view[property_key.end_offset : literal.start_offset]
    before_key = code_view[max(0, property_key.start_offset - 320) : property_key.start_offset]
    if (
        not property_key.dynamic_template
        and not property_key.malformed
        and not property_key.dynamic_concatenation
        and re.fullmatch(r"\s*:\s*", between)
        and re.search(r"(?:^|[{,])\s*$", before_key)
    ):
        return property_key.value
    return None


def _normalise_identifier(value: str) -> str:
    return value.replace("_", "").lower()


def _framework_call_ranges(
    code_view: str,
) -> tuple[tuple[int, int], ...]:
    ranges = []
    for match in _FRAMEWORK_CALL_RE.finditer(code_view):
        opening = match.end() - 1
        closing = _balanced_delimiter_end(code_view, opening, "(", ")")
        if closing is not None:
            ranges.append((opening, closing))
    return tuple(ranges)


def _configuration_container_ranges(
    code_view: str,
) -> tuple[tuple[int, int], ...]:
    ranges = []
    for match in _CONFIGURATION_CONTAINER_RE.finditer(code_view):
        if _normalise_identifier(match.group(1)) not in _CONFIGURATION_IDENTIFIERS:
            continue
        opening = match.end() - 1
        opening_char = match.group(2)
        closing_char = "]" if opening_char == "[" else "}"
        closing = _balanced_delimiter_end(
            code_view,
            opening,
            opening_char,
            closing_char,
        )
        if closing is not None:
            ranges.append((opening, closing))
    return tuple(ranges)


def _balanced_delimiter_end(
    code_view: str,
    opening: int,
    opening_char: str,
    closing_char: str,
) -> int | None:
    depth = 0
    index = opening
    while index < len(code_view):
        char = code_view[index]
        if char == opening_char:
            depth += 1
        elif char == closing_char:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return None


def _is_xml_http_request_open_argument(
    code_view: str,
    literal: JavaScriptSemanticLiteral,
    literals: tuple[JavaScriptSemanticLiteral, ...],
) -> bool:
    """Return whether ``literal`` is a static URL argument on a known XHR."""

    literal_index = _literal_index(literal, literals)
    if literal_index == 0:
        return False
    method_literal = literals[literal_index - 1]
    if (
        method_literal.dynamic_template
        or method_literal.malformed
        or method_literal.dynamic_concatenation
    ):
        return False
    between = code_view[method_literal.end_offset : literal.start_offset]
    if re.fullmatch(r"\s*,\s*", between) is None:
        return False
    prefix = code_view[max(0, method_literal.start_offset - 320) : method_literal.start_offset]
    match = _XHR_OPEN_PREFIX_RE.search(prefix)
    if match is None:
        return False
    receiver = match.group("receiver")
    call_offset = method_literal.start_offset - len(prefix) + match.start("receiver")
    return _has_current_xml_http_request_binding(
        code_view,
        receiver,
        call_offset,
    )


def _has_current_xml_http_request_binding(
    code_view: str,
    receiver: str,
    call_offset: int,
) -> bool:
    """Prove one current direct XHR binding within the call's brace block."""

    call_block = _lexical_block_path(code_view, call_offset)
    escaped_receiver = re.escape(receiver)
    event_re = re.compile(
        rf"(?<![\w$.])(?:"
        rf"(?P<xhr_declaration>\b(?:const|let|var)\s+{escaped_receiver}(?![\w$])"
        rf"\s*=\s*new\s+XMLHttpRequest\s*\(\s*\))"
        rf"|(?P<assignment>{escaped_receiver}(?![\w$])\s*=(?!=))"
        rf")"
    )
    latest_kind: str | None = None
    for event in event_re.finditer(code_view[:call_offset]):
        if _lexical_block_path(code_view, event.start()) != call_block:
            continue
        latest_kind = "xhr_declaration" if event.group("xhr_declaration") else "assignment"
    return latest_kind == "xhr_declaration"


def _lexical_block_path(code_view: str, offset: int) -> tuple[int, ...]:
    """Return exact enclosing opening-brace offsets for ``offset``.

    ``code_view`` has already blanked literals, comments, and regex bodies, so
    only executable structural braces contribute to the path.
    """

    openings: list[int] = []
    for index, char in enumerate(code_view[:offset]):
        if char == "{":
            openings.append(index)
        elif char == "}" and openings:
            openings.pop()
    return tuple(openings)


def _literal_index(
    literal: JavaScriptSemanticLiteral,
    literals: tuple[JavaScriptSemanticLiteral, ...],
) -> int:
    for index, candidate in enumerate(literals):
        if candidate.start_offset == literal.start_offset:
            return index
    return -1


def _executable_code_view(
    source: str,
    literals: tuple[JavaScriptSemanticLiteral, ...],
) -> str:
    """Mask non-code text without changing source offsets.

    The scanner already establishes literal ranges.  This companion view keeps
    executable identifiers and punctuation while blanking literal, comment, and
    regex contents, so surrounding syntax cannot be supplied by non-code text.
    """

    chars = list(source)
    literals_by_start = {literal.start_offset: literal for literal in literals}
    index = 0
    while index < len(source):
        literal = literals_by_start.get(index)
        if literal is not None:
            _blank_code_range(chars, index, literal.end_offset)
            index = max(index + 1, literal.end_offset)
            continue
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if char == "/" and next_char == "/":
            end = _skip_line_comment(source, index + 2)
            _blank_code_range(chars, index, end)
            index = end
            continue
        if char == "/" and next_char == "*":
            end = _skip_block_comment(source, index + 2)
            _blank_code_range(chars, index, end)
            index = end
            continue
        if char == "/" and _looks_like_regex_start(source, index):
            end = _skip_regex_literal(source, index + 1)
            _blank_code_range(chars, index, end)
            index = end
            continue
        index += 1
    return "".join(chars)


def _blank_code_range(chars: list[str], start: int, end: int) -> None:
    for index in range(start, min(end, len(chars))):
        if chars[index] not in "\r\n":
            chars[index] = " "


def _scan_literals(source: str) -> tuple[JavaScriptSemanticLiteral, ...]:
    literals = []
    index = 0
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if char == "/" and next_char == "/":
            index = _skip_line_comment(source, index + 2)
            continue
        if char == "/" and next_char == "*":
            index = _skip_block_comment(source, index + 2)
            continue
        if char == "/" and _looks_like_regex_start(source, index):
            index = _skip_regex_literal(source, index + 1)
            continue
        if char in {"'", '"', "`"}:
            literal, index = _read_string_literal(source, index)
            literals.append(literal)
            continue
        index += 1
    return tuple(literals)


def _read_string_literal(
    source: str,
    start: int,
) -> tuple[JavaScriptSemanticLiteral, int]:
    quote_char = source[start]
    index = start + 1
    chars = []
    dynamic_template = False
    malformed = False
    while index < len(source):
        char = source[index]
        if quote_char == "`" and char == "$" and index + 1 < len(source) and source[index + 1] == "{":
            dynamic_template = True
        if char == quote_char:
            end = index + 1
            return (
                JavaScriptSemanticLiteral(
                    value="".join(chars),
                    start_offset=start,
                    end_offset=end,
                    dynamic_template=dynamic_template,
                    malformed=malformed,
                    dynamic_concatenation=_is_concatenated(source, start, end),
                ),
                end,
            )
        if char == "\\":
            decoded, index, bad = _decode_escape(source, index)
            malformed = malformed or bad
            chars.append(decoded)
            continue
        if quote_char != "`" and char in {"\n", "\r"}:
            end = index + 1
            return JavaScriptSemanticLiteral("", start, end, malformed=True), end
        chars.append(char)
        index += 1
    return JavaScriptSemanticLiteral("", start, len(source), malformed=True), len(source)


def _decode_escape(source: str, index: int) -> tuple[str, int, bool]:
    if index + 1 >= len(source):
        return "", index + 1, True
    char = source[index + 1]
    if char in {"\n", "\r"}:
        if char == "\r" and index + 2 < len(source) and source[index + 2] == "\n":
            return "", index + 3, True
        return "", index + 2, True
    simple = {
        "\\": "\\",
        "/": "/",
        "'": "'",
        '"': '"',
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "b": "\b",
        "f": "\f",
    }
    if char in simple:
        return simple[char], index + 2, False
    if char == "x":
        value = source[index + 2 : index + 4]
        if len(value) == 2 and _is_hex(value):
            return chr(int(value, 16)), index + 4, False
        return "", min(len(source), index + 4), True
    if char == "u":
        value = source[index + 2 : index + 6]
        if len(value) == 4 and _is_hex(value):
            return chr(int(value, 16)), index + 6, False
        return "", min(len(source), index + 6), True
    return "", index + 2, True


def _is_hex(value: str) -> bool:
    return bool(value) and all(char in "0123456789abcdefABCDEF" for char in value)


def _is_concatenated(source: str, start: int, end: int) -> bool:
    before = start - 1
    while before >= 0 and source[before].isspace():
        before -= 1
    after = end
    while after < len(source) and source[after].isspace():
        after += 1
    return (before >= 0 and source[before] == "+") or (
        after < len(source) and source[after] == "+"
    )


def _looks_like_regex_start(source: str, index: int) -> bool:
    before = index - 1
    while before >= 0 and source[before].isspace():
        before -= 1
    if before < 0 or source[before] in "([{=,:;!&|?":
        return True
    if source[before] == ">" and _previous_significant_char(source, before - 1) == "=":
        return True
    return _previous_identifier(source, before) in {
        "return",
        "throw",
        "case",
        "yield",
        "await",
    }


def _previous_significant_char(source: str, index: int) -> str:
    while index >= 0 and source[index].isspace():
        index -= 1
    return source[index] if index >= 0 else ""


def _previous_identifier(source: str, end: int) -> str:
    if end < 0 or not (source[end].isalnum() or source[end] in {"_", "$"}):
        return ""
    start = end
    while start >= 0 and (source[start].isalnum() or source[start] in {"_", "$"}):
        start -= 1
    return source[start + 1 : end + 1]


def _skip_line_comment(source: str, index: int) -> int:
    while index < len(source) and source[index] not in "\r\n":
        index += 1
    return index


def _skip_block_comment(source: str, index: int) -> int:
    end = source.find("*/", index)
    return len(source) if end == -1 else end + 2


def _skip_regex_literal(source: str, index: int) -> int:
    in_class = False
    escaped = False
    while index < len(source):
        char = source[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            index += 1
            while index < len(source) and source[index].isalpha():
                index += 1
            return index
        elif char in "\r\n":
            return index
        index += 1
    return index
