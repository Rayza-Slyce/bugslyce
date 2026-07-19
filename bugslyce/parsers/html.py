"""Metadata parser for saved HTML files."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import re
import warnings

from bugslyce.core.models import HTTPArtifact


KEYWORDS = {
    "hidden",
    "user-agent",
    "allow",
    "disallow",
    "login",
    "admin",
    "upload",
    "backup",
    "secret",
    "token",
    "key",
    "hash",
    "encode",
    "decode",
    "api",
    "account",
    "password",
    "reset",
    "redirect",
    "next",
    "file",
    "download",
}
BASE64_LIKE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
ABSOLUTE_HTTP_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
REFERENCE_ATTRIBUTE = re.compile(
    r"\b(?:href|src)\s*=\s*(?:\"(?P<double>[^\"]*)\"|'(?P<single>[^']*)'|(?P<bare>[^\s>]+))",
    re.IGNORECASE,
)


def parse_html(path: Path, url: str = "") -> list[HTTPArtifact]:
    """Extract compact metadata and artifact signals from saved HTML."""

    if not path.exists():
        warnings.warn(f"HTML file does not exist: {path}", RuntimeWarning, stacklevel=2)
        return []

    text = path.read_text(encoding="utf-8", errors="replace")
    parser = _ArtifactHTMLParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception as exc:
        warnings.warn(f"HTML parsing warning for {path}: {exc}", RuntimeWarning, stacklevel=2)

    values: list[tuple[str, str]] = []
    if parser.title.strip():
        values.append(("page_title", parser.title.strip()))
    values.extend(("link", value) for value in parser.links)
    values.extend(("script_or_asset", value) for value in parser.sources)
    values.extend(("html_comment", value) for value in parser.comments if value)
    values.extend(("hidden_element", value) for value in parser.hidden_elements)
    values.extend(("form", value) for value in parser.forms)
    values.extend(("input", value) for value in parser.inputs)

    searchable = "\n".join([text, *parser.comments])
    values.extend(
        ("keyword_hit", keyword)
        for keyword in sorted(KEYWORDS)
        if re.search(
            rf"(?<![A-Za-z0-9_-]){re.escape(keyword)}(?![A-Za-z0-9_-])",
            searchable,
            re.IGNORECASE,
        )
    )
    absolute_url_spans = tuple(match.span() for match in ABSOLUTE_HTTP_URL.finditer(searchable))
    reference_spans = _reference_attribute_value_spans(searchable)
    values.extend(
        ("encoded_like_artifact", match.group(0))
        for match in BASE64_LIKE.finditer(searchable)
        if not _span_within_any(match.span(), absolute_url_spans)
        and not _span_within_any(match.span(), reference_spans)
        and not _looks_like_url_or_path_fragment(match.group(0))
    )

    artifacts: list[HTTPArtifact] = []
    seen: set[tuple[str, str]] = set()
    for artifact_type, value in values:
        key = (artifact_type, value)
        if key in seen:
            continue
        seen.add(key)
        artifacts.append(
            HTTPArtifact(
                url=url,
                artifact_type=artifact_type,
                value=value,
                source_file=str(path),
                evidence_ids=[],
                tags=[],
            )
        )
    return artifacts


class _ArtifactHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.title_parts: list[str] = []
        self.links: list[str] = []
        self.sources: list[str] = []
        self.comments: list[str] = []
        self.hidden_elements: list[str] = []
        self.forms: list[str] = []
        self.inputs: list[str] = []

    @property
    def title(self) -> str:
        return " ".join(part.strip() for part in self.title_parts if part.strip())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() == "title":
            self.in_title = True
        if "href" in attributes:
            self.links.append(attributes["href"])
        if "src" in attributes:
            self.sources.append(attributes["src"])
        if tag.lower() == "form":
            self.forms.append(attributes.get("action", ""))
        if tag.lower() == "input":
            self.inputs.append(
                f"name={attributes.get('name', '')};type={attributes.get('type', 'text')}"
            )
        style = attributes.get("style", "").replace(" ", "").lower()
        classes = attributes.get("class", "").lower().split()
        if (
            "hidden" in attributes
            or attributes.get("type", "").lower() == "hidden"
            or "display:none" in style
            or "hidden" in classes
        ):
            identifier = attributes.get("id") or attributes.get("name") or tag
            self.hidden_elements.append(identifier)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)

    def handle_comment(self, data: str) -> None:
        self.comments.append(" ".join(data.split()))


def _looks_like_url_or_path_fragment(value: str) -> bool:
    lowered = value.lower()
    if "://" in lowered or lowered.startswith("//"):
        return True
    if "/" not in value:
        return False
    if any(char in value for char in "+="):
        return False
    parts = [part for part in value.strip("/").split("/") if part]
    return (
        len(parts) >= 3
        and all(re.fullmatch(r"[A-Za-z0-9._~-]+", part) for part in parts)
        and sum(bool(re.search(r"[a-z]", part)) for part in parts) >= 2
    )


def _span_within_any(
    candidate: tuple[int, int],
    containers: tuple[tuple[int, int], ...],
) -> bool:
    start, end = candidate
    return any(
        container_start <= start and end <= container_end
        for container_start, container_end in containers
    )


def _reference_attribute_value_spans(value: str) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    for match in REFERENCE_ATTRIBUTE.finditer(value):
        for group in ("double", "single", "bare"):
            if match.group(group) is not None:
                spans.append(match.span(group))
                break
    return tuple(spans)
