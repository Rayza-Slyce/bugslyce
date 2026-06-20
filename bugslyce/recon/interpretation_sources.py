"""Map existing project evidence into offline interpretation sources."""

from __future__ import annotations

from urllib.parse import urlparse

from bugslyce.core.models import Evidence, HTTPArtifact, ProjectState
from bugslyce.recon.artefact_analysis import ArtefactSource


DEFAULT_MAX_SOURCE_CHARS = 12_000

ROBOTS_ARTIFACT_TYPES = {
    "robots",
    "user_agent",
    "unusual_user_agent",
    "allow_rule",
    "disallow_rule",
}
HTML_ARTIFACT_TYPES = {
    "page_title",
    "html_comment",
    "hidden_element",
    "form",
    "input",
    "link",
    "script_or_asset",
    "keyword_hit",
    "encoded_like_artifact",
}
GENERIC_TEXT_ARTIFACT_TYPES = {
    "response_body",
    "body",
    "html_body",
    "text_body",
    "json_body",
    "xml_body",
}
HTML_MARKERS = ("<html", "<!--", "<body", "<script", "<form", "<a ", "<div", "<input")


def artefact_sources_from_project_state(
    project_state: ProjectState,
    *,
    max_source_chars: int = DEFAULT_MAX_SOURCE_CHARS,
) -> tuple[ArtefactSource, ...]:
    """Create offline interpretation sources from already-assembled project state."""

    sources: list[ArtefactSource] = []
    for index, artifact in enumerate(project_state.http_artifacts, start=1):
        source = _source_from_http_artifact(artifact, index, max_source_chars)
        if source is not None:
            sources.append(source)

    note_index = 0
    for evidence in project_state.evidence:
        if evidence.evidence_type != "note":
            continue
        note_index += 1
        source = _source_from_note_evidence(evidence, note_index, max_source_chars)
        if source is not None:
            sources.append(source)

    return _dedupe_sources(sources)


def _source_from_http_artifact(
    artifact: HTTPArtifact,
    index: int,
    max_source_chars: int,
) -> ArtefactSource | None:
    if not artifact.value.strip():
        return None
    text = _bounded_text(_source_text_for_artifact(artifact), max_source_chars)
    if not text:
        return None
    source_kind = _infer_source_kind(artifact)
    if source_kind is None:
        return None
    parsed = urlparse(artifact.url)
    source_id = artifact.evidence_ids[0] if artifact.evidence_ids else f"HTTP-ART-SRC-{index:04d}"
    return ArtefactSource(
        source_id=source_id,
        source_kind=source_kind,
        source_label=_source_label(artifact),
        url=artifact.url or None,
        path=artifact.source_file or None,
        port=parsed.port or _default_port(parsed.scheme),
        service=parsed.scheme or None,
        field_name=artifact.artifact_type,
        text=text,
    )


def _source_from_note_evidence(
    evidence: Evidence,
    index: int,
    max_source_chars: int,
) -> ArtefactSource | None:
    text = _bounded_text(evidence.value, max_source_chars)
    if not text:
        return None
    return ArtefactSource(
        source_id=evidence.id or f"NOTE-SRC-{index:04d}",
        source_kind="notes",
        source_label=evidence.source_file or "operator note",
        url=None,
        path=evidence.source_file or None,
        port=None,
        service=None,
        field_name=evidence.evidence_type,
        text=text,
    )


def _infer_source_kind(artifact: HTTPArtifact) -> str | None:
    artifact_type = artifact.artifact_type
    lowered_url = (artifact.url or "").lower().split("?", 1)[0].split("#", 1)[0]
    lowered_file = (artifact.source_file or "").lower()
    value = artifact.value

    if artifact_type in ROBOTS_ARTIFACT_TYPES or lowered_url.endswith("/robots.txt") or lowered_file.endswith("robots.txt"):
        return "robots_txt"
    if artifact_type in HTML_ARTIFACT_TYPES:
        return "html"
    if artifact_type in GENERIC_TEXT_ARTIFACT_TYPES:
        if _looks_html_like(value):
            return "html"
        return "response_body"
    if _looks_html_like(value):
        return "html"
    return None


def _source_text_for_artifact(artifact: HTTPArtifact) -> str:
    value = artifact.value
    if artifact.artifact_type == "user_agent" or artifact.artifact_type == "unusual_user_agent":
        return f"User-agent: {value}"
    if artifact.artifact_type == "allow_rule":
        return f"Allow: {value}"
    if artifact.artifact_type == "disallow_rule":
        return f"Disallow: {value}"
    if artifact.artifact_type == "html_comment":
        return f"<!-- {value} -->"
    if artifact.artifact_type == "hidden_element":
        return f"<div hidden>{value}</div>"
    if artifact.artifact_type == "form":
        return f'<form action="{value}"></form>'
    if artifact.artifact_type == "input":
        return f"<input {value}>"
    if artifact.artifact_type == "link":
        return f'<a href="{value}">{value}</a>'
    if artifact.artifact_type == "script_or_asset":
        return f'<script src="{value}"></script>'
    return value


def _bounded_text(value: str, max_source_chars: int) -> str:
    text = value.strip()
    if not text or _looks_binary(text):
        return ""
    if len(text) <= max_source_chars:
        return text
    if max_source_chars <= 3:
        return text[:max_source_chars]
    return text[: max_source_chars - 3].rstrip() + "..."


def _looks_binary(value: str) -> bool:
    if "\x00" in value:
        return True
    sample = value[:1024]
    if not sample:
        return False
    printable = sum(character.isprintable() or character in "\r\n\t" for character in sample)
    return printable / len(sample) < 0.85


def _looks_html_like(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in HTML_MARKERS)


def _source_label(artifact: HTTPArtifact) -> str:
    if artifact.url:
        return artifact.url
    if artifact.source_file:
        return artifact.source_file
    return artifact.artifact_type


def _default_port(scheme: str) -> int | None:
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None


def _dedupe_sources(sources: list[ArtefactSource]) -> tuple[ArtefactSource, ...]:
    deduped: list[ArtefactSource] = []
    seen: set[tuple[object, ...]] = set()
    for source in sources:
        key = (
            source.source_id,
            source.source_kind,
            source.source_label,
            source.url,
            source.path,
            source.field_name,
            source.text,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(source)
    return tuple(deduped)
