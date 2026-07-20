"""Offline HTML/source analysis for already-collected evidence."""

from __future__ import annotations

from dataclasses import dataclass
import re

from bugslyce.recon.artefact_analysis import (
    ArtefactSource,
    HashArtefactCandidate,
    TransformArtefactCandidate,
    find_hash_artefacts,
    find_transform_artefacts,
)


COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)
TAG_PATTERN = re.compile(r"<([A-Za-z][A-Za-z0-9:-]*)([^<>]*)>", re.DOTALL)
ATTR_PATTERN = re.compile(
    r"([A-Za-z_:][A-Za-z0-9_:\-\.]*)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s\"'=<>`]+)",
    re.DOTALL,
)
TEXT_PATTERN = re.compile(r">([^<>]{4,240})<", re.DOTALL)
HIDDEN_STYLE_PATTERNS = (
    "display:none",
    "display: none",
    "visibility:hidden",
    "visibility: hidden",
    "opacity:0",
    "opacity: 0",
)
SUSPICIOUS_WORDS = (
    "hidden",
    "secret",
    "flag",
    "password",
    "passwd",
    "token",
    "key",
    "clue",
    "admin",
    "debug",
    "dev",
    "test",
    "backup",
)
REFERENCE_ATTRS = {"href", "src", "action"}
UNUSUAL_LOCAL_SUFFIXES = (
    ".txt",
    ".bak",
    ".old",
    ".zip",
    ".tar",
    ".gz",
    ".sql",
    ".db",
    ".log",
    ".conf",
    ".json",
    ".xml",
    ".php~",
)
ORDINARY_REFERENCE_SUFFIXES = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
)
HTML_MANUAL_VALIDATION = (
    "Review the referenced source context manually.",
    "Treat hidden source content as a clue source, not proof of vulnerability.",
    "Validate possible encoded or hash-shaped artefacts locally.",
    "Review same-origin paths manually only when they are in scope.",
    "Do not brute force, submit forms, or attempt authentication based on source clues alone.",
    "Do not submit artefacts to online decoders or hash databases automatically.",
)


@dataclass(frozen=True)
class HtmlSourceItem:
    """One source-level item parsed from already-collected HTML."""

    source_id: str
    source_kind: str
    source_label: str | None
    url: str | None
    path: str | None
    port: int | None
    service: str | None
    item_type: str
    raw_value: str
    line_number: int
    start_offset: int
    end_offset: int
    attribute_name: str | None
    tag_name: str | None
    context: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class HtmlSourceReviewLead:
    """One cautious review lead from HTML/source content."""

    lead_type: str
    priority: str
    title: str
    explanation: str
    item: HtmlSourceItem
    nearby_keywords: tuple[str, ...]
    hash_artefacts: tuple[HashArtefactCandidate, ...]
    transform_artefacts: tuple[TransformArtefactCandidate, ...]
    suggested_manual_validation: tuple[str, ...]


@dataclass(frozen=True)
class HtmlSourceAnalysis:
    """Parsed HTML source items plus review leads and artefact candidates."""

    source_id: str
    source_kind: str
    source_label: str | None
    url: str | None
    path: str | None
    port: int | None
    service: str | None
    items: tuple[HtmlSourceItem, ...]
    review_leads: tuple[HtmlSourceReviewLead, ...]
    hash_artefacts: tuple[HashArtefactCandidate, ...]
    transform_artefacts: tuple[TransformArtefactCandidate, ...]


def analyse_html_source(source: ArtefactSource) -> HtmlSourceAnalysis:
    """Analyse already-collected HTML/source text offline."""

    items = tuple(_parse_html_source_items(source))
    all_hashes: list[HashArtefactCandidate] = []
    all_transforms: list[TransformArtefactCandidate] = []
    leads: list[HtmlSourceReviewLead] = []
    seen_leads: set[tuple[str, str, int]] = set()

    for item in items:
        item_source = ArtefactSource(
            source_id=source.source_id,
            source_kind=source.source_kind or "html",
            source_label=source.source_label,
            url=source.url,
            path=source.path,
            port=source.port,
            service=source.service,
            field_name=item.item_type,
            text=item.raw_value,
            evidence_ids=source.evidence_ids,
        )
        hashes = find_hash_artefacts(item_source)
        transforms = _find_html_transform_artefacts(item, item_source)
        all_hashes.extend(hashes)
        all_transforms.extend(transforms)
        for lead in _item_review_leads(item, hashes, transforms):
            identity = (lead.lead_type, item.raw_value, item.line_number)
            if identity in seen_leads:
                continue
            seen_leads.add(identity)
            leads.append(lead)

    return HtmlSourceAnalysis(
        source_id=source.source_id,
        source_kind=source.source_kind,
        source_label=source.source_label,
        url=source.url,
        path=source.path,
        port=source.port,
        service=source.service,
        items=items,
        review_leads=tuple(leads),
        hash_artefacts=tuple(all_hashes),
        transform_artefacts=tuple(all_transforms),
    )


def _parse_html_source_items(source: ArtefactSource) -> list[HtmlSourceItem]:
    items: list[HtmlSourceItem] = []
    for match in COMMENT_PATTERN.finditer(source.text):
        value = match.group(1).strip()
        if value:
            items.append(
                _item(source, "html_comment", value, match.start(1), match.end(1))
            )

    for match in TAG_PATTERN.finditer(source.text):
        tag_name = match.group(1).lower()
        attrs = match.group(2)
        attrs_by_name = _parse_attrs(attrs)
        tag_text = match.group(0)
        if "hidden" in attrs_by_name:
            items.append(
                _item(
                    source,
                    "hidden_attribute",
                    tag_text,
                    match.start(),
                    match.end(),
                    tag_name=tag_name,
                )
            )
        style = attrs_by_name.get("style", "")
        if _style_hides_content(style):
            items.append(
                _item(
                    source,
                    "inline_style_hidden",
                    tag_text,
                    match.start(),
                    match.end(),
                    attribute_name="style",
                    tag_name=tag_name,
                )
            )
        if "type" in attrs_by_name and attrs_by_name.get("type", "").lower() == "hidden":
            items.append(
                _item(
                    source,
                    "hidden_element",
                    tag_text,
                    match.start(),
                    match.end(),
                    attribute_name="type",
                    tag_name=tag_name,
                )
            )

        for attr_name, attr_value in attrs_by_name.items():
            attr_lower = attr_name.lower()
            if attr_lower in {"id", "class", "name"} and _contains_suspicious_word(attr_value):
                items.append(
                    _item(
                        source,
                        "suspicious_id_or_class",
                        attr_value,
                        match.start(),
                        match.end(),
                        attribute_name=attr_lower,
                        tag_name=tag_name,
                    )
                )
            if attr_lower in REFERENCE_ATTRS or attr_lower.startswith("data-"):
                reference_type = _reference_item_type(attr_lower, tag_name)
                if _is_local_reference(attr_value):
                    items.append(
                        _item(
                            source,
                            reference_type,
                            attr_value,
                            match.start(),
                            match.end(),
                            attribute_name=attr_lower,
                            tag_name=tag_name,
                        )
                    )

    for match in TEXT_PATTERN.finditer(source.text):
        value = " ".join(match.group(1).split())
        if value and _contains_suspicious_word(value):
            items.append(_item(source, "inline_text", value, match.start(1), match.end(1)))
    return items


def _parse_attrs(attrs: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for match in ATTR_PATTERN.finditer(attrs):
        value = match.group(2).strip("\"'")
        parsed[match.group(1).lower()] = value
    for bare in re.findall(r"(?<![=\w-])(hidden)(?![=\w-])", attrs, flags=re.I):
        parsed[bare.lower()] = ""
    return parsed


def _item(
    source: ArtefactSource,
    item_type: str,
    value: str,
    start: int,
    end: int,
    *,
    attribute_name: str | None = None,
    tag_name: str | None = None,
) -> HtmlSourceItem:
    return HtmlSourceItem(
        source_id=source.source_id,
        source_kind=source.source_kind or "html",
        source_label=source.source_label,
        url=source.url,
        path=source.path,
        port=source.port,
        service=source.service,
        item_type=item_type,
        raw_value=value,
        line_number=source.text.count("\n", 0, start) + 1,
        start_offset=start,
        end_offset=end,
        attribute_name=attribute_name,
        tag_name=tag_name,
        context=_context_window(source.text, start, end),
        evidence_ids=source.evidence_ids,
    )


def _find_html_transform_artefacts(
    item: HtmlSourceItem,
    item_source: ArtefactSource,
) -> tuple[TransformArtefactCandidate, ...]:
    candidates = list(find_transform_artefacts(item_source))
    seen = {(candidate.candidate_type, candidate.value) for candidate in candidates}
    for segment in _value_segments(item.raw_value):
        segment_source = ArtefactSource(
            source_id=item_source.source_id,
            source_kind=item_source.source_kind,
            source_label=item_source.source_label,
            url=item_source.url,
            path=item_source.path,
            port=item_source.port,
            service=item_source.service,
            field_name=item_source.field_name,
            text=segment,
            evidence_ids=item_source.evidence_ids,
        )
        for candidate in find_transform_artefacts(segment_source):
            identity = (candidate.candidate_type, candidate.value)
            if identity in seen:
                continue
            seen.add(identity)
            candidates.append(candidate)
    return tuple(candidates)


def _item_review_leads(
    item: HtmlSourceItem,
    hashes: tuple[HashArtefactCandidate, ...],
    transforms: tuple[TransformArtefactCandidate, ...],
) -> tuple[HtmlSourceReviewLead, ...]:
    leads: list[HtmlSourceReviewLead] = []
    keywords = _nearby_keywords(item.context)
    if hashes or transforms:
        leads.append(
            _lead(
                "html_source_artefact_review",
                _priority(item, keywords, hashes, transforms),
                "Source artefact contains possible encoded or hash-shaped values.",
                "Source artefact contains possible encoded or hash-shaped values. Manual review recommended.",
                item,
                keywords,
                hashes,
                transforms,
            )
        )

    if item.item_type == "html_comment" and keywords:
        leads.append(
            _lead(
                "html_comment_clue_review",
                _priority(item, keywords, hashes, transforms),
                "HTML comment contains clue-like wording.",
                "HTML comment contains clue-like wording. Treat it as source context, not proof.",
                item,
                keywords,
                hashes,
                transforms,
            )
        )

    if item.item_type in {"hidden_attribute", "inline_style_hidden", "hidden_element"}:
        leads.append(
            _lead(
                "html_hidden_source_review",
                _priority(item, keywords, hashes, transforms),
                "Hidden HTML element contains high-signal text. Manual review recommended.",
                "Hidden source content may be a review lead if the surrounding context is in scope.",
                item,
                keywords,
                hashes,
                transforms,
            )
        )

    if item.item_type == "suspicious_id_or_class":
        leads.append(
            _lead(
                "html_suspicious_attribute_review",
                _priority(item, keywords, hashes, transforms),
                "Suspicious HTML id/class/name value detected.",
                "Source-level clue may justify manual same-origin review if in scope.",
                item,
                keywords,
                hashes,
                transforms,
            )
        )

    if item.item_type in {"local_reference", "script_reference", "image_reference", "link_reference"}:
        if _is_unusual_reference(item.raw_value) or _contains_suspicious_word(item.raw_value):
            leads.append(
                _lead(
                    "html_local_reference_review",
                    _priority(item, keywords, hashes, transforms),
                    "Source attribute contains a suspicious local reference.",
                    "Source-level local reference may justify manual same-origin review if in scope.",
                    item,
                    keywords,
                    hashes,
                    transforms,
                )
            )

    if item.item_type == "inline_text" and keywords:
        leads.append(
            _lead(
                "html_inline_text_clue_review",
                _priority(item, keywords, hashes, transforms),
                "Inline source text contains clue-like wording.",
                "Inline source text contains clue-like wording. Manual review recommended.",
                item,
                keywords,
                hashes,
                transforms,
            )
        )
    return tuple(leads)


def _lead(
    lead_type: str,
    priority: str,
    title: str,
    explanation: str,
    item: HtmlSourceItem,
    keywords: tuple[str, ...],
    hashes: tuple[HashArtefactCandidate, ...],
    transforms: tuple[TransformArtefactCandidate, ...],
) -> HtmlSourceReviewLead:
    return HtmlSourceReviewLead(
        lead_type=lead_type,
        priority=priority,
        title=title,
        explanation=explanation,
        item=item,
        nearby_keywords=keywords,
        hash_artefacts=hashes,
        transform_artefacts=transforms,
        suggested_manual_validation=HTML_MANUAL_VALIDATION,
    )


def _priority(
    item: HtmlSourceItem,
    keywords: tuple[str, ...],
    hashes: tuple[HashArtefactCandidate, ...],
    transforms: tuple[TransformArtefactCandidate, ...],
) -> str:
    if hashes or transforms:
        return "high" if keywords else "medium"
    if any(word in keywords for word in {"flag", "password", "secret", "token", "key"}):
        return "high"
    if item.item_type in {"hidden_attribute", "inline_style_hidden", "hidden_element"}:
        return "medium"
    if item.item_type == "suspicious_id_or_class":
        return "medium"
    if _is_unusual_reference(item.raw_value):
        return "medium"
    return "low"


def _reference_item_type(attr_name: str, tag_name: str) -> str:
    if attr_name == "src":
        if tag_name == "img":
            return "image_reference"
        if tag_name == "script":
            return "script_reference"
        return "script_reference"
    if attr_name == "href":
        return "link_reference"
    if attr_name == "action":
        return "local_reference"
    return "local_reference"


def _is_local_reference(value: str) -> bool:
    lowered = value.lower().strip()
    if not lowered or lowered.startswith(("http://", "https://", "mailto:", "tel:", "#")):
        return False
    return lowered.startswith(("/", "./", "../")) or not re.match(r"^[a-z][a-z0-9+.-]*:", lowered)


def _is_unusual_reference(value: str) -> bool:
    lowered = value.lower().split("?", 1)[0].split("#", 1)[0]
    if lowered.endswith(ORDINARY_REFERENCE_SUFFIXES):
        return False
    return lowered.endswith(UNUSUAL_LOCAL_SUFFIXES) or _contains_suspicious_word(lowered)


def _contains_suspicious_word(value: str) -> bool:
    lowered = value.lower()
    return any(word in lowered for word in SUSPICIOUS_WORDS)


def _style_hides_content(value: str) -> bool:
    lowered = value.lower().replace(" ", "")
    return any(pattern.replace(" ", "") in lowered for pattern in HIDDEN_STYLE_PATTERNS)


def _nearby_keywords(value: str) -> tuple[str, ...]:
    lowered = value.lower()
    return tuple(word for word in SUSPICIOUS_WORDS if word in lowered)


def _value_segments(value: str) -> tuple[str, ...]:
    separators = ("/", "?", "&", "=", ";", ",", ":", "\"", "'", "<", ">", " ")
    segments = [value]
    for separator in separators:
        next_segments: list[str] = []
        for segment in segments:
            next_segments.extend(part for part in segment.split(separator) if part)
        segments = next_segments
    return tuple(segment.strip() for segment in segments if len(segment.strip()) >= 8)


def _context_window(text: str, start: int, end: int, max_context_chars: int = 240) -> str:
    context_start = max(0, text.rfind("\n", 0, start) + 1)
    line_end = text.find("\n", end)
    context_end = len(text) if line_end == -1 else line_end
    context = text[context_start:context_end].strip()
    if len(context) <= max_context_chars:
        return context
    relative_start = max(0, start - context_start)
    window_start = max(0, relative_start - max_context_chars // 2)
    prefix = "..." if window_start > 0 else ""
    suffix = "..." if window_start + max_context_chars < len(context) else ""
    available = max_context_chars - len(prefix) - len(suffix)
    return f"{prefix}{context[window_start:window_start + available].strip()}{suffix}"
