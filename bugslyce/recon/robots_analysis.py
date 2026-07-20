"""Offline robots.txt analysis for already-collected evidence."""

from __future__ import annotations

from dataclasses import dataclass

from bugslyce.recon.artefact_analysis import (
    ArtefactSource,
    HashArtefactCandidate,
    TransformArtefactCandidate,
    find_hash_artefacts,
    find_transform_artefacts,
)


KNOWN_DIRECTIVES = {
    "user-agent",
    "disallow",
    "allow",
    "sitemap",
    "crawl-delay",
}
COMMON_USER_AGENTS = {"*"}
HIGH_SIGNAL_WORDS = (
    "hidden",
    "admin",
    "secret",
    "dev",
    "test",
    "backup",
    "flag",
    "password",
    "passwd",
    "key",
    "token",
    "clue",
)
PUZZLE_WORDING = (
    "only this can enter",
    "do not enter",
    "nothing to see",
    "go away",
)
ROBOTS_MANUAL_VALIDATION = (
    "Review the referenced same-origin path manually if it is in scope.",
    "Treat robots.txt as a clue source, not proof of vulnerability.",
    "Validate possible encoded or hash-shaped artefacts locally.",
    "Do not submit artefacts to online decoders or hash databases automatically.",
    "Do not brute force or attempt authentication based on robots.txt alone.",
)
ROBOTS_USER_AGENT_ARTEFACT_VALIDATION = (
    "Review the collected robots.txt content in context.",
    "Validate hash-shaped or encoded-looking artefacts locally.",
    "Correlate the value with other collected evidence before escalating.",
    "Do not submit artefacts to online decoders or hash databases automatically.",
    "Do not brute force or attempt authentication based on robots.txt alone.",
)


@dataclass(frozen=True)
class RobotsEntry:
    """One parsed robots.txt line with source context."""

    source_id: str
    source_label: str | None
    url: str | None
    path: str | None
    port: int | None
    service: str | None
    line_number: int
    field_name: str
    raw_name: str | None
    raw_value: str
    raw_line: str
    context: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class RobotsReviewLead:
    """One cautious review lead from robots.txt content."""

    lead_type: str
    priority: str
    title: str
    explanation: str
    entry: RobotsEntry
    nearby_keywords: tuple[str, ...]
    hash_artefacts: tuple[HashArtefactCandidate, ...]
    transform_artefacts: tuple[TransformArtefactCandidate, ...]
    suggested_manual_validation: tuple[str, ...]


@dataclass(frozen=True)
class RobotsAnalysis:
    """Parsed robots entries plus review-worthy leads and artefact candidates."""

    source_id: str
    source_label: str | None
    url: str | None
    path: str | None
    port: int | None
    service: str | None
    entries: tuple[RobotsEntry, ...]
    review_leads: tuple[RobotsReviewLead, ...]
    hash_artefacts: tuple[HashArtefactCandidate, ...]
    transform_artefacts: tuple[TransformArtefactCandidate, ...]


def analyse_robots_txt(source: ArtefactSource) -> RobotsAnalysis:
    """Parse and analyse already-collected robots.txt content offline."""

    entries = tuple(_parse_robots_entries(source))
    all_hashes: list[HashArtefactCandidate] = []
    all_transforms: list[TransformArtefactCandidate] = []
    leads: list[RobotsReviewLead] = []
    seen_leads: set[tuple[str, int, str]] = set()

    for entry in entries:
        line_source = ArtefactSource(
            source_id=source.source_id,
            source_kind="robots_txt",
            source_label=source.source_label,
            url=source.url,
            path=source.path,
            port=source.port,
            service=source.service,
            field_name=entry.field_name,
            text=entry.raw_line,
            evidence_ids=source.evidence_ids,
        )
        hashes = find_hash_artefacts(line_source)
        transforms = _find_robots_transform_artefacts(entry, line_source)
        all_hashes.extend(hashes)
        all_transforms.extend(transforms)
        for lead in _entry_review_leads(entry, hashes, transforms):
            identity = (lead.lead_type, entry.field_name, entry.raw_value)
            if identity in seen_leads:
                continue
            seen_leads.add(identity)
            leads.append(lead)

    return RobotsAnalysis(
        source_id=source.source_id,
        source_label=source.source_label,
        url=source.url,
        path=source.path,
        port=source.port,
        service=source.service,
        entries=entries,
        review_leads=tuple(leads),
        hash_artefacts=tuple(all_hashes),
        transform_artefacts=tuple(all_transforms),
    )


def _find_robots_transform_artefacts(
    entry: RobotsEntry,
    line_source: ArtefactSource,
) -> tuple[TransformArtefactCandidate, ...]:
    candidates = list(find_transform_artefacts(line_source))
    seen = {(candidate.candidate_type, candidate.value) for candidate in candidates}
    for segment in _value_segments(entry.raw_value):
        segment_source = ArtefactSource(
            source_id=line_source.source_id,
            source_kind=line_source.source_kind,
            source_label=line_source.source_label,
            url=line_source.url,
            path=line_source.path,
            port=line_source.port,
            service=line_source.service,
            field_name=line_source.field_name,
            text=segment,
            evidence_ids=line_source.evidence_ids,
        )
        for candidate in find_transform_artefacts(segment_source):
            identity = (candidate.candidate_type, candidate.value)
            if identity in seen:
                continue
            seen.add(identity)
            candidates.append(candidate)
    return tuple(candidates)


def _value_segments(value: str) -> tuple[str, ...]:
    separators = ("/", "?", "&", "=", ";", ",")
    segments = [value]
    for separator in separators:
        next_segments: list[str] = []
        for segment in segments:
            next_segments.extend(part for part in segment.split(separator) if part)
        segments = next_segments
    return tuple(segment.strip() for segment in segments if len(segment.strip()) >= 8)


def _parse_robots_entries(source: ArtefactSource) -> list[RobotsEntry]:
    lines = source.text.splitlines()
    entries: list[RobotsEntry] = []
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            field_name = "comment"
            raw_name = None
            raw_value = stripped[1:].strip()
        elif ":" in stripped:
            raw_name, raw_value = stripped.split(":", 1)
            normalized = raw_name.strip().lower()
            field_name = normalized if normalized in KNOWN_DIRECTIVES else "unknown"
            raw_value = raw_value.strip()
        else:
            raw_name = None
            raw_value = stripped
            field_name = "unknown"

        entries.append(
            RobotsEntry(
                source_id=source.source_id,
                source_label=source.source_label,
                url=source.url,
                path=source.path,
                port=source.port,
                service=source.service,
                line_number=index,
                field_name=field_name,
                raw_name=raw_name.strip() if raw_name else None,
                raw_value=raw_value,
                raw_line=line,
                context=_line_context(lines, index),
                evidence_ids=source.evidence_ids,
            )
        )
    return entries


def _entry_review_leads(
    entry: RobotsEntry,
    hashes: tuple[HashArtefactCandidate, ...],
    transforms: tuple[TransformArtefactCandidate, ...],
) -> tuple[RobotsReviewLead, ...]:
    leads: list[RobotsReviewLead] = []
    keywords = _nearby_keywords(entry.context)
    unusual_user_agent = (
        entry.field_name == "user-agent"
        and _is_unusual_user_agent(entry.raw_value)
    )
    has_artefacts = bool(hashes or transforms)

    if unusual_user_agent and has_artefacts:
        title = (
            "Robots.txt contains an unusual hash-shaped User-Agent value."
            if hashes
            else "Robots.txt contains an unusual encoded-looking User-Agent value."
        )
        pattern_description = (
            "a hash-shaped pattern"
            if hashes
            else "an encoded-looking pattern"
        )
        leads.append(
            _lead(
                "robots_unusual_user_agent_artefact_review",
                _priority(entry, keywords, hashes, transforms),
                title,
                (
                    "The robots.txt User-Agent value is unusual and also matches "
                    f"{pattern_description}. Treat it as a review signal "
                    "requiring local manual validation, not proof "
                    "of vulnerability or valid credentials."
                ),
                entry,
                keywords,
                hashes,
                transforms,
                validation=ROBOTS_USER_AGENT_ARTEFACT_VALIDATION,
            )
        )
        return tuple(leads)

    if has_artefacts:
        leads.append(
            _lead(
                "robots_artefact_review",
                _priority(entry, keywords, hashes, transforms),
                "Robots directive contains possible encoded or hash-shaped artefacts.",
                "Robots directive contains possible encoded or hash-shaped artefacts. Manual review recommended.",
                entry,
                keywords,
                hashes,
                transforms,
            )
        )

    if unusual_user_agent:
        leads.append(
            _lead(
                "robots_unusual_user_agent",
                _priority(entry, keywords, hashes, transforms),
                "Unusual robots User-Agent value detected.",
                "Unusual robots User-Agent value detected. Treat it as review context, not proof of access control.",
                entry,
                keywords,
                hashes,
                transforms,
            )
        )

    if entry.field_name == "disallow":
        if not entry.raw_value:
            leads.append(
                _lead(
                    "robots_empty_disallow",
                    "low",
                    "Empty robots Disallow directive observed.",
                    "Empty Disallow value is usually low signal but is preserved for context.",
                    entry,
                    keywords,
                    hashes,
                    transforms,
                )
            )
        elif _is_review_worthy_path(entry.raw_value):
            leads.append(
                _lead(
                    "robots_disallowed_path_review",
                    _priority(entry, keywords, hashes, transforms),
                    "Disallowed path contains high-signal wording. Manual review recommended.",
                    "Robots entry may justify manual same-origin path review if it is in scope.",
                    entry,
                    keywords,
                    hashes,
                    transforms,
                )
            )

    if entry.field_name == "comment" and (_contains_clue_wording(entry.raw_value) or keywords):
        leads.append(
            _lead(
                "robots_comment_clue_review",
                _priority(entry, keywords, hashes, transforms),
                "Robots comment contains clue-like wording.",
                "Robots comment contains clue-like wording. Treat it as a review lead, not proof.",
                entry,
                keywords,
                hashes,
                transforms,
            )
        )

    if entry.field_name == "unknown":
        leads.append(
            _lead(
                "robots_unknown_directive",
                _priority(entry, keywords, hashes, transforms),
                "Unknown or non-standard robots directive preserved for review.",
                "Unknown robots directive may be implementation-specific or clue-like. Review manually.",
                entry,
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
    entry: RobotsEntry,
    keywords: tuple[str, ...],
    hashes: tuple[HashArtefactCandidate, ...],
    transforms: tuple[TransformArtefactCandidate, ...],
    validation: tuple[str, ...] = ROBOTS_MANUAL_VALIDATION,
) -> RobotsReviewLead:
    return RobotsReviewLead(
        lead_type=lead_type,
        priority=priority,
        title=title,
        explanation=explanation,
        entry=entry,
        nearby_keywords=keywords,
        hash_artefacts=hashes,
        transform_artefacts=transforms,
        suggested_manual_validation=validation,
    )


def _priority(
    entry: RobotsEntry,
    keywords: tuple[str, ...],
    hashes: tuple[HashArtefactCandidate, ...],
    transforms: tuple[TransformArtefactCandidate, ...],
) -> str:
    if hashes or transforms:
        return "high" if keywords else "medium"
    if entry.field_name == "comment" and keywords:
        return "high"
    if entry.field_name == "unknown" and keywords:
        return "high"
    if _is_review_worthy_path(entry.raw_value):
        return "medium"
    if entry.field_name == "user-agent" and _is_unusual_user_agent(entry.raw_value):
        return "medium"
    return "low"


def _is_unusual_user_agent(value: str) -> bool:
    return bool(value.strip()) and value.strip().lower() not in COMMON_USER_AGENTS


def _is_review_worthy_path(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith("/") and any(word in lowered for word in HIGH_SIGNAL_WORDS)


def _contains_clue_wording(value: str) -> bool:
    lowered = value.lower()
    return any(phrase in lowered for phrase in PUZZLE_WORDING)


def _nearby_keywords(value: str) -> tuple[str, ...]:
    lowered = value.lower()
    return tuple(word for word in HIGH_SIGNAL_WORDS if word in lowered)


def _line_context(lines: list[str], line_number: int) -> str:
    start = max(0, line_number - 2)
    end = min(len(lines), line_number + 1)
    return "\n".join(lines[start:end]).strip()
