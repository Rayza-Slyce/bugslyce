"""Offline Deep Recon metadata review model.

This module analyses already-loaded project state only. It does not read files,
write files, fetch URLs, execute commands, or make Deep Recon executable.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlparse

from bugslyce.core.models import DiscoveredPath, Endpoint, HTTPArtifact, ProjectState


METADATA_REVIEW_CATEGORIES = (
    "robots_value",
    "robots_route_hint",
    "sitemap_reference",
    "security_contact",
    "humans_metadata",
    "policy_file",
    "favicon_reference",
    "metadata_missing",
    "metadata_uncollected",
    "metadata_noise",
)
METADATA_REVIEW_PRIORITIES = ("high", "medium", "low", "info")
MAX_VALUE_PREVIEW_LENGTH = 120
GENERIC_ROBOTS_VALUES = {"", "*", "/"}
ROBOTS_ROUTE_ARTIFACT_TYPES = {"allow_rule", "disallow_rule"}
METADATA_PATH_CATEGORIES = {
    "/security.txt": ("security_contact", "Security metadata path observed", "medium"),
    "/.well-known/security.txt": ("security_contact", "Security metadata path observed", "medium"),
    "/humans.txt": ("humans_metadata", "humans.txt metadata path observed", "low"),
    "/sitemap.xml": ("sitemap_reference", "Sitemap metadata path observed", "medium"),
    "/crossdomain.xml": ("policy_file", "Policy metadata file observed", "low"),
    "/clientaccesspolicy.xml": ("policy_file", "Policy metadata file observed", "low"),
    "/favicon.ico": ("favicon_reference", "Favicon reference observed", "info"),
}
SENSITIVE_PREVIEW_TERMS = re.compile(
    r"\b(flag|exploit|vulnerable|vulnerability)\b",
    re.IGNORECASE,
)
INTRO_TEXT = (
    "These leads are deterministic metadata review prompts from already-collected "
    "local evidence. They are not confirmed findings."
)
NO_LEADS_TEXT = "No Deep metadata review leads were generated from the collected evidence."
METADATA_SAFETY_NOTES = (
    "Treat metadata values as context, not credentials.",
    "Do not submit forms, attempt authentication, brute force, or use credentials based on metadata alone.",
)


@dataclass(frozen=True)
class DeepMetadataReviewLead:
    """One deterministic offline metadata review lead."""

    lead_id: str
    category: str
    priority: str
    title: str
    url: str
    source: str
    evidence_ids: tuple[str, ...]
    value_preview: str
    why_it_matters: str
    suggested_manual_review: str
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class DeepMetadataReviewSummary:
    """Collection of offline Deep metadata review leads."""

    leads: tuple[DeepMetadataReviewLead, ...]
    source_count: int
    ignored_count: int


@dataclass(frozen=True)
class _PendingMetadataLead:
    category: str
    priority: str
    title: str
    url: str
    source: str
    evidence_ids: tuple[str, ...]
    value_preview: str
    why_it_matters: str
    suggested_manual_review: str
    safety_notes: tuple[str, ...]


def build_deep_metadata_review_from_project_state(
    project_state: ProjectState,
) -> DeepMetadataReviewSummary:
    """Build offline metadata review leads from already-loaded project state."""

    pending: list[_PendingMetadataLead] = []
    ignored_count = 0

    for artifact in project_state.http_artifacts:
        lead = _lead_from_artifact(artifact)
        if lead is None:
            ignored_count += 1
            continue
        pending.append(lead)

    for endpoint in project_state.endpoints:
        lead = _lead_from_url_record(
            endpoint.url,
            "project-state:endpoint",
            endpoint.evidence_ids,
        )
        if lead is not None:
            pending.append(lead)

    for path in project_state.discovered_paths:
        lead = _lead_from_discovered_path(path)
        if lead is not None:
            pending.append(lead)

    deduped = _dedupe_pending_leads(pending)
    ordered = sorted(deduped, key=_lead_sort_key)
    leads = tuple(
        DeepMetadataReviewLead(
            lead_id=f"LEAD-DEEP-META-{index:04d}",
            category=lead.category,
            priority=lead.priority,
            title=lead.title,
            url=lead.url,
            source=lead.source,
            evidence_ids=lead.evidence_ids,
            value_preview=lead.value_preview,
            why_it_matters=lead.why_it_matters,
            suggested_manual_review=lead.suggested_manual_review,
            safety_notes=lead.safety_notes,
        )
        for index, lead in enumerate(ordered, start=1)
    )

    return DeepMetadataReviewSummary(
        leads=leads,
        source_count=(
            len(project_state.http_artifacts)
            + len(project_state.endpoints)
            + len(project_state.discovered_paths)
        ),
        ignored_count=ignored_count,
    )


def render_deep_metadata_review_markdown(summary: DeepMetadataReviewSummary) -> str:
    """Render Deep metadata review leads as terminal-friendly Markdown cards."""

    lines = [
        "## Deep Metadata Review",
        "",
        INTRO_TEXT,
        "",
    ]
    if not summary.leads:
        lines.extend([NO_LEADS_TEXT, ""])
        return "\n".join(lines).rstrip()

    for lead in summary.leads:
        lines.extend(
            [
                f"### {lead.lead_id}: {lead.title}",
                "",
                f"- Priority: {lead.priority}",
                f"- Category: {lead.category}",
                f"- URL: `{lead.url}`",
                f"- Source: `{lead.source}`",
            ]
        )
        if lead.evidence_ids:
            lines.append(
                "- Evidence: "
                + ", ".join(f"`{evidence_id}`" for evidence_id in lead.evidence_ids)
            )
        if lead.value_preview:
            lines.append(f"- Value preview: `{lead.value_preview}`")
        lines.extend(
            [
                f"- Why it matters: {lead.why_it_matters}",
                f"- Suggested manual review: {lead.suggested_manual_review}",
                "- Safety notes:",
            ]
        )
        lines.extend(f"  - {note}" for note in lead.safety_notes)
        lines.append("")

    return "\n".join(lines).rstrip()


def _lead_from_artifact(artifact: HTTPArtifact) -> _PendingMetadataLead | None:
    artifact_type = artifact.artifact_type
    value = artifact.value.strip()

    if artifact_type == "robots_value":
        if _is_generic_metadata_value(value):
            return None
        return _pending_lead(
            category="robots_value",
            priority="high",
            title="robots.txt clue-like value observed",
            url=artifact.url,
            source=f"http_artifact:{artifact_type}",
            evidence_ids=artifact.evidence_ids,
            value=value,
            why_it_matters=(
                "robots.txt can contain route hints or unusual operator-provided "
                "values that deserve manual context review."
            ),
            suggested_manual_review=(
                "Review the collected metadata value locally and correlate with "
                "route and service context before escalating."
            ),
        )

    if artifact_type in ROBOTS_ROUTE_ARTIFACT_TYPES:
        if _is_generic_metadata_value(value):
            return None
        return _pending_lead(
            category="robots_route_hint",
            priority="medium",
            title="robots.txt route hint observed",
            url=artifact.url,
            source=f"http_artifact:{artifact_type}",
            evidence_ids=artifact.evidence_ids,
            value=value,
            why_it_matters=(
                "robots.txt route directives can highlight paths that deserve "
                "bounded manual review in service context."
            ),
            suggested_manual_review=(
                "Review the collected directive and correlate it with discovered "
                "paths and HTTP service context before drawing conclusions."
            ),
        )

    if artifact_type == "sitemap_rule" and value:
        return _pending_lead(
            category="sitemap_reference",
            priority="medium",
            title="Sitemap reference observed",
            url=artifact.url,
            source="http_artifact:sitemap_rule",
            evidence_ids=artifact.evidence_ids,
            value=value,
            why_it_matters=(
                "Sitemap references can provide route inventory context for "
                "manual review."
            ),
            suggested_manual_review=(
                "Review the collected sitemap reference locally and confirm "
                "whether any referenced routes are in scope before manual testing."
            ),
        )

    return None


def _lead_from_discovered_path(path: DiscoveredPath) -> _PendingMetadataLead | None:
    return _lead_from_url_record(
        path.url,
        "project-state:discovered-path",
        path.evidence_ids,
    )


def _lead_from_url_record(
    url: str,
    source: str,
    evidence_ids: list[str],
) -> _PendingMetadataLead | None:
    path = _normalised_path(url)
    if path not in METADATA_PATH_CATEGORIES:
        return None
    category, title, priority = METADATA_PATH_CATEGORIES[path]
    return _pending_lead(
        category=category,
        priority=priority,
        title=title,
        url=url,
        source=source,
        evidence_ids=evidence_ids,
        value=path,
        why_it_matters=_why_it_matters_for_category(category),
        suggested_manual_review=_manual_review_for_category(category),
    )


def _pending_lead(
    *,
    category: str,
    priority: str,
    title: str,
    url: str,
    source: str,
    evidence_ids: list[str],
    value: str,
    why_it_matters: str,
    suggested_manual_review: str,
) -> _PendingMetadataLead:
    return _PendingMetadataLead(
        category=category,
        priority=priority,
        title=title,
        url=url,
        source=source,
        evidence_ids=tuple(_dedupe(evidence_ids)),
        value_preview=_safe_preview(value),
        why_it_matters=why_it_matters,
        suggested_manual_review=suggested_manual_review,
        safety_notes=METADATA_SAFETY_NOTES,
    )


def _why_it_matters_for_category(category: str) -> str:
    if category == "security_contact":
        return "Security metadata paths can indicate reporting or policy context for scoped review."
    if category == "humans_metadata":
        return "humans.txt can provide low-confidence ownership or technology context."
    if category == "policy_file":
        return "Policy metadata files can provide legacy client or cross-domain context."
    if category == "favicon_reference":
        return "Favicon observations can support low-confidence service correlation."
    return "Metadata references can provide route and service context for manual review."


def _manual_review_for_category(category: str) -> str:
    if category == "favicon_reference":
        return "Use the favicon only as supporting service context, not as a finding."
    return (
        "Review the collected metadata context locally and confirm scope before "
        "using it to guide manual testing."
    )


def _dedupe_pending_leads(
    leads: list[_PendingMetadataLead],
) -> tuple[_PendingMetadataLead, ...]:
    lead_by_key: dict[tuple[str, str, str], _PendingMetadataLead] = {}
    result: list[_PendingMetadataLead] = []
    for lead in leads:
        key = (lead.category, lead.url, lead.value_preview)
        existing = lead_by_key.get(key)
        if existing is not None:
            merged = _PendingMetadataLead(
                category=existing.category,
                priority=existing.priority,
                title=existing.title,
                url=existing.url,
                source=existing.source,
                evidence_ids=tuple(
                    _dedupe([*existing.evidence_ids, *lead.evidence_ids])
                ),
                value_preview=existing.value_preview,
                why_it_matters=existing.why_it_matters,
                suggested_manual_review=existing.suggested_manual_review,
                safety_notes=existing.safety_notes,
            )
            lead_by_key[key] = merged
            result[result.index(existing)] = merged
            continue
        lead_by_key[key] = lead
        result.append(lead)
    return tuple(result)


def _lead_sort_key(lead: _PendingMetadataLead) -> tuple[int, int, str, str, tuple[str, ...]]:
    return (
        METADATA_REVIEW_CATEGORIES.index(lead.category),
        METADATA_REVIEW_PRIORITIES.index(lead.priority),
        lead.url,
        lead.value_preview,
        lead.evidence_ids,
    )


def _normalised_path(url: str) -> str:
    try:
        path = urlparse(url).path
    except ValueError:
        return ""
    if not path:
        return "/"
    if len(path) > 1:
        return path.rstrip("/")
    return path


def _is_generic_metadata_value(value: str) -> bool:
    stripped = value.strip()
    return stripped in GENERIC_ROBOTS_VALUES


def _safe_preview(value: str) -> str:
    normalised = " ".join(value.split())
    redacted = SENSITIVE_PREVIEW_TERMS.sub("[redacted]", normalised)
    if len(redacted) <= MAX_VALUE_PREVIEW_LENGTH:
        return redacted
    return redacted[: MAX_VALUE_PREVIEW_LENGTH - 3].rstrip() + "..."


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
