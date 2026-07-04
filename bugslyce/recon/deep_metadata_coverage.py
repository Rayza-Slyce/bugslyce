"""Offline Deep metadata coverage summary.

This module compares static Deep metadata plans with already-loaded project
state only. It does not read files, write files, fetch URLs, execute commands,
or make Deep Recon executable.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

from bugslyce.core.models import ProjectState
from bugslyce.recon.deep_metadata_plan import (
    DEEP_METADATA_PATHS,
    build_deep_metadata_plan_from_project_state,
)


COVERAGE_STATUSES = (
    "collected",
    "observed",
    "planned_uncollected",
    "skipped",
)
COVERAGE_CATEGORIES = (
    "robots",
    "sitemap",
    "security",
    "humans",
    "policy",
    "favicon",
    "other_metadata",
)
KNOWN_METADATA_PATHS = {
    "/robots.txt": "robots",
    "/sitemap.xml": "sitemap",
    "/security.txt": "security",
    "/.well-known/security.txt": "security",
    "/humans.txt": "humans",
    "/crossdomain.xml": "policy",
    "/clientaccesspolicy.xml": "policy",
    "/favicon.ico": "favicon",
}
INTRO_TEXT = (
    "This summary compares Deep metadata review targets with already-collected "
    "local evidence. It does not fetch URLs and does not execute Deep Recon."
)
NOTES = (
    "This is a coverage/gap view only.",
    "Uncollected does not imply absence on the target.",
    "Do not fetch missing URLs from this summary unless explicitly authorised and in scope.",
)


@dataclass(frozen=True)
class DeepMetadataCoverageItem:
    """One metadata coverage item from planned or already-collected evidence."""

    url: str
    path: str
    status: str
    category: str
    source: str
    evidence_ids: tuple[str, ...]
    planned: bool
    collected: bool
    reason: str


@dataclass(frozen=True)
class DeepMetadataCoverageSummary:
    """Deterministic Deep metadata coverage summary."""

    items: tuple[DeepMetadataCoverageItem, ...]
    planned_count: int
    collected_count: int
    observed_count: int
    planned_uncollected_count: int
    skipped_count: int


@dataclass(frozen=True)
class _EvidenceCoverage:
    status: str
    category: str
    source: str
    evidence_ids: tuple[str, ...]
    reason: str


def build_deep_metadata_coverage_from_project_state(
    project_state: ProjectState,
) -> DeepMetadataCoverageSummary:
    """Compare planned Deep metadata URLs with already-loaded project state."""

    plan = build_deep_metadata_plan_from_project_state(project_state)
    evidence_by_url = _metadata_evidence_by_url(project_state)
    planned_urls: set[str] = set()
    items: list[DeepMetadataCoverageItem] = []

    for request in plan.requests:
        normalised_url = _normalise_url(request.url)
        if normalised_url is None:
            continue
        planned_urls.add(normalised_url)
        evidence = evidence_by_url.get(normalised_url)
        category = _coverage_category(request.category)
        if evidence is None:
            items.append(
                DeepMetadataCoverageItem(
                    url=normalised_url,
                    path=request.path,
                    status="planned_uncollected",
                    category=category,
                    source=request.source,
                    evidence_ids=(),
                    planned=True,
                    collected=False,
                    reason="planned_metadata_request_not_collected",
                )
            )
            continue
        items.append(
            DeepMetadataCoverageItem(
                url=normalised_url,
                path=request.path,
                status=evidence.status,
                category=evidence.category,
                source=evidence.source,
                evidence_ids=evidence.evidence_ids,
                planned=True,
                collected=evidence.status == "collected",
                reason=evidence.reason,
            )
        )

    for normalised_url, evidence in sorted(evidence_by_url.items()):
        if normalised_url in planned_urls:
            continue
        path = _normalised_path(normalised_url)
        items.append(
            DeepMetadataCoverageItem(
                url=normalised_url,
                path=path,
                status=evidence.status,
                category=evidence.category,
                source=evidence.source,
                evidence_ids=evidence.evidence_ids,
                planned=False,
                collected=evidence.status == "collected",
                reason="local_metadata_evidence_outside_plan",
            )
        )

    for skipped in plan.skipped_services:
        normalised_url = _normalise_url(skipped.url) or skipped.url
        path = _normalised_path(normalised_url)
        items.append(
            DeepMetadataCoverageItem(
                url=normalised_url,
                path=path,
                status="skipped",
                category=KNOWN_METADATA_PATHS.get(path, "other_metadata"),
                source=skipped.source,
                evidence_ids=(),
                planned=False,
                collected=False,
                reason=skipped.reason,
            )
        )

    return DeepMetadataCoverageSummary(
        items=tuple(items),
        planned_count=sum(1 for item in items if item.planned),
        collected_count=sum(1 for item in items if item.status == "collected"),
        observed_count=sum(1 for item in items if item.status == "observed"),
        planned_uncollected_count=sum(
            1 for item in items if item.status == "planned_uncollected"
        ),
        skipped_count=sum(1 for item in items if item.status == "skipped"),
    )


def render_deep_metadata_coverage_markdown(
    summary: DeepMetadataCoverageSummary,
) -> str:
    """Render Deep metadata coverage as terminal-friendly Markdown."""

    lines = [
        "## Deep Metadata Coverage",
        "",
        INTRO_TEXT,
        "",
        "### Summary",
        "",
        f"- Planned metadata URLs: {summary.planned_count}",
        f"- Collected metadata URLs: {summary.collected_count}",
        f"- Observed metadata references: {summary.observed_count}",
        f"- Planned but uncollected: {summary.planned_uncollected_count}",
        f"- Skipped: {summary.skipped_count}",
        "",
    ]

    for status, title in (
        ("collected", "Collected"),
        ("observed", "Observed"),
        ("planned_uncollected", "Planned But Uncollected"),
    ):
        status_items = tuple(item for item in summary.items if item.status == status)
        if not status_items:
            continue
        lines.extend([f"### {title}", ""])
        lines.extend(_render_coverage_items(status_items))
        lines.append("")

    skipped_items = tuple(item for item in summary.items if item.status == "skipped")
    duplicate_skips = tuple(item for item in skipped_items if item.reason == "duplicate_origin")
    detailed_skips = tuple(item for item in skipped_items if item.reason != "duplicate_origin")
    if detailed_skips:
        lines.extend(["### Skipped", ""])
        lines.extend(_render_coverage_items(detailed_skips))
        lines.append("")
    if duplicate_skips:
        lines.extend(["### Suppressed Planner Skips", ""])
        lines.append(
            f"- `duplicate_origin`: {len(duplicate_skips)} duplicate source URL(s) suppressed from detailed output."
        )
        lines.append(
            "- These are planner-origin skips, not missing metadata coverage."
        )
        lines.append("")

    lines.extend(["### Notes", ""])
    lines.extend(f"- {note}" for note in NOTES)
    lines.append("")
    return "\n".join(lines).rstrip()


def _render_coverage_items(items: tuple[DeepMetadataCoverageItem, ...]) -> list[str]:
    lines: list[str] = []
    for item in items:
        line = f"- `{item.url}` - {item.category}"
        if item.evidence_ids:
            evidence = ", ".join(f"`{evidence_id}`" for evidence_id in item.evidence_ids)
            line += f" - evidence: {evidence}"
        if item.reason:
            line += f" - reason: {item.reason}"
        lines.append(line)
    return lines


def _metadata_evidence_by_url(
    project_state: ProjectState,
) -> dict[str, _EvidenceCoverage]:
    evidence_by_url: dict[str, _EvidenceCoverage] = {}

    for artifact in project_state.http_artifacts:
        normalised_url = _normalise_url(artifact.url)
        if normalised_url is None:
            continue
        path = _normalised_path(normalised_url)
        category = KNOWN_METADATA_PATHS.get(path)
        if category is None:
            continue
        _merge_evidence(
            evidence_by_url,
            normalised_url,
            _EvidenceCoverage(
                status="collected",
                category=category,
                source=f"http_artifact:{artifact.artifact_type}",
                evidence_ids=tuple(_dedupe(artifact.evidence_ids)),
                reason="local_metadata_artifact_collected",
            ),
        )

    for path in project_state.discovered_paths:
        normalised_url = _normalise_url(path.url)
        if normalised_url is None:
            continue
        metadata_path = _normalised_path(normalised_url)
        category = KNOWN_METADATA_PATHS.get(metadata_path)
        if category is None:
            continue
        _merge_evidence(
            evidence_by_url,
            normalised_url,
            _EvidenceCoverage(
                status="collected",
                category=category,
                source="project-state:discovered-path",
                evidence_ids=tuple(_dedupe(path.evidence_ids)),
                reason="local_metadata_path_collected",
            ),
        )

    for endpoint in project_state.endpoints:
        normalised_url = _normalise_url(endpoint.url)
        if normalised_url is None:
            continue
        path = _normalised_path(normalised_url)
        category = KNOWN_METADATA_PATHS.get(path)
        if category is None:
            continue
        _merge_evidence(
            evidence_by_url,
            normalised_url,
            _EvidenceCoverage(
                status="observed",
                category=category,
                source="project-state:endpoint",
                evidence_ids=tuple(_dedupe(endpoint.evidence_ids)),
                reason="metadata_reference_observed",
            ),
        )

    return evidence_by_url


def _merge_evidence(
    evidence_by_url: dict[str, _EvidenceCoverage],
    url: str,
    evidence: _EvidenceCoverage,
) -> None:
    existing = evidence_by_url.get(url)
    if existing is None:
        evidence_by_url[url] = evidence
        return
    status = _stronger_status(existing.status, evidence.status)
    primary = existing if status == existing.status else evidence
    evidence_by_url[url] = _EvidenceCoverage(
        status=status,
        category=primary.category,
        source=_merge_sources(existing.source, evidence.source),
        evidence_ids=tuple(_dedupe([*existing.evidence_ids, *evidence.evidence_ids])),
        reason=primary.reason,
    )


def _stronger_status(first: str, second: str) -> str:
    order = {"collected": 0, "observed": 1, "planned_uncollected": 2, "skipped": 3}
    return first if order[first] <= order[second] else second


def _merge_sources(first: str, second: str) -> str:
    return ", ".join(_dedupe([first, second]))


def _normalise_url(raw_url: str) -> str | None:
    value = raw_url.strip() if isinstance(raw_url, str) else ""
    if not value:
        return None
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    hostname = parsed.hostname.lower()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    default_port = 443 if parsed.scheme == "https" else 80
    netloc = hostname if port in (None, default_port) else f"{hostname}:{port}"
    path = _normalise_path_value(parsed.path)
    return urlunparse((parsed.scheme.lower(), netloc, path, "", "", ""))


def _normalised_path(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    return _normalise_path_value(parsed.path)


def _normalise_path_value(path: str) -> str:
    if not path:
        return "/"
    if len(path) > 1:
        return path.rstrip("/")
    return path


def _coverage_category(planner_category: str) -> str:
    if planner_category == "client_access_policy":
        return "policy"
    if planner_category == "crossdomain":
        return "policy"
    if planner_category in COVERAGE_CATEGORIES:
        return planner_category
    return "other_metadata"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
