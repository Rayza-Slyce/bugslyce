"""Offline Standard investigation thread grouping."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlparse

from bugslyce.core.models import Candidate, ProjectState
from bugslyce.recon.interpretation import ReviewLead


PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}
THREAD_CATEGORY_ORDER = {
    "http_service": 0,
    "discovered_content": 1,
    "artefact_interpretation": 2,
}
HIDDEN_PATH_WORDS = (
    "hidden",
    "secret",
    "admin",
    "backup",
    "old",
    "dev",
    "test",
    "staging",
)
ENCODED_CANDIDATE_TYPES = {
    "encoded_artifact_review",
    "credential_like_artifact_review",
}


@dataclass(frozen=True)
class InvestigationThread:
    """A grouped manual investigation path for related review signals."""

    thread_id: str
    title: str
    priority: str
    category: str
    summary: str
    why_it_matters: str
    related_endpoints: tuple[str, ...]
    related_evidence_ids: tuple[str, ...]
    related_candidate_ids: tuple[str, ...]
    related_lead_ids: tuple[str, ...]
    suggested_manual_review_order: tuple[str, ...]
    kill_switch_guidance: str | None


@dataclass(frozen=True)
class _ThreadDraft:
    title: str
    priority: str
    category: str
    summary: str
    why_it_matters: str
    related_endpoints: tuple[str, ...]
    related_evidence_ids: tuple[str, ...]
    related_candidate_ids: tuple[str, ...]
    related_lead_ids: tuple[str, ...]
    suggested_manual_review_order: tuple[str, ...]
    kill_switch_guidance: str | None


def build_investigation_threads(
    project_state: ProjectState,
    candidates: Sequence[Candidate] = (),
    review_leads: Sequence[ReviewLead] = (),
) -> tuple[InvestigationThread, ...]:
    """Build deterministic investigation threads from existing offline evidence."""

    drafts: list[_ThreadDraft] = []
    high_port = _high_port_http_thread(project_state, candidates, review_leads)
    if high_port is not None:
        drafts.append(high_port)
    hidden_path = _hidden_path_thread(project_state, candidates)
    if hidden_path is not None:
        drafts.append(hidden_path)
    encoded = _encoded_or_source_thread(project_state, candidates, review_leads)
    if encoded is not None:
        drafts.append(encoded)
    return _assign_thread_ids(drafts)


def render_investigation_threads_markdown(
    threads: Sequence[InvestigationThread],
) -> str:
    """Render investigation threads as concise Markdown."""

    lines = [
        "## Investigation Threads",
        "",
        (
            "These threads group related review signals into practical manual "
            "investigation paths. They are not confirmed findings."
        ),
        "",
    ]
    if not threads:
        lines.extend(["No investigation threads were generated from the provided evidence.", ""])
        return "\n".join(lines).rstrip() + "\n"

    for thread in threads:
        lines.extend(
            [
                f"### {thread.thread_id}: {thread.title}",
                "",
                f"- Priority: {thread.priority}",
                f"- Category: {thread.category}",
                f"- Summary: {thread.summary}",
                f"- Why it matters: {thread.why_it_matters}",
            ]
        )
        if thread.related_endpoints:
            lines.append("- Related endpoints:")
            lines.extend(f"  - `{endpoint}`" for endpoint in thread.related_endpoints)
        if thread.related_evidence_ids:
            lines.append(
                "- Related evidence IDs: "
                + ", ".join(f"`{item}`" for item in thread.related_evidence_ids)
            )
        if thread.related_lead_ids:
            lines.append(
                "- Related Manual Review Lead IDs: "
                + ", ".join(f"`{item}`" for item in thread.related_lead_ids)
            )
        if thread.related_candidate_ids:
            lines.append(
                "- Related candidate IDs: "
                + ", ".join(f"`{item}`" for item in thread.related_candidate_ids)
            )
        if thread.suggested_manual_review_order:
            lines.append("- Suggested manual review order:")
            lines.extend(f"  - {step}" for step in thread.suggested_manual_review_order)
        if thread.kill_switch_guidance:
            lines.append(f"- Kill-switch guidance: {thread.kill_switch_guidance}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_standard_investigation_workflow_runbook_section(
    threads: Sequence[InvestigationThread],
) -> str:
    """Render a concise Standard-only runbook workflow from investigation threads."""

    lines = [
        "## Standard Investigation Workflow",
        "",
        (
            "These steps are derived from offline Investigation Threads and are "
            "manual review prompts, not confirmed findings."
        ),
        "",
    ]
    if not threads:
        lines.extend(
            [
                (
                    "No Standard Investigation Threads were generated from the "
                    "available offline evidence."
                ),
                "",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    for thread in threads:
        lines.extend(
            [
                f"### {thread.thread_id}: {thread.title}",
                "",
                f"* Priority: {thread.priority}",
                f"* Category: {thread.category}",
                f"* Summary: {thread.summary}",
            ]
        )
        if thread.related_endpoints:
            lines.append("* Related endpoints:")
            lines.extend(f"  * `{endpoint}`" for endpoint in thread.related_endpoints)
        if thread.related_evidence_ids:
            lines.append(
                "* Related evidence IDs: "
                + ", ".join(f"`{item}`" for item in thread.related_evidence_ids)
            )
        if thread.related_lead_ids:
            lines.append(
                "* Related Manual Review Lead IDs: "
                + ", ".join(f"`{item}`" for item in thread.related_lead_ids)
            )
        if thread.related_candidate_ids:
            lines.append(
                "* Related candidate IDs: "
                + ", ".join(f"`{item}`" for item in thread.related_candidate_ids)
            )
        if thread.suggested_manual_review_order:
            lines.append("* Suggested manual review order:")
            lines.extend(f"  * {step}" for step in thread.suggested_manual_review_order)
        if thread.kill_switch_guidance:
            lines.append(f"* Kill-switch guidance: {thread.kill_switch_guidance}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _high_port_http_thread(
    project_state: ProjectState,
    candidates: Sequence[Candidate],
    review_leads: Sequence[ReviewLead],
) -> _ThreadDraft | None:
    services_by_host: dict[str, list[str]] = {}
    high_port_endpoints: list[str] = []
    evidence_ids: list[str] = []
    for service in project_state.http_services:
        services_by_host.setdefault(service.hostname, []).append(service.url)
        if _is_high_port_url(service.url):
            high_port_endpoints.append(service.url)
            evidence_ids.extend(service.evidence_ids)

    multiple_high_port_hosts = {
        host
        for host, urls in services_by_host.items()
        if len(urls) > 1 and any(_is_high_port_url(url) for url in urls)
    }
    for service in project_state.http_services:
        if service.hostname in multiple_high_port_hosts:
            high_port_endpoints.append(service.url)
            evidence_ids.extend(service.evidence_ids)

    candidate_types = {"high_port_http_service", "multiple_http_services"}
    related_candidates = [item for item in candidates if item.candidate_type in candidate_types]
    for candidate in related_candidates:
        high_port_endpoints.extend(candidate.affected_endpoints)
        evidence_ids.extend(candidate.evidence_ids)

    related_leads = [lead for lead in review_leads if lead.url and _is_high_port_url(lead.url)]
    for lead in related_leads:
        if lead.url:
            high_port_endpoints.append(lead.url)

    if not high_port_endpoints and not related_candidates:
        return None
    return _ThreadDraft(
        title="High-port HTTP application review",
        priority=_highest_priority([*(item.priority for item in related_candidates), "medium"]),
        category="http_service",
        summary=(
            "A non-default HTTP port or multiple HTTP services may indicate a "
            "separate application surface."
        ),
        why_it_matters=(
            "Different HTTP ports on the same host can expose distinct application "
            "contexts, configuration, or review signals."
        ),
        related_endpoints=_unique_sorted(high_port_endpoints),
        related_evidence_ids=_unique_sorted(evidence_ids),
        related_candidate_ids=_unique_sorted(item.id for item in related_candidates),
        related_lead_ids=_unique_sorted(lead.lead_id for lead in related_leads),
        suggested_manual_review_order=(
            "Compare the high-port service with the default HTTP service.",
            "Review collected source and robots.txt artefacts for the high-port service.",
            "Locally validate hash-shaped or encoded-looking artefacts.",
            "Record request/response evidence before escalating.",
            "Stop if evidence remains generic/default-page noise.",
        ),
        kill_switch_guidance="Stop if the service is generic, unchanged, or outside authorised scope.",
    )


def _hidden_path_thread(
    project_state: ProjectState,
    candidates: Sequence[Candidate],
) -> _ThreadDraft | None:
    endpoints: list[str] = []
    evidence_ids: list[str] = []
    related_candidates = [
        item for item in candidates if item.candidate_type == "hidden_path_review"
    ]
    for candidate in related_candidates:
        endpoints.extend(candidate.affected_endpoints)
        evidence_ids.extend(candidate.evidence_ids)
    for path in project_state.discovered_paths:
        if _path_contains_hidden_word(path.url):
            endpoints.append(path.url)
            evidence_ids.extend(path.evidence_ids)
    for endpoint in project_state.endpoints:
        if _path_contains_hidden_word(endpoint.path):
            endpoints.append(endpoint.url)
            evidence_ids.extend(endpoint.evidence_ids)

    if not endpoints and not related_candidates:
        return None
    return _ThreadDraft(
        title="Discovered hidden-path review",
        priority=_highest_priority([*(item.priority for item in related_candidates), "medium"]),
        category="discovered_content",
        summary=(
            "Hidden-looking discovered paths may deserve bounded manual review "
            "when linked to stronger context."
        ),
        why_it_matters="Hidden-looking paths can concentrate useful context, but many are generic noise.",
        related_endpoints=_unique_sorted(endpoints),
        related_evidence_ids=_unique_sorted(evidence_ids),
        related_candidate_ids=_unique_sorted(item.id for item in related_candidates),
        related_lead_ids=(),
        suggested_manual_review_order=(
            "Review the collected response for the discovered path.",
            "Check whether the path is linked to stronger artefacts.",
            "Avoid repeated effort if the page is generic or unchanged.",
            "Record manual observations before escalating.",
        ),
        kill_switch_guidance="Avoid repeated effort when hidden-looking paths are default, empty, or unchanged.",
    )


def _encoded_or_source_thread(
    project_state: ProjectState,
    candidates: Sequence[Candidate],
    review_leads: Sequence[ReviewLead],
) -> _ThreadDraft | None:
    related_candidates = [
        item for item in candidates if item.candidate_type in ENCODED_CANDIDATE_TYPES
    ]
    related_leads = [
        lead
        for lead in review_leads
        if lead.related_artefact_types
        or lead.category == "html_source"
        or lead.lead_type in {"possible_hash", "possible_transform"}
    ]
    evidence_ids: list[str] = []
    endpoints: list[str] = []
    for candidate in related_candidates:
        evidence_ids.extend(candidate.evidence_ids)
        endpoints.extend(candidate.affected_endpoints)
    for artifact in project_state.http_artifacts:
        if artifact.artifact_type in {"encoded_like_artifact", "html_comment"}:
            evidence_ids.extend(artifact.evidence_ids)
            if artifact.url:
                endpoints.append(artifact.url)
    for lead in related_leads:
        if lead.url:
            endpoints.append(lead.url)

    if not related_candidates and not related_leads:
        return None
    return _ThreadDraft(
        title="Encoded or source artefact review",
        priority=_highest_priority(
            [*(item.priority for item in related_candidates), *(lead.priority for lead in related_leads), "medium"]
        ),
        category="artefact_interpretation",
        summary=(
            "Encoded-looking, hash-shaped, or source-level artefacts should be "
            "reviewed after their surrounding service and path context."
        ),
        why_it_matters=(
            "Source and transform signals are review prompts that need local "
            "validation and correlation before any claim."
        ),
        related_endpoints=_unique_sorted(endpoints),
        related_evidence_ids=_unique_sorted(evidence_ids),
        related_candidate_ids=_unique_sorted(item.id for item in related_candidates),
        related_lead_ids=_unique_sorted(lead.lead_id for lead in related_leads),
        suggested_manual_review_order=(
            "Review the surrounding source context first.",
            "Validate artefacts locally.",
            "Correlate with robots.txt, hidden paths, or service context.",
            "Do not submit artefacts to online decoders or hash databases automatically.",
            "Do not treat decoded content as valid credentials without authorisation and manual validation.",
        ),
        kill_switch_guidance="Stop if decoded previews remain generic or cannot be tied to stronger evidence.",
    )


def _assign_thread_ids(drafts: list[_ThreadDraft]) -> tuple[InvestigationThread, ...]:
    sorted_drafts = sorted(drafts, key=_thread_sort_key)
    return tuple(
        InvestigationThread(
            thread_id=f"THREAD-{index:04d}",
            title=draft.title,
            priority=draft.priority,
            category=draft.category,
            summary=draft.summary,
            why_it_matters=draft.why_it_matters,
            related_endpoints=draft.related_endpoints,
            related_evidence_ids=draft.related_evidence_ids,
            related_candidate_ids=draft.related_candidate_ids,
            related_lead_ids=draft.related_lead_ids,
            suggested_manual_review_order=draft.suggested_manual_review_order,
            kill_switch_guidance=draft.kill_switch_guidance,
        )
        for index, draft in enumerate(sorted_drafts, start=1)
    )


def _thread_sort_key(draft: _ThreadDraft) -> tuple[object, ...]:
    first_context = (
        draft.related_endpoints[0]
        if draft.related_endpoints
        else draft.related_evidence_ids[0]
        if draft.related_evidence_ids
        else ""
    )
    return (
        THREAD_CATEGORY_ORDER.get(draft.category, 99),
        PRIORITY_ORDER.get(draft.priority, 99),
        draft.title,
        first_context,
    )


def _highest_priority(priorities: Sequence[str]) -> str:
    return min(priorities, key=lambda item: PRIORITY_ORDER.get(item, 99))


def _is_high_port_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.port is not None and parsed.port not in {80, 443}


def _path_contains_hidden_word(value: str) -> bool:
    path = urlparse(value).path if "://" in value else value
    lowered = path.lower()
    return any(f"/{word}" in lowered for word in HIDDEN_PATH_WORDS)


def _unique_sorted(values) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}))
