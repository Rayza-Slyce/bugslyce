"""Offline Standard investigation thread grouping."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlparse

from bugslyce.core.engagement_context import engagement_context_review_guidance
from bugslyce.core.models import Candidate, ProjectState
from bugslyce.recon.interpretation import ReviewLead
from bugslyce.reports.artifact_classifier import (
    LIKELY_NOISE,
    classify_encoded_artifact,
    classify_http_service_priority,
)
from bugslyce.recon.http_origin import HttpOrigin, http_origin_from_url
from bugslyce.triage.workflow_leads import WorkflowLead


PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}
THREAD_CATEGORY_ORDER = {
    "account_workflow": 0,
    "object_reference_surface": 1,
    "http_service": 2,
    "discovered_content": 3,
    "artefact_interpretation": 4,
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
MAX_WORKFLOW_EVIDENCE_IDS = 12


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
    *,
    workflow_leads: Sequence[WorkflowLead] = (),
) -> tuple[InvestigationThread, ...]:
    """Build deterministic investigation threads from existing offline evidence."""

    drafts: list[_ThreadDraft] = []
    drafts.extend(_workflow_thread(lead) for lead in workflow_leads)
    drafts.extend(_high_port_http_threads(project_state, candidates, review_leads))
    hidden_path = _hidden_path_thread(project_state, candidates)
    if hidden_path is not None:
        drafts.append(hidden_path)
    encoded = _encoded_or_source_thread(project_state, candidates, review_leads)
    if encoded is not None:
        drafts.append(encoded)
    return _assign_thread_ids(drafts)


def _workflow_thread(lead: WorkflowLead) -> _ThreadDraft:
    return _ThreadDraft(
        title=lead.title,
        priority=lead.priority,
        category=lead.category,
        summary=lead.summary,
        why_it_matters=lead.why_it_matters,
        related_endpoints=lead.representative_urls,
        related_evidence_ids=lead.evidence_ids[:MAX_WORKFLOW_EVIDENCE_IDS],
        related_candidate_ids=(),
        related_lead_ids=(),
        suggested_manual_review_order=(
            lead.suggested_manual_action,
            (
                "Use the Human Triage section in `report.md` and, when present, "
                "the detailed `deep_recon_review.md` provenance before acting."
            ),
        ),
        kill_switch_guidance=(
            "Stop if the retained evidence does not support the grouped workflow; "
            "do not submit forms, attempt authentication, mutate parameters, or infer a vulnerability."
        ),
    )


def render_investigation_threads_markdown(
    threads: Sequence[InvestigationThread],
    *,
    engagement_context: str | None = None,
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
    if engagement_context is not None:
        lines.extend([engagement_context_review_guidance(engagement_context), ""])
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
    *,
    engagement_context: str | None = None,
) -> str:
    """Render a concise Standard-only runbook workflow from investigation threads."""

    lines = [
        "## Standard Investigation Workflow",
        "",
        (
            "These steps are derived from offline Investigation Threads and are "
            "manual review prompts, not confirmed findings."
        ),
        (
            "Use the report's Offline Route/Source Review section to cross-check "
            "observed route references before manual testing."
        ),
        "",
    ]
    if engagement_context is not None:
        lines.extend([engagement_context_review_guidance(engagement_context), ""])
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


def _high_port_http_threads(
    project_state: ProjectState,
    candidates: Sequence[Candidate],
    review_leads: Sequence[ReviewLead],
) -> tuple[_ThreadDraft, ...]:
    endpoints_by_origin: dict[HttpOrigin, set[str]] = {}
    for service in project_state.http_services:
        if _is_high_port_url(service.url):
            origin = http_origin_from_url(service.url)
            if origin is not None:
                endpoints_by_origin.setdefault(origin, set()).add(service.url)

    candidate_types = {"high_port_http_service", "multiple_http_services"}
    related_candidates = [item for item in candidates if item.candidate_type in candidate_types]
    for candidate in related_candidates:
        for endpoint in candidate.affected_endpoints:
            if not _is_high_port_url(endpoint):
                continue
            origin = http_origin_from_url(endpoint)
            if origin is not None:
                endpoints_by_origin.setdefault(origin, set()).add(endpoint)

    related_leads = [lead for lead in review_leads if lead.url and _is_high_port_url(lead.url)]
    for lead in related_leads:
        if lead.url:
            origin = http_origin_from_url(lead.url)
            if origin is not None:
                endpoints_by_origin.setdefault(origin, set()).add(lead.url)

    origins_by_priority: dict[str, set[HttpOrigin]] = {"medium": set(), "low": set()}
    for origin in endpoints_by_origin:
        representative = sorted(endpoints_by_origin[origin])[0]
        priority = classify_http_service_priority(
            project_state,
            representative,
        ).priority
        origins_by_priority["low" if priority == "low" else "medium"].add(origin)

    return tuple(
        draft
        for priority in ("medium", "low")
        if origins_by_priority[priority]
        for draft in (
            _high_port_http_thread_for_origins(
                project_state,
                related_candidates,
                related_leads,
                endpoints_by_origin,
                origins_by_priority[priority],
                priority=priority,
            ),
        )
    )


def _high_port_http_thread_for_origins(
    project_state: ProjectState,
    related_candidates: Sequence[Candidate],
    related_leads: Sequence[ReviewLead],
    endpoints_by_origin: dict[HttpOrigin, set[str]],
    origins: set[HttpOrigin],
    *,
    priority: str,
) -> _ThreadDraft:
    generic_only = priority == "low"
    endpoints = sorted(
        endpoint
        for origin in origins
        for endpoint in endpoints_by_origin[origin]
    )
    evidence_ids = [
        evidence_id
        for service in project_state.http_services
        if http_origin_from_url(service.url) in origins
        for evidence_id in service.evidence_ids
    ]
    matching_candidates = [
        candidate
        for candidate in related_candidates
        if _candidate_origins(candidate) & origins
    ]
    for candidate in matching_candidates:
        candidate_origins = _candidate_origins(candidate)
        if candidate_origins and candidate_origins <= origins:
            evidence_ids.extend(candidate.evidence_ids)
    matching_leads = [
        lead
        for lead in related_leads
        if lead.url and http_origin_from_url(lead.url) in origins
    ]
    return _ThreadDraft(
        title=(
            "Generic high-port HTTP service context"
            if generic_only
            else "High-port HTTP application review"
        ),
        priority=priority,
        category="http_service",
        summary=(
            "A generic/default landing page was observed on a non-default HTTP "
            "port and remains low-priority service inventory context."
            if generic_only
            else "A non-default HTTP port or multiple HTTP services may indicate a "
            "separate application surface."
        ),
        why_it_matters=(
            "The unusual port remains useful for service mapping, but it does not "
            "outweigh direct application evidence by itself."
            if generic_only
            else "Different HTTP ports on the same host can expose distinct application "
            "contexts, configuration, or review signals."
        ),
        related_endpoints=tuple(endpoints),
        related_evidence_ids=_unique_sorted(evidence_ids),
        related_candidate_ids=_unique_sorted(item.id for item in matching_candidates),
        related_lead_ids=_unique_sorted(lead.lead_id for lead in matching_leads),
        suggested_manual_review_order=(
            "Compare the high-port service with the default HTTP service.",
            "Review collected source and robots.txt artefacts for the high-port service.",
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
    hidden_source_artifacts = [
        artifact
        for artifact in project_state.http_artifacts
        if artifact.artifact_type == "hidden_element"
        and classify_encoded_artifact(artifact).category != LIKELY_NOISE
    ]
    evidence_ids: list[str] = []
    endpoints: list[str] = []
    for candidate in related_candidates:
        evidence_ids.extend(candidate.evidence_ids)
        endpoints.extend(candidate.affected_endpoints)
    for artifact in project_state.http_artifacts:
        if artifact.artifact_type in {
            "encoded_like_artifact",
            "hidden_element",
            "html_comment",
        }:
            evidence_ids.extend(artifact.evidence_ids)
            if artifact.url:
                endpoints.append(artifact.url)
    for lead in related_leads:
        if lead.url:
            endpoints.append(lead.url)

    if not related_candidates and not related_leads and not hidden_source_artifacts:
        return None
    has_encoded_evidence = _has_encoded_thread_evidence(
        project_state,
        related_candidates,
        related_leads,
    )
    has_credential_candidate = any(
        item.candidate_type == "credential_like_artifact_review"
        for item in related_candidates
    )
    title = (
        "Encoded or source artefact review"
        if has_encoded_evidence
        else "Source artefact review"
    )
    summary = (
        "Encoded-looking, hash-shaped, or source-level artefacts should be "
        "reviewed after their surrounding service and path context."
        if has_encoded_evidence
        else "Source-level artefacts should be reviewed after their surrounding "
        "service and path context."
    )
    review_order = ["Review the surrounding source context first."]
    if has_encoded_evidence:
        review_order.append("Validate encoded or hash-shaped artefacts locally.")
    review_order.append("Correlate with robots.txt, hidden paths, or service context.")
    if has_encoded_evidence:
        review_order.append(
            "Do not submit artefacts to online decoders or hash databases automatically."
        )
    if has_credential_candidate:
        review_order.append(
            "Do not treat source values as valid credentials without authorisation "
            "and manual validation."
        )
    if not has_encoded_evidence:
        review_order.append(
            "Record exact source evidence before escalating a manual-review lead."
        )
    return _ThreadDraft(
        title=title,
        priority=_highest_priority(
            [*(item.priority for item in related_candidates), *(lead.priority for lead in related_leads), "medium"]
        ),
        category="artefact_interpretation",
        summary=summary,
        why_it_matters=(
            "Source and transform signals are review prompts that need local "
            "validation and correlation before any claim."
            if has_encoded_evidence
            else "Source evidence is a manual-review prompt that needs local "
            "validation and correlation before any claim."
        ),
        related_endpoints=_unique_sorted(endpoints),
        related_evidence_ids=_unique_sorted(evidence_ids),
        related_candidate_ids=_unique_sorted(item.id for item in related_candidates),
        related_lead_ids=_unique_sorted(lead.lead_id for lead in related_leads),
        suggested_manual_review_order=tuple(review_order),
        kill_switch_guidance=(
            "Stop if decoded previews remain generic or cannot be tied to stronger evidence."
            if has_encoded_evidence
            else "Stop if source context remains generic or cannot be tied to stronger evidence."
        ),
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
        PRIORITY_ORDER.get(draft.priority, 99),
        THREAD_CATEGORY_ORDER.get(draft.category, 99),
        draft.title,
        first_context,
    )


def _has_encoded_thread_evidence(
    project_state: ProjectState,
    candidates: Sequence[Candidate],
    review_leads: Sequence[ReviewLead],
) -> bool:
    if any(item.candidate_type == "encoded_artifact_review" for item in candidates):
        return True
    if any(
        lead.lead_type in {"possible_hash", "possible_transform"}
        or any(
            marker in related.lower()
            for related in lead.related_artefact_types
            for marker in ("base64", "encoded", "hash", "transform")
        )
        for lead in review_leads
    ):
        return True
    return any(
        artifact.artifact_type == "encoded_like_artifact"
        and classify_encoded_artifact(artifact).category != LIKELY_NOISE
        for artifact in project_state.http_artifacts
    )


def _highest_priority(priorities: Sequence[str]) -> str:
    return min(priorities, key=lambda item: PRIORITY_ORDER.get(item, 99))


def _is_high_port_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.port is not None and parsed.port not in {80, 443}
    except (TypeError, ValueError):
        return False


def _candidate_origins(candidate: Candidate) -> set[HttpOrigin]:
    return {
        origin
        for endpoint in candidate.affected_endpoints
        if (origin := http_origin_from_url(endpoint)) is not None
        and _is_high_port_url(endpoint)
    }


def _path_contains_hidden_word(value: str) -> bool:
    path = urlparse(value).path if "://" in value else value
    lowered = path.lower()
    return any(f"/{word}" in lowered for word in HIDDEN_PATH_WORDS)


def _unique_sorted(values) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}))
