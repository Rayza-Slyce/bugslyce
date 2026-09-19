"""Offline Standard investigation thread grouping."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Protocol
from urllib.parse import urljoin, urlparse

from bugslyce.core.engagement_context import engagement_context_review_guidance
from bugslyce.core.models import Candidate, HTTPArtifact, ProjectState
from bugslyce.recon.application_service_composition import (
    ApplicationServiceRelationKind,
    ApplicationServiceSupportBasis,
)
from bugslyce.recon.application_service_model import ApplicationServiceModel
from bugslyce.recon.deep_collection_review_bundle import DeepCollectionReviewPriority
from bugslyce.recon.deep_metadata_review import DeepMetadataReviewLead
from bugslyce.recon.deep_response_similarity_review import (
    DeepResponseSimilarityReview,
    PAGE_REVIEW_WEAKENING_GROUP_CATEGORIES,
)
from bugslyce.recon.deep_successful_content import (
    SuccessfulDeepContentReview,
    prometheus_metrics_exposition,
)
from bugslyce.recon.http_route_relationships import canonical_relationship_url
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
    "application_interface": 2,
    "http_service": 3,
    "discovered_content": 4,
    "artefact_interpretation": 5,
    "service_context": 6,
}
_COMPATIBILITY_SUMMARY_FAMILIES = frozenset(
    {
        "structured_configuration_body",
        "structured_json_routes",
        "distinctive_access_boundary_response",
        "directory_listing_response",
        "fetched_application_page",
        "successful_deep_content",
        "smb_disk_share_review",
        "non_http_service_context",
        "unusual_robots_user_agent",
    }
)
class CompatibilitySummaryLead(Protocol):
    """Legacy summary evidence accepted without importing ranking authority."""

    lead_type: str
    endpoints: Sequence[str]
    evidence_ids: Sequence[str]


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
    related_native_observation_ids: tuple[str, ...] = ()
    related_application_relation_ids: tuple[str, ...] = ()
    limitation_codes: tuple[str, ...] = ()
    subsumed_by_thread_id: str | None = None
    subsumption_reason: str | None = None

    def __post_init__(self) -> None:
        if (self.subsumed_by_thread_id is None) != (self.subsumption_reason is None):
            raise ValueError(
                "investigation thread subsumption requires both parent ID and reason"
            )
        if self.subsumption_reason is not None and not self.subsumption_reason.strip():
            raise ValueError(
                "investigation thread subsumption reason must not be empty"
            )


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
    identity_key: tuple[str, ...] = ()
    related_native_observation_ids: tuple[str, ...] = ()
    related_application_relation_ids: tuple[str, ...] = ()
    limitation_codes: tuple[str, ...] = ()
    attention_coverage_urls: tuple[str, ...] = ()
    compatibility_lead_type: str | None = None


def build_investigation_threads(
    project_state: ProjectState,
    candidates: Sequence[Candidate] = (),
    review_leads: Sequence[ReviewLead] = (),
    *,
    workflow_leads: Sequence[WorkflowLead] = (),
    application_service_model: ApplicationServiceModel | None = None,
    compatibility_summary_leads: Sequence[CompatibilitySummaryLead] = (),
    response_similarity_review: DeepResponseSimilarityReview | None = None,
    successful_content_reviews: Sequence[SuccessfulDeepContentReview] = (),
    collection_review_priorities: Sequence[DeepCollectionReviewPriority] = (),
    metadata_review_leads: Sequence[DeepMetadataReviewLead] = (),
) -> tuple[InvestigationThread, ...]:
    """Build deterministic investigation threads from existing offline evidence."""

    if any(
        not isinstance(review, SuccessfulDeepContentReview)
        for review in successful_content_reviews
    ):
        raise TypeError(
            "successful content reviews must be SuccessfulDeepContentReview values"
        )
    if any(
        not isinstance(priority, DeepCollectionReviewPriority)
        for priority in collection_review_priorities
    ):
        raise TypeError(
            "collection review priorities must be DeepCollectionReviewPriority values"
        )
    if any(
        not isinstance(lead, DeepMetadataReviewLead)
        for lead in metadata_review_leads
    ):
        raise TypeError(
            "metadata review leads must be DeepMetadataReviewLead values"
        )

    drafts: list[_ThreadDraft] = []
    drafts.extend(_workflow_thread(lead) for lead in workflow_leads)
    drafts.extend(_high_port_http_threads(project_state, candidates, review_leads))
    hidden_path = _hidden_path_thread(
        project_state,
        candidates,
        response_similarity_review,
    )
    if hidden_path is not None:
        drafts.append(hidden_path)
    encoded = _encoded_or_source_thread(project_state, candidates, review_leads)
    if encoded is not None:
        drafts.append(encoded)
    if application_service_model is not None:
        drafts.extend(_application_interface_threads(application_service_model))
    drafts.extend(_collection_review_threads(collection_review_priorities))
    drafts.extend(
        _compatibility_summary_threads(
            project_state,
            compatibility_summary_leads,
            successful_content_reviews,
            metadata_review_leads,
        )
    )
    return _assign_thread_ids(drafts)


def _collection_review_threads(
    priorities: Sequence[DeepCollectionReviewPriority],
) -> tuple[_ThreadDraft, ...]:
    drafts: list[_ThreadDraft] = []

    for priority in priorities:
        if priority.category != "security_metadata_found":
            continue
        if (
            "metadata_collection_review" not in priority.source_sections
            or not priority.related_urls
            or not priority.related_evidence_ids
        ):
            continue

        urls = _unique_sorted(priority.related_urls)
        evidence_ids = _unique_sorted(priority.related_evidence_ids)

        drafts.append(
            _ThreadDraft(
                title="Security reporting metadata successfully collected",
                priority="medium",
                category="application_interface",
                summary=(
                    "A bounded metadata request successfully collected a "
                    "security.txt response for offline review."
                ),
                why_it_matters=(
                    "security.txt can provide reporting and policy context for "
                    "authorised review, but successful collection does not by "
                    "itself establish a vulnerability."
                ),
                related_endpoints=urls,
                related_evidence_ids=evidence_ids,
                related_candidate_ids=(),
                related_lead_ids=(),
                suggested_manual_review_order=(
                    priority.suggested_manual_review,
                ),
                kill_switch_guidance=(
                    "Treat the retained security metadata as reporting or policy "
                    "context only; do not infer a vulnerability from successful "
                    "collection."
                ),
                identity_key=("security_metadata_found", *urls),
                limitation_codes=(
                    "security_metadata_not_security_finding",
                ),
            )
        )

    return tuple(drafts)


def _workflow_thread(lead: WorkflowLead) -> _ThreadDraft:
    return _ThreadDraft(
        title=lead.title,
        priority=lead.priority,
        category=lead.category,
        summary=lead.summary,
        why_it_matters=lead.why_it_matters,
        related_endpoints=lead.representative_urls,
        related_evidence_ids=lead.evidence_ids,
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
        attention_coverage_urls=(
            _unique_sorted(lead.covered_urls)
            if lead.category == "account_workflow"
            else ()
        ),
    )



def primary_investigation_threads(
    threads: Sequence[InvestigationThread],
) -> tuple[InvestigationThread, ...]:
    """Project canonical primary attention without re-inferring subsumption."""

    if any(not isinstance(thread, InvestigationThread) for thread in threads):
        raise TypeError(
            "primary investigation-thread projection requires "
            "InvestigationThread values"
        )

    by_id = {thread.thread_id: thread for thread in threads}
    for thread in threads:
        parent_id = thread.subsumed_by_thread_id
        if parent_id is None:
            continue
        if parent_id == thread.thread_id or parent_id not in by_id:
            raise ValueError(
                "investigation thread has an invalid subsumption parent"
            )

    return tuple(
        thread
        for thread in threads
        if thread.subsumed_by_thread_id is None
    )


def _subsumed_investigation_threads(
    threads: Sequence[InvestigationThread],
) -> tuple[InvestigationThread, ...]:
    primary_investigation_threads(threads)
    return tuple(
        thread
        for thread in threads
        if thread.subsumed_by_thread_id is not None
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

    primary_threads = primary_investigation_threads(threads)
    subsumed_threads = _subsumed_investigation_threads(threads)

    if not primary_threads:
        lines.extend(
            [
                "No investigation threads were generated from the provided evidence.",
                "",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    for thread in primary_threads:
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

    if subsumed_threads:
        lines.extend(["### Subsumed Supporting Threads", ""])

        for thread in subsumed_threads:
            lines.extend(
                [
                    f"#### {thread.thread_id}: {thread.title}",
                    "",
                    f"- Subsumed by: `{thread.subsumed_by_thread_id}`",
                    f"- Reason: {thread.subsumption_reason}",
                ]
            )

            if thread.related_endpoints:
                lines.append("- Related endpoints:")
                lines.extend(
                    f"  - `{endpoint}`"
                    for endpoint in thread.related_endpoints
                )

            if thread.related_evidence_ids:
                lines.append(
                    "- Related evidence IDs: "
                    + ", ".join(
                        f"`{item}`"
                        for item in thread.related_evidence_ids
                    )
                )

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

    primary_threads = primary_investigation_threads(threads)

    if not primary_threads:
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

    for thread in primary_threads:
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


def _response_family_weakening_for_endpoints(
    endpoints: tuple[str, ...],
    response_similarity_review: DeepResponseSimilarityReview | None,
) -> tuple[bool, tuple[str, ...]]:
    if response_similarity_review is None or not endpoints:
        return False, ()

    evidence_by_url: dict[str, set[str]] = {}
    for group in response_similarity_review.groups:
        if group.category not in PAGE_REVIEW_WEAKENING_GROUP_CATEGORIES:
            continue
        group_evidence_ids = _unique_sorted(group.evidence_ids)
        if not group_evidence_ids:
            continue
        for requested_url in group.requested_urls:
            canonical_url = canonical_relationship_url(requested_url)
            if canonical_url:
                evidence_by_url.setdefault(canonical_url, set()).update(
                    group_evidence_ids
                )

    endpoint_urls: list[str] = []
    for endpoint in endpoints:
        canonical_url = canonical_relationship_url(endpoint)
        if not canonical_url:
            return False, ()
        endpoint_urls.append(canonical_url)

    if not all(url in evidence_by_url for url in endpoint_urls):
        return False, ()

    return True, _unique_sorted(
        evidence_id
        for url in endpoint_urls
        for evidence_id in evidence_by_url[url]
    )


def _hidden_path_thread(
    project_state: ProjectState,
    candidates: Sequence[Candidate],
    response_similarity_review: DeepResponseSimilarityReview | None = None,
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

    related_endpoints = _unique_sorted(endpoints)
    weakened, weakening_evidence_ids = _response_family_weakening_for_endpoints(
        related_endpoints,
        response_similarity_review,
    )
    if weakened:
        evidence_ids.extend(weakening_evidence_ids)

    return _ThreadDraft(
        title="Discovered hidden-path review",
        priority=(
            "low"
            if weakened
            else _highest_priority(
                [*(item.priority for item in related_candidates), "medium"]
            )
        ),
        category="discovered_content",
        summary=(
            "Hidden-looking discovered paths are retained, but repeated "
            "response-family context weakens their standalone lexical signal."
            if weakened
            else (
                "Hidden-looking discovered paths may deserve bounded manual review "
                "when linked to stronger context."
            )
        ),
        why_it_matters=(
            "Repeated response-family context weakens the lexical path-name signal; "
            "the retained routes remain useful as review evidence but should not be "
            "treated as distinct application behaviour by path name alone."
            if weakened
            else (
                "Hidden-looking paths can concentrate useful context, but many are "
                "generic noise."
            )
        ),
        related_endpoints=related_endpoints,
        related_evidence_ids=_unique_sorted(evidence_ids),
        related_candidate_ids=_unique_sorted(
            item.id for item in related_candidates
        ),
        related_lead_ids=(),
        suggested_manual_review_order=(
            "Review the collected response for the discovered path.",
            "Check whether the path is linked to stronger artefacts.",
            "Avoid repeated effort if the page is generic or unchanged.",
            "Record manual observations before escalating.",
        ),
        kill_switch_guidance=(
            "Avoid repeated effort when hidden-looking paths are default, "
            "empty, or unchanged."
        ),
        limitation_codes=(
            ("response_family_weakens_path_name_signal",)
            if weakened
            else ()
        ),
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
    direct_source_artifacts = (
        _direct_source_artifacts(project_state)
        if not related_candidates and not related_leads
        else ()
    )
    evidence_ids: list[str] = []
    endpoints: list[str] = []
    for candidate in related_candidates:
        evidence_ids.extend(candidate.evidence_ids)
        endpoints.extend(candidate.affected_endpoints)
    for lead in related_leads:
        evidence_ids.extend(lead.evidence_ids)
        if lead.url:
            endpoints.append(lead.url)
    for artifact in direct_source_artifacts:
        evidence_ids.extend(artifact.evidence_ids)
        if artifact.url:
            endpoints.append(artifact.url)

    if not related_candidates and not related_leads and not direct_source_artifacts:
        return None
    has_encoded_evidence = _has_encoded_thread_evidence(
        related_candidates,
        related_leads,
        direct_source_artifacts,
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


def _native_observation_id(candidate_index: int, exchange_index: int) -> str:
    return f"native-observation:{candidate_index}:{exchange_index}"


def _hostname_path_subject(
    value: str,
) -> tuple[str, str, str, str] | None:
    parsed = urlparse(value)
    if not parsed.hostname:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    scheme = parsed.scheme.casefold()
    hostname = parsed.hostname.casefold().rstrip(".")
    path = parsed.path.rstrip("/") or "/"
    query = parsed.query

    if (
        (scheme == "http" and port in (None, 80))
        or (scheme == "https" and port in (None, 443))
    ):
        transport_subject = "default-http-https"
    else:
        transport_subject = f"{scheme}:{'' if port is None else port}"

    return hostname, path, query, transport_subject


def _api_graphql_route(value: str) -> bool:
    parsed = urlparse(value)
    hostname = parsed.hostname.casefold().rstrip(".") if parsed.hostname else ""
    labels = hostname.split(".") if hostname else ()
    segments = tuple(
        segment.casefold() for segment in parsed.path.split("/") if segment
    )
    return "api" in labels or "api" in segments or "graphql" in segments


def _application_interface_threads(
    model: ApplicationServiceModel,
) -> tuple[_ThreadDraft, ...]:
    if not isinstance(model, ApplicationServiceModel):
        raise TypeError("application service model must be typed")

    routes_by_id = {
        route.entity_id: route
        for route in model.application_composition.routes
    }
    source_sets_by_id = {
        source_set.entity_id: source_set
        for source_set in model.application_composition.source_sets
    }
    native_evidence = model.native_observation_evidence
    mobile_sources = {
        _native_observation_id(item.candidate_index, item.exchange_index)
        for item in native_evidence.mobile_association_declarations
    }
    facts_by_subject = {}
    for fact in native_evidence.structured_responses:
        source_id = _native_observation_id(fact.candidate_index, fact.exchange_index)
        if source_id in mobile_sources:
            continue
        subject = _hostname_path_subject(fact.request_url)
        if subject is not None:
            facts_by_subject.setdefault(subject, []).append(fact)

    drafts: list[_ThreadDraft] = []

    for subject in sorted(facts_by_subject):
        facts = tuple(
            sorted(
                facts_by_subject[subject],
                key=lambda item: (
                    item.candidate_index,
                    item.exchange_index,
                    item.body_sha256,
                ),
            )
        )

        matched_redirects = tuple(
            redirect
            for redirect in native_evidence.redirect_relationships
            if (
                _hostname_path_subject(redirect.source_url) == subject
                or _hostname_path_subject(redirect.target_url) == subject
            )
        )

        relation_ids = set()
        for relation in model.application_composition.relations:
            if relation.relation_kind is not ApplicationServiceRelationKind.REDIRECTS_TO:
                continue

            source = routes_by_id.get(relation.source_entity_id)
            target = routes_by_id.get(relation.target_entity_id)
            if source is None or target is None:
                continue

            if any(
                source.canonical_url == redirect.source_url
                and target.canonical_url == redirect.target_url
                for redirect in matched_redirects
            ):
                relation_ids.add(relation.relation_id)

        native_observation_ids = {
            _native_observation_id(
                fact.candidate_index,
                fact.exchange_index,
            )
            for fact in facts
        }
        native_observation_ids.update(
            redirect.source_id
            for redirect in matched_redirects
        )

        endpoints = {fact.request_url for fact in facts}
        for redirect in matched_redirects:
            endpoints.add(redirect.source_url)
            endpoints.add(redirect.target_url)

        limitations = set()
        if any(not fact.confirmed_api for fact in facts):
            limitations.add("structured_response_not_confirmed_api")
        if any(not redirect.destination_fetched for redirect in matched_redirects):
            limitations.add("redirect_destination_not_fetched")

        drafts.append(
            _ThreadDraft(
                title="Observed structured application interface",
                priority="medium",
                category="application_interface",
                summary=(
                    "A directly observed response contains structured JSON "
                    "content suitable for bounded application review."
                ),
                why_it_matters=(
                    "Structured application responses can reveal useful interface "
                    "and business context without proving an API or vulnerability."
                ),
                related_endpoints=_unique_sorted(endpoints),
                related_evidence_ids=(),
                related_candidate_ids=(),
                related_lead_ids=(),
                suggested_manual_review_order=(
                    "Review the retained structured response and its surrounding application context.",
                    "Correlate related redirects and documented interfaces before escalating.",
                    "Do not infer API status, authentication behaviour, or vulnerability from structure alone.",
                ),
                kill_switch_guidance=(
                    "Stop if the retained response is generic, unrelated to the "
                    "application under review, or outside authorised scope."
                ),
                identity_key=("structured_response", *subject),
                related_native_observation_ids=_unique_sorted(
                    native_observation_ids
                ),
                related_application_relation_ids=_unique_sorted(
                    relation_ids
                ),
                limitation_codes=_unique_sorted(limitations),
            )
        )

    mobile_groups: dict[tuple[str, str], list[object]] = {}
    for declaration in native_evidence.mobile_association_declarations:
        mobile_groups.setdefault(
            (declaration.platform, declaration.package_name), []
        ).append(declaration)
    for platform, package_name in sorted(mobile_groups):
        declarations = tuple(
            sorted(
                mobile_groups[(platform, package_name)],
                key=lambda item: (
                    item.candidate_index,
                    item.exchange_index,
                    item.document_url,
                ),
            )
        )
        drafts.append(
            _ThreadDraft(
                title=(
                    f"Observed {platform} application association: {package_name}"
                ),
                priority="medium",
                category="application_interface",
                summary=(
                    "Retained mobile association documents directly declare this "
                    f"{platform} application package."
                ),
                why_it_matters=(
                    "Mobile association declarations can provide useful application "
                    "and deep-link context without establishing ownership or impact."
                ),
                related_endpoints=_unique_sorted(
                    item.document_url for item in declarations
                ),
                related_evidence_ids=(),
                related_candidate_ids=(),
                related_lead_ids=(),
                suggested_manual_review_order=(
                    "Review the retained association documents and surrounding application context.",
                    "Do not infer application ownership, reachability, or a vulnerability from the declaration alone.",
                ),
                kill_switch_guidance=(
                    "Stop if the declaration cannot be tied to useful authorised "
                    "application context."
                ),
                identity_key=("mobile_association", platform, package_name),
                related_native_observation_ids=_unique_sorted(
                    _native_observation_id(item.candidate_index, item.exchange_index)
                    for item in declarations
                ),
                limitation_codes=("mobile_association_ownership_not_confirmed",),
            )
        )

    redirect_boundaries: dict[str, list[object]] = {}
    for relation in model.application_composition.relations:
        if relation.relation_kind is not ApplicationServiceRelationKind.REDIRECTS_TO:
            continue
        if not any(
            support.basis is ApplicationServiceSupportBasis.DIRECT_OBSERVATION
            for support in relation.supports
        ):
            continue
        source = routes_by_id.get(relation.source_entity_id)
        target = routes_by_id.get(relation.target_entity_id)
        if source is None or target is None:
            continue
        source_origin = http_origin_from_url(source.canonical_url)
        target_origin = http_origin_from_url(target.canonical_url)
        if (
            source_origin is None
            or target_origin is None
            or source_origin.hostname == target_origin.hostname
        ):
            continue
        redirect_boundaries.setdefault(target_origin.origin_url, []).append(relation)
    for target_origin, relations in sorted(redirect_boundaries.items()):
        related_endpoints: set[str] = set()
        evidence_ids: set[str] = set()
        native_ids: set[str] = set()
        limitations: set[str] = set()
        relation_ids: set[str] = set()
        for relation in relations:
            source = routes_by_id[relation.source_entity_id]
            target = routes_by_id[relation.target_entity_id]
            related_endpoints.update((source.canonical_url, target.canonical_url))
            relation_ids.add(relation.relation_id)
            for support in relation.supports:
                if support.basis is not ApplicationServiceSupportBasis.DIRECT_OBSERVATION:
                    continue
                source_id = support.source_reference.source_id
                if source_id.startswith("native-observation:"):
                    native_ids.add(source_id)
                    evidence_ids.update(
                        evidence_id
                        for evidence_id in support.evidence_ids
                        if evidence_id != source_id
                    )
                    limitations.add("redirect_destination_not_fetched")
                else:
                    evidence_ids.update(support.evidence_ids)
        hostname = urlparse(target_origin).hostname or target_origin
        drafts.append(
            _ThreadDraft(
                title=f"Observed redirect/service boundary to {hostname}",
                priority="medium",
                category="application_interface",
                summary=(
                    "Retained direct redirect evidence crosses from the observed "
                    "application to this service origin."
                ),
                why_it_matters=(
                    "Cross-origin redirects can identify account or service "
                    "boundaries worth bounded contextual review."
                ),
                related_endpoints=_unique_sorted(related_endpoints),
                related_evidence_ids=_unique_sorted(evidence_ids),
                related_candidate_ids=(),
                related_lead_ids=(),
                suggested_manual_review_order=(
                    "Review the retained redirect support and the source/target service context.",
                    "Do not claim destination reachability, ownership, or a vulnerability without further authorised evidence.",
                ),
                kill_switch_guidance=(
                    "Stop if the redirect is generic infrastructure routing or "
                    "outside authorised scope."
                ),
                identity_key=("redirect_boundary", target_origin),
                related_native_observation_ids=_unique_sorted(native_ids),
                related_application_relation_ids=_unique_sorted(relation_ids),
                limitation_codes=_unique_sorted(limitations),
            )
        )

    api_relations: dict[str, list[object]] = {}
    for relation in model.application_composition.relations:
        if relation.relation_kind is not ApplicationServiceRelationKind.REFERENCES_ROUTE:
            continue
        target = routes_by_id.get(relation.target_entity_id)
        if target is not None and _api_graphql_route(target.canonical_url):
            api_relations.setdefault(target.canonical_url, []).append(relation)
    for target_url, relations in sorted(api_relations.items()):
        related_endpoints = {target_url}
        evidence_ids: set[str] = set()
        relation_ids: set[str] = set()
        for relation in relations:
            source_set = source_sets_by_id.get(relation.source_entity_id)
            if source_set is not None:
                related_endpoints.update(source_set.resource_urls)
            relation_ids.add(relation.relation_id)
            for support in relation.supports:
                evidence_ids.update(support.evidence_ids)
        drafts.append(
            _ThreadDraft(
                title="Referenced API/GraphQL interface",
                priority="medium",
                category="application_interface",
                summary=(
                    "Retained application content references this precise API/GraphQL-shaped interface."
                ),
                why_it_matters=(
                    "A typed application reference can provide useful interface context, "
                    "but does not establish reachability, behaviour, or vulnerability."
                ),
                related_endpoints=_unique_sorted(related_endpoints),
                related_evidence_ids=_unique_sorted(evidence_ids),
                related_candidate_ids=(),
                related_lead_ids=(),
                suggested_manual_review_order=(
                    "Review the retained reference and its surrounding application context.",
                    "Do not request or classify the referenced interface without separate authorised evidence.",
                ),
                kill_switch_guidance=(
                    "Stop if the retained reference is generic, unsupported, or outside authorised scope."
                ),
                identity_key=("referenced_api_graphql", target_url),
                related_application_relation_ids=_unique_sorted(relation_ids),
                limitation_codes=("referenced_interface_not_confirmed_reachable",),
            )
        )

    return tuple(drafts)


def _directory_listing_robots_corroboration(
    endpoints: Sequence[str],
    metadata_review_leads: Sequence[DeepMetadataReviewLead],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Correlate proven listings with exact same-origin robots Disallow hints."""

    canonical_endpoints = {
        canonical
        for endpoint in endpoints
        if (canonical := canonical_relationship_url(endpoint))
    }
    if not canonical_endpoints:
        return (), ()

    evidence_ids: set[str] = set()
    lead_ids: set[str] = set()

    for lead in metadata_review_leads:
        if (
            lead.category != "robots_route_hint"
            or lead.source != "http_artifact:disallow_rule"
        ):
            continue

        directive = lead.value_preview.strip()
        if not directive.startswith("/"):
            continue

        source_url = canonical_relationship_url(lead.url)
        if not source_url:
            continue

        target_url = canonical_relationship_url(urljoin(source_url, directive))
        source_origin = http_origin_from_url(source_url)
        target_origin = http_origin_from_url(target_url)

        if (
            not target_url
            or source_origin is None
            or target_origin != source_origin
            or target_url not in canonical_endpoints
        ):
            continue

        evidence_ids.update(
            evidence_id
            for evidence_id in lead.evidence_ids
            if evidence_id
        )
        if lead.lead_id:
            lead_ids.add(lead.lead_id)

    return tuple(sorted(evidence_ids)), tuple(sorted(lead_ids))


def _compatibility_summary_threads(
    project_state: ProjectState,
    leads: Sequence[CompatibilitySummaryLead],
    successful_content_reviews: Sequence[SuccessfulDeepContentReview] = (),
    metadata_review_leads: Sequence[DeepMetadataReviewLead] = (),
) -> tuple[_ThreadDraft, ...]:
    """Adapt selected direct-evidence summary families without importing rank."""

    grouped: dict[tuple[str, tuple[str, ...]], set[str]] = {}
    grouped_endpoints: dict[tuple[str, tuple[str, ...]], set[str]] = {}

    for lead in leads:
        lead_type = getattr(lead, "lead_type", None)
        raw_endpoints = getattr(lead, "endpoints", None)
        raw_evidence_ids = getattr(lead, "evidence_ids", None)

        if (
            not isinstance(lead_type, str)
            or not isinstance(raw_endpoints, Sequence)
            or isinstance(raw_endpoints, (str, bytes))
            or not isinstance(raw_evidence_ids, Sequence)
            or isinstance(raw_evidence_ids, (str, bytes))
            or any(not isinstance(item, str) for item in raw_endpoints)
            or any(not isinstance(item, str) for item in raw_evidence_ids)
        ):
            raise TypeError("compatibility summary leads must expose typed semantic fields")

        if lead_type not in _COMPATIBILITY_SUMMARY_FAMILIES:
            continue

        endpoints = _unique_sorted(raw_endpoints)
        evidence_ids = _unique_sorted(raw_evidence_ids)

        if not endpoints or not evidence_ids:
            continue

        key = (
            lead_type,
            _compatibility_subject(
                project_state,
                lead_type,
                endpoints,
                evidence_ids,
            ),
        )
        grouped.setdefault(key, set()).update(evidence_ids)
        grouped_endpoints.setdefault(key, set()).update(endpoints)

    drafts: list[_ThreadDraft] = []
    for lead_type, subject in sorted(grouped):
        evidence_ids = tuple(sorted(grouped[(lead_type, subject)]))
        if lead_type == "successful_deep_content":
            endpoints = tuple(sorted(grouped_endpoints[(lead_type, subject)]))
        elif lead_type == "smb_disk_share_review":
            typed_share_name = _typed_smb_share_name(project_state, evidence_ids)
            endpoints = subject[1:] if typed_share_name is not None else subject
        else:
            endpoints = subject

        related_lead_ids: tuple[str, ...] = ()

        if lead_type == "successful_deep_content":
            typed_partition = _typed_successful_content_partition(
                endpoints,
                evidence_ids,
                successful_content_reviews,
            )
            if typed_partition is not None:
                specific_drafts, endpoints, evidence_ids = typed_partition
                drafts.extend(specific_drafts)
                if not endpoints:
                    continue

        if lead_type == "structured_json_routes":
            title = "Observed structured route disclosure"
            summary = "A retained structured response directly discloses route values."
            why = (
                "Direct route values can provide useful application context without "
                "proving that an uncollected route is reachable or vulnerable."
            )
            limitations = ("structured_response_not_confirmed_api",)
            priority = "medium"
            category = "application_interface"
        elif lead_type == "structured_configuration_body":
            title = "Observed structured application configuration"
            summary = (
                "A retained response contains coherent structured configuration."
            )
            why = (
                "Configuration context can inform bounded application review "
                "without proving impact."
            )
            limitations = ()
            priority = "medium"
            category = "application_interface"
        elif lead_type == "distinctive_access_boundary_response":
            title = "Observed distinctive access boundary"
            summary = (
                "A retained response differs meaningfully at an access boundary."
            )
            why = (
                "A distinctive access boundary can merit careful contextual review "
                "without proving an authorization flaw."
            )
            limitations = ()
            priority = "medium"
            category = "application_interface"
        elif lead_type == "directory_listing_response":
            title = "Observed directory listing response"
            robots_evidence_ids, related_lead_ids = (
                _directory_listing_robots_corroboration(
                    endpoints,
                    metadata_review_leads,
                )
            )
            if robots_evidence_ids:
                evidence_ids = _unique_sorted(
                    (*evidence_ids, *robots_evidence_ids)
                )
                summary = (
                    "A retained response presents directory-listing evidence, "
                    "independently corroborated by a matching robots.txt "
                    "Disallow route directive."
                )
                why = (
                    "The matching robots.txt directive strengthens route context "
                    "for bounded review, but neither signal alone nor their "
                    "correlation establishes a vulnerability."
                )
            else:
                summary = "A retained response presents directory-listing evidence."
                why = (
                    "Directory-listing evidence may expose useful application context "
                    "and deserves bounded review."
                )
            limitations = ()
            priority = "medium"
            category = "application_interface"
        elif lead_type == "fetched_application_page":
            title = "Fetched application page review"
            summary = "A retained application page is available for contextual review."
            why = (
                "A collected application page can provide useful context without "
                "making its status or title a vulnerability claim."
            )
            limitations = ("fetched_response_not_security_finding",)
            priority = "medium"
            category = "application_interface"
        elif lead_type == "successful_deep_content":
            title = "Successfully collected Deep content available offline"
            summary = "Grouped retained Deep responses are available for offline review."
            why = (
                "Successful retained content can provide application context without "
                "treating an HTTP success response as a security finding."
            )
            limitations = ("successful_response_not_security_finding",)
            priority = "medium"
            category = "application_interface"
        elif lead_type == "smb_disk_share_review":
            share_name = _typed_smb_share_name(project_state, evidence_ids)
            title = (
                f"SMB Disk share observed for review: {share_name}"
                if share_name is not None
                else "Observed SMB service context"
            )
            summary = (
                "A bounded SMB enumeration directly observed a non-administrative Disk share."
                if share_name is not None
                else "SMB service context is retained without a uniquely associated share name."
            )
            why = (
                "Direct share evidence merits authorised contextual review without "
                "authorising connection, traversal, or access testing."
            )
            limitations = ("smb_observation_not_access_authority",)
            priority = "medium"
            category = "service_context"
        elif lead_type == "non_http_service_context":
            title = "Observed non-HTTP service context"
            summary = "An open non-HTTP service is retained as bounded service context."
            why = "Service context is useful for topology review but does not itself establish impact."
            limitations = ("service_context_not_security_finding",)
            priority = "low"
            category = "service_context"
        else:
            title = "Unusual robots user-agent context"
            summary = "Collected robots.txt evidence contains non-default user-agent context."
            why = "Robots context is low-priority supporting evidence until corroborated."
            limitations = ("robots_context_not_security_finding",)
            priority = "low"
            category = "discovered_content"

        drafts.append(
            _ThreadDraft(
                title=title,
                priority=priority,
                category=category,
                summary=summary,
                why_it_matters=why,
                related_endpoints=endpoints,
                related_evidence_ids=evidence_ids,
                related_candidate_ids=(),
                related_lead_ids=related_lead_ids,
                suggested_manual_review_order=(
                    "Review the retained direct evidence and its surrounding "
                    "application context.",
                    "Do not request uncollected routes or infer a vulnerability "
                    "from this evidence alone.",
                ),
                kill_switch_guidance=(
                    "Stop if the retained evidence is generic, repeated, or "
                    "unsupported by its provenance."
                ),
                identity_key=(lead_type, *subject),
                limitation_codes=limitations,
                compatibility_lead_type=lead_type,
            )
        )

    return tuple(drafts)



def _typed_successful_content_partition(
    endpoints: tuple[str, ...],
    evidence_ids: tuple[str, ...],
    reviews: Sequence[SuccessfulDeepContentReview],
) -> (
    tuple[
        tuple[_ThreadDraft, ...],
        tuple[str, ...],
        tuple[str, ...],
    ]
    | None
):
    """Split typed metrics exposition from a fully correlated legacy aggregate."""

    if not reviews:
        return None

    endpoint_set = frozenset(endpoints)
    evidence_set = frozenset(evidence_ids)

    correlated = tuple(
        review
        for review in reviews
        if review.canonical_url in endpoint_set
        and review.evidence_ids
        and frozenset(review.evidence_ids).issubset(evidence_set)
    )

    if not correlated:
        return None

    correlated_endpoints = frozenset(
        review.canonical_url
        for review in correlated
    )
    correlated_evidence = frozenset(
        evidence_id
        for review in correlated
        for evidence_id in review.evidence_ids
        if evidence_id
    )

    if (
        correlated_endpoints != endpoint_set
        or correlated_evidence != evidence_set
    ):
        return None

    prometheus_reviews = tuple(
        review
        for review in correlated
        if prometheus_metrics_exposition(review)
    )
    remaining_reviews = tuple(
        review
        for review in correlated
        if not prometheus_metrics_exposition(review)
    )

    specific_drafts: list[_ThreadDraft] = []

    for endpoint in sorted(
        {
            review.canonical_url
            for review in prometheus_reviews
        }
    ):
        endpoint_reviews = tuple(
            review
            for review in prometheus_reviews
            if review.canonical_url == endpoint
        )
        endpoint_evidence = _unique_sorted(
            evidence_id
            for review in endpoint_reviews
            for evidence_id in review.evidence_ids
            if evidence_id
        )

        specific_drafts.append(
            _ThreadDraft(
                title="Prometheus-style metrics exposition observed",
                priority="medium",
                category="application_interface",
                summary=(
                    "A retained successful response contains body evidence "
                    "matching Prometheus metrics exposition structure."
                ),
                why_it_matters=(
                    "Prometheus-style metrics exposition can provide useful "
                    "observability and application context, but successful "
                    "access does not by itself establish a vulnerability."
                ),
                related_endpoints=(endpoint,),
                related_evidence_ids=endpoint_evidence,
                related_candidate_ids=(),
                related_lead_ids=(),
                suggested_manual_review_order=(
                    "Inspect the retained bounded metrics preview offline and "
                    "identify what operational or application context it exposes.",
                    "Assess intended exposure and data sensitivity from existing "
                    "authorised evidence before considering any further action.",
                ),
                kill_switch_guidance=(
                    "Stop if the retained body does not support Prometheus-style "
                    "metrics exposition or if further action would require "
                    "uncollected requests."
                ),
                identity_key=(
                    "prometheus_metrics_exposition",
                    endpoint,
                ),
                limitation_codes=(
                    "metrics_exposition_not_security_finding",
                ),
                compatibility_lead_type="successful_deep_content",
            )
        )

    remaining_endpoints = _unique_sorted(
        review.canonical_url
        for review in remaining_reviews
    )
    remaining_evidence = _unique_sorted(
        evidence_id
        for review in remaining_reviews
        for evidence_id in review.evidence_ids
        if evidence_id
    )

    return (
        tuple(specific_drafts),
        remaining_endpoints,
        remaining_evidence,
    )


def _compatibility_subject(
    project_state: ProjectState,
    lead_type: str,
    endpoints: tuple[str, ...],
    evidence_ids: tuple[str, ...],
) -> tuple[str, ...]:
    """Group a legacy summary family by semantic subject, never legacy rank."""

    if lead_type == "successful_deep_content":
        return ()
    if lead_type == "smb_disk_share_review":
        share_name = _typed_smb_share_name(project_state, evidence_ids)
        return (share_name.casefold(), *endpoints) if share_name is not None else endpoints
    return endpoints


def _typed_smb_share_name(
    project_state: ProjectState,
    evidence_ids: Sequence[str],
) -> str | None:
    """Return one typed Disk-share subject linked by direct evidence, if unique."""

    evidence_id_set = frozenset(evidence_ids)
    names = {
        share.share_name.strip()
        for share in project_state.smb_shares
        if share.share_type.casefold() == "disk"
        and share.share_name.strip()
        and evidence_id_set.intersection(share.evidence_ids)
    }
    if len(names) != 1:
        return None
    return next(iter(names))

def _semantic_thread_id(draft: _ThreadDraft) -> str:
    subject = (
        draft.identity_key
        or draft.related_endpoints
        or draft.related_candidate_ids
        or draft.related_lead_ids
        or draft.related_evidence_ids
    )

    digest = sha256()
    for value in (draft.category, *subject):
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)

    return f"THREAD-{digest.hexdigest()}"


def _assign_thread_ids(
    drafts: list[_ThreadDraft],
) -> tuple[InvestigationThread, ...]:
    sorted_drafts = sorted(drafts, key=_thread_sort_key)
    paired = tuple(
        (
            draft,
            InvestigationThread(
                thread_id=_semantic_thread_id(draft),
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
                related_native_observation_ids=draft.related_native_observation_ids,
                related_application_relation_ids=(
                    draft.related_application_relation_ids
                ),
                limitation_codes=draft.limitation_codes,
            ),
        )
        for draft in sorted_drafts
    )
    return _apply_account_workflow_subsumption(paired)


def _apply_account_workflow_subsumption(
    paired: tuple[tuple[_ThreadDraft, InvestigationThread], ...],
) -> tuple[InvestigationThread, ...]:
    threads = [thread for _draft, thread in paired]
    parents = tuple(
        (index, draft)
        for index, (draft, thread) in enumerate(paired)
        if thread.category == "account_workflow"
        and draft.attention_coverage_urls
    )

    for child_index, (child_draft, child) in enumerate(paired):
        if (
            child_draft.compatibility_lead_type != "fetched_application_page"
            or len(child.related_endpoints) != 1
        ):
            continue

        endpoint = child.related_endpoints[0]
        matching_parents = tuple(
            parent_index
            for parent_index, parent_draft in parents
            if endpoint in parent_draft.attention_coverage_urls
        )

        if len(matching_parents) != 1:
            continue

        parent_index = matching_parents[0]
        parent = threads[parent_index]
        reason = (
            "Generic fetched-page review is covered by the broader account workflow."
        )

        threads[parent_index] = replace(
            parent,
            related_evidence_ids=_unique_sorted(
                (*parent.related_evidence_ids, *child.related_evidence_ids)
            ),
        )
        threads[child_index] = replace(
            child,
            subsumed_by_thread_id=parent.thread_id,
            subsumption_reason=reason,
        )

    return tuple(threads)


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
    candidates: Sequence[Candidate],
    review_leads: Sequence[ReviewLead],
    direct_source_artifacts: Sequence[HTTPArtifact],
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
        for artifact in direct_source_artifacts
    )


def _direct_source_artifacts(project_state: ProjectState) -> tuple[HTTPArtifact, ...]:
    return tuple(
        artifact
        for artifact in project_state.http_artifacts
        if artifact.artifact_type == "hidden_element"
        and classify_encoded_artifact(artifact).category != LIKELY_NOISE
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
