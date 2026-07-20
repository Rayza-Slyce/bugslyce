"""Human-readable Standard report triage brief and evidence cards."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from urllib.parse import urlparse

from bugslyce.core.models import Candidate, Endpoint, HTTPArtifact, ProjectState
from bugslyce.reports.artifact_classifier import (
    LIKELY_NOISE,
    LIKELY_SIGNAL,
    classify_encoded_artifact,
    classify_http_service_priority,
)
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.route_provenance import (
    RouteEvidenceProvenance,
    canonical_route_url,
    route_evidence_provenance,
)
from bugslyce.triage.workflow_leads import (
    WorkflowLead,
    build_grouped_workflow_leads,
    canonical_workflow_url,
)


MAX_BRIEF_ITEMS = 8
MAX_VALUE_ITEMS = 6
MAX_IGNORE_ITEMS = 5
MAX_CARDS = 8

AUTH_PATH_TERMS = {
    "account",
    "auth",
    "login",
    "logout",
    "oauth",
    "password",
    "profile",
    "register",
    "reset",
    "session",
    "signin",
    "signup",
}
ADMIN_PATH_TERMS = {
    "admin",
}
TEST_DEVELOPMENT_PATH_TERMS = {
    "debug",
    "dev",
    "staging",
    "test",
}
HIDDEN_OPERATIONAL_PATH_TERMS = {
    "backup",
    "console",
    "hidden",
    "internal",
    "old",
    "secret",
    "server-info",
    "status",
}
STATIC_TERMS = {
    "bootstrap",
    "fontawesome",
    "jquery",
    "modernizr",
}
STATIC_SUFFIXES = {
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".png",
    ".svg",
    ".ttf",
    ".woff",
    ".woff2",
}
VALUE_SIGNAL_TERMS = {
    "api_key",
    "apikey",
    "auth",
    "bearer",
    "credential",
    "key",
    "password",
    "secret",
    "token",
    "username",
}
GENERIC_LOGIN_FORM_KEYWORDS = {"login", "password"}
LOGIN_FORM_ARTIFACT_TYPES = {"form", "input"}
SOURCE_CONTEXT_ARTIFACT_TYPES = {
    "encoded_like_artifact",
    "hidden_element",
    "html_comment",
    "keyword_hit",
}
CLUE_LIKE_TERMS = {
    "clue",
    "hint",
    "key",
    "note",
    "remember",
    "token",
    "username",
}
COMMENT_ACTION_TERMS = {
    "add",
    "change",
    "check",
    "clean",
    "configure",
    "confirm",
    "create",
    "disable",
    "enable",
    "fix",
    "move",
    "remove",
    "replace",
    "restore",
    "review",
    "rotate",
    "switch",
    "update",
    "verify",
}
COMMENT_OBJECT_TERMS = {
    "account",
    "application",
    "backup",
    "cache",
    "certificate",
    "config",
    "configuration",
    "credential",
    "database",
    "deployment",
    "endpoint",
    "environment",
    "host",
    "login",
    "page",
    "path",
    "release",
    "route",
    "secret",
    "server",
    "service",
    "source",
    "staging",
    "token",
}
COMMENT_STATE_TERMS = {
    "broken",
    "deprecated",
    "legacy",
    "missing",
    "old",
    "pending",
    "stale",
    "temporary",
    "unused",
    "wrong",
}
COMMENT_TASK_MARKERS = {
    "do",
    "don't",
    "please",
    "todo",
    "fixme",
}
COMMENT_RESOURCE_LABEL_TERMS = {
    "asset",
    "component",
    "documentation",
    "font",
    "heading",
    "icon",
    "image",
    "include",
    "integration",
    "library",
    "license",
    "licence",
    "load",
    "metadata",
    "module",
    "plugin",
    "script",
    "section",
    "social",
    "style",
    "subscribe",
}
COMMENT_STATIC_EXTENSIONS = {
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".png",
    ".svg",
    ".ttf",
    ".woff",
    ".woff2",
}
SENSITIVE_PREVIEW_TERMS = re.compile(
    r"\b(flag|exploit|vulnerable|vulnerability)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class HumanTriageItem:
    """One compact human-facing triage prompt."""

    title: str
    priority: str
    category: str
    source: str
    value: str
    why_it_matters: str
    suggested_manual_action: str
    evidence_ids: tuple[str, ...] = ()
    url: str | None = None
    signal: str = ""


@dataclass(frozen=True)
class ReadableEvidenceCard:
    """Terminal-friendly evidence card for high-value report context."""

    title: str
    url: str | None
    signal: str
    why_it_matters: str
    suggested_manual_action: str
    evidence_ids: tuple[str, ...]
    value_preview: str | None = None
    source: str | None = None


@dataclass(frozen=True)
class HumanTriageBrief:
    """Deterministic front-page triage data for Standard reports."""

    start_here: tuple[HumanTriageItem, ...]
    evidence_values: tuple[HumanTriageItem, ...]
    review_next: tuple[str, ...]
    ignore_for_now: tuple[HumanTriageItem, ...]
    raw_evidence_pointers: tuple[str, ...]
    evidence_cards: tuple[ReadableEvidenceCard, ...]


@dataclass(frozen=True)
class _SourceContextGroup:
    """Internal grouped source context for Human Triage consolidation."""

    item: HumanTriageItem
    evidence_ids: tuple[str, ...]
    url: str | None


def build_human_triage_brief(
    project_state: ProjectState,
    candidates: list[Candidate],
    *,
    engagement_context: str | None = None,
    deep_orchestration: object | None = None,
    workflow_leads: Sequence[WorkflowLead] | None = None,
) -> HumanTriageBrief:
    """Build a deterministic Standard human triage brief from local state."""

    del engagement_context
    start: list[HumanTriageItem] = []
    values: list[HumanTriageItem] = []
    ignore: list[HumanTriageItem] = []
    source_groups = _build_source_context_groups(project_state)
    grouped_evidence_ids = {
        evidence_id
        for group in source_groups
        for evidence_id in group.evidence_ids
    }
    direct_comment_evidence_ids = _useful_source_comment_evidence_ids(project_state)
    grouped_urls = {group.url for group in source_groups if group.url}
    grouped_workflows = tuple(
        workflow_leads
        if workflow_leads is not None
        else build_grouped_workflow_leads(project_state, deep_orchestration)
    )
    grouped_account_urls = {
        url
        for lead in grouped_workflows
        if lead.category == "account_workflow"
        for url in lead.covered_urls
    }
    direct_structured_urls = _direct_structured_review_urls(deep_orchestration)
    start.extend(_workflow_triage_item(lead) for lead in grouped_workflows)

    _add_candidate_items(
        start,
        ignore,
        candidates,
        project_state=project_state,
        grouped_evidence_ids=grouped_evidence_ids | direct_comment_evidence_ids,
        grouped_urls=grouped_urls,
        grouped_account_urls=grouped_account_urls,
        direct_structured_urls=direct_structured_urls,
    )
    _add_http_service_items(start, ignore, project_state)
    _add_port_service_items(start, project_state)
    access_boundary_paths = _access_boundary_paths_by_url(project_state)
    _add_endpoint_items(
        start,
        ignore,
        project_state,
        access_boundary_paths,
        grouped_account_urls,
        direct_structured_urls,
    )
    _add_discovered_path_items(
        start,
        ignore,
        project_state,
        grouped_account_urls,
        direct_structured_urls,
    )
    _add_artifact_items(
        start,
        values,
        ignore,
        project_state,
        grouped_evidence_ids=grouped_evidence_ids,
    )
    for group in source_groups:
        start.append(group.item)
        values.append(group.item)

    start = _rank_items(start)[:MAX_BRIEF_ITEMS]
    values = _rank_items(values)[:MAX_VALUE_ITEMS]
    ignore = _rank_items(ignore)[:MAX_IGNORE_ITEMS]

    return HumanTriageBrief(
        start_here=tuple(start),
        evidence_values=tuple(values),
        review_next=tuple(_review_next_lines(start, values)),
        ignore_for_now=tuple(ignore),
        raw_evidence_pointers=tuple(_raw_evidence_pointers(project_state, candidates)),
        evidence_cards=tuple(_build_cards(start, values, project_state)[:MAX_CARDS]),
    )


def render_human_triage_brief_markdown(brief: HumanTriageBrief) -> str:
    """Render the compact Standard Human Triage Brief section."""

    if not brief.start_here and not brief.evidence_values:
        return "\n".join(
            [
                "## Human Triage Brief",
                "",
                "No high-confidence manual triage leads were identified from the collected evidence.",
                "",
                (
                    "Suggested next step: review open services and raw evidence manually, "
                    "or consider an approved broader follow-up if the engagement allows it."
                ),
                "",
            ]
        ).rstrip()

    lines = [
        "## Human Triage Brief",
        "",
        (
            "This brief highlights evidence-backed manual review prompts. "
            "They require local validation and are not confirmed findings."
        ),
        "",
        "### Start Here",
        "",
    ]
    if brief.start_here:
        for index, item in enumerate(brief.start_here, start=1):
            lines.extend(_render_numbered_item(index, item))
    else:
        lines.extend(["No high-confidence start-here prompts were identified.", ""])

    lines.extend(["### Evidence Values Worth Noting", ""])
    if brief.evidence_values:
        for item in brief.evidence_values:
            lines.extend(_render_bullet_item(item))
        lines.append("")
    else:
        lines.extend(
            [
                (
                    "- No additional source-comment, metadata, or encoded values were "
                    "promoted in this section; review the Operator Summary and Start "
                    "Here sections for other direct evidence."
                ),
                "",
            ]
        )

    lines.extend(["### Review Next", ""])
    if brief.review_next:
        lines.extend(f"- {_md(item)}" for item in brief.review_next)
    else:
        lines.append("- Review open services and raw evidence manually.")
    lines.append("")

    lines.extend(["### Ignore For Now", ""])
    if brief.ignore_for_now:
        for item in brief.ignore_for_now:
            lines.extend(_render_bullet_item(item))
    else:
        lines.append("- No low-value static or duplicate evidence was promoted into this section.")
    lines.append("")

    lines.extend(["### Raw Evidence Pointers", ""])
    lines.extend(f"- {_md(item)}" for item in brief.raw_evidence_pointers)
    lines.append("")
    return "\n".join(lines).rstrip()


def render_readable_evidence_cards_markdown(brief: HumanTriageBrief) -> str:
    """Render terminal-friendly evidence cards above raw wide tables."""

    lines = ["## Readable Evidence Cards", ""]
    if not brief.evidence_cards:
        lines.extend(
            [
                "No high-value evidence cards were generated from the collected evidence.",
                "",
            ]
        )
        return "\n".join(lines).rstrip()

    lines.extend(
        [
            (
                "These cards summarise high-value evidence in a terminal-friendly format. "
                "Use the raw tables below for full audit detail."
            ),
            "",
        ]
    )
    for card in brief.evidence_cards:
        lines.extend(
            [
                f"### {_md(card.title)}",
                "",
                f"- URL: {_code(card.url or 'not recorded')}",
                f"- Signal: {_md(card.signal)}",
                f"- Why it matters: {_md(card.why_it_matters)}",
                f"- Suggested manual action: {_md(card.suggested_manual_action)}",
                f"- Evidence: {format_evidence_ids(card.evidence_ids)}",
            ]
        )
        if card.value_preview:
            lines.append(f"- Value preview: {_code(card.value_preview)}")
        if card.source:
            lines.append(f"- Source: {_md(card.source)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _add_candidate_items(
    start: list[HumanTriageItem],
    ignore: list[HumanTriageItem],
    candidates: list[Candidate],
    *,
    project_state: ProjectState,
    grouped_evidence_ids: set[str],
    grouped_urls: set[str],
    grouped_account_urls: set[str],
    direct_structured_urls: set[str],
) -> None:
    for candidate in candidates:
        if candidate.candidate_type == "object_reference_review":
            continue
        if (
            candidate.candidate_type == "auth_surface"
            and grouped_account_urls
            and any(
                _canonical_triage_url(endpoint) in grouped_account_urls
                for endpoint in candidate.affected_endpoints
            )
        ):
            continue
        if (
            candidate.candidate_type == "high_port_http_service"
            and _candidate_matches_generic_default_service(candidate, project_state)
        ):
            continue
        if (
            candidate.candidate_type in {"admin_surface", "hidden_path_review"}
            and candidate.affected_endpoints
            and all(
                _canonical_triage_url(endpoint) in direct_structured_urls
                for endpoint in candidate.affected_endpoints
            )
        ):
            continue
        if _candidate_duplicate_of_source_group(
            candidate,
            grouped_evidence_ids=grouped_evidence_ids,
            grouped_urls=grouped_urls,
        ):
            continue
        item = HumanTriageItem(
            title=candidate.title,
            priority=candidate.priority if candidate.priority in {"high", "medium", "low"} else "low",
            category=candidate.candidate_type,
            source="candidate",
            value=", ".join(candidate.affected_endpoints[:2]) or candidate.id,
            why_it_matters=_candidate_why(candidate),
            suggested_manual_action=_candidate_action(candidate),
            evidence_ids=tuple(candidate.evidence_ids),
            url=candidate.affected_endpoints[0] if candidate.affected_endpoints else None,
            signal=_candidate_signal(candidate),
        )
        if candidate.candidate_type in {"low_signal_static", "dead_low_signal_path"}:
            ignore.append(item)
        elif candidate.priority in {"high", "medium"}:
            start.append(item)


def _candidate_matches_generic_default_service(
    candidate: Candidate,
    project_state: ProjectState,
) -> bool:
    candidate_origins = {
        origin
        for endpoint in candidate.affected_endpoints
        if (origin := http_origin_from_url(endpoint)) is not None
    }
    if not candidate_origins:
        return False
    matching_services = [
        service
        for service in project_state.http_services
        if http_origin_from_url(service.url) in candidate_origins
    ]
    return bool(matching_services) and all(
        classify_http_service_priority(project_state, service.url).priority == "low"
        for service in matching_services
    )


def _add_http_service_items(
    start: list[HumanTriageItem],
    ignore: list[HumanTriageItem],
    project_state: ProjectState,
) -> None:
    for service in project_state.http_services:
        if not service.evidence_ids:
            continue
        parsed = urlparse(service.url)
        port = parsed.port
        high_port = port is not None and port not in {80, 443}
        status = service.status_code if service.status_code is not None else "unknown"
        item = HumanTriageItem(
            title=(
                "High-port HTTP service review"
                if high_port
                else "HTTP application surface review"
            ),
            priority="medium",
            category="http_service",
            source="http_service",
            value=service.url,
            why_it_matters=(
                "A non-default HTTP port may indicate a separate application surface."
                if high_port
                else "An HTTP application surface is available for scoped manual review."
            ),
            suggested_manual_action=(
                "Compare title, status, technology, and nearby evidence before deeper manual review."
            ),
            evidence_ids=tuple(service.evidence_ids),
            url=service.url,
            signal=f"HTTP {status}: {service.title or 'untitled'}",
        )
        service_priority = classify_http_service_priority(project_state, service.url)
        if service_priority.priority == "low":
            ignore.append(
                HumanTriageItem(
                    title="Generic/default HTTP landing page",
                    priority="low",
                    category="default_page_context",
                    source="http_service",
                    value=service.url,
                    why_it_matters=(
                        "The service remains useful surface evidence, but its title "
                        "matches a generic/default landing page without stronger "
                        "independent application evidence."
                    ),
                    suggested_manual_action=(
                        "Keep the service in the inventory and prioritise direct "
                        "application evidence first."
                    ),
                    evidence_ids=tuple(service.evidence_ids),
                    url=service.url,
                    signal=f"HTTP {status}: generic/default landing page",
                )
            )
        else:
            start.append(item)


def _add_port_service_items(start: list[HumanTriageItem], project_state: ProjectState) -> None:
    for service in project_state.port_services:
        if service.state != "open" or not service.evidence_ids:
            continue
        service_name = (service.service or "unknown").lower()
        if service_name in {"http", "https", "http-proxy", "ssl/http"}:
            continue
        start.append(
            HumanTriageItem(
                title=f"{(service.service or 'Service').upper()} service context",
                priority="low",
                category="service_context",
                source="port_service",
                value=f"{service.host}:{service.port}/{service.protocol}",
                why_it_matters="Open non-HTTP services can guide authorised manual review and service ownership checks.",
                suggested_manual_action=(
                    "Record service purpose and version context; do not attempt login or password testing from this brief."
                ),
                evidence_ids=tuple(service.evidence_ids),
                url=None,
                signal=f"{service.service or 'unknown'} on {service.port}/{service.protocol}",
            )
        )


def _add_endpoint_items(
    start: list[HumanTriageItem],
    ignore: list[HumanTriageItem],
    project_state: ProjectState,
    access_boundary_paths: dict[str, RouteEvidenceProvenance],
    grouped_account_urls: set[str],
    direct_structured_urls: set[str],
) -> None:
    for endpoint in project_state.endpoints:
        if _canonical_triage_url(endpoint.url) in grouped_account_urls:
            continue
        access_boundary = access_boundary_paths.get(_canonical_triage_url(endpoint.url))
        if access_boundary is not None:
            if access_boundary.independent_reference_evidence_ids:
                start.append(_independent_access_boundary_item(endpoint, access_boundary))
            continue
        if _canonical_triage_url(endpoint.url) in direct_structured_urls:
            continue
        terms = _path_terms(endpoint.path)
        if _is_static_path(endpoint.path):
            ignore.append(
                HumanTriageItem(
                    title="Static or library route",
                    priority="low",
                    category="static_noise",
                    source="endpoint",
                    value=endpoint.url,
                    why_it_matters="Static/library paths rarely deserve first-pass manual attention unless linked to stronger evidence.",
                    suggested_manual_action="Leave this for later unless another lead references it.",
                    evidence_ids=tuple(endpoint.evidence_ids),
                    url=endpoint.url,
                    signal="low-value static/library path",
                )
            )
            continue
        if terms & AUTH_PATH_TERMS:
            start.append(_path_item(endpoint.url, endpoint.evidence_ids, "Auth/account route observed", "auth_route"))
        elif terms & ADMIN_PATH_TERMS:
            start.append(_path_item(endpoint.url, endpoint.evidence_ids, "Admin-labelled route observed", "admin_route"))
        elif terms & TEST_DEVELOPMENT_PATH_TERMS:
            start.append(
                _path_item(
                    endpoint.url,
                    endpoint.evidence_ids,
                    "Test/development route observed",
                    "environment_route",
                )
            )
        elif terms & HIDDEN_OPERATIONAL_PATH_TERMS:
            start.append(
                _path_item(
                    endpoint.url,
                    endpoint.evidence_ids,
                    "Hidden/operational route observed",
                    "hidden_route",
                )
            )


def _add_discovered_path_items(
    start: list[HumanTriageItem],
    ignore: list[HumanTriageItem],
    project_state: ProjectState,
    grouped_account_urls: set[str],
    direct_structured_urls: set[str],
) -> None:
    for path in project_state.discovered_paths:
        if _canonical_triage_url(path.url) in grouped_account_urls:
            continue
        parsed = urlparse(path.url)
        terms = _path_terms(parsed.path)
        tags = {tag.lower() for tag in path.tags}
        if "directory_listing" in tags or "index_of" in tags:
            start.append(
                HumanTriageItem(
                    title="Directory listing or browsable path observed",
                    priority="high",
                    category="directory_listing",
                    source="discovered_path",
                    value=path.url,
                    why_it_matters="Browsable directories may expose files or context useful for scoped manual review.",
                    suggested_manual_action="Review the collected response and record relevant request/response evidence before escalating.",
                    evidence_ids=tuple(path.evidence_ids),
                    url=path.url,
                    signal="directory listing",
                )
            )
            continue
        if _is_static_path(parsed.path):
            ignore.append(
                HumanTriageItem(
                    title="Static discovered path",
                    priority="low",
                    category="static_noise",
                    source="discovered_path",
                    value=path.url,
                    why_it_matters="Static assets and libraries are usually lower-value than application routes.",
                    suggested_manual_action="Review only if a stronger lead points back to this path.",
                    evidence_ids=tuple(path.evidence_ids),
                    url=path.url,
                    signal="static/library path",
                )
            )
            continue
        if path.status_code in {401, 403} and path.evidence_ids:
            continue
        elif _canonical_triage_url(path.url) in direct_structured_urls:
            continue
        elif terms & AUTH_PATH_TERMS:
            start.append(_path_item(path.url, path.evidence_ids, "Auth/account path discovered", "auth_route"))
        elif terms & ADMIN_PATH_TERMS:
            start.append(_path_item(path.url, path.evidence_ids, "Admin-labelled path discovered", "admin_route"))
        elif terms & TEST_DEVELOPMENT_PATH_TERMS:
            start.append(
                _path_item(
                    path.url,
                    path.evidence_ids,
                    "Test/development path discovered",
                    "environment_route",
                )
            )
        elif terms & HIDDEN_OPERATIONAL_PATH_TERMS:
            start.append(
                _path_item(
                    path.url,
                    path.evidence_ids,
                    "Hidden/operational path discovered",
                    "hidden_route",
                )
            )


def _workflow_triage_item(lead: WorkflowLead) -> HumanTriageItem:
    return HumanTriageItem(
        title=lead.title,
        priority=lead.priority,
        category=lead.category,
        source="grouped_workflow_evidence",
        value=lead.summary,
        why_it_matters=lead.why_it_matters,
        suggested_manual_action=lead.suggested_manual_action,
        evidence_ids=lead.evidence_ids,
        url=lead.representative_urls[0] if lead.representative_urls else None,
        signal=lead.signal,
    )


def _access_boundary_paths_by_url(
    project_state: ProjectState,
) -> dict[str, RouteEvidenceProvenance]:
    result: dict[str, RouteEvidenceProvenance] = {}
    for path in project_state.discovered_paths:
        if path.status_code not in {401, 403}:
            continue
        canonical = _canonical_triage_url(path.url)
        if canonical and canonical not in result:
            result[canonical] = route_evidence_provenance(project_state, path.url)
    return result


def _independent_access_boundary_item(
    endpoint: Endpoint,
    access_boundary: RouteEvidenceProvenance,
) -> HumanTriageItem:
    evidence_ids = tuple(
        _dedupe(
            [
                *access_boundary.independent_reference_evidence_ids,
                *access_boundary.access_boundary_evidence_ids,
            ]
        )
    )
    status = "/".join(str(value) for value in access_boundary.access_boundary_status_codes)
    return HumanTriageItem(
        title="Independently referenced access-boundary route",
        priority="medium",
        category="access_boundary_context",
        source="endpoint+discovered_path",
        value=endpoint.url,
        why_it_matters=(
            f"Saved source or route evidence references {endpoint.url}, and a bounded request "
            f"returned HTTP {status}. This is access-control context, "
            "not a confirmed weakness."
        ),
        suggested_manual_action=(
            "Correlate the saved source reference with the recorded HTTP response and scope. "
            "Do not attempt login, bypass, brute force, or form submission from this prompt."
        ),
        evidence_ids=evidence_ids,
        url=endpoint.url,
        signal=f"independent route reference + HTTP {status}",
    )


def _canonical_triage_url(value: str | None) -> str:
    return canonical_route_url(value)


def _direct_structured_review_urls(deep_orchestration: object | None) -> set[str]:
    source_review = getattr(deep_orchestration, "source_route_collection_review", None)
    urls: set[str] = set()
    for lead in getattr(source_review, "review_leads", ()):
        if getattr(lead, "category", "") not in {
            "structured_configuration_body",
            "structured_json_routes",
        }:
            continue
        for attribute in ("urls", "final_urls"):
            for value in getattr(lead, attribute, ()):
                canonical = _canonical_triage_url(value)
                if canonical:
                    urls.add(canonical)
    return urls


def _add_artifact_items(
    start: list[HumanTriageItem],
    values: list[HumanTriageItem],
    ignore: list[HumanTriageItem],
    project_state: ProjectState,
    *,
    grouped_evidence_ids: set[str],
) -> None:
    for artifact in project_state.http_artifacts:
        if grouped_evidence_ids.intersection(artifact.evidence_ids):
            continue
        artifact_type = artifact.artifact_type
        if artifact_type in {"encoded_like_artifact", "hidden_element"}:
            classification = classify_encoded_artifact(artifact)
            if classification.category == LIKELY_NOISE:
                ignore.append(_artifact_item(artifact, "Low-signal encoded/source detector match", "static_noise", "low", classification.reason))
                continue
            item = _artifact_item(
                artifact,
                "Encoded-looking source artefact observed",
                "encoded_source",
                "high" if classification.category == LIKELY_SIGNAL else "medium",
                "Encoded-looking or hidden source text should be reviewed in its surrounding local context.",
            )
            start.append(item)
            values.append(item)
            continue
        if artifact_type == "html_comment":
            if not _is_useful_source_comment(artifact.value):
                continue
            item = _artifact_item(
                artifact,
                "Human-authored source comment observed",
                "source_comment",
                "medium",
                "A specific source comment can provide direct manual-review context when correlated with saved source and route evidence.",
            )
            start.append(item)
            values.append(item)
            continue
        if artifact_type == "keyword_hit":
            continue
        if artifact_type == "robots_value":
            item = _artifact_item(
                artifact,
                "robots.txt clue-like value observed",
                "robots_metadata_value",
                "high",
                (
                    "robots.txt and metadata files can contain route hints or unusual "
                    "operator-provided values that deserve manual context review."
                ),
            )
            start.append(item)
            values.append(item)
            continue
        if artifact_type == "user_agent" and artifact.value.strip() == "*":
            continue
        if artifact_type in {
            "robots",
            "user_agent",
            "unusual_user_agent",
            "allow_rule",
            "disallow_rule",
            "sitemap_rule",
        }:
            if artifact_type == "robots" and _looks_like_local_path(artifact.value):
                continue
            item = _artifact_item(
                artifact,
                "robots.txt or metadata clue observed",
                "robots_metadata",
                "medium",
                "robots.txt and metadata entries can guide manual review when linked to collected service context.",
            )
            start.append(item)
            values.append(item)


def _build_source_context_groups(project_state: ProjectState) -> tuple[_SourceContextGroup, ...]:
    grouped: dict[tuple[str, str], list[HTTPArtifact]] = defaultdict(list)
    artifacts_by_url: dict[str, list[HTTPArtifact]] = defaultdict(list)
    for artifact in project_state.http_artifacts:
        if artifact.url:
            artifacts_by_url[artifact.url].append(artifact)
    for artifact in project_state.http_artifacts:
        if artifact.artifact_type not in SOURCE_CONTEXT_ARTIFACT_TYPES:
            continue
        if artifact.artifact_type in {"html_comment", "keyword_hit"}:
            continue
        if artifact.artifact_type in {"encoded_like_artifact", "hidden_element"}:
            classification = classify_encoded_artifact(artifact)
            if classification.category == LIKELY_NOISE:
                continue
        grouped[(artifact.url or "", artifact.source_file or "")].append(artifact)

    result: list[_SourceContextGroup] = []
    for (url, source_file), artifacts in grouped.items():
        if _is_generic_login_form_source_group(artifacts, artifacts_by_url.get(url, [])):
            continue
        if len(artifacts) < 2 or not _source_group_has_signal(artifacts):
            continue
        evidence_ids = tuple(
            _dedupe(
                [
                    evidence_id
                    for artifact in artifacts
                    for evidence_id in artifact.evidence_ids
                ]
            )
        )
        if not evidence_ids:
            continue
        preview = _source_group_preview(artifacts)
        item = HumanTriageItem(
            title="Source credential/context clue group observed",
            priority="high",
            category="source_context_group",
            source=f"source_context:{source_file or 'unknown'}",
            value=preview,
            why_it_matters=(
                "Multiple source-level clues on the same page can help guide manual review "
                "when correlated with route and metadata context."
            ),
            suggested_manual_action=(
                "Review the surrounding saved source locally and validate each value in context "
                "before treating it as meaningful."
            ),
            evidence_ids=evidence_ids,
            url=url or None,
            signal="source credential/context cluster",
        )
        result.append(
            _SourceContextGroup(
                item=item,
                evidence_ids=evidence_ids,
                url=url or None,
            )
        )
    return tuple(result)


def _source_group_has_signal(artifacts: list[HTTPArtifact]) -> bool:
    artifact_types = {artifact.artifact_type for artifact in artifacts}
    if artifact_types & {"encoded_like_artifact", "hidden_element"}:
        return True
    if any(
        artifact.artifact_type == "html_comment"
        and _is_useful_source_comment(artifact.value)
        for artifact in artifacts
    ):
        return True
    values = " ".join(
        artifact.value.lower()
        for artifact in artifacts
        if artifact.artifact_type != "keyword_hit"
    )
    return any(term in values for term in VALUE_SIGNAL_TERMS | CLUE_LIKE_TERMS)


def _is_useful_source_comment(value: str) -> bool:
    compact = " ".join(value.split())
    if not compact:
        return False
    lowered = compact.lower()
    if _is_generic_comment_noise(compact):
        return False
    words = re.findall(r"[A-Za-z][A-Za-z'-]*", compact)
    if len(words) < 5:
        return False
    word_set = {word.lower() for word in words}
    has_action = bool(word_set & COMMENT_ACTION_TERMS)
    has_object = bool(word_set & COMMENT_OBJECT_TERMS)
    has_state = bool(word_set & COMMENT_STATE_TERMS)
    has_task_marker = bool(word_set & COMMENT_TASK_MARKERS)
    has_actor = _has_comment_actor_or_addressee(compact, words)
    has_reference = bool(re.search(r"[/._-][A-Za-z0-9]", compact)) or any(
        token.isupper() and len(token) > 1 for token in compact.split()
    )
    if has_action and has_object and (has_actor or has_state or has_reference):
        return True
    if has_actor and has_object and has_state:
        return True
    return has_actor and has_task_marker and len(words) >= 6


def _is_generic_comment_noise(compact: str) -> bool:
    lowered = compact.lower()
    words = re.findall(r"[A-Za-z][A-Za-z'-]*", compact)
    word_set = {word.lower() for word in words}
    if re.search(r"(?i)\b(copyright|all rights reserved|mit license|apache license|gnu|licensed)\b", compact):
        return True
    if re.search(r"(?i)^\s*(?:\[?if\s+|endif\b)", compact):
        return True
    if any(extension in lowered for extension in COMMENT_STATIC_EXTENSIONS):
        return True
    if word_set & COMMENT_RESOURCE_LABEL_TERMS:
        return True
    if len(words) <= 4 and not (word_set & COMMENT_ACTION_TERMS and word_set & COMMENT_OBJECT_TERMS):
        return True
    return False


def _has_comment_actor_or_addressee(compact: str, words: list[str]) -> bool:
    if re.match(r"^[A-Z][A-Za-z'-]{1,30}\s*,", compact):
        return True
    if re.match(r"^[A-Z][A-Za-z0-9 _/-]{1,40}:", compact):
        return True
    if re.match(r"^[A-Z][A-Za-z'-]{1,30}\s+", compact):
        return True
    lowered = {word.lower() for word in words}
    return bool(lowered & {"admin", "developer", "dev", "operator", "ops", "team"})


def _useful_source_comment_evidence_ids(project_state: ProjectState) -> set[str]:
    return {
        evidence_id
        for artifact in project_state.http_artifacts
        if artifact.artifact_type == "html_comment"
        and _is_useful_source_comment(artifact.value)
        for evidence_id in artifact.evidence_ids
    }


def _is_generic_login_form_source_group(
    grouped_artifacts: list[HTTPArtifact],
    url_artifacts: list[HTTPArtifact],
) -> bool:
    grouped_types = {artifact.artifact_type for artifact in grouped_artifacts}
    if grouped_types != {"keyword_hit"}:
        return False
    values = {artifact.value.strip().lower() for artifact in grouped_artifacts}
    if not values or not values.issubset(GENERIC_LOGIN_FORM_KEYWORDS):
        return False
    return any(artifact.artifact_type in LOGIN_FORM_ARTIFACT_TYPES for artifact in url_artifacts)


def _source_group_preview(artifacts: list[HTTPArtifact]) -> str:
    previews: list[str] = []
    for artifact in artifacts:
        preview = _safe_preview(artifact.value, limit=80)
        if preview and preview not in previews:
            previews.append(preview)
        if len(previews) >= 4:
            break
    if len(artifacts) > len(previews):
        previews.append(f"+{len(artifacts) - len(previews)} more")
    return "; ".join(previews)


def _candidate_duplicate_of_source_group(
    candidate: Candidate,
    *,
    grouped_evidence_ids: set[str],
    grouped_urls: set[str],
) -> bool:
    if candidate.candidate_type != "credential_like_artifact_review":
        return False
    if grouped_evidence_ids.intersection(candidate.evidence_ids):
        return True
    return any(endpoint in grouped_urls for endpoint in candidate.affected_endpoints)


def _path_item(url: str, evidence_ids: list[str], title: str, category: str) -> HumanTriageItem:
    return HumanTriageItem(
        title=title,
        priority="high" if category == "auth_route" else "medium",
        category=category,
        source="path",
        value=url,
        why_it_matters="The path name suggests an application workflow that may deserve scoped manual review.",
        suggested_manual_action="Review the collected response and correlate with source, robots, and service context.",
        evidence_ids=tuple(evidence_ids),
        url=url,
        signal="application route",
    )


def _artifact_item(
    artifact: HTTPArtifact,
    title: str,
    category: str,
    priority: str,
    why: str,
) -> HumanTriageItem:
    suggested_action = (
        "Review the saved metadata body locally and correlate manually with route, "
        "source, and service context before treating the value as meaningful."
        if category == "robots_metadata_value"
        else "Review the collected source context locally and correlate before treating the value as meaningful."
    )
    signal = "robots value" if category == "robots_metadata_value" else artifact.artifact_type
    return HumanTriageItem(
        title=title,
        priority=priority,
        category=category,
        source=f"http_artifact:{artifact.artifact_type}",
        value=_safe_preview(artifact.value),
        why_it_matters=why,
        suggested_manual_action=suggested_action,
        evidence_ids=tuple(artifact.evidence_ids),
        url=artifact.url or None,
        signal=signal,
    )


def _rank_items(items: list[HumanTriageItem]) -> list[HumanTriageItem]:
    deduped: dict[tuple[str, str, str], HumanTriageItem] = {}
    for item in items:
        key = (item.category, item.url or "", item.value)
        existing = deduped.get(key)
        if existing is None or _priority_rank(item.priority) < _priority_rank(existing.priority):
            deduped[key] = item
    return sorted(
        deduped.values(),
        key=lambda item: (
            _priority_rank(item.priority),
            _category_rank(item.category),
            item.title,
            item.url or "",
            item.value,
        ),
    )


def _build_cards(
    start: list[HumanTriageItem],
    values: list[HumanTriageItem],
    project_state: ProjectState,
) -> list[ReadableEvidenceCard]:
    cards: list[ReadableEvidenceCard] = []
    seen_card_keys: set[tuple[str, str, str, tuple[str, ...], str, str]] = set()
    for item in [*start, *values]:
        if item.category in {"account_workflow", "object_reference_surface"}:
            continue
        if not item.evidence_ids:
            continue
        card = ReadableEvidenceCard(
            title=item.title,
            url=item.url,
            signal=item.signal or item.category,
            why_it_matters=item.why_it_matters,
            suggested_manual_action=item.suggested_manual_action,
            evidence_ids=item.evidence_ids,
            value_preview=(
                item.value
                if item.source.startswith(("http_artifact:", "source_context:"))
                else None
            ),
            source=item.source,
        )
        key = _card_key(card)
        if key in seen_card_keys:
            continue
        seen_card_keys.add(key)
        cards.append(card)
    for service in project_state.http_services:
        if len(cards) >= MAX_CARDS:
            break
        service_evidence_ids = tuple(service.evidence_ids)
        if not service_evidence_ids:
            continue
        if _has_http_service_card(cards, service.url, service_evidence_ids):
            continue
        card = ReadableEvidenceCard(
            title="HTTP service",
            url=service.url,
            signal=f"HTTP {service.status_code if service.status_code is not None else 'unknown'}",
            why_it_matters="HTTP service metadata anchors later manual review.",
            suggested_manual_action="Compare this service with discovered paths, source artefacts, and route hints.",
            evidence_ids=service_evidence_ids,
            value_preview=service.title,
            source="http_service",
        )
        key = _card_key(card)
        if key in seen_card_keys:
            continue
        seen_card_keys.add(key)
        cards.append(card)
    return cards


def _card_key(
    card: ReadableEvidenceCard,
) -> tuple[str, str, str, tuple[str, ...], str, str]:
    return (
        card.title,
        card.url or "",
        card.signal,
        tuple(card.evidence_ids),
        card.source or "",
        card.value_preview or "",
    )


def _has_http_service_card(
    cards: list[ReadableEvidenceCard],
    service_url: str,
    service_evidence_ids: tuple[str, ...],
) -> bool:
    service_evidence = set(service_evidence_ids)
    for card in cards:
        if card.url != service_url:
            continue
        if service_evidence.intersection(card.evidence_ids):
            return True
        if card.source == "http_service":
            return True
    return False


def _review_next_lines(
    start: list[HumanTriageItem],
    values: list[HumanTriageItem],
) -> list[str]:
    lines: list[str] = []
    for item in start[:3]:
        location = item.url or item.value
        lines.append(f"Review {item.title.lower()} at {location} in collected evidence context.")
    if values:
        lines.append("Validate notable source or metadata values locally before escalating.")
    lines.append("Record request/response evidence and stop if the evidence remains generic or default-page noise.")
    return _dedupe(lines)


def _raw_evidence_pointers(project_state: ProjectState, candidates: list[Candidate]) -> list[str]:
    return [
        f"HTTP services: {len(project_state.http_services)}",
        f"Port services: {len(project_state.port_services)}",
        f"Endpoints: {len(project_state.endpoints)}",
        f"Discovered paths: {len(project_state.discovered_paths)}",
        f"HTTP artefacts: {len(project_state.http_artifacts)}",
        f"Manual review candidates: {len(candidates)}",
    ]


def _candidate_why(candidate: Candidate) -> str:
    if candidate.candidate_type == "credential_like_artifact_review":
        return "A deterministic candidate links source text to credential-shaped or sensitive keyword context."
    if candidate.candidate_type == "high_port_http_service":
        return "A non-default HTTP port may represent a separate application surface."
    if candidate.candidate_type == "multiple_http_services":
        return "Multiple HTTP services on the same host can indicate distinct application contexts."
    return candidate.rationale


def _candidate_action(candidate: Candidate) -> str:
    if candidate.suggested_manual_validation:
        return candidate.suggested_manual_validation[0]
    return "Review the linked evidence manually and validate locally before escalating."


def _candidate_signal(candidate: Candidate) -> str:
    if candidate.candidate_type == "credential_like_artifact_review":
        return "credential-shaped/source context"
    return candidate.candidate_type.replace("_", " ")


def _path_terms(path: str) -> set[str]:
    terms: set[str] = set()
    for segment in PurePosixPath(path or "/").parts:
        clean_segment = segment.strip("/").lower().replace("_", "-")
        for chunk in clean_segment.split("-"):
            for token in chunk.split("."):
                if token:
                    terms.add(token)
        if clean_segment:
            terms.add(clean_segment)
    stripped = (path or "").strip("/").lower()
    if stripped:
        terms.add(stripped)
    return terms


def _is_static_path(path: str) -> bool:
    lowered = path.lower()
    return (
        any(term in lowered for term in STATIC_TERMS)
        or any(lowered.endswith(suffix) for suffix in STATIC_SUFFIXES)
        or "/static/" in lowered
        or "/assets/" in lowered
    )


def _looks_like_local_path(value: str) -> bool:
    lowered = value.lower()
    return (
        lowered.startswith("/")
        or lowered.startswith("~")
        or lowered.startswith("./")
        or lowered.startswith("../")
        or "bugslyce-output" in lowered
    )


def _priority_rank(priority: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(priority, 3)


def _category_rank(category: str) -> int:
    order = {
        "account_workflow": 0,
        "auth_route": 1,
        "directory_listing": 2,
        "source_context_group": 3,
        "object_reference_surface": 4,
        "admin_route": 5,
        "environment_route": 6,
        "hidden_route": 7,
        "robots_metadata_value": 8,
        "robots_metadata": 9,
        "source_comment": 10,
        "encoded_source": 11,
        "http_service": 12,
        "access_control_context": 13,
        "service_context": 14,
        "static_noise": 15,
    }
    return order.get(category, 20)


def _render_numbered_item(index: int, item: HumanTriageItem) -> list[str]:
    lines = [
        f"{index}. **{_md(item.title)}**",
        f"   - Why it matters: {_md(item.why_it_matters)}",
    ]
    if item.category in {"account_workflow", "object_reference_surface"}:
        lines.append(f"   - Direct context: {_code(item.value)}")
    lines.extend(
        [
            f"   - Evidence: {format_evidence_ids(item.evidence_ids)}",
            f"   - Suggested manual action: {_md(item.suggested_manual_action)}",
            f"   - Signal: {_md(item.signal or item.category)}",
            "",
        ]
    )
    return lines


def _render_bullet_item(item: HumanTriageItem) -> list[str]:
    return [
        f"- **{_md(item.title)}** ({_md(item.source)}): {_code(item.value)}",
        f"  - Why it matters: {_md(item.why_it_matters)}",
        f"  - Evidence: {format_evidence_ids(item.evidence_ids)}",
    ]


def format_evidence_ids(values: tuple[str, ...] | list[str]) -> str:
    """Format evidence IDs for compact Markdown output."""

    if not values:
        return "`none`"
    return ", ".join(_code(value) for value in values)


def _safe_preview(value: str, *, limit: int = 120) -> str:
    preview = _compact(value, limit=limit)
    return SENSITIVE_PREVIEW_TERMS.sub("[review-term]", preview)


def _compact(value: str, *, limit: int = 120) -> str:
    compacted = " ".join(str(value).split())
    if len(compacted) <= limit:
        return compacted
    return compacted[: limit - 3].rstrip() + "..."


def _md(value: object) -> str:
    return str(value).replace("|", "\\|")


def _code(value: object) -> str:
    text = str(value).replace("`", "'")
    return f"`{text}`"


def _dedupe(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result
