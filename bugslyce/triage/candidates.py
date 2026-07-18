"""Generate evidence-backed manual review candidates from ProjectState."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
import re
from urllib.parse import urlparse

from bugslyce.core.models import Asset, Candidate, Endpoint, ProjectState
from bugslyce.triage.classify import (
    ADMIN_SURFACE,
    API_SURFACE,
    AUTH_SURFACE,
    CREDENTIAL_LIKE_ARTIFACT_REVIEW,
    ENVIRONMENT_SURFACE,
    ENCODED_ARTIFACT_REVIEW,
    EXPOSED_SERVICE_CONTEXT,
    FILE_OR_CONTENT_SURFACE,
    HIGH_PORT_HTTP_SERVICE,
    HIDDEN_PATH_REVIEW,
    KILL_SWITCH,
    LOW_SIGNAL_STATIC,
    MULTIPLE_HTTP_SERVICES,
    OBJECT_REFERENCE_REVIEW,
    REDIRECT_PARAMETER_REVIEW,
    ROBOTS_ARTIFACT,
    DEAD_LOW_SIGNAL_PATH,
    TECHNOLOGY_REVIEW,
)
from bugslyce.triage.killswitch import (
    LOW_SIGNAL_GUIDANCE,
    VALIDATION_GUIDANCE,
    asset_kill_switch_guidance,
    endpoint_kill_switch_guidance,
)
from bugslyce.triage.scoring import (
    priority_for_asset,
    priority_for_endpoint,
    priority_for_service,
)

KEYWORD_SIGNAL_TERMS = {
    "password",
    "secret",
}
ASSIGNMENT_LIKE_COMMENT = re.compile(
    r"(?i)\b(?P<label>"
    r"api[_ -]?key|database[_ -]?(?:user|password)|db[_ -]?(?:user|password)|"
    r"password|passwd|pwd|secret|token|username|user"
    r")\b"
    r"\s*[:=]\s*['\"]?(?P<value>[A-Za-z0-9._~+/=-]{3,})"
)
GENERIC_LOGIN_FORM_KEYWORDS = {"login", "password"}
LOGIN_FORM_ARTIFACT_TYPES = {"form", "input"}
DOCUMENTATION_VALUE_WORDS = {
    "documentation",
    "field",
    "generation",
    "management",
    "reset",
    "style",
    "styling",
    "workflow",
}


def generate_candidates(project_state: ProjectState) -> list[Candidate]:
    """Generate deterministic manual-review leads from assembled project state."""

    candidates: list[Candidate] = []
    seen: set[tuple[str, str]] = set()
    assets_by_host = {asset.hostname: asset for asset in project_state.assets}
    endpoint_groups: dict[tuple[str, str], _EndpointCandidateGroup] = {}
    endpoint_group_order: list[tuple[str, str]] = []

    for endpoint in project_state.endpoints:
        asset = assets_by_host.get(endpoint.hostname)
        if "static_asset" in endpoint.tags and _only_static_context(endpoint):
            _record_endpoint_group(
                endpoint_groups,
                endpoint_group_order,
                endpoint,
                asset,
                LOW_SIGNAL_STATIC,
                title=f"Low-signal static asset on {endpoint.hostname}",
                rationale="This endpoint is a static asset in the parsed recon data and has no stronger linked context.",
                suggested_manual_validation=[
                    "Treat this as low signal unless manual recon adds stronger context.",
                    "Record request/response evidence before escalating this lead.",
                ],
            )
            continue

        if "auth_surface" in endpoint.tags:
            _record_endpoint_group(
                endpoint_groups,
                endpoint_group_order,
                endpoint,
                asset,
                AUTH_SURFACE,
                f"Auth-flow manual review for {endpoint.hostname}",
                "This endpoint has auth, login, reset, account, or session path context in parsed URL evidence.",
                [
                    "Review the programme scope before any manual testing.",
                    "Manually inspect the auth flow and note expected behaviours.",
                    "Record request/response evidence before escalating this lead.",
                ],
            )
        if "admin_surface" in endpoint.tags:
            _record_endpoint_group(
                endpoint_groups,
                endpoint_group_order,
                endpoint,
                asset,
                ADMIN_SURFACE,
                f"Admin-surface manual review for {endpoint.hostname}",
                "This endpoint has admin path context in parsed URL evidence.",
                [
                    "Review the programme scope before any manual testing.",
                    "Manually inspect expected access requirements for this admin-labelled surface.",
                    "Do not treat this as a finding without manual validation.",
                ],
            )
        if "api_surface" in endpoint.tags:
            _record_endpoint_group(
                endpoint_groups,
                endpoint_group_order,
                endpoint,
                asset,
                API_SURFACE,
                f"API-surface manual review for {endpoint.hostname}",
                "This endpoint has API-style path context in parsed URL evidence.",
                [
                    "Review the programme scope before any manual testing.",
                    "Manually inspect documented API behaviour and expected access requirements.",
                    "Record request/response evidence before escalating this lead.",
                ],
            )
        if "file_or_content_surface" in endpoint.tags:
            _record_endpoint_group(
                endpoint_groups,
                endpoint_group_order,
                endpoint,
                asset,
                FILE_OR_CONTENT_SURFACE,
                f"File or content-flow manual review for {endpoint.hostname}",
                "This endpoint has upload, import, export, download, file, or content context in parsed URL evidence.",
                [
                    "Check whether upload or download functionality has documented constraints.",
                    "Review the programme scope before any manual testing.",
                    "Record request/response evidence before escalating this lead.",
                ],
            )
        if "object_reference" in endpoint.tags:
            _record_endpoint_group(
                endpoint_groups,
                endpoint_group_order,
                endpoint,
                asset,
                OBJECT_REFERENCE_REVIEW,
                f"Object reference review for {endpoint.hostname}",
                "This endpoint has object-like query parameters in parsed URL evidence.",
                [
                    "Check whether object-like parameters are tied to the authenticated user context.",
                    "Review expected access boundaries using authorised accounts only.",
                    "Record request/response evidence before escalating this lead.",
                ],
            )
        if "redirect_parameter" in endpoint.tags:
            _record_endpoint_group(
                endpoint_groups,
                endpoint_group_order,
                endpoint,
                asset,
                REDIRECT_PARAMETER_REVIEW,
                f"Redirect-parameter review for {endpoint.hostname}",
                "This endpoint has redirect-like query parameters in parsed URL evidence.",
                [
                    "Review redirect-like parameters for intended navigation behaviour.",
                    "Manually inspect expected destinations using authorised flows only.",
                    "Record request/response evidence before escalating this lead.",
                ],
            )
        if endpoint.path.lower().endswith("/robots.txt") or endpoint.path.lower() == "/robots.txt":
            _record_endpoint_group(
                endpoint_groups,
                endpoint_group_order,
                endpoint,
                asset,
                ROBOTS_ARTIFACT,
                f"Robots artefact review for {endpoint.hostname}",
                "A robots.txt URL is present in structured URL evidence and may reference additional paths.",
                [
                    "Review the robots.txt content already collected or retrieve it only within authorised scope.",
                    "Treat referenced paths as recon leads that require manual validation.",
                    "Record evidence before adding any path to the manual review queue.",
                ],
            )
        if _has_hidden_path_marker(endpoint.path):
            _record_endpoint_group(
                endpoint_groups,
                endpoint_group_order,
                endpoint,
                asset,
                HIDDEN_PATH_REVIEW,
                f"Hidden-looking path review for {endpoint.hostname}",
                "This URL contains a hidden, secret, private, backup, old, dev, staging, or test path segment.",
                [
                    "Review the programme scope before inspecting this path further.",
                    "Manually determine whether the path is intended, current, and relevant.",
                    "Record request/response evidence before escalating this lead.",
                ],
            )

    for key in endpoint_group_order:
        group = endpoint_groups[key]
        _add_candidate(
            candidates,
            seen,
            group.candidate_type,
            group.hostname,
            title=group.title,
            priority=_combine_priorities(group.priorities),
            rationale=group.rationale,
            affected_assets=[group.hostname],
            affected_endpoints=group.affected_endpoints,
            evidence_ids=group.evidence_ids,
            suggested_manual_validation=group.suggested_manual_validation,
            kill_switch_guidance=_select_guidance(group.kill_switch_guidance),
        )

    for asset in project_state.assets:
        if "environment" in asset.tags:
            _add_candidate(
                candidates,
                seen,
                ENVIRONMENT_SURFACE,
                asset.hostname,
                title=f"Environment-labelled host review for {asset.hostname}",
                priority=priority_for_asset(asset, ENVIRONMENT_SURFACE),
                rationale="This host has staging, stage, dev, or test naming context in parsed asset evidence.",
                affected_assets=[asset.hostname],
                affected_endpoints=[],
                evidence_ids=asset.evidence_ids,
                suggested_manual_validation=[
                    "Review the programme scope before any manual testing.",
                    "Manually inspect whether the host is intended for tester access.",
                    "Do not treat this as a finding without manual validation.",
                ],
                kill_switch_guidance=asset_kill_switch_guidance(asset) or VALIDATION_GUIDANCE,
            )
        if "static_or_cdn" in asset.tags and len(asset.tags) == 1:
            _add_candidate(
                candidates,
                seen,
                LOW_SIGNAL_STATIC,
                asset.hostname,
                title=f"Low-signal static or CDN host for {asset.hostname}",
                priority="low" if asset.in_scope is True else "kill_switch",
                rationale="This host has static or CDN naming context and no stronger linked host tag.",
                affected_assets=[asset.hostname],
                affected_endpoints=[],
                evidence_ids=asset.evidence_ids,
                suggested_manual_validation=[
                    "Treat this as low signal unless manual recon adds stronger context.",
                    "Do not spend time here unless new evidence links it to sensitive functionality.",
                ],
                kill_switch_guidance=asset_kill_switch_guidance(asset) or LOW_SIGNAL_GUIDANCE,
            )

    for service in project_state.http_services:
        asset = assets_by_host.get(service.hostname)
        if not service.evidence_ids or not service.technologies:
            continue
        if not asset or not any(tag in asset.tags for tag in ("admin", "api", "environment")):
            continue
        _add_candidate(
            candidates,
            seen,
            TECHNOLOGY_REVIEW,
            service.url,
            title=f"Technology-context review for {service.hostname}",
            priority=priority_for_service(service, asset),
            rationale="This HTTP service has technology metadata plus admin, API, or environment host context.",
            affected_assets=[service.hostname],
            affected_endpoints=[],
            evidence_ids=service.evidence_ids,
            suggested_manual_validation=[
                "Review observed technology metadata as context only.",
                "Manually inspect expected service behaviour within programme scope.",
                "Record request/response evidence before escalating this lead.",
            ],
            kill_switch_guidance=asset_kill_switch_guidance(asset) or VALIDATION_GUIDANCE,
        )

    services_by_host: dict[str, list] = {}
    for service in project_state.http_services:
        services_by_host.setdefault(service.hostname, []).append(service)
        port = urlparse(service.url).port
        if port is None or port <= 1024:
            continue
        asset = assets_by_host.get(service.hostname)
        _add_candidate(
            candidates,
            seen,
            HIGH_PORT_HTTP_SERVICE,
            service.url,
            title=f"High-port HTTP service review for {service.hostname}:{port}",
            priority="medium" if asset and asset.in_scope is True else "kill_switch",
            rationale="Structured HTTP metadata shows an HTTP service on a port above 1024.",
            affected_assets=[service.hostname],
            affected_endpoints=[service.url],
            evidence_ids=service.evidence_ids,
            suggested_manual_validation=[
                "Review programme scope before manual inspection of this service.",
                "Compare the service with other HTTP services on the same host.",
                "Record response metadata and observed functionality before escalating this lead.",
            ],
            kill_switch_guidance=asset_kill_switch_guidance(asset) or VALIDATION_GUIDANCE,
        )

    for hostname, services in services_by_host.items():
        distinct_urls = _dedupe(service.url for service in services)
        if len(distinct_urls) < 2:
            continue
        asset = assets_by_host.get(hostname)
        _add_candidate(
            candidates,
            seen,
            MULTIPLE_HTTP_SERVICES,
            hostname,
            title=f"Multiple HTTP services review for {hostname}",
            priority="medium" if asset and asset.in_scope is True else "kill_switch",
            rationale="Structured HTTP metadata shows multiple distinct HTTP service URLs for this host.",
            affected_assets=[hostname],
            affected_endpoints=distinct_urls,
            evidence_ids=_dedupe(
                evidence_id
                for service in services
                for evidence_id in service.evidence_ids
            ),
            suggested_manual_validation=[
                "Compare titles, technologies, and exposed functionality across the services.",
                "Review programme scope before manual inspection.",
                "Record service-specific evidence before escalating a lead.",
            ],
            kill_switch_guidance=asset_kill_switch_guidance(asset) or VALIDATION_GUIDANCE,
        )

    for port_service in project_state.port_services:
        if port_service.state != "open" or "http_service" in port_service.tags:
            continue
        asset = assets_by_host.get(port_service.host)
        service_label = port_service.service or "unknown service"
        _add_candidate(
            candidates,
            seen,
            EXPOSED_SERVICE_CONTEXT,
            f"{port_service.host}:{port_service.port}/{port_service.protocol}",
            title=f"Exposed service context for {port_service.host}:{port_service.port}",
            priority="low" if asset and asset.in_scope is True else "kill_switch",
            rationale=f"Structured nmap evidence records an open {service_label} service.",
            affected_assets=[port_service.host],
            affected_endpoints=[],
            evidence_ids=port_service.evidence_ids,
            suggested_manual_validation=[
                "Review programme scope before inspecting this service.",
                "Record the expected service role and version context.",
                "Treat service metadata as recon context rather than a finding.",
            ],
            kill_switch_guidance=asset_kill_switch_guidance(asset) or VALIDATION_GUIDANCE,
        )

    artifact_groups: dict[tuple[str, str], list] = {}
    for artifact in project_state.http_artifacts:
        host = normalise_artifact_host(artifact.url)
        if not host:
            continue
        if "robots_artifact" in artifact.tags:
            artifact_groups.setdefault((ROBOTS_ARTIFACT, host), []).append(artifact)
        if "encoded_or_hidden_artifact" in artifact.tags:
            artifact_groups.setdefault((ENCODED_ARTIFACT_REVIEW, host), []).append(artifact)

    for (candidate_type, host), artifacts in artifact_groups.items():
        asset = assets_by_host.get(host)
        if candidate_type == ROBOTS_ARTIFACT:
            title = f"Robots artefact review for {host}"
            rationale = "Structured robots evidence includes directives or user-agent context."
            validation = [
                "Review robots directives as recon context.",
                "Treat referenced paths as manual review leads only when they are in scope.",
                "Record linked path evidence before escalating a lead.",
            ]
        else:
            title = f"Encoded or hidden artefact review for {host}"
            rationale = "Saved HTML metadata contains a hidden element or encoded-looking artefact."
            validation = [
                "Review the saved HTML context without assuming the artefact meaning.",
                "Do not decode or interpret content without authorised manual review.",
                "Record surrounding page evidence before escalating a lead.",
            ]
        _add_candidate(
            candidates,
            seen,
            candidate_type,
            host,
            title=title,
            priority="low" if asset and asset.in_scope is True else "kill_switch",
            rationale=rationale,
            affected_assets=[host],
            affected_endpoints=_dedupe(artifact.url for artifact in artifacts if artifact.url),
            evidence_ids=_dedupe(
                evidence_id
                for artifact in artifacts
                for evidence_id in artifact.evidence_ids
            ),
            suggested_manual_validation=validation,
            kill_switch_guidance=asset_kill_switch_guidance(asset) or VALIDATION_GUIDANCE,
        )

    credential_groups = _credential_like_artifact_groups(project_state)
    for url, artifacts in credential_groups.items():
        host = normalise_artifact_host(url)
        if not host:
            continue
        asset = assets_by_host.get(host)
        has_secret_comment = any(_is_secret_comment(artifact) for artifact in artifacts)
        priority = "high" if has_secret_comment else "medium"
        if asset and asset.in_scope is False:
            priority = "kill_switch"
        path = urlparse(url).path or "/"
        title_context = "homepage HTML" if path in {"", "/"} else f"HTML for {path}"
        _add_candidate(
            candidates,
            seen,
            CREDENTIAL_LIKE_ARTIFACT_REVIEW,
            url,
            title=f"Credential-like artefact review in {title_context}",
            priority=priority,
            rationale=(
                "Parsed HTML/comment evidence contains credential-like or sensitive "
                "keyword context requiring manual review."
            ),
            affected_assets=[host],
            affected_endpoints=[url],
            evidence_ids=_dedupe(
                evidence_id
                for artifact in artifacts
                for evidence_id in artifact.evidence_ids
            ),
            suggested_manual_validation=[
                "Review saved HTML/source context before interpreting the artefact.",
                "Confirm whether the artefact is a clue, placeholder, or sensitive exposure.",
                "Do not attempt authentication unless explicitly authorised.",
                "Do not brute force.",
                "Record evidence before escalating any claim.",
            ],
            kill_switch_guidance=(
                "Do not treat keyword-only hits as valid credentials without manual validation."
                if priority != "kill_switch"
                else asset_kill_switch_guidance(asset) or VALIDATION_GUIDANCE
            ),
        )

    dead_groups: dict[str, list] = {}
    for path in project_state.discovered_paths:
        if "dead_path" in path.tags:
            host = normalise_artifact_host(path.url)
            if host:
                dead_groups.setdefault(host, []).append(path)
    for host, paths in dead_groups.items():
        asset = assets_by_host.get(host)
        _add_candidate(
            candidates,
            seen,
            DEAD_LOW_SIGNAL_PATH,
            host,
            title=f"Dead or low-signal path context for {host}",
            priority="low" if asset and asset.in_scope is True else "kill_switch",
            rationale="Structured path or header evidence records one or more 404 responses.",
            affected_assets=[host],
            affected_endpoints=_dedupe(path.url for path in paths),
            evidence_ids=_dedupe(
                evidence_id
                for path in paths
                for evidence_id in path.evidence_ids
            ),
            suggested_manual_validation=[
                "Treat these paths as low signal unless new evidence changes the response context.",
                "Avoid repeated manual effort on unchanged 404 paths.",
            ],
            kill_switch_guidance=LOW_SIGNAL_GUIDANCE,
        )

    for asset in project_state.assets:
        if asset.in_scope is not False:
            continue
        _add_candidate(
            candidates,
            seen,
            KILL_SWITCH,
            asset.hostname,
            title=f"Scope review before testing {asset.hostname}",
            priority="kill_switch",
            rationale="This host appears to match out-of-scope information in the assembled project state.",
            affected_assets=[asset.hostname],
            affected_endpoints=[],
            evidence_ids=asset.evidence_ids,
            suggested_manual_validation=["Review programme scope before testing this host further."],
            kill_switch_guidance="Review programme scope before testing this host further.",
        )

    result = [_with_candidate_id(index, candidate) for index, candidate in enumerate(candidates, start=1)]
    if project_state.recon_summary is not None:
        project_state.recon_summary.candidate_count = len(result)
    return result


@dataclass
class _EndpointCandidateGroup:
    candidate_type: str
    hostname: str
    title: str
    rationale: str
    suggested_manual_validation: list[str]
    priorities: list[str] = field(default_factory=list)
    affected_endpoints: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    kill_switch_guidance: list[str] = field(default_factory=list)


def _record_endpoint_group(
    groups: dict[tuple[str, str], _EndpointCandidateGroup],
    order: list[tuple[str, str]],
    endpoint: Endpoint,
    asset: Asset | None,
    candidate_type: str,
    title: str,
    rationale: str,
    suggested_manual_validation: list[str],
) -> None:
    if not endpoint.evidence_ids:
        return

    key = (candidate_type, endpoint.hostname)
    if key not in groups:
        order.append(key)
        groups[key] = _EndpointCandidateGroup(
            candidate_type=candidate_type,
            hostname=endpoint.hostname,
            title=title,
            rationale=rationale,
            suggested_manual_validation=suggested_manual_validation,
        )

    group = groups[key]
    _append_unique(group.affected_endpoints, endpoint.url)
    for evidence_id in endpoint.evidence_ids:
        _append_unique(group.evidence_ids, evidence_id)
    group.priorities.append(priority_for_endpoint(endpoint, asset, candidate_type))
    guidance = endpoint_kill_switch_guidance(endpoint, asset)
    if guidance:
        _append_unique(group.kill_switch_guidance, guidance)


def _combine_priorities(priorities: list[str]) -> str:
    rank = {"low": 0, "medium": 1, "high": 2, "kill_switch": 3}
    if not priorities:
        return "low"
    return max(priorities, key=lambda priority: rank[priority])


def _select_guidance(guidance_values: list[str]) -> str | None:
    if not guidance_values:
        return None
    for guidance in guidance_values:
        if guidance != VALIDATION_GUIDANCE:
            return guidance
    return guidance_values[0]


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _add_candidate(
    candidates: list[Candidate],
    seen: set[tuple[str, str]],
    candidate_type: str,
    dedupe_key: str,
    *,
    title: str,
    priority: str,
    rationale: str,
    affected_assets: list[str],
    affected_endpoints: list[str],
    evidence_ids: list[str],
    suggested_manual_validation: list[str],
    kill_switch_guidance: str | None,
) -> None:
    if not evidence_ids:
        return
    key = (candidate_type, dedupe_key)
    if key in seen:
        return
    seen.add(key)
    candidates.append(
        Candidate(
            id="",
            candidate_type=candidate_type,
            title=title,
            priority=priority,
            rationale=rationale,
            affected_assets=_dedupe(affected_assets),
            affected_endpoints=_dedupe(affected_endpoints),
            evidence_ids=_dedupe(evidence_ids),
            suggested_manual_validation=suggested_manual_validation,
            kill_switch_guidance=kill_switch_guidance,
        )
    )


def _with_candidate_id(index: int, candidate: Candidate) -> Candidate:
    return Candidate(
        id=f"CAND-{index:04d}",
        candidate_type=candidate.candidate_type,
        title=candidate.title,
        priority=candidate.priority,
        rationale=candidate.rationale,
        affected_assets=candidate.affected_assets,
        affected_endpoints=candidate.affected_endpoints,
        evidence_ids=candidate.evidence_ids,
        suggested_manual_validation=candidate.suggested_manual_validation,
        kill_switch_guidance=candidate.kill_switch_guidance,
    )


def _only_static_context(endpoint: Endpoint) -> bool:
    return "static_asset" in endpoint.tags and all(tag == "static_asset" for tag in endpoint.tags)


def _has_hidden_path_marker(path: str) -> bool:
    markers = {"hidden", "secret", "private", "backup", "old", "dev", "staging", "test"}
    segments = {segment.lower() for segment in path.strip("/").split("/") if segment}
    return bool(segments & markers)


def normalise_artifact_host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _credential_like_artifact_groups(project_state: ProjectState) -> dict[str, list]:
    groups: dict[str, list] = {}
    artifacts_by_url: dict[str, list] = {}
    for artifact in project_state.http_artifacts:
        if not artifact.url:
            continue
        artifacts_by_url.setdefault(artifact.url, []).append(artifact)

    supporting_keywords_by_url: dict[str, list] = {}
    for artifact in project_state.http_artifacts:
        if not artifact.url or not artifact.evidence_ids:
            continue
        if _is_sensitive_comment(artifact):
            groups.setdefault(artifact.url, []).append(artifact)
        elif _is_sensitive_keyword_hit(artifact):
            supporting_keywords_by_url.setdefault(artifact.url, []).append(artifact)
    for url, supporting_keywords in supporting_keywords_by_url.items():
        if url in groups:
            groups[url].extend(supporting_keywords)
    return {
        url: artifacts
        for url, artifacts in groups.items()
        if not _is_generic_login_form_keyword_group(artifacts, artifacts_by_url.get(url, []))
    }


def _is_generic_login_form_keyword_group(
    grouped_artifacts: list,
    url_artifacts: list,
) -> bool:
    if any(_is_sensitive_comment(artifact) for artifact in grouped_artifacts):
        return False
    grouped_types = {artifact.artifact_type for artifact in grouped_artifacts}
    if grouped_types != {"keyword_hit"}:
        return False
    values = {artifact.value.strip().lower() for artifact in grouped_artifacts}
    if not values or not values.issubset(GENERIC_LOGIN_FORM_KEYWORDS):
        return False
    return any(artifact.artifact_type in LOGIN_FORM_ARTIFACT_TYPES for artifact in url_artifacts)


def _is_sensitive_comment(artifact) -> bool:
    if artifact.artifact_type != "html_comment":
        return False
    return any(
        _is_sensitive_assignment(label, value)
        for label, value in _comment_assignments(artifact.value)
    )


def _is_secret_comment(artifact) -> bool:
    if artifact.artifact_type != "html_comment":
        return False
    return any(
        _is_secret_assignment(label, value)
        for label, value in _comment_assignments(artifact.value)
    )


def _comment_assignments(value: str) -> list[tuple[str, str]]:
    return [
        (_normalise_assignment_label(match.group("label")), match.group("value").strip("'\""))
        for match in ASSIGNMENT_LIKE_COMMENT.finditer(value)
    ]


def _is_sensitive_assignment(label: str, value: str) -> bool:
    if _is_secret_assignment(label, value):
        return True
    return _is_username_label(label) and _is_plausible_username(value)


def _normalise_assignment_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")


def _is_username_label(label: str) -> bool:
    return label in {"user", "username", "db_user", "database_user"}


def _is_secret_label(label: str) -> bool:
    return label in {
        "api_key",
        "db_password",
        "database_password",
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
    }


def _is_secret_assignment(label: str, value: str) -> bool:
    if not _is_secret_label(label):
        return False
    if label == "api_key":
        return _looks_like_api_key(value) or _looks_like_config_secret(value)
    if label == "token":
        return _looks_like_token(value)
    return _looks_like_config_secret(value)


def _is_plausible_username(value: str) -> bool:
    if len(value) < 4 or len(value) > 64:
        return False
    if not re.fullmatch(r"[A-Za-z0-9._-]+", value):
        return False
    return value.lower() not in DOCUMENTATION_VALUE_WORDS


def _looks_like_config_secret(value: str) -> bool:
    if len(value) < 10 or _looks_like_documentation_word(value):
        return False
    classes = sum(
        bool(pattern.search(value))
        for pattern in (
            re.compile(r"[a-z]"),
            re.compile(r"[A-Z]"),
            re.compile(r"\d"),
            re.compile(r"[-_./+=~]"),
        )
    )
    return classes >= 2


def _looks_like_api_key(value: str) -> bool:
    return bool(re.match(r"(?i)^[a-z]{2,}_[A-Za-z0-9][A-Za-z0-9._-]{10,}$", value))


def _looks_like_token(value: str) -> bool:
    if value.count(".") >= 2 and len(value) >= 20:
        return True
    return _looks_like_config_secret(value)


def _looks_like_documentation_word(value: str) -> bool:
    return value.lower() in DOCUMENTATION_VALUE_WORDS


def _is_sensitive_keyword_hit(artifact) -> bool:
    return (
        artifact.artifact_type == "keyword_hit"
        and artifact.value.strip().lower() in KEYWORD_SIGNAL_TERMS
    )


def _dedupe(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
