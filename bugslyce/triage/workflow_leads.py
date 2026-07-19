"""Shared deterministic grouping for concise operator workflow leads."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import re
from urllib.parse import parse_qsl, urljoin, urlparse

from bugslyce.core.models import ProjectState
from bugslyce.recon.http_origin import HttpOrigin, http_origin_from_url


QUERY_PARAMETER_CONTEXTS = frozenset(
    {
        "form_action_query",
        "html_route_query",
        "javascript_route_query",
        "source_requested_url_query",
        "source_final_url_query",
        "shallow_observed_query",
        "shallow_final_url_query",
    }
)
_FORM_ACTION_QUERY_CONTEXTS = frozenset({"form_action_query"})
_ROUTE_QUERY_CONTEXTS = frozenset(
    {"html_route_query", "javascript_route_query"}
)
_SOURCE_QUERY_CONTEXTS = QUERY_PARAMETER_CONTEXTS - (
    _FORM_ACTION_QUERY_CONTEXTS | _ROUTE_QUERY_CONTEXTS
)

_AUTH_PATH_TERMS = {
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
_AUTHENTICATION_PATH_TERMS = {
    "auth",
    "login",
    "logout",
    "oauth",
    "password",
    "session",
    "signin",
}
_ACCOUNT_REGISTRATION_TERMS = {"create-account", "join", "register", "signup"}
_ACCOUNT_RECOVERY_TERMS = {
    "forgot",
    "password-recovery",
    "password-reset",
    "recover",
    "recover-access",
    "recovery",
    "reset",
}
_OBJECT_PARAMETER_TERMS = {
    "account",
    "document",
    "entry",
    "identifier",
    "item",
    "member",
    "object",
    "order",
    "record",
    "ref",
    "reference",
    "resource",
    "user",
}
_STATIC_ROUTE_SUFFIXES = (
    ".js",
    ".mjs",
    ".cjs",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".avif",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".mp3",
    ".wav",
    ".ogg",
    ".mp4",
    ".webm",
    ".avi",
    ".mov",
    ".pdf",
)
_STATIC_OR_DOCUMENTATION_SEGMENTS = {
    "asset",
    "assets",
    "doc",
    "docs",
    "documentation",
    "font",
    "fonts",
    "image",
    "images",
    "img",
    "media",
    "script",
    "scripts",
    "static",
    "style",
    "styles",
}
_MAX_REPRESENTATIVE_ROUTES = 4
_MAX_CONTEXT_ROUTES = 3
_MAX_PARAMETER_NAMES = 5
_MAX_FIELD_NAMES = 6
_MAX_EVIDENCE_IDS = 12


@dataclass(frozen=True)
class WorkflowLead:
    """One bounded grouped decision shared by report and runbook renderers."""

    title: str
    priority: str
    category: str
    summary: str
    why_it_matters: str
    suggested_manual_action: str
    representative_urls: tuple[str, ...]
    covered_urls: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    signal: str


@dataclass(frozen=True)
class _AccountObservation:
    url: str
    kind: str
    evidence_ids: tuple[str, ...]
    methods: tuple[str, ...] = ()
    field_names: tuple[str, ...] = ()
    redirect_target_url: str | None = None


@dataclass
class _ParameterEvidenceGroup:
    urls: set[str]
    evidence_ids: list[str]
    occurrences: int = 0
    numeric_occurrences: int = 0


def build_grouped_workflow_leads(
    project_state: ProjectState,
    deep_orchestration: object | None = None,
) -> tuple[WorkflowLead, ...]:
    """Build bounded account and direct-query workflow leads deterministically."""

    leads = [
        *_account_workflow_leads(project_state, deep_orchestration),
        *_object_reference_workflow_leads(project_state, deep_orchestration),
    ]
    return tuple(
        sorted(
            leads,
            key=lambda item: (
                {"high": 0, "medium": 1, "low": 2}.get(item.priority, 99),
                {"account_workflow": 0, "object_reference_surface": 1}.get(
                    item.category,
                    99,
                ),
                _workflow_lead_origin(item),
                item.title,
            ),
        )
    )


def canonical_workflow_url(value: str | None) -> str:
    """Return a query-free canonical URL for grouping and concise display."""

    if not value:
        return ""
    try:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except (TypeError, ValueError):
        return value.rstrip("/")
    if not scheme or not host:
        return value.rstrip("/")
    default_port = 80 if scheme == "http" else 443 if scheme == "https" else None
    netloc = host if port in {None, default_port} else f"{host}:{port}"
    path = parsed.path or "/"
    return f"{scheme}://{netloc}{path.rstrip('/') or '/'}"


def _account_workflow_leads(
    project_state: ProjectState,
    deep_orchestration: object | None,
) -> tuple[WorkflowLead, ...]:
    observations: list[_AccountObservation] = []

    for endpoint in getattr(project_state, "endpoints", ()):
        if _account_route_kind(endpoint.url) is not None:
            observations.append(
                _AccountObservation(
                    url=endpoint.url,
                    kind="observed_route",
                    evidence_ids=tuple(endpoint.evidence_ids),
                )
            )

    for path in getattr(project_state, "discovered_paths", ()):
        route_kind = _account_route_kind(path.url)
        target_url = _resolved_redirect_target(path.url, path.redirect_location)
        target_kind = _account_route_kind(target_url or "")
        if path.status_code in {401, 403}:
            if route_kind is None:
                continue
            kind = "access_boundary"
        elif path.status_code is not None and 300 <= path.status_code < 400:
            if _is_authentication_redirect_kind(target_kind):
                kind = "authentication_redirect"
            elif route_kind is not None:
                kind = "account_route_redirect"
            else:
                continue
        else:
            if route_kind is None:
                continue
            kind = "observed_route"
        observations.append(
            _AccountObservation(
                url=path.url,
                kind=kind,
                evidence_ids=tuple(path.evidence_ids),
                redirect_target_url=(
                    target_url
                    if kind in {"authentication_redirect", "account_route_redirect"}
                    else None
                ),
            )
        )

    forms = tuple(
        getattr(getattr(deep_orchestration, "form_inventory", None), "forms", ())
    )
    for form in forms:
        document_urls = tuple(getattr(form, "safe_document_urls", ()))
        action_url = getattr(form, "safe_resolved_action_url", None)
        available_urls = tuple(
            value
            for value in (*document_urls, action_url)
            if isinstance(value, str) and value and value != "unresolved"
        )
        relevant_urls = tuple(
            value for value in available_urls if _account_route_kind(value) is not None
        )
        password_controls = int(
            getattr(getattr(form, "control_summary", None), "password_controls", 0)
            or 0
        )
        if not relevant_urls and password_controls:
            relevant_urls = available_urls[:1]
        form_context_urls = {
            canonical_workflow_url(value)
            for value in available_urls
            if canonical_workflow_url(value)
        }
        field_names = _deep_form_field_names(
            deep_orchestration,
            form_context_urls,
        )
        for index, url in enumerate(relevant_urls):
            observations.append(
                _AccountObservation(
                    url=url,
                    kind="observed_form" if index == 0 else "observed_route",
                    evidence_ids=tuple(getattr(form, "evidence_ids", ())),
                    methods=tuple(getattr(form, "methods", ())) if index == 0 else (),
                    field_names=field_names if index == 0 else (),
                )
            )

    for route in getattr(
        getattr(deep_orchestration, "html_route_extraction", None),
        "routes",
        (),
    ):
        url = getattr(route, "safe_resolved_url", "")
        if _account_route_kind(url) is not None:
            observations.append(
                _AccountObservation(
                    url=url,
                    kind="observed_route",
                    evidence_ids=tuple(getattr(route, "evidence_ids", ())),
                )
            )
    for route in getattr(
        getattr(deep_orchestration, "javascript_route_extraction", None),
        "candidates",
        (),
    ):
        url = getattr(route, "safe_resolved_url", None) or getattr(
            route,
            "safe_candidate",
            "",
        )
        if _account_route_kind(url) is not None:
            observations.append(
                _AccountObservation(
                    url=url,
                    kind="observed_route",
                    evidence_ids=tuple(getattr(route, "evidence_ids", ())),
                )
            )

    for redirect in getattr(
        getattr(deep_orchestration, "redirect_auth_flow_review", None),
        "observations",
        (),
    ):
        source_url = getattr(redirect, "safe_source_url", "")
        target_url = getattr(redirect, "safe_resolved_target_url", None)
        source_kind = _account_route_kind(source_url)
        target_kind = _account_route_kind(
            target_url if isinstance(target_url, str) else ""
        )
        if _is_authentication_redirect_kind(target_kind):
            kind = "authentication_redirect"
        elif source_kind is not None:
            kind = "account_route_redirect"
        else:
            continue
        if source_url and source_url != "unresolved":
            observations.append(
                _AccountObservation(
                    url=source_url,
                    kind=kind,
                    evidence_ids=tuple(getattr(redirect, "evidence_ids", ())),
                    redirect_target_url=(
                        target_url
                        if isinstance(target_url, str) and target_url != "unresolved"
                        else None
                    ),
                )
            )

    observations = _dedupe_account_observations(observations)
    by_origin: dict[HttpOrigin, list[_AccountObservation]] = {}
    for item in observations:
        origin = http_origin_from_url(item.url)
        if origin is not None:
            by_origin.setdefault(origin, []).append(item)
    leads = [
        lead
        for origin in sorted(by_origin)
        if (lead := _account_origin_workflow_lead(origin, by_origin[origin]))
        is not None
    ]
    return tuple(leads)


def _account_origin_workflow_lead(
    origin: HttpOrigin,
    observations: list[_AccountObservation],
) -> WorkflowLead | None:
    route_urls = tuple(
        sorted(
            {
                canonical_workflow_url(item.url)
                for item in observations
                if canonical_workflow_url(item.url)
            }
        )
    )
    form_count = sum(item.kind == "observed_form" for item in observations)
    if not observations or (form_count == 0 and len(route_urls) < 2):
        return None

    counts = {
        kind: sum(item.kind == kind for item in observations)
        for kind in (
            "observed_form",
            "authentication_redirect",
            "account_route_redirect",
            "access_boundary",
        )
    }
    facts = [f"{len(route_urls)} account-related route(s)"]
    if counts["observed_form"]:
        facts.append(f"{counts['observed_form']} directly observed form structure(s)")
    if counts["authentication_redirect"]:
        facts.append(f"{counts['authentication_redirect']} authentication redirect(s)")
    if counts["account_route_redirect"]:
        facts.append(f"{counts['account_route_redirect']} account-route redirect(s)")
    if counts["access_boundary"]:
        facts.append(f"{counts['access_boundary']} access-boundary response(s)")
    methods = _dedupe(
        method for item in observations for method in item.methods if method
    )
    fields = _dedupe(
        name for item in observations for name in item.field_names if name
    )
    summary = _account_context_summary(observations)
    if fields:
        summary += "; observed field names: " + _bounded_values(
            sorted(fields),
            max_items=_MAX_FIELD_NAMES,
        )
    return WorkflowLead(
        title="Authentication and account workflow review",
        priority="high",
        category="account_workflow",
        summary=summary,
        why_it_matters=(
            "Collected direct evidence records "
            + ", ".join(facts)
            + ". This maps an account workflow; it does not establish unexpected "
            "or unsafe behaviour."
        ),
        suggested_manual_action=(
            "Review the saved forms, redirects, and access-boundary responses in "
            "context. Do not submit forms, attempt login, or create test values from "
            "this prompt."
        ),
        representative_urls=route_urls[:_MAX_REPRESENTATIVE_ROUTES],
        covered_urls=route_urls,
        evidence_ids=tuple(
            _dedupe(
                evidence_id
                for item in observations
                for evidence_id in item.evidence_ids
            )
        )[:_MAX_EVIDENCE_IDS],
        signal=(
            f"grouped account workflow; origin={origin.origin_url}"
            + (f"; methods={','.join(sorted(methods))}" if methods else "")
        ),
    )


def _object_reference_workflow_leads(
    project_state: ProjectState,
    deep_orchestration: object | None,
) -> tuple[WorkflowLead, ...]:
    grouped: dict[tuple[HttpOrigin, str], _ParameterEvidenceGroup] = {}

    def observe(
        name: str,
        urls: Iterable[str],
        evidence_ids: Iterable[str],
        *,
        occurrence_count: int = 1,
        numeric_count: int = 0,
    ) -> None:
        normalised = name.strip().lower()
        if not _is_object_parameter_name(normalised):
            return
        urls_by_origin: dict[HttpOrigin, set[str]] = {}
        for url in urls:
            origin = http_origin_from_url(url)
            canonical = canonical_workflow_url(url)
            if origin is not None and canonical:
                urls_by_origin.setdefault(origin, set()).add(canonical)
        for origin, canonical_urls in urls_by_origin.items():
            entry = grouped.setdefault(
                (origin, normalised),
                _ParameterEvidenceGroup(urls=set(), evidence_ids=[]),
            )
            entry.urls.update(canonical_urls)
            for evidence_id in evidence_ids:
                if evidence_id and evidence_id not in entry.evidence_ids:
                    entry.evidence_ids.append(evidence_id)
            attributable_occurrences = len(canonical_urls)
            if len(urls_by_origin) == 1:
                attributable_occurrences = max(
                    attributable_occurrences,
                    max(1, int(occurrence_count)),
                )
            entry.occurrences += attributable_occurrences
            entry.numeric_occurrences += numeric_count

    for endpoint in getattr(project_state, "endpoints", ()):
        try:
            query_items = parse_qsl(
                urlparse(endpoint.url).query,
                keep_blank_values=True,
            )
        except (TypeError, ValueError):
            continue
        for name, value in query_items:
            observe(
                name,
                (endpoint.url,),
                endpoint.evidence_ids,
                numeric_count=int(bool(re.fullmatch(r"[0-9]{1,18}", value))),
            )

    for parameter in getattr(
        getattr(deep_orchestration, "parameter_inventory", None),
        "parameters",
        (),
    ):
        name = getattr(parameter, "name", "")
        contexts = set(getattr(parameter, "contexts", ()))
        query_contexts = contexts & QUERY_PARAMETER_CONTEXTS
        if not query_contexts:
            continue
        query_urls: set[str] = set()
        if query_contexts & _FORM_ACTION_QUERY_CONTEXTS:
            query_urls.update(getattr(parameter, "safe_form_action_urls", ()))
        if query_contexts & _ROUTE_QUERY_CONTEXTS:
            query_urls.update(getattr(parameter, "safe_route_urls", ()))
        if query_contexts & _SOURCE_QUERY_CONTEXTS:
            query_urls.update(getattr(parameter, "safe_source_urls", ()))
        query_urls = {
            url
            for url in query_urls
            if _url_contains_parameter_name(url, name)
        }
        if not query_urls:
            continue
        observe(
            name,
            query_urls,
            tuple(getattr(parameter, "evidence_ids", ())),
            occurrence_count=max(len(query_urls), len(query_contexts)),
        )

    qualifying_by_origin: dict[
        HttpOrigin,
        list[tuple[str, _ParameterEvidenceGroup, list[str]]],
    ] = {}
    for (origin, name), entry in grouped.items():
        urls = sorted(entry.urls)
        if len(urls) < 2 and entry.numeric_occurrences < 2:
            continue
        if entry.occurrences < 2 and entry.numeric_occurrences < 2:
            continue
        qualifying_by_origin.setdefault(origin, []).append((name, entry, urls))

    leads: list[WorkflowLead] = []
    for origin in sorted(qualifying_by_origin):
        qualifying = sorted(
            qualifying_by_origin[origin],
            key=lambda item: (item[0], item[2]),
        )
        names = [item[0] for item in qualifying]
        urls = sorted(
            {url for _name, _entry, values in qualifying for url in values}
        )
        evidence_ids = _dedupe(
            evidence_id
            for _name, entry, _urls in qualifying
            for evidence_id in entry.evidence_ids
        )
        leads.append(
            WorkflowLead(
                title="Repeated object-reference parameter surface",
                priority="medium",
                category="object_reference_surface",
                summary=(
                    f"Origin: {origin.origin_url}; parameter names: "
                    + _bounded_values(names, max_items=_MAX_PARAMETER_NAMES)
                    + "; representative routes: "
                    + _bounded_values(urls, max_items=_MAX_REPRESENTATIVE_ROUTES)
                ),
                why_it_matters=(
                    "The same object-shaped query parameter name was directly observed "
                    "across multiple routes or repeated numeric URL references. This is a "
                    "review surface, not a confirmed authorisation issue."
                ),
                suggested_manual_action=(
                    "Review retained responses and directly observed URLs for expected "
                    "access-behaviour differences within the authorised scope. Any active "
                    "parameter testing is outside BugSlyce v1 and requires separate "
                    "authorisation."
                ),
                representative_urls=tuple(urls[:_MAX_REPRESENTATIVE_ROUTES]),
                covered_urls=tuple(urls),
                evidence_ids=tuple(evidence_ids[:_MAX_EVIDENCE_IDS]),
                signal=(
                    "repeated direct query-parameter evidence; "
                    f"origin={origin.origin_url}"
                ),
            )
        )
    return tuple(leads)


def _deep_form_field_names(
    deep_orchestration: object | None,
    form_urls: set[str],
) -> tuple[str, ...]:
    fields: list[str] = []
    parameters = getattr(
        getattr(deep_orchestration, "parameter_inventory", None),
        "parameters",
        (),
    )
    for parameter in parameters:
        if "form_control" not in set(getattr(parameter, "contexts", ())):
            continue
        related_urls = {
            canonical_workflow_url(value)
            for attribute in ("safe_form_action_urls", "safe_source_urls")
            for value in getattr(parameter, attribute, ())
            if value
        }
        if form_urls and not form_urls.intersection(related_urls):
            continue
        name = getattr(parameter, "name", "")
        if isinstance(name, str) and name:
            fields.append(name)
    return tuple(sorted(set(fields)))


def _dedupe_account_observations(
    observations: list[_AccountObservation],
) -> list[_AccountObservation]:
    grouped: dict[tuple[str, str, str], _AccountObservation] = {}
    for item in observations:
        canonical = canonical_workflow_url(item.url)
        if not canonical:
            continue
        redirect_target = canonical_workflow_url(item.redirect_target_url)
        key = (canonical, item.kind, redirect_target)
        current = grouped.get(key)
        if current is None:
            grouped[key] = _AccountObservation(
                url=canonical,
                kind=item.kind,
                evidence_ids=tuple(_dedupe(item.evidence_ids)),
                methods=tuple(sorted(set(item.methods))),
                field_names=tuple(sorted(set(item.field_names))),
                redirect_target_url=redirect_target or None,
            )
            continue
        grouped[key] = _AccountObservation(
            url=canonical,
            kind=item.kind,
            evidence_ids=tuple(_dedupe([*current.evidence_ids, *item.evidence_ids])),
            methods=tuple(sorted({*current.methods, *item.methods})),
            field_names=tuple(sorted({*current.field_names, *item.field_names})),
            redirect_target_url=current.redirect_target_url,
        )
    return [grouped[key] for key in sorted(grouped)]


def _account_context_summary(observations: list[_AccountObservation]) -> str:
    labels = (
        ("observed forms", "observed_form"),
        ("authentication redirects", "authentication_redirect"),
        ("account-route redirects", "account_route_redirect"),
        ("access boundaries", "access_boundary"),
        ("other account routes", "observed_route"),
    )
    already_listed: set[str] = set()
    parts: list[str] = []
    for label, kind in labels:
        values: list[str] = []
        for item in observations:
            source_url = canonical_workflow_url(item.url)
            if item.kind != kind or not source_url or source_url in already_listed:
                continue
            already_listed.add(source_url)
            target_url = canonical_workflow_url(item.redirect_target_url)
            values.append(
                f"{source_url} -> {target_url}"
                if target_url
                else source_url
            )
        values.sort()
        if not values:
            continue
        parts.append(
            f"{label}: {_bounded_values(values, max_items=_MAX_CONTEXT_ROUTES)}"
        )
    return "; ".join(parts) if parts else "no bounded account routes recorded"


def _account_route_kind(value: str) -> str | None:
    if not value:
        return None
    try:
        path = urlparse(value).path if "://" in value else value
    except (TypeError, ValueError):
        return None
    if _is_static_or_documentation_path(path):
        return None
    terms = _path_terms(path)
    if terms & _ACCOUNT_RECOVERY_TERMS:
        return "recovery"
    if terms & _ACCOUNT_REGISTRATION_TERMS:
        return "registration"
    if terms & _AUTHENTICATION_PATH_TERMS:
        return "authentication"
    if terms & _AUTH_PATH_TERMS or terms & {"dashboard", "member"}:
        return "account"
    return None


def _is_authentication_redirect_kind(kind: str | None) -> bool:
    return kind in {"authentication", "recovery", "registration"}


def _is_static_or_documentation_path(path: str) -> bool:
    lowered = (path or "").casefold()
    if lowered.endswith(_STATIC_ROUTE_SUFFIXES):
        return True
    segments = {
        segment
        for segment in lowered.strip("/").split("/")
        if segment
    }
    return bool(segments & _STATIC_OR_DOCUMENTATION_SEGMENTS)


def _resolved_redirect_target(source_url: str, location: str | None) -> str | None:
    if not isinstance(location, str) or not location.strip():
        return None
    try:
        target = urljoin(source_url, location.strip())
    except (TypeError, ValueError):
        return None
    return target if http_origin_from_url(target) is not None else None


def _workflow_lead_origin(lead: WorkflowLead) -> str:
    for url in lead.representative_urls:
        origin = http_origin_from_url(url)
        if origin is not None:
            return origin.origin_url
    return ""


def _path_terms(path: str) -> set[str]:
    terms: set[str] = set()
    for segment in path.split("/"):
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


def _is_object_parameter_name(name: str) -> bool:
    tokens = {
        token for token in re.split(r"[^a-z0-9]+", name.lower()) if token
    }
    return name.lower() == "id" or bool(tokens & _OBJECT_PARAMETER_TERMS)


def _url_contains_parameter_name(url: str, name: str) -> bool:
    if not isinstance(url, str) or not url or url == "unresolved":
        return False
    try:
        names = {
            observed_name
            for observed_name, _value in parse_qsl(
                urlparse(url).query,
                keep_blank_values=True,
            )
        }
    except (TypeError, ValueError):
        return False
    return name in names


def _bounded_values(values: list[str], *, max_items: int) -> str:
    visible = values[:max_items]
    rendered = ", ".join(visible) if visible else "none"
    remaining = len(values) - len(visible)
    if remaining > 0:
        rendered += f" ... +{remaining} more"
    return rendered


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result
