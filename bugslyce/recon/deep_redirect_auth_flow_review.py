"""Offline one-hop redirect/auth-path review for Deep HTTP fingerprints.

This module interprets already-collected Deep HTTP fingerprint evidence only.
It does not read files, write files, make network requests, follow redirects,
attempt authentication, invoke collectors, or make Deep Recon available.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urljoin, urlparse

from bugslyce.recon.deep_http_fingerprint_summary import (
    DeepHttpFingerprintSummary,
    DeepHttpResponseFingerprint,
)


REDIRECT_STATUS_CODES = (300, 301, 302, 303, 307, 308)
MAX_RENDERED_VALUES = 6
MAX_RENDERED_VALUE_CHARS = 120
STANDALONE_AUTH_PATH_TOKENS = frozenset(
    {
    "login",
    "signin",
    "auth",
    "authenticate",
    "authentication",
    "sso",
    "oauth",
    "oidc",
    "session",
    }
)
SAFETY_NOTES = (
    "This is offline one-hop interpretation of existing HTTP fingerprint evidence.",
    "No redirects were followed.",
    "No network request was made.",
    "Origin comparison is based only on parsed source and Location evidence.",
    "Auth-related classification is lexical path evidence only.",
    "Query values, fragments, and URL userinfo are not retained.",
    "Cookie values are not retained or rendered.",
    "No authentication was attempted.",
    "This stage produces static manual-review context only.",
)


@dataclass(frozen=True)
class DeepRedirectAuthFlowObservation:
    """One cautious one-hop redirect/auth-path observation."""

    observation_id: str
    source_fingerprint_id: str
    collection_section: str
    redirect_status_code: int
    safe_source_url: str
    location_present: bool
    location_reference_form: str
    safe_resolved_target_url: str | None
    origin_relationship: str
    source_path_auth_related: bool
    target_path_auth_related: bool
    auth_path_transition: str
    source_query_parameter_names: tuple[str, ...]
    target_query_parameter_names: tuple[str, ...]
    fragment_present: bool
    userinfo_present_and_omitted: bool
    set_cookie_present: bool
    set_cookie_count: int
    cookie_names: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    interpretation_note: str


@dataclass(frozen=True)
class DeepRedirectAuthFlowSummaryCounts:
    """Immutable count summary for redirect/auth-path observations."""

    total_http_fingerprints_considered: int
    redirect_status_responses: int
    redirects_with_location_evidence: int
    redirects_without_location_evidence: int
    same_origin_redirect_targets: int
    cross_origin_redirect_targets: int
    targets_not_origin_comparable: int
    redirects_to_auth_looking_paths: int
    redirects_from_auth_looking_paths: int
    auth_path_to_auth_path_redirects: int
    redirects_setting_cookies: int
    redirects_containing_query_parameter_names: int
    redirects_with_userinfo_omitted: int


@dataclass(frozen=True)
class DeepRedirectAuthFlowReview:
    """Offline redirect/auth-path review built from HTTP fingerprints."""

    observations: tuple[DeepRedirectAuthFlowObservation, ...]
    summary_counts: DeepRedirectAuthFlowSummaryCounts
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class _SafeUrl:
    display_url: str | None
    query_parameter_names: tuple[str, ...]
    fragment_present: bool
    userinfo_present: bool
    scheme: str | None
    hostname: str | None
    effective_port: int | None
    path: str
    comparable: bool


@dataclass(frozen=True)
class _PendingObservation:
    source_fingerprint_id: str
    collection_section: str
    redirect_status_code: int
    safe_source_url: str
    location_present: bool
    location_reference_form: str
    safe_resolved_target_url: str | None
    origin_relationship: str
    source_path_auth_related: bool
    target_path_auth_related: bool
    auth_path_transition: str
    source_query_parameter_names: tuple[str, ...]
    target_query_parameter_names: tuple[str, ...]
    fragment_present: bool
    userinfo_present_and_omitted: bool
    set_cookie_present: bool
    set_cookie_count: int
    cookie_names: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    interpretation_note: str


def build_deep_redirect_auth_flow_review(
    http_summary: DeepHttpFingerprintSummary,
) -> DeepRedirectAuthFlowReview:
    """Build a deterministic one-hop redirect/auth-path review."""

    pending = tuple(
        _observation_from_fingerprint(fingerprint)
        for fingerprint in http_summary.fingerprints
        if fingerprint.status_code in REDIRECT_STATUS_CODES
    )
    ordered = tuple(sorted(pending, key=_observation_sort_key))
    observations = tuple(
        DeepRedirectAuthFlowObservation(
            observation_id=f"DEEP-REDIR-REV-{index:04d}",
            source_fingerprint_id=observation.source_fingerprint_id,
            collection_section=observation.collection_section,
            redirect_status_code=observation.redirect_status_code,
            safe_source_url=observation.safe_source_url,
            location_present=observation.location_present,
            location_reference_form=observation.location_reference_form,
            safe_resolved_target_url=observation.safe_resolved_target_url,
            origin_relationship=observation.origin_relationship,
            source_path_auth_related=observation.source_path_auth_related,
            target_path_auth_related=observation.target_path_auth_related,
            auth_path_transition=observation.auth_path_transition,
            source_query_parameter_names=observation.source_query_parameter_names,
            target_query_parameter_names=observation.target_query_parameter_names,
            fragment_present=observation.fragment_present,
            userinfo_present_and_omitted=observation.userinfo_present_and_omitted,
            set_cookie_present=observation.set_cookie_present,
            set_cookie_count=observation.set_cookie_count,
            cookie_names=observation.cookie_names,
            evidence_ids=observation.evidence_ids,
            interpretation_note=observation.interpretation_note,
        )
        for index, observation in enumerate(ordered, start=1)
    )
    return DeepRedirectAuthFlowReview(
        observations=observations,
        summary_counts=_summary_counts(
            total_fingerprints=len(http_summary.fingerprints),
            observations=observations,
        ),
        safety_notes=SAFETY_NOTES,
    )


def render_deep_redirect_auth_flow_review_markdown(
    review: DeepRedirectAuthFlowReview,
) -> str:
    """Render redirect/auth-path review as terminal-friendly Markdown."""

    counts = review.summary_counts
    lines = [
        "## Deep Redirect/Auth-Flow Review",
        "",
        "This is offline one-hop interpretation of existing HTTP fingerprint "
        "evidence. No redirects were followed and no network request was made.",
        "",
        "### Summary",
        "",
        f"- HTTP fingerprints considered: {counts.total_http_fingerprints_considered}",
        f"- Redirect-status responses: {counts.redirect_status_responses}",
        f"- Redirects with Location evidence: {counts.redirects_with_location_evidence}",
        f"- Redirects without Location evidence: {counts.redirects_without_location_evidence}",
        f"- Same-origin redirect targets: {counts.same_origin_redirect_targets}",
        f"- Cross-origin redirect targets: {counts.cross_origin_redirect_targets}",
        f"- Targets not origin-comparable: {counts.targets_not_origin_comparable}",
        f"- Redirects to auth-looking paths: {counts.redirects_to_auth_looking_paths}",
        f"- Redirects from auth-looking paths: {counts.redirects_from_auth_looking_paths}",
        f"- Auth-path-to-auth-path redirects: {counts.auth_path_to_auth_path_redirects}",
        f"- Redirects setting cookies: {counts.redirects_setting_cookies}",
        "- Redirects containing query parameter names: "
        f"{counts.redirects_containing_query_parameter_names}",
        f"- Redirects with URL userinfo omitted: {counts.redirects_with_userinfo_omitted}",
        "",
        "### Redirect Flow Observations",
        "",
    ]
    if review.observations:
        for observation in review.observations:
            lines.extend(_render_observation(observation))
    else:
        lines.append("- None.")

    lines.extend(
        [
            "",
            "### Interpretation Notes",
            "",
            "- This review uses one-hop Location evidence only; no redirects were followed.",
            "- Origin comparison uses parsed source URL and Location evidence only.",
            "- Auth-related classification is lexical path evidence only.",
            "- Query values, fragment contents, and URL userinfo are not retained.",
            "- Cookie-setting response observed alongside redirect evidence does not "
            "mean authentication occurred.",
            "",
            "### Safety Notes",
            "",
        ]
    )
    lines.extend(f"- {note}" for note in review.safety_notes)
    lines.append("")
    return "\n".join(lines).rstrip()


def _observation_from_fingerprint(
    fingerprint: DeepHttpResponseFingerprint,
) -> _PendingObservation:
    source = _safe_url_from_url(fingerprint.requested_url)
    location = fingerprint.redirect_location
    reference_form = _location_reference_form(location)
    target = _safe_target_from_location(fingerprint.requested_url, location, reference_form)
    origin_relationship = _origin_relationship(source, target)
    source_auth = _path_is_auth_related(source.path)
    target_auth = _path_is_auth_related(target.path) if target else False
    transition = _auth_transition(source_auth, target_auth)
    location_present = bool(location and location.strip())
    userinfo_present = source.userinfo_present or bool(target and target.userinfo_present)
    fragment_present = source.fragment_present or bool(target and target.fragment_present)
    target_query_names = target.query_parameter_names if target else ()
    return _PendingObservation(
        source_fingerprint_id=fingerprint.fingerprint_id,
        collection_section=fingerprint.collection_section,
        redirect_status_code=fingerprint.status_code,
        safe_source_url=source.display_url or "unresolved",
        location_present=location_present,
        location_reference_form=reference_form,
        safe_resolved_target_url=target.display_url if target else None,
        origin_relationship=origin_relationship,
        source_path_auth_related=source_auth,
        target_path_auth_related=target_auth,
        auth_path_transition=transition,
        source_query_parameter_names=source.query_parameter_names,
        target_query_parameter_names=target_query_names,
        fragment_present=fragment_present,
        userinfo_present_and_omitted=userinfo_present,
        set_cookie_present=fingerprint.set_cookie_present,
        set_cookie_count=fingerprint.set_cookie_count,
        cookie_names=fingerprint.cookie_names,
        evidence_ids=fingerprint.evidence_ids,
        interpretation_note=_interpretation_note(
            location_present=location_present,
            origin_relationship=origin_relationship,
            auth_path_transition=transition,
            set_cookie_present=fingerprint.set_cookie_present,
        ),
    )


def _location_reference_form(location: str | None) -> str:
    if not location:
        return "missing"
    stripped = location.strip()
    if stripped.startswith("//"):
        return "scheme_relative"
    if stripped.startswith("/"):
        return "root_relative"
    if stripped.startswith("?"):
        return "query_relative"
    if stripped.startswith("#"):
        return "fragment_relative"
    parsed = urlparse(stripped)
    if parsed.scheme:
        scheme = parsed.scheme.lower()
        if scheme == "http":
            return "absolute_http"
        if scheme == "https":
            return "absolute_https"
        return "unsupported_scheme"
    return "path_relative"


def _safe_target_from_location(
    requested_url: str,
    location: str | None,
    reference_form: str,
) -> _SafeUrl | None:
    if not location or reference_form in {"missing", "unsupported_scheme"}:
        return None
    try:
        if reference_form in {"absolute_http", "absolute_https"}:
            resolved = location.strip()
        else:
            resolved = urljoin(requested_url, location.strip())
    except ValueError:
        return None
    target = _safe_url_from_url(resolved)
    if not target.comparable:
        return None
    return target


def _safe_url_from_url(url: str) -> _SafeUrl:
    try:
        parsed = urlparse(url)
    except ValueError:
        return _unresolved_url()
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower() if parsed.hostname else None
    query_names = _query_parameter_names(parsed.query)
    userinfo = parsed.username is not None or parsed.password is not None
    fragment = bool(parsed.fragment)
    if scheme not in {"http", "https"} or hostname is None:
        return _SafeUrl(
            display_url=None,
            query_parameter_names=query_names,
            fragment_present=fragment,
            userinfo_present=userinfo,
            scheme=scheme or None,
            hostname=hostname,
            effective_port=None,
            path=parsed.path or "/",
            comparable=False,
        )
    effective_port = _effective_port(parsed)
    explicit_port = _explicit_port(parsed)
    if effective_port is None:
        return _SafeUrl(
            display_url=None,
            query_parameter_names=query_names,
            fragment_present=fragment,
            userinfo_present=userinfo,
            scheme=scheme,
            hostname=hostname,
            effective_port=None,
            path=parsed.path or "/",
            comparable=False,
        )
    path = parsed.path or "/"
    display = _safe_display_url(
        scheme=scheme,
        hostname=hostname,
        explicit_port=explicit_port,
        path=path,
        query_names=query_names,
    )
    return _SafeUrl(
        display_url=display,
        query_parameter_names=query_names,
        fragment_present=fragment,
        userinfo_present=userinfo,
        scheme=scheme,
        hostname=hostname,
        effective_port=effective_port,
        path=path,
        comparable=True,
    )


def _unresolved_url() -> _SafeUrl:
    return _SafeUrl(
        display_url=None,
        query_parameter_names=(),
        fragment_present=False,
        userinfo_present=False,
        scheme=None,
        hostname=None,
        effective_port=None,
        path="/",
        comparable=False,
    )


def _effective_port(parsed) -> int | None:
    try:
        if parsed.port is not None:
            return parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() == "http":
        return 80
    if parsed.scheme.lower() == "https":
        return 443
    return None


def _explicit_port(parsed) -> int | None:
    try:
        return parsed.port
    except ValueError:
        return None


def _safe_display_url(
    *,
    scheme: str,
    hostname: str,
    explicit_port: int | None,
    path: str,
    query_names: tuple[str, ...],
) -> str:
    host = hostname
    if explicit_port is not None:
        host = f"{host}:{explicit_port}"
    query = ""
    if query_names:
        query = "?" + "&".join(query_names)
    return f"{scheme}://{host}{path}{query}"


def _query_parameter_names(query: str) -> tuple[str, ...]:
    if not query:
        return ()
    names = [name for name, _value in parse_qsl(query, keep_blank_values=True) if name]
    if not names:
        names = [part.split("=", 1)[0] for part in query.split("&") if part.split("=", 1)[0]]
    return tuple(_dedupe(names))


def _origin_relationship(source: _SafeUrl, target: _SafeUrl | None) -> str:
    if target is None or not source.comparable or not target.comparable:
        return "not_comparable"
    source_origin = (source.scheme, source.hostname, source.effective_port)
    target_origin = (target.scheme, target.hostname, target.effective_port)
    if source_origin == target_origin:
        return "same_origin"
    return "cross_origin"


def _path_is_auth_related(path: str) -> bool:
    decoded = unquote(path).lower()
    tokens = [token for token in re_split_path(decoded) if token]
    if "log" in tokens and "in" in tokens:
        return True
    if "sign" in tokens and "in" in tokens:
        return True
    return any(token in STANDALONE_AUTH_PATH_TOKENS for token in tokens)


def re_split_path(value: str) -> list[str]:
    result: list[str] = []
    current = []
    for char in value:
        if char in "/-_.":
            if current:
                result.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        result.append("".join(current))
    return result


def _auth_transition(source_auth: bool, target_auth: bool) -> str:
    if source_auth and target_auth:
        return "auth_path_to_auth_path"
    if target_auth:
        return "redirect_to_auth_path"
    if source_auth:
        return "redirect_from_auth_path"
    return "no_auth_path_signal"


def _interpretation_note(
    *,
    location_present: bool,
    origin_relationship: str,
    auth_path_transition: str,
    set_cookie_present: bool,
) -> str:
    notes = []
    if not location_present:
        notes.append("Redirect status observed without Location evidence.")
    elif origin_relationship == "cross_origin":
        notes.append("Redirect target origin differs from the source origin.")
    elif origin_relationship == "same_origin":
        notes.append("Redirect target origin matches the source origin.")
    else:
        notes.append("Redirect target origin was not comparable from collected evidence.")
    if auth_path_transition != "no_auth_path_signal":
        notes.append("Auth-looking path signal is lexical path evidence only.")
    if set_cookie_present:
        notes.append("Cookie-setting response observed alongside redirect evidence.")
    return " ".join(notes)


def _summary_counts(
    *,
    total_fingerprints: int,
    observations: tuple[DeepRedirectAuthFlowObservation, ...],
) -> DeepRedirectAuthFlowSummaryCounts:
    return DeepRedirectAuthFlowSummaryCounts(
        total_http_fingerprints_considered=total_fingerprints,
        redirect_status_responses=len(observations),
        redirects_with_location_evidence=sum(1 for item in observations if item.location_present),
        redirects_without_location_evidence=sum(1 for item in observations if not item.location_present),
        same_origin_redirect_targets=sum(
            1 for item in observations if item.origin_relationship == "same_origin"
        ),
        cross_origin_redirect_targets=sum(
            1 for item in observations if item.origin_relationship == "cross_origin"
        ),
        targets_not_origin_comparable=sum(
            1 for item in observations if item.origin_relationship == "not_comparable"
        ),
        redirects_to_auth_looking_paths=sum(
            1 for item in observations if item.auth_path_transition == "redirect_to_auth_path"
        ),
        redirects_from_auth_looking_paths=sum(
            1 for item in observations if item.auth_path_transition == "redirect_from_auth_path"
        ),
        auth_path_to_auth_path_redirects=sum(
            1 for item in observations if item.auth_path_transition == "auth_path_to_auth_path"
        ),
        redirects_setting_cookies=sum(1 for item in observations if item.set_cookie_present),
        redirects_containing_query_parameter_names=sum(
            1
            for item in observations
            if item.source_query_parameter_names or item.target_query_parameter_names
        ),
        redirects_with_userinfo_omitted=sum(
            1 for item in observations if item.userinfo_present_and_omitted
        ),
    )


def _observation_sort_key(observation: _PendingObservation) -> tuple:
    return (
        observation.safe_source_url,
        observation.redirect_status_code,
        observation.safe_resolved_target_url or "",
        observation.origin_relationship,
        observation.auth_path_transition,
        observation.source_fingerprint_id,
        observation.location_reference_form,
        tuple(sorted(observation.cookie_names)),
        tuple(sorted(observation.evidence_ids)),
    )


def _render_observation(observation: DeepRedirectAuthFlowObservation) -> list[str]:
    lines = [
        f"#### {observation.observation_id} - Redirect evidence",
        "",
        f"- Source fingerprint: `{observation.source_fingerprint_id}`",
        f"- Collection section: `{observation.collection_section}`",
        f"- Redirect status: `{observation.redirect_status_code}`",
        f"- Safe source URL: `{_compact_single(observation.safe_source_url)}`",
        f"- Location evidence observed: {'yes' if observation.location_present else 'no'}",
        f"- Location reference form: `{observation.location_reference_form}`",
    ]
    if observation.safe_resolved_target_url:
        lines.append(
            f"- Safe resolved target: `{_compact_single(observation.safe_resolved_target_url)}`"
        )
    lines.extend(
        [
            f"- Origin relationship: `{observation.origin_relationship}`",
            f"- Auth-path transition: `{observation.auth_path_transition}`",
            f"- Source path auth-looking: {'yes' if observation.source_path_auth_related else 'no'}",
            f"- Target path auth-looking: {'yes' if observation.target_path_auth_related else 'no'}",
        ]
    )
    if observation.source_query_parameter_names:
        lines.append(
            "- Source query parameter names: "
            + _format_compact_values(observation.source_query_parameter_names)
        )
    if observation.target_query_parameter_names:
        lines.append(
            "- Target query parameter names: "
            + _format_compact_values(observation.target_query_parameter_names)
        )
    if observation.fragment_present:
        lines.append("- Fragment present: yes; fragment content omitted.")
    if observation.userinfo_present_and_omitted:
        lines.append("- URL userinfo present: yes; userinfo omitted.")
    if observation.set_cookie_present:
        lines.append(
            "- Set-Cookie on redirect: "
            f"yes ({observation.set_cookie_count} line(s))"
        )
        if observation.cookie_names:
            lines.append("- Cookie names: " + _format_compact_values(observation.cookie_names))
    else:
        lines.append("- Set-Cookie on redirect: no")
    if observation.evidence_ids:
        lines.append("- Evidence: " + _format_compact_values(observation.evidence_ids))
    lines.extend(
        [
            f"- Interpretation: {observation.interpretation_note}",
            "",
        ]
    )
    return lines


def _format_compact_values(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    rendered = ", ".join(f"`{_compact_single(value)}`" for value in values[:MAX_RENDERED_VALUES])
    remaining = len(values) - MAX_RENDERED_VALUES
    if remaining > 0:
        rendered += f", ... +{remaining} more"
    return rendered


def _compact_single(value: str, *, max_chars: int = MAX_RENDERED_VALUE_CHARS) -> str:
    compact = " ".join(value.strip().split())
    if len(compact) <= max_chars:
        return compact
    return compact[: max_chars - 24].rstrip() + " ... [truncated]"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
