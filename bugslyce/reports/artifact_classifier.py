"""Conservative deterministic classification for encoded-looking artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import urlparse

from bugslyce.core.models import Candidate, HTTPArtifact, ProjectState
from bugslyce.recon.http_origin import http_origin_from_url


LIKELY_SIGNAL = "likely_signal"
POSSIBLE_SIGNAL = "possible_signal"
LIKELY_NOISE = "likely_noise"

HEX_LIKE = re.compile(r"^[0-9a-fA-F]{32,}$")
BASE64_LIKE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
BASE64URL_LIKE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
PATH_LIKE = re.compile(r"^[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+){2,}/?$")
NOISE_MARKERS = (
    "/usr/share/doc",
    "/usr/share/man",
    "w3.org",
    "xhtml",
    "doctype",
    "dtd/",
    ".dtd",
    "schema.org",
    "xmlschema",
    "apache2/README",
)
DEFAULT_PAGE_MARKERS = (
    "apache2 ubuntu default page",
    "it works!",
    "welcome to nginx",
)
STATIC_SUFFIXES = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
)


@dataclass(frozen=True)
class ArtifactClassification:
    """One explainable classification without decoding or interpretation."""

    category: str
    reason: str


@dataclass(frozen=True)
class HttpServicePriority:
    """Shared concise-report priority for one HTTP service origin."""

    priority: str
    generic_default_page: bool
    independent_application_evidence: bool
    reason: str


def classify_encoded_artifact(artifact: HTTPArtifact) -> ArtifactClassification:
    """Classify one artifact using value shape and conservative source context."""

    value = artifact.value.strip()
    lowered = value.lower()
    if not value:
        return ArtifactClassification(LIKELY_NOISE, "Empty artefact value.")
    if is_absolute_http_reference(value):
        return ArtifactClassification(
            LIKELY_NOISE,
            "Looks like an ordinary absolute HTTP documentation or resource reference.",
        )
    if any(marker.lower() in lowered for marker in NOISE_MARKERS):
        return ArtifactClassification(
            LIKELY_NOISE,
            "Matches documentation, schema, DTD, or local package-path boilerplate.",
        )
    if any(marker in lowered for marker in DEFAULT_PAGE_MARKERS):
        return ArtifactClassification(
            LIKELY_NOISE,
            "Matches common default-page boilerplate.",
        )
    if lowered.endswith(STATIC_SUFFIXES):
        return ArtifactClassification(
            LIKELY_NOISE,
            "Looks like an ordinary static resource name.",
        )

    body_fetched_path = _is_body_fetched_non_root(artifact)
    if artifact.artifact_type == "hidden_element":
        return ArtifactClassification(
            LIKELY_SIGNAL if body_fetched_path else POSSIBLE_SIGNAL,
            (
                "Hidden-element metadata came from a body-fetched discovered path."
                if body_fetched_path
                else "Hidden-element metadata requires surrounding HTML context."
            ),
        )
    if artifact.artifact_type == "unusual_user_agent":
        return ArtifactClassification(
            POSSIBLE_SIGNAL,
            "A non-default robots user-agent value is unusual but requires correlation.",
        )

    if HEX_LIKE.fullmatch(value):
        return ArtifactClassification(
            LIKELY_SIGNAL,
            "Long hexadecimal-looking value with at least 32 characters.",
        )

    if PATH_LIKE.fullmatch(value):
        return ArtifactClassification(
            LIKELY_NOISE,
            "Looks like an ordinary slash-delimited URL or path fragment.",
        )

    if len(value) >= 24 and _encoded_character_diversity(value):
        category = LIKELY_SIGNAL if body_fetched_path or len(value) >= 32 else POSSIBLE_SIGNAL
        return ArtifactClassification(
            category,
            (
                "Encoded-looking token has sufficient length and character diversity"
                + (
                    " in body-fetched discovered-path context."
                    if body_fetched_path
                    else "."
                )
            ),
        )

    if len(value) >= 16 and _encoded_character_diversity(value):
        return ArtifactClassification(
            POSSIBLE_SIGNAL,
            "Medium-length encoded-looking token requires contextual review.",
        )

    return ArtifactClassification(
        LIKELY_NOISE,
        "Value is short, low-diversity, or lacks enough context for review priority.",
    )


def is_generic_default_page_text(value: str | None) -> bool:
    """Return whether text carries an established generic landing-page marker."""

    lowered = (value or "").strip().lower()
    return bool(lowered) and any(marker in lowered for marker in DEFAULT_PAGE_MARKERS)


def has_nondefault_application_title(
    project_state: ProjectState,
    service_url: str,
) -> bool:
    """Return whether a non-root title provides application evidence on an origin."""

    origin = http_origin_from_url(service_url)
    if origin is None:
        return False
    return any(
        artifact.artifact_type == "page_title"
        and http_origin_from_url(artifact.url) == origin
        and urlparse(artifact.url).path not in {"", "/"}
        and not is_generic_default_page_text(artifact.value)
        for artifact in project_state.http_artifacts
    )


def classify_http_service_priority(
    project_state: ProjectState,
    service_url: str,
) -> HttpServicePriority:
    """Classify service presence consistently across concise report layers."""

    origin = http_origin_from_url(service_url)
    if origin is None:
        return HttpServicePriority(
            priority="medium",
            generic_default_page=False,
            independent_application_evidence=False,
            reason="The service origin could not be compared with collected page evidence.",
        )

    matching_services = [
        service
        for service in project_state.http_services
        if http_origin_from_url(service.url) == origin
    ]
    root_titles = [
        artifact.value
        for artifact in project_state.http_artifacts
        if artifact.artifact_type == "page_title"
        and http_origin_from_url(artifact.url) == origin
        and urlparse(artifact.url).path in {"", "/"}
    ]
    titles = [
        *(service.title for service in matching_services if service.title),
        *root_titles,
    ]
    generic_default = any(is_generic_default_page_text(title) for title in titles)
    nondefault_service_title = any(
        title and not is_generic_default_page_text(title)
        for title in titles
    )
    independent_application = (
        nondefault_service_title
        or has_nondefault_application_title(project_state, service_url)
    )
    if generic_default and not independent_application:
        return HttpServicePriority(
            priority="low",
            generic_default_page=True,
            independent_application_evidence=False,
            reason=(
                "The origin presents a generic/default landing page without "
                "independent non-default application evidence."
            ),
        )
    return HttpServicePriority(
        priority="medium",
        generic_default_page=generic_default,
        independent_application_evidence=independent_application,
        reason=(
            "Independent non-default application evidence is present on this origin."
            if independent_application
            else "The service is not established as a generic/default landing page."
        ),
    )


def effective_candidate_priority(
    project_state: ProjectState,
    candidate: Candidate,
) -> str:
    """Return the shared concise priority without mutating candidate evidence."""

    if candidate.priority == "kill_switch" or candidate.candidate_type not in {
        "high_port_http_service",
        "multiple_http_services",
    }:
        return candidate.priority
    candidate_origins = {
        origin
        for endpoint in candidate.affected_endpoints
        if (origin := http_origin_from_url(endpoint)) is not None
    }
    matching_services = [
        service
        for service in project_state.http_services
        if http_origin_from_url(service.url) in candidate_origins
    ]
    relevant_services = (
        [
            service
            for service in matching_services
            if (urlparse(service.url).port or 0) not in {0, 80, 443}
        ]
        if candidate.candidate_type == "multiple_http_services"
        else matching_services
    )
    if relevant_services and all(
        classify_http_service_priority(project_state, service.url).priority == "low"
        for service in relevant_services
    ):
        return "low"
    return candidate.priority


def is_absolute_http_reference(value: str) -> bool:
    """Recognise a complete HTTP(S) reference without interpreting its path."""

    try:
        parsed = urlparse(value.strip())
        _port = parsed.port
    except (TypeError, ValueError):
        return False
    return (
        parsed.scheme.lower() in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _encoded_character_diversity(value: str) -> bool:
    if not (BASE64_LIKE.fullmatch(value) or BASE64URL_LIKE.fullmatch(value)):
        return False
    classes = sum(
        (
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
            any(character in "+/_-" for character in value),
        )
    )
    return classes >= 3 and len(set(value.rstrip("="))) >= 8


def _is_body_fetched_non_root(artifact: HTTPArtifact) -> bool:
    source_name = Path(artifact.source_file).name
    path = urlparse(artifact.url).path
    return source_name.startswith("body-fetch-") and path not in {"", "/"}
