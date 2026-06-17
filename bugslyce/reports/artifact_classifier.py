"""Conservative deterministic classification for encoded-looking artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import urlparse

from bugslyce.core.models import HTTPArtifact


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


def classify_encoded_artifact(artifact: HTTPArtifact) -> ArtifactClassification:
    """Classify one artifact using value shape and conservative source context."""

    value = artifact.value.strip()
    lowered = value.lower()
    if not value:
        return ArtifactClassification(LIKELY_NOISE, "Empty artefact value.")
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
            LIKELY_SIGNAL if body_fetched_path else POSSIBLE_SIGNAL,
            (
                "Path-like value came from a body-fetched discovered path and is not obvious documentation."
                if body_fetched_path
                else "Path-like value is not obvious documentation but lacks stronger context."
            ),
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
