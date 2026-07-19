"""Tests for deterministic encoded-artifact classification."""

from __future__ import annotations

from bugslyce.core.models import HTTPArtifact
from bugslyce.reports.artifact_classifier import (
    LIKELY_NOISE,
    LIKELY_SIGNAL,
    POSSIBLE_SIGNAL,
    classify_encoded_artifact,
)


def test_classifier_marks_long_hex_as_likely_signal() -> None:
    result = classify_encoded_artifact(
        _artifact("9fdafbd64c47471a8f54cd3fc64cd312")
    )

    assert result.category == LIKELY_SIGNAL
    assert "hexadecimal-looking" in result.reason


def test_classifier_marks_diverse_base64_like_token_as_review_signal() -> None:
    result = classify_encoded_artifact(_artifact("ObsJmP173N2X6dOrAgEAL0Vu"))

    assert result.category in {LIKELY_SIGNAL, POSSIBLE_SIGNAL}
    assert "character diversity" in result.reason


def test_classifier_marks_documentation_and_dtd_paths_as_noise() -> None:
    values = [
        "org/TR/xhtml1/DTD/xhtml1",
        "/usr/share/doc/apache2/README",
        "https://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd",
    ]

    results = [classify_encoded_artifact(_artifact(value)) for value in values]

    assert all(result.category == LIKELY_NOISE for result in results)
    assert all("documentation" in result.reason.lower() or "schema" in result.reason.lower() for result in results)


def test_classifier_marks_static_and_low_diversity_values_as_noise() -> None:
    assert classify_encoded_artifact(_artifact("assets/application.js")).category == LIKELY_NOISE
    assert classify_encoded_artifact(_artifact("aaaaaaaaaaaaaaaaaaaaaaaa")).category == LIKELY_NOISE


def test_path_like_fragments_are_noise_even_from_body_fetched_context() -> None:
    ordinary = _artifact("com/photo/2016/12/24/11/48/lost")
    body_fetched = HTTPArtifact(
        url="http://10.10.10.10/portal/",
        artifact_type="encoded_like_artifact",
        value=ordinary.value,
        source_file="body-fetch-10.10.10.10-80-portal.html",
        evidence_ids=["EVID-ART-0002"],
        tags=["encoded_or_hidden_artifact"],
    )

    ordinary_result = classify_encoded_artifact(ordinary)
    body_result = classify_encoded_artifact(body_fetched)

    assert ordinary_result.category == LIKELY_NOISE
    assert body_result.category == LIKELY_NOISE
    assert "path fragment" in body_result.reason


def test_absolute_documentation_url_is_noise_but_standalone_encoded_value_is_signal() -> None:
    documentation = classify_encoded_artifact(
        _artifact("https://tracker.example/issues/AbCdEfGhIjKlMnOpQrStUvWxYz012345")
    )
    standalone = classify_encoded_artifact(
        _artifact("QWxwaGEvQmV0YStHYW1tYTEyMzQ1Njc4OTA=")
    )
    slash_containing = classify_encoded_artifact(
        _artifact("AbCdEfGhIjKlMnOp/QrStUvWxYz0123456789ABC")
    )

    assert documentation.category == LIKELY_NOISE
    assert "absolute HTTP" in documentation.reason
    assert standalone.category in {LIKELY_SIGNAL, POSSIBLE_SIGNAL}
    assert slash_containing.category in {LIKELY_SIGNAL, POSSIBLE_SIGNAL}


def test_unusual_robots_user_agent_is_possible_signal() -> None:
    artifact = HTTPArtifact(
        url="http://10.10.10.10/robots.txt",
        artifact_type="unusual_user_agent",
        value="CUSTOM_USER_AGENT_PLACEHOLDER",
        source_file="robots-80.txt",
        evidence_ids=["EVID-ART-0003"],
        tags=["robots_artifact"],
    )

    result = classify_encoded_artifact(artifact)

    assert result.category == POSSIBLE_SIGNAL
    assert "requires correlation" in result.reason


def test_classifier_does_not_mutate_or_decode_artifact() -> None:
    value = "ObsJmP173N2X6dOrAgEAL0Vu"
    artifact = _artifact(value)

    result = classify_encoded_artifact(artifact)

    assert artifact.value == value
    assert result.category in {LIKELY_SIGNAL, POSSIBLE_SIGNAL}
    assert value not in result.reason
    assert "credential" not in result.reason.lower()
    assert "flag" not in result.reason.lower()


def _artifact(value: str) -> HTTPArtifact:
    return HTTPArtifact(
        url="http://10.10.10.10/",
        artifact_type="encoded_like_artifact",
        value=value,
        source_file="homepage-80.html",
        evidence_ids=["EVID-ART-0001"],
        tags=["encoded_or_hidden_artifact"],
    )
