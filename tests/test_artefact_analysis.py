"""Offline artefact/context analysis tests."""

from __future__ import annotations

from bugslyce.recon.artefact_analysis import (
    POSSIBLE_BCRYPT_SHAPE,
    POSSIBLE_HASH,
    POSSIBLE_MD5_SHAPE,
    POSSIBLE_SHA1_SHAPE,
    POSSIBLE_SHA256_SHAPE,
    POSSIBLE_UNIX_CRYPT_SHAPE,
    ArtefactSource,
    find_hash_artefacts,
)


def test_detects_32_hex_possible_md5_shape() -> None:
    source = ArtefactSource(
        source_id="robots-1",
        source_kind="robots_txt",
        source_label="robots.txt",
        text="User-agent: abcdefabcdefabcdefabcdefabcdefab\n",
    )

    candidates = find_hash_artefacts(source)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.value == "abcdefabcdefabcdefabcdefabcdefab"
    assert candidate.category == POSSIBLE_HASH
    assert candidate.candidate_type == POSSIBLE_MD5_SHAPE
    assert candidate.source_id == "robots-1"
    assert candidate.source_kind == "robots_txt"
    assert candidate.source_label == "robots.txt"
    assert candidate.line_number == 1


def test_detects_40_hex_possible_sha1_shape() -> None:
    source = ArtefactSource(
        source_id="html-1",
        source_kind="html",
        text="value 0123456789abcdef0123456789abcdef01234567",
    )

    candidates = find_hash_artefacts(source)

    assert [candidate.candidate_type for candidate in candidates] == [
        POSSIBLE_SHA1_SHAPE
    ]


def test_detects_64_hex_possible_sha256_shape() -> None:
    value = "a" * 64
    source = ArtefactSource(source_id="body-1", source_kind="response_body", text=value)

    candidates = find_hash_artefacts(source)

    assert len(candidates) == 1
    assert candidates[0].candidate_type == POSSIBLE_SHA256_SHAPE
    assert candidates[0].value == value


def test_detects_unix_crypt_and_bcrypt_shapes() -> None:
    unix_crypt = "$6$saltstring$abcdefghijklmnopqrstuvwxzy0123456789ABCDEFGHIJ"
    bcrypt = "$2b$12$abcdefghijklmnopqrstuvABCDEFGHIJKLMNO0123456789abcdef"
    source = ArtefactSource(
        source_id="note-1",
        source_kind="note",
        text=f"shadow candidates {unix_crypt} and {bcrypt}",
    )

    candidates = find_hash_artefacts(source)

    assert [candidate.candidate_type for candidate in candidates] == [
        POSSIBLE_UNIX_CRYPT_SHAPE,
        POSSIBLE_BCRYPT_SHAPE,
    ]


def test_context_window_and_source_metadata_are_preserved_but_bounded() -> None:
    source = ArtefactSource(
        source_id="homepage",
        source_kind="html",
        source_label="homepage HTML",
        url="http://example.test/",
        path="/",
        port=80,
        service="http",
        field_name="body",
        text=(
            "intro line\n"
            "before " + ("x" * 80) + "\n"
            "comment secret value abcdefabcdefabcdefabcdefabcdefab appears here\n"
            "after " + ("y" * 80)
        ),
    )

    candidate = find_hash_artefacts(source, max_context_chars=120)[0]

    assert candidate.source_id == "homepage"
    assert candidate.url == "http://example.test/"
    assert candidate.path == "/"
    assert candidate.port == 80
    assert candidate.service == "http"
    assert candidate.field_name == "body"
    assert candidate.line_number == 3
    assert "abcdefabcdefabcdefabcdefabcdefab" in candidate.context
    assert len(candidate.context) <= 120


def test_high_signal_keywords_raise_priority() -> None:
    source = ArtefactSource(
        source_id="robots",
        source_kind="robots_txt",
        text="User-agent: crawler\nDisallow: /hidden\npassword flag abcdefabcdefabcdefabcdefabcdefab",
    )

    candidate = find_hash_artefacts(source)[0]

    assert candidate.priority == "high"
    assert "flag" in candidate.nearby_keywords
    assert "password" in candidate.nearby_keywords
    assert "robots" not in candidate.nearby_keywords
    assert "Hash-shaped value appears near high-signal wording" in candidate.explanation


def test_hash_shape_without_high_signal_context_is_medium_priority() -> None:
    source = ArtefactSource(
        source_id="text",
        source_kind="text",
        text="cache marker abcdefabcdefabcdefabcdefabcdefab",
    )

    candidate = find_hash_artefacts(source)[0]

    assert candidate.priority == "medium"
    assert candidate.nearby_keywords == ()
    assert "Possible hash candidate detected." in candidate.explanation


def test_cautious_wording_does_not_claim_confirmation_or_vulnerability() -> None:
    source = ArtefactSource(
        source_id="note",
        source_kind="note",
        text="secret abcdefabcdefabcdefabcdefabcdefab",
    )

    candidate = find_hash_artefacts(source)[0]
    rendered = " ".join(
        (
            candidate.candidate_type,
            candidate.explanation,
            " ".join(candidate.suggested_manual_validation),
        )
    ).lower()

    assert "possible_md5_shape" == candidate.candidate_type
    assert "shape alone does not confirm the hash type" in rendered
    assert "md5_hash" not in rendered
    assert "confirmed_md5" not in rendered
    assert "valid_hash" not in rendered
    assert "cracked_hash" not in rendered
    assert "confirmed credential" not in rendered
    assert "confirmed vulnerability" not in rendered


def test_manual_validation_guidance_is_local_and_warns_against_online_lookup() -> None:
    source = ArtefactSource(
        source_id="note",
        text="abcdefabcdefabcdefabcdefabcdefab",
    )

    candidate = find_hash_artefacts(source)[0]
    guidance = " ".join(candidate.suggested_manual_validation).lower()

    assert "locally" in guidance
    assert "authorised/local wordlists" in guidance
    assert "do not submit hashes to online databases automatically" in guidance


def test_duplicate_same_value_in_same_source_is_reported_once() -> None:
    value = "abcdefabcdefabcdefabcdefabcdefab"
    source = ArtefactSource(
        source_id="note",
        text=f"{value}\nrepeat {value}\n",
    )

    candidates = find_hash_artefacts(source)

    assert len(candidates) == 1
    assert candidates[0].value == value


def test_public_names_use_uk_artefact_spelling() -> None:
    source = ArtefactSource(source_id="uk", text="abcdefabcdefabcdefabcdefabcdefab")
    candidate = find_hash_artefacts(source)[0]

    assert ArtefactSource.__name__ == "ArtefactSource"
    assert candidate.__class__.__name__ == "HashArtefactCandidate"
