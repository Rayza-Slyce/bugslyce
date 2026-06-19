"""Offline artefact/context analysis tests."""

from __future__ import annotations

from bugslyce.recon.artefact_analysis import (
    POSSIBLE_BCRYPT_SHAPE,
    POSSIBLE_BASE32,
    POSSIBLE_BASE64,
    POSSIBLE_BINARY_ASCII,
    POSSIBLE_HEX_ENCODING,
    POSSIBLE_HASH,
    POSSIBLE_MD5_SHAPE,
    POSSIBLE_REVERSED_TEXT,
    POSSIBLE_ROT_OR_CAESAR,
    POSSIBLE_SHA1_SHAPE,
    POSSIBLE_SHA256_SHAPE,
    POSSIBLE_TRANSFORM,
    POSSIBLE_UNIX_CRYPT_SHAPE,
    POSSIBLE_URL_ENCODING,
    ArtefactSource,
    find_hash_artefacts,
    find_transform_artefacts,
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


def test_detects_base64_candidate_with_path_like_preview() -> None:
    source = ArtefactSource(
        source_id="html-base64",
        source_kind="html",
        url="http://example.test/",
        text="secret encoded clue: L2hpZGRlbi9mbGFn",
    )

    candidate = find_transform_artefacts(source)[0]

    assert candidate.category == POSSIBLE_TRANSFORM
    assert candidate.candidate_type == POSSIBLE_BASE64
    assert candidate.value == "L2hpZGRlbi9mbGFn"
    assert candidate.decoded_preview == "/hidden/flag"
    assert candidate.priority == "high"
    assert "secret" in candidate.nearby_keywords
    assert "encoded" in candidate.nearby_keywords
    assert "Decoded preview appears path-like" in candidate.explanation


def test_detects_base32_candidate() -> None:
    source = ArtefactSource(
        source_id="robots-base32",
        source_kind="robots_txt",
        text="decode this: JBSWY3DPEB3W64TMMQ======",
    )

    candidates = find_transform_artefacts(source)

    assert len(candidates) == 1
    assert candidates[0].candidate_type == POSSIBLE_BASE32
    assert candidates[0].decoded_preview == "Hello world"


def test_detects_hex_encoded_candidate_but_not_css_colour() -> None:
    source = ArtefactSource(
        source_id="html-hex",
        source_kind="html",
        text="style #ffcc00; clue hex 2f61646d696e",
    )

    candidates = find_transform_artefacts(source)

    assert len(candidates) == 1
    assert candidates[0].candidate_type == POSSIBLE_HEX_ENCODING
    assert candidates[0].decoded_preview == "/admin"
    assert candidates[0].value != "ffcc00"


def test_detects_url_encoded_candidate() -> None:
    source = ArtefactSource(
        source_id="url-encoded",
        source_kind="text",
        text="redirect clue %2Fhidden%2Fflag",
    )

    candidate = find_transform_artefacts(source)[0]

    assert candidate.candidate_type == POSSIBLE_URL_ENCODING
    assert candidate.decoded_preview == "/hidden/flag"
    assert candidate.priority == "high"


def test_detects_binary_ascii_candidate() -> None:
    source = ArtefactSource(
        source_id="binary",
        source_kind="note",
        text="binary clue 01100110 01101100 01100001 01100111",
    )

    candidate = find_transform_artefacts(source)[0]

    assert candidate.candidate_type == POSSIBLE_BINARY_ASCII
    assert candidate.decoded_preview == "flag"


def test_rot_candidate_requires_context_hint() -> None:
    value = "syntcngu"
    without_hint = ArtefactSource(source_id="plain", text=f"value {value}")
    with_hint = ArtefactSource(source_id="rot", text=f"rot13 cipher clue: {value}")

    assert find_transform_artefacts(without_hint) == ()
    candidates = find_transform_artefacts(with_hint)

    assert any(candidate.candidate_type == POSSIBLE_ROT_OR_CAESAR for candidate in candidates)
    rot_candidate = next(
        candidate
        for candidate in candidates
        if candidate.candidate_type == POSSIBLE_ROT_OR_CAESAR
        and candidate.value == value
    )
    assert rot_candidate.decoded_preview == "flagpath"


def test_reversed_text_candidate_requires_context_hint() -> None:
    without_hint = ArtefactSource(source_id="plain", text="token '/nimda'")
    with_hint = ArtefactSource(source_id="reverse", text="reverse this path '/nimda'")

    assert find_transform_artefacts(without_hint) == ()
    candidate = find_transform_artefacts(with_hint)[0]

    assert candidate.candidate_type == POSSIBLE_REVERSED_TEXT
    assert candidate.decoded_preview == "admin/"


def test_transform_context_and_source_metadata_are_preserved() -> None:
    source = ArtefactSource(
        source_id="homepage",
        source_kind="html",
        source_label="homepage HTML",
        url="http://example.test/",
        path="/",
        port=80,
        service="http",
        field_name="body",
        text="intro\nencoded clue L2hpZGRlbi9mbGFn\noutro",
    )

    candidate = find_transform_artefacts(source, max_context_chars=80)[0]

    assert candidate.source_id == "homepage"
    assert candidate.source_kind == "html"
    assert candidate.source_label == "homepage HTML"
    assert candidate.url == "http://example.test/"
    assert candidate.path == "/"
    assert candidate.port == 80
    assert candidate.service == "http"
    assert candidate.field_name == "body"
    assert candidate.line_number == 2
    assert "L2hpZGRlbi9mbGFn" in candidate.context
    assert len(candidate.context) <= 80


def test_transform_preview_is_bounded_and_malformed_values_do_not_crash() -> None:
    long_value = "/" + ("a" * 150)
    import base64

    encoded = base64.b64encode(long_value.encode("utf-8")).decode("ascii")
    source = ArtefactSource(
        source_id="long",
        text=f"decode {encoded} malformed !!!!",
    )

    candidate = find_transform_artefacts(source, max_preview_chars=40)[0]

    assert candidate.candidate_type == POSSIBLE_BASE64
    assert candidate.decoded_preview is not None
    assert len(candidate.decoded_preview) <= 40
    assert candidate.decoded_preview.endswith("...")


def test_noisy_short_values_are_ignored() -> None:
    source = ArtefactSource(
        source_id="noise",
        text="words TEST TESTING abc 1234 ff00 #aabbcc",
    )

    assert find_transform_artefacts(source) == ()


def test_duplicate_transform_value_in_same_source_is_reported_once() -> None:
    value = "L2hpZGRlbi9mbGFn"
    source = ArtefactSource(source_id="dup", text=f"decode {value}\nrepeat {value}")

    candidates = [
        candidate
        for candidate in find_transform_artefacts(source)
        if candidate.candidate_type == POSSIBLE_BASE64
    ]

    assert len(candidates) == 1
    assert candidates[0].value == value


def test_transform_cautious_wording_and_manual_validation() -> None:
    source = ArtefactSource(source_id="cautious", text="secret L2hpZGRlbi9mbGFn")

    candidate = find_transform_artefacts(source)[0]
    rendered = " ".join(
        (
            candidate.candidate_type,
            candidate.explanation,
            " ".join(candidate.suggested_manual_validation),
        )
    ).lower()

    assert "possible_base64" == candidate.candidate_type
    assert "advisory" in rendered
    assert "validate" in rendered
    assert "do not submit artefacts to online decoders automatically" in rendered
    assert "authorised/local tooling" in rendered
    assert "this is base64" not in rendered
    assert "decoded flag found" not in rendered
    assert "confirmed credential" not in rendered
    assert "confirmed secret" not in rendered
    assert "confirmed vulnerability" not in rendered
    assert "exploit this" not in rendered


def test_transform_public_names_use_uk_artefact_spelling() -> None:
    source = ArtefactSource(source_id="uk-transform", text="decode L2hpZGRlbi9mbGFn")
    candidate = find_transform_artefacts(source)[0]

    assert candidate.__class__.__name__ == "TransformArtefactCandidate"
