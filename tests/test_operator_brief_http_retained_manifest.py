from __future__ import annotations

from dataclasses import fields
from hashlib import sha256
from inspect import signature
import os
from pathlib import Path

import pytest

from bugslyce.core.models import ReconManifest, ReconManifestArtifact
from bugslyce.recon.deep_http_fingerprint_summary import EMPTY_BODY_SHA256
from bugslyce.recon.http_origin import HttpOrigin
from bugslyce.recon.http_route_relationships import canonical_relationship_url


def _api():
    from bugslyce.reports.operator_brief_http_retained_manifest import (
        OperatorBriefHttpRetainedManifestRejection,
        OperatorBriefHttpRetainedManifestRejectionReason,
        OperatorBriefHttpRetainedManifestResult,
        build_operator_brief_http_inputs_from_retained_manifest_html,
    )

    return locals()


def _artifact(
    file: str,
    url: str | None = "https://example.test/app",
    *,
    artifact_type: str = "html",
    status_code: int | None = None,
) -> ReconManifestArtifact:
    return ReconManifestArtifact(
        type=artifact_type,
        file=file,
        url=url,
        status_code=status_code,
    )


def _manifest(*artifacts: ReconManifestArtifact) -> ReconManifest:
    return ReconManifest(
        schema_version="1.0",
        target="example.test",
        artifacts=list(artifacts),
        source_file="recon_manifest.json",
    )


def _adapt(api, root: Path, *artifacts: ReconManifestArtifact, maximum: int = 128):
    return api["build_operator_brief_http_inputs_from_retained_manifest_html"](
        _manifest(*artifacts),
        root,
        maximum_body_bytes=maximum,
    )


def _write(root: Path, name: str, body: bytes = b"retained html") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return path


def _reason(api, name: str):
    return getattr(api["OperatorBriefHttpRetainedManifestRejectionReason"], name)


def test_adapter_result_and_rejection_apis_import() -> None:
    api = _api()

    assert api["OperatorBriefHttpRetainedManifestResult"].__module__.endswith(
        "operator_brief_http_retained_manifest"
    )
    assert api["OperatorBriefHttpRetainedManifestRejection"].__module__.endswith(
        "operator_brief_http_retained_manifest"
    )


def test_rejection_reason_enum_is_narrow_and_typed() -> None:
    api = _api()
    reason_type = api["OperatorBriefHttpRetainedManifestRejectionReason"]

    assert {item.value for item in reason_type} == {
        "unsafe_path",
        "symlink",
        "missing_file",
        "non_regular_file",
        "oversized_file",
        "invalid_url",
        "read_error",
    }


def test_valid_manifest_html_produces_one_retained_observation(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "page.html")

    result = _adapt(api, tmp_path, _artifact("page.html"))

    assert isinstance(result, api["OperatorBriefHttpRetainedManifestResult"])
    assert len(result.inputs.retained_content) == 1
    assert result.rejections == ()


def test_manifest_retained_source_kind_is_semantic_constant(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "page.html")

    result = _adapt(api, tmp_path, _artifact("page.html"))

    assert result.inputs.retained_content[0].source_kind == "manifest_retained_html"


def test_manifest_only_input_creates_no_complete_http_observation(
    tmp_path: Path,
) -> None:
    api = _api()
    _write(tmp_path, "page.html")

    result = _adapt(api, tmp_path, _artifact("page.html"))

    assert result.inputs.observations == ()


def test_optional_manifest_status_does_not_create_complete_response(
    tmp_path: Path,
) -> None:
    api = _api()
    _write(tmp_path, "missing.html")

    result = _adapt(
        api,
        tmp_path,
        _artifact("missing.html", status_code=404),
    )

    assert result.inputs.observations == ()
    assert len(result.inputs.retained_content) == 1


def test_retained_output_has_no_complete_response_fields(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "page.html")

    item = _adapt(api, tmp_path, _artifact("page.html")).inputs.retained_content[0]

    assert {"method", "status_code", "status_bucket", "final_url"}.isdisjoint(
        {field.name for field in fields(item)}
    )


def test_endpoint_uses_existing_relationship_canonicalisation(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "page.html")
    url = "https://example.test/app?mode=full#fragment"

    item = _adapt(api, tmp_path, _artifact("page.html", url)).inputs.retained_content[0]

    assert item.endpoint == canonical_relationship_url(url)


def test_default_https_origin_is_preserved(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "page.html")

    item = _adapt(api, tmp_path, _artifact("page.html")).inputs.retained_content[0]

    assert item.origin == HttpOrigin("https", "example.test", 443)


def test_explicit_http_default_port_uses_canonical_origin(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "page.html")

    item = _adapt(
        api,
        tmp_path,
        _artifact("page.html", "http://example.test:80/app"),
    ).inputs.retained_content[0]

    assert item.origin == HttpOrigin("http", "example.test", 80)


def test_high_port_origin_remains_distinct(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "page.html")

    item = _adapt(
        api,
        tmp_path,
        _artifact("page.html", "http://example.test:8080/app"),
    ).inputs.retained_content[0]

    assert item.origin == HttpOrigin("http", "example.test", 8080)


def test_logical_manifest_artefact_reference_is_preserved(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "nested/page.html")

    item = _adapt(
        api, tmp_path, _artifact("nested/page.html")
    ).inputs.retained_content[0]

    assert item.artefact_references == ("nested/page.html",)


def test_normalized_output_contains_no_absolute_path(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "nested/page.html")

    item = _adapt(
        api, tmp_path, _artifact("nested/page.html")
    ).inputs.retained_content[0]

    assert all(not Path(value).is_absolute() for value in item.artefact_references)
    assert str(tmp_path) not in repr(item)


def test_manifest_only_observation_has_empty_evidence_ids(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "page.html")

    item = _adapt(api, tmp_path, _artifact("page.html")).inputs.retained_content[0]

    assert item.evidence_ids == ()


def test_exact_raw_binary_bytes_are_hashed_without_text_processing(
    tmp_path: Path,
) -> None:
    api = _api()
    body = b"\xff\r\n\x00<html>binary</html>"
    _write(tmp_path, "binary.html", body)

    item = _adapt(api, tmp_path, _artifact("binary.html")).inputs.retained_content[0]

    assert item.body_sha256 == sha256(body).hexdigest()


def test_exact_raw_binary_byte_count_is_preserved(tmp_path: Path) -> None:
    api = _api()
    body = b"\xff\r\n\x00<html>binary</html>"
    _write(tmp_path, "binary.html", body)

    item = _adapt(api, tmp_path, _artifact("binary.html")).inputs.retained_content[0]

    assert item.body_bytes == len(body)


def test_empty_file_is_retained_direct_evidence(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "empty.html", b"")

    item = _adapt(api, tmp_path, _artifact("empty.html")).inputs.retained_content[0]

    assert item.body_sha256 == EMPTY_BODY_SHA256
    assert item.body_bytes == 0
    assert item.body_empty is True


def test_file_at_exact_maximum_is_accepted(tmp_path: Path) -> None:
    api = _api()
    body = b"x" * 32
    _write(tmp_path, "boundary.html", body)

    result = _adapt(api, tmp_path, _artifact("boundary.html"), maximum=32)

    assert result.inputs.retained_content[0].body_bytes == 32
    assert result.rejections == ()


def test_oversized_file_is_rejected_per_entry(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "large.html", b"x" * 33)

    result = _adapt(api, tmp_path, _artifact("large.html"), maximum=32)

    assert result.inputs.retained_content == ()
    assert result.rejections[0].reason is _reason(api, "OVERSIZED_FILE")


def test_oversized_read_is_bounded_even_when_stat_underreports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = _api()
    path = _write(tmp_path, "large.html", b"x" * 33)
    real_stat = Path.stat

    def underreported_stat(candidate: Path, *args, **kwargs):
        result = real_stat(candidate, *args, **kwargs)
        if candidate == path:
            values = list(result)
            values[6] = 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(Path, "stat", underreported_stat)

    result = _adapt(api, tmp_path, _artifact("large.html"), maximum=32)

    assert result.rejections[0].reason is _reason(api, "OVERSIZED_FILE")


@pytest.mark.parametrize("maximum", [True, "32"])
def test_invalid_maximum_type_fails_whole_call(tmp_path: Path, maximum) -> None:
    api = _api()

    with pytest.raises((TypeError, ValueError)):
        _adapt(api, tmp_path, maximum=maximum)


@pytest.mark.parametrize("maximum", [0, -1])
def test_non_positive_maximum_fails_whole_call(tmp_path: Path, maximum: int) -> None:
    api = _api()

    with pytest.raises(ValueError):
        _adapt(api, tmp_path, maximum=maximum)


@pytest.mark.parametrize("root_kind", ["missing", "file"])
def test_unusable_project_root_fails_whole_call(tmp_path: Path, root_kind: str) -> None:
    api = _api()
    root = tmp_path / root_kind
    if root_kind == "file":
        root.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ValueError):
        _adapt(api, root)


def test_absolute_artefact_path_is_rejected_per_entry(tmp_path: Path) -> None:
    api = _api()
    outside = _write(tmp_path.parent, "outside-absolute.html")

    result = _adapt(api, tmp_path, _artifact(str(outside)))

    assert result.rejections[0].reason is _reason(api, "UNSAFE_PATH")


def test_parent_traversal_is_rejected_per_entry(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path.parent, "outside-parent.html")

    result = _adapt(api, tmp_path, _artifact("../outside-parent.html"))

    assert result.rejections[0].reason is _reason(api, "UNSAFE_PATH")


def test_nested_containment_escape_is_rejected_per_entry(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path.parent, "outside-nested.html")

    result = _adapt(api, tmp_path, _artifact("nested/../../outside-nested.html"))

    assert result.rejections[0].reason is _reason(api, "UNSAFE_PATH")


def test_embedded_nul_path_is_rejected_without_aborting_valid_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    _write(tmp_path, "valid.html")
    real_open = Path.open
    opened_paths: list[str] = []

    def tracking_open(candidate: Path, *args, **kwargs):
        opened_paths.append(str(candidate))
        return real_open(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "open", tracking_open)

    result = _adapt(
        api,
        tmp_path,
        _artifact("bad\x00page.html", "https://example.test/bad"),
        _artifact("valid.html", "https://example.test/valid"),
    )

    assert tuple(item.endpoint for item in result.inputs.retained_content) == (
        "https://example.test/valid",
    )
    assert result.rejections == (
        api["OperatorBriefHttpRetainedManifestRejection"](
            artefact_reference="bad\x00page.html",
            manifest_url="https://example.test/bad",
            reason=_reason(api, "UNSAFE_PATH"),
        ),
    )
    assert "embedded null byte" not in repr(result.rejections)
    assert str(tmp_path.resolve()) not in repr(result.rejections)
    assert all("\x00" not in path for path in opened_paths)


def test_leaf_symlink_is_rejected_without_following_it(tmp_path: Path) -> None:
    api = _api()
    outside = _write(tmp_path.parent, "outside-leaf-target.html")
    (tmp_path / "page.html").symlink_to(outside)

    result = _adapt(api, tmp_path, _artifact("page.html"))

    assert result.rejections[0].reason is _reason(api, "SYMLINK")


def test_intermediate_symlink_is_rejected_without_following_it(tmp_path: Path) -> None:
    api = _api()
    outside = tmp_path.parent / "outside-linked-directory"
    _write(outside, "page.html")
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)

    result = _adapt(api, tmp_path, _artifact("linked/page.html"))

    assert result.rejections[0].reason is _reason(api, "SYMLINK")


def test_missing_file_is_rejected_per_entry(tmp_path: Path) -> None:
    api = _api()

    result = _adapt(api, tmp_path, _artifact("missing.html"))

    assert result.rejections[0].reason is _reason(api, "MISSING_FILE")


def test_directory_is_rejected_as_non_regular_file(tmp_path: Path) -> None:
    api = _api()
    (tmp_path / "page.html").mkdir()

    result = _adapt(api, tmp_path, _artifact("page.html"))

    assert result.rejections[0].reason is _reason(api, "NON_REGULAR_FILE")


@pytest.mark.parametrize("url", ["ftp://example.test/page", None, "   "])
def test_invalid_or_missing_url_is_rejected_per_entry(
    tmp_path: Path, url: str | None
) -> None:
    api = _api()
    _write(tmp_path, "page.html")

    result = _adapt(api, tmp_path, _artifact("page.html", url))

    assert result.rejections[0].reason is _reason(api, "INVALID_URL")


@pytest.mark.parametrize(
    "url",
    [
        "https://[::1/page",
        "https://example.test:abc/page",
        "https://example.test:70000/page",
        "https://[v.invalid]/page",
    ],
)
def test_malformed_url_is_rejected_without_aborting_valid_sibling(
    tmp_path: Path,
    url: str,
) -> None:
    api = _api()
    _write(tmp_path, "bad.html")
    _write(tmp_path, "valid.html")

    assert canonical_relationship_url(url) == ""
    result = _adapt(
        api,
        tmp_path,
        _artifact("bad.html", url),
        _artifact("valid.html", "https://example.test/valid"),
    )

    assert tuple(item.endpoint for item in result.inputs.retained_content) == (
        "https://example.test/valid",
    )
    assert result.rejections[0].reason is _reason(api, "INVALID_URL")


def test_read_error_is_rejected_without_aborting_valid_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    failed = _write(tmp_path, "failed.html")
    _write(tmp_path, "valid.html")
    real_open = Path.open

    def failing_open(candidate: Path, *args, **kwargs):
        if candidate == failed:
            raise OSError("private read failure detail")
        return real_open(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)

    result = _adapt(
        api,
        tmp_path,
        _artifact("failed.html", "https://example.test/failed"),
        _artifact("valid.html", "https://example.test/valid"),
    )

    assert tuple(item.endpoint for item in result.inputs.retained_content) == (
        "https://example.test/valid",
    )
    assert result.rejections[0].reason is _reason(api, "READ_ERROR")
    assert "private read failure detail" not in repr(result.rejections)


def test_non_html_manifest_entry_is_ignored_without_rejection(tmp_path: Path) -> None:
    api = _api()

    result = _adapt(
        api,
        tmp_path,
        _artifact("missing.js", "not-a-url", artifact_type="javascript"),
    )

    assert result.inputs.retained_content == ()
    assert result.rejections == ()


def test_valid_and_invalid_entries_return_evidence_and_rejection(
    tmp_path: Path,
) -> None:
    api = _api()
    _write(tmp_path, "valid.html")

    result = _adapt(
        api,
        tmp_path,
        _artifact("valid.html", "https://example.test/valid"),
        _artifact("../outside.html", "https://example.test/unsafe"),
    )

    assert len(result.inputs.retained_content) == 1
    assert result.inputs.retained_content[0].endpoint.endswith("/valid")
    assert result.rejections == (
        api["OperatorBriefHttpRetainedManifestRejection"](
            artefact_reference="../outside.html",
            manifest_url="https://example.test/unsafe",
            reason=_reason(api, "UNSAFE_PATH"),
        ),
    )


def test_all_eligible_entries_may_be_rejected_without_aborting(tmp_path: Path) -> None:
    api = _api()

    result = _adapt(
        api,
        tmp_path,
        _artifact("missing.html", "https://example.test/missing"),
        _artifact("page.html", None),
    )

    assert result.inputs.retained_content == ()
    assert {item.reason for item in result.rejections} == {
        _reason(api, "INVALID_URL"),
        _reason(api, "MISSING_FILE"),
    }


def test_every_eligible_entry_is_accepted_or_rejected(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "first.html", b"first")
    _write(tmp_path, "second.html", b"second")
    artifacts = (
        _artifact("first.html", "https://example.test/first"),
        _artifact("second.html", "https://example.test/second"),
        _artifact("missing.html", "https://example.test/missing"),
    )

    result = _adapt(api, tmp_path, *artifacts)

    assert len(result.inputs.retained_content) + len(result.rejections) == len(
        artifacts
    )


def test_duplicate_retained_semantics_collapse_with_provenance_union(
    tmp_path: Path,
) -> None:
    api = _api()
    body = b"same retained body"
    _write(tmp_path, "first.html", body)
    _write(tmp_path, "second.html", body)

    result = _adapt(
        api,
        tmp_path,
        _artifact("first.html"),
        _artifact("second.html"),
    )

    assert len(result.inputs.retained_content) == 1
    assert result.inputs.retained_content[0].artefact_references == (
        "first.html",
        "second.html",
    )


def test_duplicate_retained_semantics_are_permutation_deterministic(
    tmp_path: Path,
) -> None:
    api = _api()
    body = b"same retained body"
    _write(tmp_path, "first.html", body)
    _write(tmp_path, "second.html", body)
    first = _artifact("first.html")
    second = _artifact("second.html")

    forward = _adapt(api, tmp_path, first, second)
    reverse = _adapt(api, tmp_path, second, first)

    assert forward == reverse


def test_same_endpoint_with_different_bytes_remains_distinct(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "first.html", b"first")
    _write(tmp_path, "second.html", b"second")

    result = _adapt(
        api,
        tmp_path,
        _artifact("first.html"),
        _artifact("second.html"),
    )

    assert len(result.inputs.retained_content) == 2
    assert len({item.observation_id for item in result.inputs.retained_content}) == 2


def test_same_nonempty_bytes_at_distinct_endpoints_create_equality(
    tmp_path: Path,
) -> None:
    api = _api()
    body = b"same alias bytes"
    _write(tmp_path, "first.html", body)
    _write(tmp_path, "second.html", body)

    result = _adapt(
        api,
        tmp_path,
        _artifact("first.html", "https://example.test/"),
        _artifact("second.html", "https://example.test/index"),
    )

    assert len(result.inputs.exact_equivalences) == 1


def test_retained_equality_uses_generic_hash_authority_only(tmp_path: Path) -> None:
    api = _api()
    body = b"same alias bytes"
    _write(tmp_path, "first.html", body)
    _write(tmp_path, "second.html", body)

    equality = _adapt(
        api,
        tmp_path,
        _artifact("first.html", "https://example.test/"),
        _artifact("second.html", "https://example.test/index"),
    ).inputs.exact_equivalences[0]

    assert {item.source_kind for item in equality.authority_references} == {
        "retained_body_exact_hash"
    }
    assert equality.source_repeated_body_group_id is None


def test_retained_equality_has_distinct_semantic_member_ids(tmp_path: Path) -> None:
    api = _api()
    body = b"same alias bytes"
    _write(tmp_path, "first.html", body)
    _write(tmp_path, "second.html", body)

    equality = _adapt(
        api,
        tmp_path,
        _artifact("first.html", "https://example.test/"),
        _artifact("second.html", "https://example.test/index"),
    ).inputs.exact_equivalences[0]

    assert len(equality.observation_ids) >= 2
    assert len(set(equality.observation_ids)) == len(equality.observation_ids)


def test_multiple_empty_files_do_not_create_equality(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "first.html", b"")
    _write(tmp_path, "second.html", b"")

    result = _adapt(
        api,
        tmp_path,
        _artifact("first.html", "https://example.test/"),
        _artifact("second.html", "https://example.test/index"),
    )

    assert len(result.inputs.retained_content) == 2
    assert result.inputs.exact_equivalences == ()


def test_different_bytes_do_not_create_equality(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "first.html", b"first")
    _write(tmp_path, "second.html", b"second")

    result = _adapt(
        api,
        tmp_path,
        _artifact("first.html", "https://example.test/"),
        _artifact("second.html", "https://example.test/index"),
    )

    assert result.inputs.exact_equivalences == ()


def test_equality_group_excludes_different_digest_and_byte_count(
    tmp_path: Path,
) -> None:
    api = _api()
    shared = b"same"
    _write(tmp_path, "first.html", shared)
    _write(tmp_path, "second.html", shared)
    _write(tmp_path, "third.html", b"different-length")

    result = _adapt(
        api,
        tmp_path,
        _artifact("first.html", "https://example.test/a"),
        _artifact("second.html", "https://example.test/b"),
        _artifact("third.html", "https://example.test/c"),
    )
    equality = result.inputs.exact_equivalences[0]
    members = {
        item.observation_id: item for item in result.inputs.retained_content
    }

    assert {members[item].body_bytes for item in equality.observation_ids} == {
        len(shared)
    }
    outside_member = next(iter(set(members) - set(equality.observation_ids)))
    assert members[outside_member].body_bytes != len(shared)


def test_semantic_deduplication_does_not_create_self_equality(tmp_path: Path) -> None:
    api = _api()
    body = b"same retained body"
    _write(tmp_path, "first.html", body)
    _write(tmp_path, "second.html", body)

    result = _adapt(
        api,
        tmp_path,
        _artifact("first.html"),
        _artifact("second.html"),
    )

    assert len(result.inputs.retained_content) == 1
    assert result.inputs.exact_equivalences == ()


def test_complete_result_is_manifest_order_deterministic(tmp_path: Path) -> None:
    api = _api()
    body = b"same alias bytes"
    _write(tmp_path, "first.html", body)
    _write(tmp_path, "second.html", body)
    first = _artifact("first.html", "https://example.test/a")
    second = _artifact("second.html", "https://example.test/b")
    missing = _artifact("missing.html", "https://example.test/missing")

    forward = _adapt(api, tmp_path, first, missing, second)
    reverse = _adapt(api, tmp_path, second, missing, first)

    assert forward == reverse


def test_normalized_result_stores_no_raw_body(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path, "page.html")
    result = _adapt(api, tmp_path, _artifact("page.html"))
    forbidden = {"body", "response_body", "body_text", "body_preview", "content"}

    assert forbidden.isdisjoint(
        {field.name for field in fields(result.inputs.retained_content[0])}
    )
    assert forbidden.isdisjoint({field.name for field in fields(result)})


def test_adapter_requires_no_project_state_or_report_join(tmp_path: Path) -> None:
    api = _api()
    parameters = signature(
        api["build_operator_brief_http_inputs_from_retained_manifest_html"]
    ).parameters

    assert set(parameters) == {"manifest", "project_root", "maximum_body_bytes"}


def test_adapter_requires_no_deep_input(tmp_path: Path) -> None:
    api = _api()
    parameters = signature(
        api["build_operator_brief_http_inputs_from_retained_manifest_html"]
    ).parameters

    assert all("deep" not in name for name in parameters)


def test_adapter_creates_no_manifest_to_deep_equality(tmp_path: Path) -> None:
    api = _api()
    body = b"same alias bytes"
    _write(tmp_path, "first.html", body)
    _write(tmp_path, "second.html", body)

    result = _adapt(
        api,
        tmp_path,
        _artifact("first.html", "https://example.test/a"),
        _artifact("second.html", "https://example.test/b"),
    )

    assert all(
        reference.source_kind != "deep_http_repeated_body_group"
        for equality in result.inputs.exact_equivalences
        for reference in equality.authority_references
    )


def test_rejection_model_contains_only_stable_local_safe_diagnostics() -> None:
    api = _api()
    names = {
        field.name
        for field in fields(api["OperatorBriefHttpRetainedManifestRejection"])
    }

    assert {"artefact_reference", "manifest_url", "reason"} <= names
    assert {
        "resolved_path",
        "absolute_path",
        "exception",
        "error",
        "traceback",
        "manifest_index",
    }.isdisjoint(names)


def test_rejection_contains_no_resolved_absolute_path(tmp_path: Path) -> None:
    api = _api()
    _write(tmp_path.parent, "outside-rejection.html")

    rejection = _adapt(
        api, tmp_path, _artifact("../outside-rejection.html")
    ).rejections[0]

    assert rejection.artefact_reference == "../outside-rejection.html"
    assert str(tmp_path.resolve()) not in repr(rejection)


def test_identical_rejection_records_are_deduplicated(tmp_path: Path) -> None:
    api = _api()
    artifact = _artifact("missing.html", "https://example.test/missing")

    result = _adapt(api, tmp_path, artifact, artifact)

    assert len(result.rejections) == 1


def test_rejection_order_is_manifest_permutation_deterministic(tmp_path: Path) -> None:
    api = _api()
    missing = _artifact("missing.html", "https://example.test/missing")
    invalid = _artifact("invalid.html", None)

    forward = _adapt(api, tmp_path, missing, invalid)
    reverse = _adapt(api, tmp_path, invalid, missing)

    assert forward.rejections == reverse.rejections
