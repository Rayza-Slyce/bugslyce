"""Tests for deterministic HTTP route and response relationship clusters."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from bugslyce.core.models import (
    DiscoveredPath,
    Endpoint,
    HTTPArtifact,
    PortService,
    ProjectState,
)
from bugslyce.project_pipeline import (
    DEEP_PIPELINE_PROFILE,
    DeepPipelineOutputs,
    _build_standard_investigation_runbook_section_if_needed,
    _write_interpretation_report_if_needed,
)
from bugslyce.recon.deep_orchestration import build_deep_recon_orchestration
from bugslyce.recon.deep_shallow_route_followup import (
    DeepShallowRouteFollowupResult,
    DeepShallowRouteFollowupResultSummaryCounts,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.deep_successful_content import SuccessfulDeepContentReview
from bugslyce.recon.http_route_relationships import (
    _portable_artefact_reference,
    build_http_route_relationship_clusters,
    canonical_relationship_url,
    render_http_route_relationship_clusters_markdown,
    render_http_route_relationship_clusters_runbook,
)


def test_source_reference_with_retained_child_response_forms_cluster() -> None:
    parent = "https://portal.example.test/library/"
    child = "https://portal.example.test/library/notice.txt"
    state = _state(
        http_artifacts=[
            HTTPArtifact(
                url=parent,
                artifact_type="link",
                value="notice.txt",
                source_file=" saved-parent.html ",
                evidence_ids=[" EVID-LINK-NOTICE ", "EVID-LINK-NOTICE", " "],
                tags=[],
            )
        ]
    )
    review = _review(
        "DEEP-CONTENT-0001",
        child,
        evidence_ids=("EVID-LINK-NOTICE",),
    )

    clusters = build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(review,),
    )

    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster.route_nodes == (parent, child)
    assert len(cluster.edges) == 1
    assert cluster.edges[0].edge_type == "source_reference"
    assert cluster.edges[0].source_url == parent
    assert cluster.edges[0].target_url == child
    assert cluster.edges[0].evidence_ids == ("EVID-LINK-NOTICE",)
    assert cluster.edges[0].artefact_references == ("saved-parent.html",)
    assert cluster.edges[0].corroborated_review_ids == ("DEEP-CONTENT-0001",)
    assert cluster.retained_responses == (review,)
    assert cluster.evidence_ids == ("EVID-LINK-NOTICE",)


def test_source_reference_without_exact_evidence_is_not_admitted() -> None:
    parent = "https://portal.example.test/library/"
    child = "https://portal.example.test/library/notice.txt"
    state = _state(
        http_artifacts=[
            _link(
                parent,
                "notice.txt",
                None,
                source_file="saved-parent.html",
            )
        ]
    )

    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review("DEEP-CONTENT-0001", child, evidence_ids=("EVID-RESPONSE",)),
        ),
    ) == ()


@pytest.mark.parametrize(
    "source_file",
    ("../../outside.html", "/tmp/outside.html"),
)
def test_source_reference_without_portable_retained_artefact_is_not_admitted(
    source_file: str,
) -> None:
    parent = "https://portal.example.test/library/"
    child = "https://portal.example.test/library/notice.txt"
    state = _state(
        http_artifacts=[
            _link(parent, "notice.txt", "EVID-LINK", source_file=source_file)
        ]
    )

    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review("DEEP-CONTENT-0001", child, evidence_ids=("EVID-LINK",)),
        ),
    ) == ()


@pytest.mark.parametrize(
    "path_suffix",
    ("../outside.html", "sub/../../outside.html"),
)
def test_absolute_traversal_beneath_lexical_root_is_not_portable(
    tmp_path: Path,
    path_suffix: str,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    source_file = root / path_suffix
    parent = "https://portal.example.test/library/"
    child = "https://portal.example.test/library/notice.txt"
    state = _state(
        input_dir=root,
        http_artifacts=[
            _link(parent, "notice.txt", "EVID-LINK", source_file=str(source_file))
        ],
    )

    assert _portable_artefact_reference(str(source_file), str(root)) == ""
    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review("DEEP-CONTENT-0001", child, evidence_ids=("EVID-LINK",)),
        ),
    ) == ()


def test_symlink_escape_source_artefact_is_not_portable(tmp_path: Path) -> None:
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "source.html").write_text("retained elsewhere", encoding="utf-8")
    escape = root / "escape"
    try:
        escape.symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    source_file = escape / "source.html"
    parent = "https://portal.example.test/library/"
    child = "https://portal.example.test/library/notice.txt"
    state = _state(
        input_dir=root,
        http_artifacts=[
            _link(parent, "notice.txt", "EVID-LINK", source_file=str(source_file))
        ],
    )

    assert _portable_artefact_reference(str(source_file), str(root)) == ""
    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review("DEEP-CONTENT-0001", child, evidence_ids=("EVID-LINK",)),
        ),
    ) == ()


def test_nested_and_absolute_in_root_source_artefacts_remain_portable(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    nested = root / "nested"
    nested.mkdir(parents=True)
    relative_file = nested / "source.html"
    absolute_file = nested / "other.html"
    relative_file.write_text("retained", encoding="utf-8")
    absolute_file.write_text("retained", encoding="utf-8")
    parent = "https://portal.example.test/library/"
    first = "https://portal.example.test/library/first.txt"
    second = "https://portal.example.test/library/second.txt"
    state = _state(
        input_dir=root,
        http_artifacts=[
            _link(parent, "first.txt", "EVID-FIRST", source_file="nested/source.html"),
            _link(parent, "second.txt", "EVID-SECOND", source_file=str(absolute_file)),
        ],
    )

    assert _portable_artefact_reference("nested/source.html", str(root)) == "nested/source.html"
    assert _portable_artefact_reference(str(absolute_file), str(root)) == "nested/other.html"
    cluster = build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review("DEEP-CONTENT-0001", first, evidence_ids=("EVID-FIRST",)),
            _review("DEEP-CONTENT-0002", second, evidence_ids=("EVID-SECOND",)),
        ),
    )[0]
    assert cluster.artefact_references == (
        "deep_source_route_collection.json",
        "nested/other.html",
        "nested/source.html",
    )


def test_redirect_without_exact_evidence_is_not_admitted() -> None:
    source = "https://portal.example.test/library"
    target = "https://portal.example.test/library/"
    state = _state(
        discovered_paths=[
            DiscoveredPath(
                url=source,
                status_code=301,
                content_length=0,
                redirect_location=target,
                source="bounded-discovery.txt",
                evidence_ids=[],
                tags=[],
            )
        ]
    )

    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review("DEEP-CONTENT-0001", target, evidence_ids=("EVID-RESPONSE",)),
        ),
    ) == ()


def test_deep_redirect_without_exact_evidence_is_not_admitted() -> None:
    source = "https://portal.example.test/library"
    target = "https://portal.example.test/library/"

    assert build_http_route_relationship_clusters(
        _state(),
        source_collection=_source_result(
            _collected_redirect(source, target, evidence_ids=())
        ),
        successful_reviews=(
            _review("DEEP-CONTENT-0001", target, evidence_ids=("EVID-RESPONSE",)),
        ),
    ) == ()


def test_redirect_without_portable_retained_artefact_is_not_admitted() -> None:
    source = "https://portal.example.test/library"
    target = "https://portal.example.test/library/"
    state = _state(
        discovered_paths=[
            DiscoveredPath(
                url=source,
                status_code=301,
                content_length=0,
                redirect_location=target,
                source="../../outside-discovery.txt",
                evidence_ids=["EVID-REDIRECT"],
                tags=[],
            )
        ]
    )

    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review("DEEP-CONTENT-0001", target, evidence_ids=("EVID-RESPONSE",)),
        ),
    ) == ()


def test_source_reference_to_its_own_canonical_route_is_not_admitted() -> None:
    page = "https://portal.example.test/"
    state = _state(http_artifacts=[_link(page, "/", "EVID-SELF")])

    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review("DEEP-CONTENT-0001", page, evidence_ids=("EVID-SELF",)),
        ),
    ) == ()


@pytest.mark.parametrize(
    "location",
    ("#section", "https://portal.example.test/path#section"),
)
def test_redirect_to_its_own_canonical_route_is_not_admitted(location: str) -> None:
    page = "https://portal.example.test/path"
    state = _state(
        discovered_paths=[
            DiscoveredPath(
                url=page,
                status_code=301,
                content_length=0,
                redirect_location=location,
                source="bounded-discovery.txt",
                evidence_ids=["EVID-SELF-REDIRECT"],
                tags=[],
            )
        ]
    )

    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review("DEEP-CONTENT-0001", page, evidence_ids=("EVID-RESPONSE",)),
        ),
    ) == ()


def test_valid_trailing_slash_redirect_remains_admitted() -> None:
    source = "https://portal.example.test/library"
    target = "https://portal.example.test/library/"
    state = _state(
        discovered_paths=[
            DiscoveredPath(
                url=source,
                status_code=301,
                content_length=0,
                redirect_location=target,
                source="bounded-discovery.txt",
                evidence_ids=["EVID-REDIRECT"],
                tags=[],
            )
        ]
    )

    cluster = build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review("DEEP-CONTENT-0001", target, evidence_ids=("EVID-RESPONSE",)),
        ),
    )[0]
    assert cluster.route_nodes == (source, target)
    assert tuple(edge.edge_type for edge in cluster.edges) == ("redirect",)
    assert cluster.edges[0].source_url != cluster.edges[0].target_url


def test_source_reference_and_redirect_meet_at_exact_target() -> None:
    parent = "https://portal.example.test/library/"
    redirect_source = "https://portal.example.test/library/archive"
    target = "https://portal.example.test/library/archive/"
    state = _state(
        http_artifacts=[
            _link(parent, "archive/", "EVID-LINK-ARCHIVE"),
        ]
    )
    source = _source_result(
        _collected_redirect(
            redirect_source,
            target,
            evidence_ids=("EVID-DEEP-REDIRECT",),
        )
    )

    clusters = build_http_route_relationship_clusters(
        state,
        source_collection=source,
        successful_reviews=(),
    )

    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster.route_nodes == (parent, redirect_source, target)
    assert tuple(edge.edge_type for edge in cluster.edges) == (
        "redirect",
        "source_reference",
    )
    redirect = cluster.edges[0]
    assert redirect.source_url == redirect_source
    assert redirect.target_url == target
    assert redirect.status_code == 301
    assert redirect.evidence_ids == ("EVID-DEEP-REDIRECT",)
    assert cluster.edges[1].target_url == redirect.target_url


def test_root_redirect_parent_response_and_child_form_one_component() -> None:
    redirect_source = "https://portal.example.test/library"
    parent = "https://portal.example.test/library/"
    child = "https://portal.example.test/library/notice.txt"
    state = _state(
        http_artifacts=[_link(parent, "notice.txt", "EVID-LINK")],
        discovered_paths=[
            DiscoveredPath(
                url=redirect_source,
                status_code=301,
                content_length=0,
                redirect_location=parent,
                source="bounded-discovery.txt",
                evidence_ids=["EVID-ROOT-REDIRECT"],
                tags=[],
            )
        ],
    )
    reviews = (
        _review("DEEP-CONTENT-0001", parent, evidence_ids=("EVID-PARENT",)),
        _review("DEEP-CONTENT-0002", child, evidence_ids=("EVID-LINK",)),
    )

    clusters = build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=reviews,
    )

    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster.route_nodes == (redirect_source, parent, child)
    assert cluster.retained_response_review_ids == (
        "DEEP-CONTENT-0001",
        "DEEP-CONTENT-0002",
    )
    assert {edge.edge_type for edge in cluster.edges} == {
        "redirect",
        "source_reference",
    }
    assert cluster.summary.endswith("2 retained successful responses attach to exact nodes.")


def test_singular_cluster_summary_uses_singular_verb() -> None:
    parent = "https://portal.example.test/library/"
    child = "https://portal.example.test/library/notice.txt"

    cluster = build_http_route_relationship_clusters(
        _state(http_artifacts=[_link(parent, "notice.txt", "EVID-LINK")]),
        source_collection=None,
        successful_reviews=(
            _review("DEEP-CONTENT-0001", child, evidence_ids=("EVID-LINK",)),
        ),
    )[0]

    assert cluster.summary.endswith("1 retained successful response attaches to exact nodes.")


def test_shared_host_and_path_prefix_do_not_create_cluster() -> None:
    state = _state(
        endpoints=[
            Endpoint(
                url="https://portal.example.test/library/one",
                hostname="portal.example.test",
                path="/library/one",
                query_params=[],
                evidence_ids=["EVID-ONE"],
                tags=[],
            ),
            Endpoint(
                url="https://portal.example.test/library/two",
                hostname="portal.example.test",
                path="/library/two",
                query_params=[],
                evidence_ids=["EVID-TWO"],
                tags=[],
            ),
        ]
    )

    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(),
    ) == ()


def test_network_service_name_is_not_a_relationship_edge() -> None:
    parent = "https://portal.example.test/transfer/"
    child = "https://portal.example.test/transfer/ftp/"
    state = _state(
        http_artifacts=[_link(parent, "ftp/", "EVID-HTTP-LINK")],
        port_services=[
            PortService(
                host="portal.example.test",
                port=21,
                protocol="tcp",
                state="open",
                service="ftp",
                product="Example service",
                version="1.0",
                source_file="services.txt",
                evidence_ids=["EVID-FTP-SERVICE"],
                tags=[],
            )
        ],
    )

    cluster = build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review("DEEP-CONTENT-0001", child, evidence_ids=("EVID-HTTP-LINK",)),
        ),
    )[0]

    assert "EVID-FTP-SERVICE" not in cluster.evidence_ids
    assert all(":21" not in route for route in cluster.route_nodes)
    assert all("Example service" not in edge.raw_references for edge in cluster.edges)


def test_link_only_sort_controls_and_static_assets_do_not_cluster() -> None:
    parent = "https://portal.example.test/library/"
    state = _state(
        http_artifacts=[
            _link(parent, "?sort=name", "EVID-SORT"),
            _link(parent, "cover.jpg", "EVID-STATIC"),
            _link(parent, "ordinary", "EVID-ORDINARY"),
        ]
    )

    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review(
                "DEEP-CONTENT-STATIC",
                "https://portal.example.test/library/cover.jpg",
                evidence_ids=("EVID-STATIC",),
            ),
        ),
    ) == ()


def test_distinct_children_attach_only_their_exact_responses() -> None:
    parent = "https://portal.example.test/library/"
    first = "https://portal.example.test/library/first.txt"
    second = "https://portal.example.test/library/second.txt"
    state = _state(
        http_artifacts=[
            _link(parent, "first.txt", "EVID-FIRST"),
            _link(parent, "second.txt", "EVID-SECOND"),
        ]
    )
    reviews = (
        _review("DEEP-CONTENT-0001", first, evidence_ids=("EVID-FIRST",)),
        _review("DEEP-CONTENT-0002", second, evidence_ids=("EVID-SECOND",)),
    )

    cluster = build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=reviews,
    )[0]

    assert cluster.route_nodes == (parent, first, second)
    assert cluster.retained_responses == reviews
    first_edge = next(edge for edge in cluster.edges if edge.target_url == first)
    second_edge = next(edge for edge in cluster.edges if edge.target_url == second)
    assert first_edge.corroborated_review_ids == ("DEEP-CONTENT-0001",)
    assert second_edge.corroborated_review_ids == ("DEEP-CONTENT-0002",)
    assert "EVID-SECOND" not in first_edge.evidence_ids
    assert "EVID-FIRST" not in second_edge.evidence_ids


def test_duplicate_reversed_inputs_produce_identical_cluster() -> None:
    parent = "https://portal.example.test/library/"
    child = "https://portal.example.test/library/notice.txt"
    link_a = _link(parent, "notice.txt", "EVID-B")
    link_b = _link(parent, "notice.txt", "EVID-A")
    first_review = _review(
        "DEEP-CONTENT-0001",
        child,
        evidence_ids=("EVID-B", "EVID-A"),
    )
    second_review = replace(
        first_review,
        evidence_ids=("EVID-A", "EVID-B"),
        artefact_references=(
            "deep_source_route_collection.md",
            "deep_source_route_collection.json",
        ),
    )

    forward = build_http_route_relationship_clusters(
        _state(http_artifacts=[link_a, link_b]),
        source_collection=None,
        successful_reviews=(first_review, second_review),
    )
    reverse = build_http_route_relationship_clusters(
        _state(http_artifacts=[link_b, link_a]),
        source_collection=None,
        successful_reviews=(second_review, first_review),
    )

    assert forward == reverse
    assert forward[0].cluster_id == "ROUTE-CLUSTER-0001"
    assert forward[0].evidence_ids == ("EVID-A", "EVID-B")
    assert forward[0].artefact_references == (
        "deep_source_route_collection.json",
        "deep_source_route_collection.md",
        "saved-parent.html",
    )


def test_cross_origin_source_and_redirect_targets_are_excluded() -> None:
    state = _state(
        http_artifacts=[
            _link(
                "https://portal.example.test/library/",
                "https://outside.example.test/notice.txt",
                "EVID-OUTSIDE-LINK",
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url="https://portal.example.test/redirect",
                status_code=302,
                content_length=0,
                redirect_location="https://outside.example.test/target",
                source="bounded-discovery.txt",
                evidence_ids=["EVID-OUTSIDE-REDIRECT"],
                tags=[],
            )
        ],
    )

    assert build_http_route_relationship_clusters(
        state,
        source_collection=None,
        successful_reviews=(
            _review(
                "DEEP-CONTENT-OUTSIDE",
                "https://outside.example.test/notice.txt",
                evidence_ids=("EVID-OUTSIDE-LINK",),
            ),
        ),
    ) == ()


def test_report_and_runbook_render_the_same_cluster_without_preview_or_commands() -> None:
    parent = "https://portal.example.test/library/"
    child = "https://portal.example.test/library/notice.txt"
    preview = "This bounded preview belongs only in successful-content detail."
    review = replace(
        _review("DEEP-CONTENT-0001", child, evidence_ids=("EVID-LINK",)),
        body_preview=preview,
    )
    cluster = build_http_route_relationship_clusters(
        _state(http_artifacts=[_link(parent, "notice.txt", "EVID-LINK")]),
        source_collection=None,
        successful_reviews=(review,),
    )[0]

    report = render_http_route_relationship_clusters_markdown((cluster,))
    runbook = render_http_route_relationship_clusters_runbook((cluster,))

    for rendered in (report, runbook):
        assert cluster.cluster_id in rendered
        assert parent in rendered
        assert child in rendered
        assert "Source reference" in rendered
        assert "EVID-LINK" in rendered
        assert review.review_id in rendered
        assert "deep_source_route_collection.json" in rendered
        assert preview not in rendered
        assert "curl " not in rendered
        assert "wget " not in rendered
        assert "confirmed finding" in rendered or "do not establish a vulnerability" in rendered
        assert "ftp" not in rendered.lower()
    assert all(edge.evidence_ids for edge in cluster.edges)
    assert all(edge.artefact_references for edge in cluster.edges)
    assert all(edge.source_url != edge.target_url for edge in cluster.edges)
    assert len(cluster.route_nodes) >= 2


def test_relationship_canonicalisation_preserves_route_identity() -> None:
    assert canonical_relationship_url(
        "HTTPS://Portal.Example.Test:443/library/?sort=name#section"
    ) == "https://portal.example.test/library/?sort=name"
    assert canonical_relationship_url(
        "https://portal.example.test/library"
    ) != canonical_relationship_url("https://portal.example.test/library/")
    assert canonical_relationship_url(
        "https://portal.example.test:8443/library/"
    ) != canonical_relationship_url("https://portal.example.test/library/")


def test_typed_deep_pipeline_seams_render_the_same_cluster(
    tmp_path,
    monkeypatch,
) -> None:
    parent = "https://portal.example.test/library/"
    child = "https://portal.example.test/library/notice.txt"
    state = _state(http_artifacts=[_link(parent, "notice.txt", "EVID-LINK")])
    source = _source_result(
        _collected_success(
            parent,
            b"<html>Retained parent.</html>",
            "text/html",
            ("EVID-PARENT",),
        ),
        _collected_success(child, b"Retained notice.", "text/plain", ("EVID-LINK",)),
    )
    shallow = _empty_shallow_result()
    orchestration = build_deep_recon_orchestration(
        source,
        shallow,
        deep_profile_selected=True,
        deep_collection_completed=True,
    )
    context = {
        "deep_outputs": DeepPipelineOutputs(
            source_collection=source,
            shallow_followups=shallow,
            orchestration=orchestration,
        )
    }
    monkeypatch.setattr(
        "bugslyce.project_pipeline.build_project_state",
        lambda _path: state,
    )

    report_paths = _write_interpretation_report_if_needed(
        DEEP_PIPELINE_PROFILE,
        tmp_path,
        context,
    )
    runbook = _build_standard_investigation_runbook_section_if_needed(
        DEEP_PIPELINE_PROFILE,
        tmp_path,
        context,
    )
    report = (tmp_path / "report.md").read_text(encoding="utf-8")

    assert report_paths[0] == str(tmp_path / "report.md")
    assert runbook is not None
    for rendered in (report, runbook):
        assert "ROUTE-CLUSTER-0001" in rendered
        assert parent in rendered
        assert child in rendered
        assert "EVID-LINK" in rendered
        assert "DEEP-CONTENT-0002" in rendered
        assert "deep_source_route_collection.json" in rendered
    assert report.count("This bounded preview belongs only") == 0


def _review(
    review_id: str,
    url: str,
    *,
    evidence_ids: tuple[str, ...],
) -> SuccessfulDeepContentReview:
    return SuccessfulDeepContentReview(
        review_id=review_id,
        canonical_url=url,
        requested_urls=(url,),
        status_code=200,
        content_type="text/plain",
        body_bytes=24,
        body_sha256="a" * 64,
        body_preview="Retained response preview.",
        evidence_ids=evidence_ids,
        artefact_references=("deep_source_route_collection.json",),
    )


def _link(
    source: str,
    value: str,
    evidence_id: str | None,
    *,
    source_file: str = "saved-parent.html",
) -> HTTPArtifact:
    return HTTPArtifact(
        url=source,
        artifact_type="link",
        value=value,
        source_file=source_file,
        evidence_ids=[evidence_id] if evidence_id else [],
        tags=[],
    )


def _source_result(
    *items: DeepSourceRouteCollectedItem,
) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _collected_redirect(
    url: str,
    location: str,
    *,
    evidence_ids: tuple[str, ...],
) -> DeepSourceRouteCollectedItem:
    body = b"redirect response"
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=301,
        final_url=url,
        headers=(("Location", location), ("Content-Type", "text/html")),
        body_preview=body.decode("ascii"),
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.1,
        source="source_route_coverage",
        reason="bounded source review",
        evidence_ids=evidence_ids,
        body=body,
    )


def _collected_success(
    url: str,
    body: bytes,
    content_type: str,
    evidence_ids: tuple[str, ...],
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=200,
        final_url=url,
        headers=(("Content-Type", content_type),),
        body_preview=body.decode("utf-8"),
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.1,
        source="source_route_coverage",
        reason="bounded source review",
        evidence_ids=evidence_ids,
        body=body,
    )


def _empty_shallow_result() -> DeepShallowRouteFollowupResult:
    return DeepShallowRouteFollowupResult(
        collected=(),
        skipped=(),
        summary_counts=DeepShallowRouteFollowupResultSummaryCounts(
            requests_planned=0,
            responses_collected=0,
            requests_skipped_or_failed=0,
            fetch_errors=0,
            invalid_fetch_responses=0,
            responses_too_large=0,
        ),
        safety_notes=(),
    )


def _state(
    *,
    http_artifacts: list[HTTPArtifact] | None = None,
    discovered_paths: list[DiscoveredPath] | None = None,
    endpoints: list[Endpoint] | None = None,
    port_services: list[PortService] | None = None,
    input_dir: Path | str = "/tmp/route-relationship-test",
) -> ProjectState:
    return ProjectState(
        project_name="route-relationship-test",
        input_dir=str(input_dir),
        processed_files=[],
        scope_summary="No scope file parsed.",
        assets=[],
        http_services=[],
        endpoints=endpoints or [],
        port_services=port_services or [],
        http_artifacts=http_artifacts or [],
        discovered_paths=discovered_paths or [],
        recon_summary=None,
        recon_manifest=None,
        evidence=[],
        warnings=[],
        generated_at="2026-08-01T00:00:00Z",
        engagement_context="unknown",
    )
