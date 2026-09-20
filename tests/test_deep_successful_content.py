"""Tests for bounded successful Deep content promotion."""

from __future__ import annotations

import hashlib

from bugslyce.recon.deep_source_route_collection_export import (
    deep_source_route_collection_result_from_dict,
    deep_source_route_collection_result_to_dict,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
    DeepSourceRouteSkippedItem,
    MAX_RENDERED_BODY_PREVIEW_CHARS,
)
from bugslyce.recon.deep_successful_content import (
    build_successful_deep_content_reviews,
    directory_listing_title,
    prometheus_metrics_exposition,
    render_successful_deep_content_runbook,
)


def test_successful_text_and_html_responses_remain_distinct() -> None:
    text = _item(
        "https://portal.example.test/public/notice.txt",
        body=b"Maintenance window details.",
        content_type="text/plain",
        evidence_ids=("EVID-TEXT",),
    )
    html = _item(
        "https://portal.example.test/public/",
        body=b"<html><title>Available documents</title></html>",
        content_type="text/html",
        evidence_ids=("EVID-HTML",),
    )

    reviews = build_successful_deep_content_reviews(_result(text, html))

    assert tuple(item.canonical_url for item in reviews) == (
        "https://portal.example.test/public/",
        "https://portal.example.test/public/notice.txt",
    )
    assert reviews[1].status_code == 200
    assert reviews[1].content_type == "text/plain"
    assert reviews[1].evidence_ids == ("EVID-TEXT",)
    assert reviews[1].artefact_references == (
        "deep_source_route_collection.json",
    )
    assert "directory listing" not in render_successful_deep_content_runbook(reviews).lower()


def test_directory_listing_title_requires_html_and_exact_path_match() -> None:
    reviews = build_successful_deep_content_reviews(
        _result(
            _item(
                "https://portal.example.test/public/",
                body=b"<html><title>Index of /public/</title></html>",
                content_type="text/html",
                evidence_ids=("EVID-INDEX",),
            ),
            _item(
                "https://portal.example.test/downloads",
                body=b"<html><title>Directory listing for /downloads/</title></html>",
                content_type="text/html; charset=utf-8",
                evidence_ids=("EVID-DIRECTORY",),
            ),
            _item(
                "https://portal.example.test/shared",
                body=b"<html><title>listing directory /shared</title></html>",
                content_type="application/xhtml+xml",
                evidence_ids=("EVID-LISTING",),
            ),
        )
    )

    assert tuple(directory_listing_title(review) for review in reviews) == (
        "Directory listing for /downloads/",
        "Index of /public/",
        "listing directory /shared",
    )

def test_directory_listing_title_rejects_pathname_only_and_weak_titles() -> None:
    reviews = build_successful_deep_content_reviews(
        _result(
            _item(
                "https://portal.example.test/ftp",
                body=b"<html><title>Available documents</title></html>",
                content_type="text/html",
                evidence_ids=("EVID-ORDINARY",),
            ),
            _item(
                "https://portal.example.test/files",
                body=b"<html><title>Index of /other/</title></html>",
                content_type="text/html",
                evidence_ids=("EVID-MISMATCH",),
            ),
            _item(
                "https://portal.example.test/archive",
                body=b"<html><title>Index of /archive</title></html>",
                content_type="text/plain",
                evidence_ids=("EVID-NON-HTML",),
            ),
        )
    )

    assert all(directory_listing_title(review) is None for review in reviews)

def test_negative_failed_redirect_and_empty_responses_are_not_promoted() -> None:
    collected = tuple(
        _item(
            f"https://portal.example.test/status-{status}",
            body=b"retained response",
            status_code=status,
            evidence_ids=(f"EVID-{status}",),
        )
        for status in (301, 403, 404, 500)
    ) + (
        _item(
            "https://portal.example.test/empty",
            body=b"",
            status_code=204,
            evidence_ids=("EVID-EMPTY",),
        ),
    )
    result = DeepSourceRouteCollectionResult(
        collected=collected,
        skipped=(
            DeepSourceRouteSkippedItem(
                url="https://portal.example.test/timeout",
                method="GET",
                reason="fetch_error",
                source="source_route_coverage",
                evidence_ids=("EVID-TIMEOUT",),
            ),
            DeepSourceRouteSkippedItem(
                url="https://portal.example.test/planned",
                method="GET",
                reason="policy_blocked",
                source="source_route_coverage",
                evidence_ids=("EVID-PLANNED",),
            ),
        ),
        total_considered=7,
        total_collected=5,
        total_skipped=2,
    )

    assert build_successful_deep_content_reviews(result) == ()
    assert len(result.collected) == 5
    assert len(result.skipped) == 2


def test_exact_duplicates_merge_evidence_deterministically() -> None:
    url = "https://portal.example.test/content/item.json"
    first = _item(url, body=b'{"state":"ready"}', evidence_ids=("EVID-B",))
    second = _item(url, body=b'{"state":"ready"}', evidence_ids=("EVID-A", "EVID-B"))

    forward = build_successful_deep_content_reviews(_result(first, second))
    reverse = build_successful_deep_content_reviews(_result(second, first))

    assert forward == reverse
    assert len(forward) == 1
    assert forward[0].evidence_ids == ("EVID-A", "EVID-B")
    assert forward[0].requested_urls == (url,)


def test_distinct_bodies_at_one_url_are_not_collapsed() -> None:
    url = "https://portal.example.test/content/current"

    reviews = build_successful_deep_content_reviews(
        _result(
            _item(url, body=b"first retained body", evidence_ids=("EVID-ONE",)),
            _item(url, body=b"second retained body", evidence_ids=("EVID-TWO",)),
        )
    )

    assert len(reviews) == 2
    assert len({item.body_sha256 for item in reviews}) == 2


def test_cross_origin_final_response_is_not_promoted() -> None:
    item = _item(
        "https://portal.example.test/content",
        final_url="https://outside.example.test/content",
        body=b"retained body",
    )

    assert build_successful_deep_content_reviews(_result(item)) == ()


def test_promotion_uses_persisted_preview_and_survives_json_round_trip() -> None:
    body = b"x" * 800
    item = _item(
        "https://portal.example.test/archive/image.png",
        body=body,
        body_preview="x" * 500,
        content_type="image/png",
    )
    result = _result(item)
    restored = deep_source_route_collection_result_from_dict(
        deep_source_route_collection_result_to_dict(result)
    )

    before = build_successful_deep_content_reviews(result)
    after = build_successful_deep_content_reviews(restored)

    assert before == after
    assert len(before[0].body_preview) <= MAX_RENDERED_BODY_PREVIEW_CHARS
    assert restored.collected[0].body == b""
    assert before[0].canonical_url.endswith("/archive/image.png")



def test_prometheus_exposition_detection_requires_structure_not_keywords() -> None:
    positive = build_successful_deep_content_reviews(
        _result(
            _item(
                "https://portal.example.test/internal/telemetry",
                body=(
                    b"# HELP process_cpu_seconds_total CPU time.\n"
                    b"# TYPE process_cpu_seconds_total counter\n"
                    b"process_cpu_seconds_total 12.5\n"
                ),
                content_type="text/plain; version=0.0.4",
                evidence_ids=("EVID-PROM",),
            )
        )
    )[0]

    mismatched = build_successful_deep_content_reviews(
        _result(
            _item(
                "https://portal.example.test/metrics",
                body=(
                    b"# TYPE process_cpu_seconds_total counter\n"
                    b"unrelated_metric 12.5\n"
                ),
                content_type="text/plain; version=0.0.4",
                evidence_ids=("EVID-MISMATCH",),
            )
        )
    )[0]

    keyword_only = build_successful_deep_content_reviews(
        _result(
            _item(
                "https://portal.example.test/metrics",
                body=b"Prometheus metrics exposition is documented elsewhere.",
                content_type="text/plain",
                evidence_ids=("EVID-WORDS",),
            )
        )
    )[0]

    assert prometheus_metrics_exposition(positive)
    assert not prometheus_metrics_exposition(mismatched)
    assert not prometheus_metrics_exposition(keyword_only)


def _result(
    *items: DeepSourceRouteCollectedItem,
) -> DeepSourceRouteCollectionResult:
    return DeepSourceRouteCollectionResult(
        collected=tuple(items),
        skipped=(),
        total_considered=len(items),
        total_collected=len(items),
        total_skipped=0,
    )


def _item(
    url: str,
    *,
    body: bytes,
    status_code: int = 200,
    final_url: str | None = None,
    body_preview: str | None = None,
    content_type: str = "text/plain",
    evidence_ids: tuple[str, ...] = ("EVID-DEEP",),
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=status_code,
        final_url=final_url or url,
        headers=(("Content-Type", content_type),),
        body_preview=(
            body.decode("utf-8", errors="replace")[:500]
            if body_preview is None
            else body_preview
        ),
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_bytes=len(body),
        elapsed_seconds=0.1,
        source="source_route_coverage",
        reason="bounded source review",
        evidence_ids=evidence_ids,
        body=body,
    )


def test_retained_body_fetch_prometheus_enters_successful_content_review(
    tmp_path: Path,
) -> None:
    import json
    from hashlib import sha256

    from bugslyce.core.project import build_project_state
    import bugslyce.recon.deep_successful_content as successful_content
    from bugslyce.recon.deep_source_route_collector import (
        DeepSourceRouteCollectionResult,
    )

    url = "https://example.test/metrics"
    body = (
        b"# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.\n"
        b"# TYPE process_cpu_seconds_total counter\n"
        b"process_cpu_seconds_total 12.5\n"
    )

    (tmp_path / "metrics.headers").write_text(
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/plain; version=0.0.4\n"
        f"Content-Length: {len(body)}\n"
        "\n",
        encoding="utf-8",
    )
    (tmp_path / "metrics.body").write_bytes(body)
    (tmp_path / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "example.test",
                "profile": "deep-bounded",
                "artifacts": [
                    {
                        "type": "http_headers",
                        "file": "metrics.headers",
                        "url": url,
                        "description": (
                            "Bounded header request for content-discovery result follow-up"
                        ),
                    },
                    {
                        "type": "html",
                        "file": "metrics.body",
                        "url": url,
                        "description": (
                            "Bounded body request for selected high-signal "
                            "content-discovery follow-up path"
                        ),
                    },
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)
    empty_collection = DeepSourceRouteCollectionResult(
        collected=(),
        skipped=(),
        total_considered=0,
        total_collected=0,
        total_skipped=0,
    )

    reviews = successful_content.build_retained_successful_content_reviews(
        state,
        source_collection=empty_collection,
    )

    assert len(reviews) == 1
    review = reviews[0]
    assert review.canonical_url == url
    assert review.status_code == 200
    assert review.content_type == "text/plain; version=0.0.4"
    assert review.body_bytes == len(body)
    assert review.body_sha256 == sha256(body).hexdigest()
    assert set(review.artefact_references) == {
        "metrics.body",
        "metrics.headers",
    }
    assert successful_content.prometheus_metrics_exposition(review)


def test_retained_body_fetch_requires_exact_success_header_correlation(
    tmp_path: Path,
) -> None:
    import json

    from bugslyce.core.project import build_project_state
    import bugslyce.recon.deep_successful_content as successful_content
    from bugslyce.recon.deep_source_route_collector import (
        DeepSourceRouteCollectionResult,
    )

    body_url = "https://example.test/metrics"
    body = (
        b"# HELP process_cpu_seconds_total CPU time.\n"
        b"# TYPE process_cpu_seconds_total counter\n"
        b"process_cpu_seconds_total 1\n"
    )

    empty_collection = DeepSourceRouteCollectionResult(
        collected=(),
        skipped=(),
        total_considered=0,
        total_collected=0,
        total_skipped=0,
    )

    cases = (
        ("non-2xx", body_url, 403),
        ("wrong-url", "https://example.test/other", 200),
    )

    for name, header_url, status in cases:
        root = tmp_path / name
        root.mkdir()

        (root / "response.headers").write_text(
            f"HTTP/1.1 {status} {'OK' if status == 200 else 'Forbidden'}\n"
            "Content-Type: text/plain; version=0.0.4\n"
            "\n",
            encoding="utf-8",
        )
        (root / "response.body").write_bytes(body)
        (root / "recon_manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "target": "example.test",
                    "profile": "deep-bounded",
                    "artifacts": [
                        {
                            "type": "http_headers",
                            "file": "response.headers",
                            "url": header_url,
                            "description": (
                                "Bounded header request for content-discovery "
                                "result follow-up"
                            ),
                        },
                        {
                            "type": "html",
                            "file": "response.body",
                            "url": body_url,
                            "description": (
                                "Bounded body request for selected high-signal "
                                "content-discovery follow-up path"
                            ),
                        },
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )

        state = build_project_state(root)

        assert successful_content.build_retained_successful_content_reviews(
            state,
            source_collection=empty_collection,
        ) == ()


def test_retained_body_fetch_skips_response_already_owned_by_deep_collection(
    tmp_path: Path,
) -> None:
    import json
    from hashlib import sha256

    from bugslyce.core.project import build_project_state
    import bugslyce.recon.deep_successful_content as successful_content
    from bugslyce.recon.deep_source_route_collector import (
        DeepSourceRouteCollectedItem,
        DeepSourceRouteCollectionResult,
    )

    url = "https://example.test/metrics"
    body = (
        b"# HELP process_cpu_seconds_total CPU time.\n"
        b"# TYPE process_cpu_seconds_total counter\n"
        b"process_cpu_seconds_total 2\n"
    )

    (tmp_path / "metrics.headers").write_text(
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/plain; version=0.0.4\n"
        "\n",
        encoding="utf-8",
    )
    (tmp_path / "metrics.body").write_bytes(body)
    (tmp_path / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "example.test",
                "profile": "deep-bounded",
                "artifacts": [
                    {
                        "type": "http_headers",
                        "file": "metrics.headers",
                        "url": url,
                        "description": (
                            "Bounded header request for content-discovery result follow-up"
                        ),
                    },
                    {
                        "type": "html",
                        "file": "metrics.body",
                        "url": url,
                        "description": (
                            "Bounded body request for selected high-signal "
                            "content-discovery follow-up path"
                        ),
                    },
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)
    collection = DeepSourceRouteCollectionResult(
        collected=(
            DeepSourceRouteCollectedItem(
                url=url,
                method="GET",
                status_code=200,
                final_url=url,
                headers=(("Content-Type", "text/plain; version=0.0.4"),),
                body_preview=body.decode("utf-8"),
                body_sha256=sha256(body).hexdigest(),
                body_bytes=len(body),
                elapsed_seconds=0.01,
                source="source_route_coverage",
                reason="fixture",
                evidence_ids=("EVID-DEEP",),
                body=body,
            ),
        ),
        skipped=(),
        total_considered=1,
        total_collected=1,
        total_skipped=0,
    )

    assert successful_content.build_retained_successful_content_reviews(
        state,
        source_collection=collection,
    ) == ()
