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
