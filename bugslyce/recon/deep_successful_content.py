"""Bounded priority-review views of successful 2xx Deep content."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

from bugslyce.recon.deep_source_route_collection_export import (
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
    MAX_RENDERED_BODY_PREVIEW_CHARS,
    PREVIEW_TRUNCATED_MARKER,
)
from bugslyce.recon.http_origin import http_origin_from_url, same_http_origin


_LISTING_TITLE_PREFIXES = (
    "index of ",
    "directory listing for ",
    "directory listing of ",
    "listing directory ",
)


class _TitleParser(HTMLParser):
    """Extract the first HTML title from a retained bounded preview."""

    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title" and not self._parts:
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            compact = " ".join(data.split())
            if compact:
                self._parts.append(compact)

    @property
    def title(self) -> str | None:
        compact = " ".join(self._parts).strip()
        return compact or None


@dataclass(frozen=True)
class SuccessfulDeepContentReview:
    """One successful 2xx Deep response promoted for priority content review."""

    review_id: str
    canonical_url: str
    requested_urls: tuple[str, ...]
    status_code: int
    content_type: str | None
    body_bytes: int
    body_sha256: str
    body_preview: str
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]


def build_successful_deep_content_reviews(
    result: DeepSourceRouteCollectionResult,
) -> tuple[SuccessfulDeepContentReview, ...]:
    """Select successful inspectable responses from retained bounded data."""

    grouped: dict[
        tuple[str, int, str],
        list[DeepSourceRouteCollectedItem],
    ] = {}
    for item in result.collected:
        canonical_url = _canonical_response_url(item.final_url or item.url)
        if not _eligible(item, canonical_url):
            continue
        key = (canonical_url, item.status_code, item.body_sha256)
        grouped.setdefault(key, []).append(item)

    reviews: list[SuccessfulDeepContentReview] = []
    for index, key in enumerate(sorted(grouped), start=1):
        canonical_url, status_code, body_sha256 = key
        items = grouped[key]
        representative = min(
            items,
            key=lambda item: (
                item.url,
                item.final_url,
                item.body_preview,
                item.evidence_ids,
            ),
        )
        reviews.append(
            SuccessfulDeepContentReview(
                review_id=f"DEEP-CONTENT-{index:04d}",
                canonical_url=canonical_url,
                requested_urls=tuple(sorted({item.url for item in items})),
                status_code=status_code,
                content_type=_content_type(representative),
                body_bytes=representative.body_bytes,
                body_sha256=body_sha256,
                body_preview=_bounded_preview(representative.body_preview),
                evidence_ids=tuple(
                    sorted(
                        {
                            evidence_id
                            for item in items
                            for evidence_id in item.evidence_ids
                            if evidence_id
                        }
                    )
                ),
                artefact_references=(DEEP_SOURCE_ROUTE_COLLECTION_JSON,),
            )
        )
    return tuple(reviews)


def directory_listing_title(
    review: SuccessfulDeepContentReview,
) -> str | None:
    """Return a path-matched listing title from direct retained HTML evidence."""

    if not (200 <= review.status_code <= 299):
        return None
    content_type = (review.content_type or "").split(";", 1)[0].strip().lower()
    if content_type not in {"text/html", "application/xhtml+xml"}:
        return None

    parser = _TitleParser()
    parser.feed(review.body_preview)
    title = parser.title
    if title is None:
        return None

    lowered = title.casefold()
    for prefix in _LISTING_TITLE_PREFIXES:
        if not lowered.startswith(prefix):
            continue
        claimed_path = title[len(prefix) :].strip()
        if _normalised_listing_path(claimed_path) == _normalised_listing_path(
            urlsplit(review.canonical_url).path or "/"
        ):
            return title
    return None


def _normalised_listing_path(value: str) -> str | None:
    compact = value.strip()
    if not compact.startswith("/") or "?" in compact or "#" in compact:
        return None
    if compact == "/":
        return compact
    return compact.rstrip("/")

def render_successful_deep_content_runbook(
    reviews: tuple[SuccessfulDeepContentReview, ...],
) -> str:
    """Render compact offline actions from the shared promoted-response model."""

    if not reviews:
        return ""
    lines = [
        "## Successful Deep Content Review",
        "",
        (
            "These successful 2xx responses were promoted for priority offline content "
            "review. Other status classes may still have collected response records. "
            "These are direct response evidence, not confirmed findings."
        ),
        "",
    ]
    for index, review in enumerate(reviews, start=1):
        lines.extend(
            [
                f"{index}. URL: `{_code_value(review.canonical_url)}`",
                f"   - Review ID: `{_code_value(review.review_id)}`",
                f"   - Response: `HTTP {review.status_code}`; content type: "
                f"`{_code_value(review.content_type or 'not recorded')}`; bytes: "
                f"`{review.body_bytes}`",
                f"   - Evidence: {_code_list(review.evidence_ids)}",
                f"   - Retained artefact: {_code_list(review.artefact_references)}",
                (
                    "   - Action: inspect the retained artefact locally and correlate the "
                    "bounded preview with existing evidence. Do not re-fetch the URL."
                ),
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def _eligible(item: DeepSourceRouteCollectedItem, canonical_url: str) -> bool:
    return (
        item.source == "source_route_coverage"
        and item.method.upper() in {"GET", "HEAD"}
        and 200 <= item.status_code <= 299
        and bool(canonical_url)
        and same_http_origin(item.url, item.final_url or item.url)
        and item.body_bytes > 0
        and bool(item.body_preview.strip())
        and bool(item.body_sha256)
    )


def _canonical_response_url(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
        parsed.port
    except (TypeError, ValueError):
        return ""
    origin = http_origin_from_url(value)
    if origin is None:
        return ""
    path = parsed.path or "/"
    return urlunsplit(
        (origin.scheme, origin.authority, path, parsed.query, "")
    )


def _content_type(item: DeepSourceRouteCollectedItem) -> str | None:
    for name, value in item.headers:
        if name.lower() == "content-type":
            compact = " ".join(value.split())
            return compact or None
    return None


def _bounded_preview(value: str) -> str:
    compact = " ".join(value.split())
    if len(compact) <= MAX_RENDERED_BODY_PREVIEW_CHARS:
        return compact
    keep = max(0, MAX_RENDERED_BODY_PREVIEW_CHARS - len(PREVIEW_TRUNCATED_MARKER))
    return compact[:keep].rstrip() + PREVIEW_TRUNCATED_MARKER


def _code_value(value: str) -> str:
    return value.replace("`", "'").replace("\n", " ").replace("\r", " ")


def _code_list(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    return ", ".join(f"`{_code_value(value)}`" for value in values)
