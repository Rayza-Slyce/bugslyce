"""Bounded priority-review views of successful 2xx Deep content."""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit

from bugslyce.core.models import ProjectState
from bugslyce.parsers.http_headers import parse_http_headers
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
from bugslyce.recon.modes import DEEP_RECON_BOUNDS


_BODY_FETCH_DESCRIPTION = (
    "Bounded body request for selected high-signal "
    "content-discovery follow-up path"
)
_CONTENT_FOLLOWUP_HEADER_DESCRIPTION = (
    "Bounded header request for content-discovery result follow-up"
)


_LISTING_TITLE_PREFIXES = (
    "index of ",
    "directory listing for ",
    "directory listing of ",
    "listing directory ",
)


_PROMETHEUS_TYPE_DIRECTIVE = re.compile(
    r"(?:^|\s)#\s*TYPE\s+([A-Za-z_:][A-Za-z0-9_:]*)\s+"
    r"(counter|gauge|histogram|summary|untyped|info|stateset|gaugehistogram)"
    r"(?=\s|$)",
    re.IGNORECASE,
)
_PROMETHEUS_NUMBER = (
    r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?"
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


def build_retained_successful_content_reviews(
    project_state: ProjectState,
    *,
    source_collection: DeepSourceRouteCollectionResult | None = None,
) -> tuple[SuccessfulDeepContentReview, ...]:
    """Rebuild successful-content reviews from completed retained body fetches."""

    manifest = project_state.recon_manifest
    if manifest is None:
        return ()

    root = Path(project_state.input_dir).expanduser().resolve()
    headers_by_url: dict[str, list[tuple[object, object, Path]]] = {}

    for artifact in manifest.artifacts:
        if (
            artifact.type != "http_headers"
            or artifact.description != _CONTENT_FOLLOWUP_HEADER_DESCRIPTION
            or not artifact.url
        ):
            continue

        canonical_url = _canonical_response_url(artifact.url)
        if not canonical_url:
            continue

        header_path = _safe_manifest_path(root, artifact.file)
        if (
            header_path is None
            or header_path.is_symlink()
            or not header_path.is_file()
        ):
            continue

        parsed = parse_http_headers(header_path)
        if parsed.status_code is None:
            continue

        headers_by_url.setdefault(canonical_url, []).append(
            (artifact, parsed, header_path)
        )

    represented = _source_collection_response_identities(source_collection)
    pending: list[SuccessfulDeepContentReview] = []

    body_artifacts = sorted(
        (
            artifact
            for artifact in manifest.artifacts
            if artifact.type == "html"
            and artifact.description == _BODY_FETCH_DESCRIPTION
            and artifact.url
        ),
        key=lambda artifact: (artifact.url or "", artifact.file),
    )

    for artifact in body_artifacts:
        canonical_url = _canonical_response_url(artifact.url or "")
        if not canonical_url:
            continue

        matching_headers = headers_by_url.get(canonical_url, ())
        if len(matching_headers) != 1:
            continue

        header_artifact, parsed_headers, header_path = matching_headers[0]
        if not 200 <= parsed_headers.status_code <= 299:
            continue

        body_path = _safe_manifest_path(root, artifact.file)
        if body_path is None or body_path.is_symlink() or not body_path.is_file():
            continue

        try:
            size = body_path.stat().st_size
            if size <= 0 or size > DEEP_RECON_BOUNDS.max_body_bytes:
                continue
            with body_path.open("rb") as handle:
                body = handle.read(DEEP_RECON_BOUNDS.max_body_bytes + 1)
        except OSError:
            continue

        if not body or len(body) > DEEP_RECON_BOUNDS.max_body_bytes:
            continue

        body_sha256 = sha256(body).hexdigest()
        if (canonical_url, body_sha256) in represented:
            continue

        source_paths = (body_path, header_path)
        pending.append(
            SuccessfulDeepContentReview(
                review_id="",
                canonical_url=canonical_url,
                requested_urls=(artifact.url,),
                status_code=parsed_headers.status_code,
                content_type=parsed_headers.content_type,
                body_bytes=len(body),
                body_sha256=body_sha256,
                body_preview=_bounded_preview(
                    body.decode("utf-8", errors="replace")
                ),
                evidence_ids=_evidence_ids_for_paths(
                    project_state,
                    source_paths,
                ),
                artefact_references=tuple(
                    sorted(
                        {
                            artifact.file,
                            header_artifact.file,
                        }
                    )
                ),
            )
        )

    ordered = sorted(
        pending,
        key=lambda review: (
            review.canonical_url,
            review.status_code,
            review.body_sha256,
            review.artefact_references,
        ),
    )
    return tuple(
        replace(
            review,
            review_id=f"DEEP-RETAINED-CONTENT-{index:04d}",
        )
        for index, review in enumerate(ordered, start=1)
    )


def merge_successful_deep_content_reviews(
    *groups: tuple[SuccessfulDeepContentReview, ...],
) -> tuple[SuccessfulDeepContentReview, ...]:
    """Merge successful-content owners into one deterministic review sequence."""

    grouped: dict[
        tuple[str, int, str],
        list[SuccessfulDeepContentReview],
    ] = {}

    for reviews in groups:
        for review in reviews:
            if not isinstance(review, SuccessfulDeepContentReview):
                raise TypeError(
                    "Successful-content merge requires "
                    "SuccessfulDeepContentReview values"
                )
            key = (
                review.canonical_url,
                review.status_code,
                review.body_sha256,
            )
            grouped.setdefault(key, []).append(review)

    merged: list[SuccessfulDeepContentReview] = []
    for index, key in enumerate(sorted(grouped), start=1):
        canonical_url, status_code, body_sha256 = key
        reviews = grouped[key]
        representative = min(
            reviews,
            key=lambda review: (
                review.content_type or "",
                review.body_bytes,
                review.body_preview,
                review.requested_urls,
                review.evidence_ids,
                review.artefact_references,
            ),
        )
        merged.append(
            SuccessfulDeepContentReview(
                review_id=f"DEEP-CONTENT-{index:04d}",
                canonical_url=canonical_url,
                requested_urls=tuple(
                    sorted(
                        {
                            url
                            for review in reviews
                            for url in review.requested_urls
                        }
                    )
                ),
                status_code=status_code,
                content_type=representative.content_type,
                body_bytes=representative.body_bytes,
                body_sha256=body_sha256,
                body_preview=representative.body_preview,
                evidence_ids=tuple(
                    sorted(
                        {
                            evidence_id
                            for review in reviews
                            for evidence_id in review.evidence_ids
                            if evidence_id
                        }
                    )
                ),
                artefact_references=tuple(
                    sorted(
                        {
                            reference
                            for review in reviews
                            for reference in review.artefact_references
                            if reference
                        }
                    )
                ),
            )
        )

    return tuple(merged)


def _source_collection_response_identities(
    source_collection: DeepSourceRouteCollectionResult | None,
) -> set[tuple[str, str]]:
    if source_collection is None:
        return set()

    identities: set[tuple[str, str]] = set()
    for item in source_collection.collected:
        canonical_url = _canonical_response_url(item.final_url or item.url)
        body_sha256 = (item.body_sha256 or "").strip().lower()
        if canonical_url and body_sha256:
            identities.add((canonical_url, body_sha256))
    return identities


def _safe_manifest_path(root: Path, value: str) -> Path | None:
    try:
        candidate = Path(value)
        path = (
            candidate.expanduser().resolve()
            if candidate.is_absolute()
            else (root / candidate).resolve()
        )
        path.relative_to(root)
    except (OSError, ValueError):
        return None
    return path


def _evidence_ids_for_paths(
    project_state: ProjectState,
    paths: tuple[Path, ...],
) -> tuple[str, ...]:
    root = Path(project_state.input_dir).expanduser().resolve()
    wanted = {path.resolve() for path in paths}
    evidence_ids: set[str] = set()

    for evidence in project_state.evidence:
        try:
            source = Path(evidence.source_file)
            resolved = (
                source.expanduser().resolve()
                if source.is_absolute()
                else (root / source).resolve()
            )
        except (OSError, ValueError):
            continue

        if resolved in wanted and evidence.id:
            evidence_ids.add(evidence.id)

    return tuple(sorted(evidence_ids))


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



def prometheus_metrics_exposition(
    review: SuccessfulDeepContentReview,
) -> bool:
    """Return whether retained body evidence has Prometheus exposition structure."""

    if not isinstance(review, SuccessfulDeepContentReview):
        raise TypeError(
            "Prometheus exposition classification requires "
            "SuccessfulDeepContentReview"
        )

    if not (200 <= review.status_code <= 299):
        return False

    content_type = (
        (review.content_type or "")
        .split(";", 1)[0]
        .strip()
        .casefold()
    )
    if content_type and content_type not in {
        "text/plain",
        "application/openmetrics-text",
    }:
        return False

    preview = " ".join(review.body_preview.split())
    if not preview:
        return False

    for type_match in _PROMETHEUS_TYPE_DIRECTIVE.finditer(preview):
        metric_name = type_match.group(1)
        metric_type = type_match.group(2).casefold()

        expected_names = {metric_name}

        if metric_type == "counter":
            expected_names.update(
                {
                    f"{metric_name}_total",
                    f"{metric_name}_created",
                }
            )
        elif metric_type in {"histogram", "gaugehistogram"}:
            expected_names.update(
                {
                    f"{metric_name}_bucket",
                    f"{metric_name}_sum",
                    f"{metric_name}_count",
                    f"{metric_name}_created",
                }
            )
        elif metric_type == "summary":
            expected_names.update(
                {
                    f"{metric_name}_sum",
                    f"{metric_name}_count",
                    f"{metric_name}_created",
                }
            )
        elif metric_type == "info":
            expected_names.add(f"{metric_name}_info")

        remainder = preview[type_match.end():]

        for expected_name in sorted(expected_names):
            sample = re.compile(
                r"(?:^|\s)"
                + re.escape(expected_name)
                + r"(?:\{[^{}]*\})?\s+"
                + _PROMETHEUS_NUMBER
                + r"(?:\s+\d+)?(?=\s|$)"
            )
            if sample.search(remainder) is not None:
                return True

    return False



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
