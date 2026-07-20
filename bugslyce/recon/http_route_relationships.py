"""Deterministic clusters for direct HTTP route and response relationships."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from bugslyce.core.models import ProjectState
from bugslyce.recon.deep_redirect_auth_flow_review import REDIRECT_STATUS_CODES
from bugslyce.recon.deep_source_route_collector import DeepSourceRouteCollectionResult
from bugslyce.recon.deep_source_route_collection_export import (
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
)
from bugslyce.recon.deep_successful_content import SuccessfulDeepContentReview
from bugslyce.recon.http_origin import http_origin_from_url, same_http_origin


SOURCE_REFERENCE_TYPES = frozenset({"form", "link", "script_or_asset"})
STATIC_REFERENCE_SUFFIXES = frozenset(
    {
        ".avif",
        ".bmp",
        ".cjs",
        ".css",
        ".eot",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".map",
        ".mjs",
        ".otf",
        ".png",
        ".svg",
        ".ttf",
        ".webp",
        ".woff",
        ".woff2",
    }
)


@dataclass(frozen=True)
class HttpRouteRelationshipEdge:
    """One direct typed relationship between two canonical HTTP routes."""

    edge_type: str
    source_url: str
    target_url: str
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...] = ()
    raw_references: tuple[str, ...] = ()
    status_code: int | None = None
    corroborated_review_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class HttpRouteRelationshipCluster:
    """One connected component of directly represented HTTP relationships."""

    cluster_id: str
    title: str
    anchor_url: str
    route_nodes: tuple[str, ...]
    edges: tuple[HttpRouteRelationshipEdge, ...]
    retained_responses: tuple[SuccessfulDeepContentReview, ...]
    evidence_ids: tuple[str, ...]
    retained_response_review_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    summary: str
    manual_review_order: tuple[str, ...]


@dataclass
class _EdgeAccumulator:
    evidence_ids: set[str]
    artefact_references: set[str]
    raw_references: set[str]


def build_http_route_relationship_clusters(
    project_state: ProjectState,
    *,
    source_collection: DeepSourceRouteCollectionResult | None,
    successful_reviews: tuple[SuccessfulDeepContentReview, ...],
) -> tuple[HttpRouteRelationshipCluster, ...]:
    """Build stable eligible clusters from direct structured relationships."""

    reviews = _normalise_reviews(successful_reviews)
    reviews_by_url: dict[str, list[SuccessfulDeepContentReview]] = defaultdict(list)
    for review in reviews:
        canonical = canonical_relationship_url(review.canonical_url)
        if canonical:
            reviews_by_url[canonical].append(review)

    redirect_edges = _redirect_edges(project_state, source_collection)
    redirect_nodes = {
        url
        for edge in redirect_edges
        for url in (edge.source_url, edge.target_url)
    }
    source_edges = tuple(
        edge
        for edge in _source_reference_edges(project_state, reviews_by_url)
        if edge.target_url in reviews_by_url or edge.target_url in redirect_nodes
    )
    edges = tuple(
        sorted(
            (*redirect_edges, *source_edges),
            key=_edge_sort_key,
        )
    )
    if not edges:
        return ()

    clusters: list[HttpRouteRelationshipCluster] = []
    for nodes, component_edges in _connected_components(edges):
        component_reviews = tuple(
            review
            for url in nodes
            for review in sorted(
                reviews_by_url.get(url, ()),
                key=_review_sort_key,
            )
        )
        if not _eligible_cluster(component_edges, component_reviews):
            continue
        anchor = _cluster_anchor(nodes, component_edges, component_reviews)
        evidence_ids = tuple(
            sorted(
                {
                    evidence_id
                    for edge in component_edges
                    for evidence_id in edge.evidence_ids
                }
                | {
                    evidence_id
                    for review in component_reviews
                    for evidence_id in review.evidence_ids
                }
            )
        )
        review_ids = tuple(
            sorted({review.review_id for review in component_reviews})
        )
        artefact_references = tuple(
            sorted(
                {
                    reference
                    for edge in component_edges
                    for reference in edge.artefact_references
                }
                | {
                    reference
                    for review in component_reviews
                    for reference in review.artefact_references
                }
            )
        )
        clusters.append(
            HttpRouteRelationshipCluster(
                cluster_id="",
                title=f"Direct HTTP route relationships from {anchor}",
                anchor_url=anchor,
                route_nodes=nodes,
                edges=component_edges,
                retained_responses=component_reviews,
                evidence_ids=evidence_ids,
                retained_response_review_ids=review_ids,
                artefact_references=artefact_references,
                summary=(
                    f"{len(nodes)} exact route nodes are connected by "
                    f"{len(component_edges)} direct source-reference or redirect "
                    f"relationship{'s' if len(component_edges) != 1 else ''}; "
                    f"{len(component_reviews)} retained successful response"
                    f"{'s' if len(component_reviews) != 1 else ''} "
                    f"{'attaches' if len(component_reviews) == 1 else 'attach'} "
                    "to exact nodes."
                ),
                manual_review_order=_manual_review_order(
                    component_edges,
                    component_reviews,
                ),
            )
        )

    ordered = sorted(
        clusters,
        key=lambda cluster: (
            cluster.anchor_url,
            cluster.route_nodes,
            tuple(_edge_sort_key(edge) for edge in cluster.edges),
        ),
    )
    return tuple(
        replace(cluster, cluster_id=f"ROUTE-CLUSTER-{index:04d}")
        for index, cluster in enumerate(ordered, start=1)
    )


def render_http_route_relationship_clusters_markdown(
    clusters: tuple[HttpRouteRelationshipCluster, ...],
) -> str:
    """Render compact primary-report relationship clusters without body previews."""

    if not clusters:
        return ""
    lines = [
        "## HTTP Route Relationship Clusters",
        "",
        (
            "These clusters join only direct same-origin source references, represented "
            "HTTP redirects, and exact retained-response records. They are relationship "
            "evidence for offline review, not confirmed findings."
        ),
        "",
    ]
    for cluster in clusters:
        lines.extend(
            [
                f"### {cluster.cluster_id}: {_md(cluster.title)}",
                "",
                f"- Anchor: {_code(cluster.anchor_url)}",
                f"- Summary: {_md(cluster.summary)}",
                "- Route nodes:",
            ]
        )
        lines.extend(f"  - {_code(route)}" for route in cluster.route_nodes)
        lines.append("- Typed edges:")
        lines.extend(_render_edge(edge, prefix="  - ") for edge in cluster.edges)
        if cluster.retained_responses:
            lines.append("- Retained successful responses:")
            for review in cluster.retained_responses:
                lines.append(
                    f"  - {_code(review.canonical_url)}: {_code(review.review_id)}, "
                    f"HTTP {review.status_code}, body SHA-256 {_code(review.body_sha256)}"
                )
        lines.extend(
            [
                f"- Evidence: {_code_list(cluster.evidence_ids)}",
                f"- Retained response review IDs: "
                f"{_code_list(cluster.retained_response_review_ids)}",
                f"- Retained artefacts: {_code_list(cluster.artefact_references)}",
                "- Bounded offline review order:",
            ]
        )
        lines.extend(
            f"  {index}. {_md(step)}"
            for index, step in enumerate(cluster.manual_review_order, start=1)
        )
        lines.append("")
    return "\n".join(lines).rstrip()


def render_http_route_relationship_clusters_runbook(
    clusters: tuple[HttpRouteRelationshipCluster, ...],
) -> str:
    """Render one offline runbook workflow per relationship cluster."""

    if not clusters:
        return ""
    lines = [
        "## HTTP Route Relationship Review",
        "",
        (
            "Use only the retained local artefacts and exact evidence below. "
            "These relationships do not establish a vulnerability or a cross-service link."
        ),
        "",
    ]
    for cluster in clusters:
        lines.extend(
            [
                f"### {cluster.cluster_id}: {_md(cluster.title)}",
                "",
                f"* Route nodes: {_code_list(cluster.route_nodes)}",
                "* Typed edges:",
            ]
        )
        lines.extend(_render_edge(edge, prefix="  * ") for edge in cluster.edges)
        lines.extend(
            [
                f"* Evidence: {_code_list(cluster.evidence_ids)}",
                f"* Retained response review IDs: "
                f"{_code_list(cluster.retained_response_review_ids)}",
                f"* Retained artefacts: {_code_list(cluster.artefact_references)}",
                "* Offline review order:",
            ]
        )
        lines.extend(
            f"  {index}. {_md(step)}"
            for index, step in enumerate(cluster.manual_review_order, start=1)
        )
        lines.append("")
    return "\n".join(lines).rstrip()


def canonical_relationship_url(value: str | None) -> str:
    """Canonicalise an HTTP route while preserving query and trailing slash."""

    if not value:
        return ""
    try:
        parsed = urlsplit(value.strip())
        parsed.port
    except (TypeError, ValueError):
        return ""
    origin = http_origin_from_url(value)
    if origin is None:
        return ""
    return urlunsplit(
        (
            origin.scheme,
            origin.authority,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


def _source_reference_edges(
    project_state: ProjectState,
    reviews_by_url: dict[str, list[SuccessfulDeepContentReview]],
) -> tuple[HttpRouteRelationshipEdge, ...]:
    accumulators: dict[tuple[str, str, str, int | None], _EdgeAccumulator] = {}
    for artefact in project_state.http_artifacts:
        if artefact.artifact_type not in SOURCE_REFERENCE_TYPES or not artefact.url:
            continue
        raw_reference = artefact.value.strip()
        if not raw_reference or raw_reference.startswith("#"):
            continue
        source_url = canonical_relationship_url(artefact.url)
        target_url = canonical_relationship_url(urljoin(artefact.url, raw_reference))
        if (
            not source_url
            or not target_url
            or not same_http_origin(source_url, target_url)
            or source_url == target_url
            or _is_static_reference(target_url)
        ):
            continue
        evidence_ids = _nonempty_sorted(artefact.evidence_ids)
        portable_reference = _portable_artefact_reference(
            artefact.source_file,
            project_state.input_dir,
        )
        if not evidence_ids or not portable_reference:
            continue
        key = ("source_reference", source_url, target_url, None)
        accumulator = accumulators.setdefault(
            key,
            _EdgeAccumulator(
                evidence_ids=set(),
                artefact_references=set(),
                raw_references=set(),
            ),
        )
        accumulator.evidence_ids.update(evidence_ids)
        accumulator.artefact_references.add(portable_reference)
        accumulator.raw_references.add(raw_reference)

    edges: list[HttpRouteRelationshipEdge] = []
    for key, accumulator in accumulators.items():
        edge_type, source_url, target_url, status_code = key
        evidence_ids = tuple(sorted(accumulator.evidence_ids))
        corroborated = tuple(
            sorted(
                {
                    review.review_id
                    for review in reviews_by_url.get(target_url, ())
                    if set(evidence_ids).intersection(review.evidence_ids)
                }
            )
        )
        edges.append(
            HttpRouteRelationshipEdge(
                edge_type=edge_type,
                source_url=source_url,
                target_url=target_url,
                evidence_ids=evidence_ids,
                artefact_references=tuple(sorted(accumulator.artefact_references)),
                raw_references=tuple(sorted(accumulator.raw_references)),
                status_code=status_code,
                corroborated_review_ids=corroborated,
            )
        )
    return tuple(sorted(edges, key=_edge_sort_key))


def _redirect_edges(
    project_state: ProjectState,
    source_collection: DeepSourceRouteCollectionResult | None,
) -> tuple[HttpRouteRelationshipEdge, ...]:
    accumulators: dict[tuple[str, str, str, int | None], _EdgeAccumulator] = {}
    for path in project_state.discovered_paths:
        _add_redirect(
            accumulators,
            path.url,
            path.status_code,
            path.redirect_location,
            tuple(path.evidence_ids),
            (_portable_artefact_reference(path.source, project_state.input_dir),),
        )
    if source_collection is not None:
        for item in source_collection.collected:
            locations = tuple(
                value
                for name, value in item.headers
                if name.lower() == "location" and value.strip()
            )
            for location in locations:
                _add_redirect(
                    accumulators,
                    item.final_url or item.url,
                    item.status_code,
                    location,
                    item.evidence_ids,
                    (DEEP_SOURCE_ROUTE_COLLECTION_JSON,),
                )

    edges: list[HttpRouteRelationshipEdge] = []
    for key, accumulator in accumulators.items():
        edge_type, source_url, target_url, status_code = key
        edges.append(
            HttpRouteRelationshipEdge(
                edge_type=edge_type,
                source_url=source_url,
                target_url=target_url,
                evidence_ids=tuple(sorted(accumulator.evidence_ids)),
                artefact_references=tuple(sorted(accumulator.artefact_references)),
                raw_references=tuple(sorted(accumulator.raw_references)),
                status_code=status_code,
            )
        )
    return tuple(sorted(edges, key=_edge_sort_key))


def _add_redirect(
    accumulators: dict[tuple[str, str, str, int | None], _EdgeAccumulator],
    source: str,
    status_code: int | None,
    location: str | None,
    evidence_ids: tuple[str, ...],
    artefact_references: tuple[str, ...],
) -> None:
    if status_code not in REDIRECT_STATUS_CODES or not location:
        return
    normalised_evidence_ids = _nonempty_sorted(evidence_ids)
    normalised_artefact_references = _nonempty_sorted(artefact_references)
    if not normalised_evidence_ids or not normalised_artefact_references:
        return
    source_url = canonical_relationship_url(source)
    target_url = canonical_relationship_url(urljoin(source, location))
    if (
        not source_url
        or not target_url
        or source_url == target_url
        or not same_http_origin(source_url, target_url)
    ):
        return
    key = ("redirect", source_url, target_url, status_code)
    accumulator = accumulators.setdefault(
        key,
        _EdgeAccumulator(
            evidence_ids=set(),
            artefact_references=set(),
            raw_references=set(),
        ),
    )
    accumulator.evidence_ids.update(normalised_evidence_ids)
    accumulator.artefact_references.update(normalised_artefact_references)
    accumulator.raw_references.add(location)


def _connected_components(
    edges: tuple[HttpRouteRelationshipEdge, ...],
) -> tuple[tuple[tuple[str, ...], tuple[HttpRouteRelationshipEdge, ...]], ...]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        adjacency[edge.source_url].add(edge.target_url)
        adjacency[edge.target_url].add(edge.source_url)

    components: list[tuple[tuple[str, ...], tuple[HttpRouteRelationshipEdge, ...]]] = []
    remaining = set(adjacency)
    while remaining:
        pending = [min(remaining)]
        nodes: set[str] = set()
        while pending:
            node = pending.pop()
            if node in nodes:
                continue
            nodes.add(node)
            pending.extend(sorted(adjacency[node] - nodes, reverse=True))
        remaining.difference_update(nodes)
        component_edges = tuple(
            edge
            for edge in edges
            if edge.source_url in nodes and edge.target_url in nodes
        )
        components.append((tuple(sorted(nodes)), component_edges))
    return tuple(sorted(components, key=lambda component: component[0]))


def _eligible_cluster(
    edges: tuple[HttpRouteRelationshipEdge, ...],
    reviews: tuple[SuccessfulDeepContentReview, ...],
) -> bool:
    response_urls = {
        canonical_relationship_url(review.canonical_url) for review in reviews
    }
    source_edges = tuple(edge for edge in edges if edge.edge_type == "source_reference")
    redirect_edges = tuple(edge for edge in edges if edge.edge_type == "redirect")
    if any(edge.target_url in response_urls for edge in source_edges):
        return True
    if any(
        edge.source_url in response_urls or edge.target_url in response_urls
        for edge in redirect_edges
    ):
        return True
    if source_edges and redirect_edges:
        redirect_nodes = {
            url
            for edge in redirect_edges
            for url in (edge.source_url, edge.target_url)
        }
        return any(edge.target_url in redirect_nodes for edge in source_edges)
    return False


def _normalise_reviews(
    reviews: tuple[SuccessfulDeepContentReview, ...],
) -> tuple[SuccessfulDeepContentReview, ...]:
    grouped: dict[tuple[str, int, str], list[SuccessfulDeepContentReview]] = defaultdict(list)
    for review in reviews:
        canonical = canonical_relationship_url(review.canonical_url)
        if canonical:
            grouped[(canonical, review.status_code, review.body_sha256)].append(review)

    normalised: list[SuccessfulDeepContentReview] = []
    for key in sorted(grouped):
        canonical, _status, _body_hash = key
        items = grouped[key]
        representative = min(items, key=_review_sort_key)
        normalised.append(
            replace(
                representative,
                canonical_url=canonical,
                requested_urls=tuple(
                    sorted({url for item in items for url in item.requested_urls})
                ),
                evidence_ids=tuple(
                    _nonempty_sorted(
                        evidence_id
                        for item in items
                        for evidence_id in item.evidence_ids
                    )
                ),
                artefact_references=tuple(
                    _nonempty_sorted(
                        reference
                        for item in items
                        for reference in item.artefact_references
                    )
                ),
            )
        )
    return tuple(normalised)


def _cluster_anchor(
    nodes: tuple[str, ...],
    edges: tuple[HttpRouteRelationshipEdge, ...],
    reviews: tuple[SuccessfulDeepContentReview, ...],
) -> str:
    response_urls = {
        canonical_relationship_url(review.canonical_url) for review in reviews
    }
    outgoing_counts = {
        node: sum(
            1
            for edge in edges
            if edge.edge_type == "source_reference" and edge.source_url == node
        )
        for node in nodes
    }
    return min(
        nodes,
        key=lambda node: (
            -outgoing_counts[node],
            0 if node in response_urls else 1,
            node,
        ),
    )


def _manual_review_order(
    edges: tuple[HttpRouteRelationshipEdge, ...],
    reviews: tuple[SuccessfulDeepContentReview, ...],
) -> tuple[str, ...]:
    steps: list[str] = []
    if reviews:
        steps.append(
            "Inspect the retained response artefacts for the exact attached route nodes."
        )
    if any(edge.edge_type == "source_reference" for edge in edges):
        steps.append(
            "Confirm each source-reference edge against its exact saved artefact evidence."
        )
    if any(edge.edge_type == "redirect" for edge in edges):
        steps.append(
            "Review each represented redirect status and Location without following it."
        )
    steps.append(
        "Stop before inferring vulnerability, credential, or cross-service meaning."
    )
    return tuple(steps)


def _is_static_reference(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(path.endswith(suffix) for suffix in STATIC_REFERENCE_SUFFIXES)


def _review_sort_key(review: SuccessfulDeepContentReview) -> tuple[object, ...]:
    return (
        canonical_relationship_url(review.canonical_url),
        review.status_code,
        review.body_sha256,
        review.review_id,
        tuple(sorted(review.evidence_ids)),
        tuple(sorted(review.artefact_references)),
    )


def _edge_sort_key(edge: HttpRouteRelationshipEdge) -> tuple[object, ...]:
    return (
        edge.edge_type,
        edge.source_url,
        edge.target_url,
        edge.status_code if edge.status_code is not None else -1,
        edge.evidence_ids,
        edge.artefact_references,
        edge.raw_references,
    )


def _render_edge(edge: HttpRouteRelationshipEdge, *, prefix: str) -> str:
    if edge.edge_type == "redirect":
        label = f"Redirect (HTTP {edge.status_code})"
    else:
        label = "Source reference"
    details = (
        f"{prefix}{label}: {_code(edge.source_url)} -> {_code(edge.target_url)}; "
        f"evidence {_code_list(edge.evidence_ids)}"
    )
    if edge.raw_references:
        details += f"; raw reference {_code_list(edge.raw_references)}"
    if edge.artefact_references:
        details += f"; retained artefact {_code_list(edge.artefact_references)}"
    if edge.corroborated_review_ids:
        details += (
            "; exact-evidence corroboration with "
            + _code_list(edge.corroborated_review_ids)
        )
    return details


def _md(value: str) -> str:
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("_", "\\_")


def _code(value: str) -> str:
    sanitised = value.replace("`", "'").replace("\n", " ").replace("\r", " ")
    return f"`{sanitised}`"


def _code_list(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    return ", ".join(_code(value) for value in values)


def _portable_artefact_reference(source_file: str, input_dir: str) -> str:
    if not source_file or not source_file.strip():
        return ""
    if not input_dir or not input_dir.strip():
        return ""
    source = Path(source_file.strip())
    root = Path(input_dir.strip())
    if source == Path(".") or ".." in source.parts:
        return ""
    try:
        resolved_root = root.resolve(strict=False)
        resolved_source = (
            source.resolve(strict=False)
            if source.is_absolute()
            else (resolved_root / source).resolve(strict=False)
        )
        reference = resolved_source.relative_to(resolved_root).as_posix()
    except (OSError, RuntimeError, ValueError):
        return ""
    if reference in {"", "."} or ".." in Path(reference).parts:
        return ""
    return reference


def _nonempty_sorted(values: Iterable[object]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value.strip()
                for value in values
                if isinstance(value, str) and value.strip()
            }
        )
    )
