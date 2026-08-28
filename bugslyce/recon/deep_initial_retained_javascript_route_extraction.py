"""Deep-only static route analysis of manifest-retained initial HTML.

This adapter reads complete, manifest-described initial HTML already retained
locally and delegates static JavaScript semantics to the existing Deep
extractor. It does not plan, fetch, execute JavaScript, or treat the source as
Deep-collected content.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlparse

from bugslyce.core.models import ProjectState, ReconManifestArtifact
from bugslyce.recon.deep_javascript_route_extraction import (
    DeepJavaScriptRouteCandidate,
    build_deep_javascript_route_extraction,
    safe_javascript_route_url,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)
from bugslyce.recon.modes import DEEP_RECON_BOUNDS


MAX_RENDERED_VALUES = 6
SAFETY_NOTES = (
    "This is Deep-only offline analysis of complete initial HTML retained locally.",
    "Initial retained HTML was not treated as Deep-collected content.",
    "No network request was made or planned by this analysis.",
    "No JavaScript was executed.",
    "Extracted static candidates did not feed shallow follow-up planning.",
    "Static candidates are manual-review context, not confirmed endpoints.",
)


@dataclass(frozen=True)
class DeepInitialRetainedJavaScriptRouteSourceObservation:
    """One authoritative manifest-retained HTML source behind a route candidate."""

    source_role: str
    source_id: str
    manifest_file: str
    safe_document_url: str
    source_body_sha256: str
    evidence_ids: tuple[str, ...]
    source_selection_reasons: tuple[str, ...]
    script_types: tuple[str, ...]
    candidate_forms: tuple[str, ...]
    resolution_contexts: tuple[str, ...]
    occurrence_count: int
    semantic_contexts: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeepInitialRetainedJavaScriptRouteCandidate:
    """One aggregated static route candidate from retained initial HTML."""

    candidate_id: str
    safe_candidate: str
    safe_resolved_url: str | None
    path: str
    query_parameter_names: tuple[str, ...]
    source_observations: tuple[
        DeepInitialRetainedJavaScriptRouteSourceObservation, ...
    ]
    occurrence_count: int
    interpretation: str

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return _observation_values(self.source_observations, "evidence_ids")

    @property
    def source_ids(self) -> tuple[str, ...]:
        return _unique_sorted(
            tuple(item.source_id for item in self.source_observations)
        )

    @property
    def semantic_contexts(self) -> tuple[str, ...]:
        return _observation_values(self.source_observations, "semantic_contexts")


@dataclass(frozen=True)
class DeepInitialRetainedJavaScriptRouteExtractionSummaryCounts:
    """Bounded counts for the initial-retained source adapter."""

    manifest_html_sources_considered: int
    retained_html_sources_scanned: int
    source_limit_sources_skipped: int
    duplicate_retained_observations_skipped: int
    already_represented_by_deep_collection_skipped: int
    unreadable_or_missing_sources_skipped: int
    oversized_sources_skipped: int
    binary_sources_skipped: int
    invalid_source_urls_skipped: int
    candidate_occurrences_found: int
    unique_aggregated_candidates: int
    dynamic_template_strings_skipped: int
    dynamic_concatenation_strings_skipped: int


@dataclass(frozen=True)
class DeepInitialRetainedJavaScriptRouteExtractionResult:
    """Derived Deep-only static route analysis from retained initial HTML."""

    candidates: tuple[DeepInitialRetainedJavaScriptRouteCandidate, ...]
    summary_counts: DeepInitialRetainedJavaScriptRouteExtractionSummaryCounts
    safety_notes: tuple[str, ...]


def empty_deep_initial_retained_javascript_route_extraction() -> (
    DeepInitialRetainedJavaScriptRouteExtractionResult
):
    """Return the deterministic empty result for standalone Deep orchestration."""

    return DeepInitialRetainedJavaScriptRouteExtractionResult(
        candidates=(),
        summary_counts=DeepInitialRetainedJavaScriptRouteExtractionSummaryCounts(
            manifest_html_sources_considered=0,
            retained_html_sources_scanned=0,
            source_limit_sources_skipped=0,
            duplicate_retained_observations_skipped=0,
            already_represented_by_deep_collection_skipped=0,
            unreadable_or_missing_sources_skipped=0,
            oversized_sources_skipped=0,
            binary_sources_skipped=0,
            invalid_source_urls_skipped=0,
            candidate_occurrences_found=0,
            unique_aggregated_candidates=0,
            dynamic_template_strings_skipped=0,
            dynamic_concatenation_strings_skipped=0,
        ),
        safety_notes=SAFETY_NOTES,
    )


@dataclass(frozen=True)
class _RetainedSource:
    source_id: str
    manifest_file: str
    safe_document_url: str
    source_body_sha256: str
    evidence_ids: tuple[str, ...]
    item: DeepSourceRouteCollectedItem


@dataclass(frozen=True)
class _CandidateObservation:
    candidate: DeepJavaScriptRouteCandidate
    source: _RetainedSource


def build_deep_initial_retained_javascript_route_extraction(
    project_state: ProjectState,
    source_collection: DeepSourceRouteCollectionResult | None = None,
) -> DeepInitialRetainedJavaScriptRouteExtractionResult:
    """Rebuild supported Deep JavaScript facts from local manifest HTML only."""

    retained, skipped = _retained_html_sources(project_state, source_collection)
    observations: list[_CandidateObservation] = []
    candidate_occurrences = 0
    dynamic_templates = 0
    dynamic_concatenations = 0

    for source in retained:
        extraction = build_deep_javascript_route_extraction(
            DeepSourceRouteCollectionResult(
                collected=(source.item,),
                skipped=(),
                total_considered=1,
                total_collected=1,
                total_skipped=0,
            )
        )
        counts = extraction.summary_counts
        candidate_occurrences += counts.accepted_static_route_occurrences
        dynamic_templates += counts.dynamic_template_strings_skipped
        dynamic_concatenations += counts.dynamic_concatenation_strings_skipped
        observations.extend(
            _CandidateObservation(candidate=candidate, source=source)
            for candidate in extraction.candidates
        )

    candidates = _build_candidates(observations)
    return DeepInitialRetainedJavaScriptRouteExtractionResult(
        candidates=candidates,
        summary_counts=DeepInitialRetainedJavaScriptRouteExtractionSummaryCounts(
            manifest_html_sources_considered=skipped["considered"],
            retained_html_sources_scanned=len(retained),
            source_limit_sources_skipped=skipped["source_limit"],
            duplicate_retained_observations_skipped=skipped["duplicate"],
            already_represented_by_deep_collection_skipped=skipped[
                "already_represented"
            ],
            unreadable_or_missing_sources_skipped=skipped["unreadable"],
            oversized_sources_skipped=skipped["oversized"],
            binary_sources_skipped=skipped["binary"],
            invalid_source_urls_skipped=skipped["invalid_url"],
            candidate_occurrences_found=candidate_occurrences,
            unique_aggregated_candidates=len(candidates),
            dynamic_template_strings_skipped=dynamic_templates,
            dynamic_concatenation_strings_skipped=dynamic_concatenations,
        ),
        safety_notes=SAFETY_NOTES,
    )


def render_deep_initial_retained_javascript_route_extraction_markdown(
    result: DeepInitialRetainedJavaScriptRouteExtractionResult,
) -> str:
    """Render the distinct initial-retained static-route result for Deep review."""

    counts = result.summary_counts
    lines = [
        "## Deep Initial Retained HTML JavaScript Route Analysis",
        "",
        "This is offline static analysis of complete initial HTML retained through the recon manifest.",
        "These sources were not Deep-collected and extracted candidates were not requested.",
        "",
        "### Summary",
        "",
        f"- Manifest HTML sources considered: {counts.manifest_html_sources_considered}",
        f"- Retained HTML sources scanned: {counts.retained_html_sources_scanned}",
        f"- Sources over the Deep source-file limit skipped: {counts.source_limit_sources_skipped}",
        f"- Duplicate retained observations skipped: {counts.duplicate_retained_observations_skipped}",
        "- Already represented by Deep collection skipped: "
        f"{counts.already_represented_by_deep_collection_skipped}",
        f"- Missing or unreadable sources skipped: {counts.unreadable_or_missing_sources_skipped}",
        f"- Oversized sources skipped: {counts.oversized_sources_skipped}",
        f"- Binary sources skipped: {counts.binary_sources_skipped}",
        f"- Invalid source URLs skipped: {counts.invalid_source_urls_skipped}",
        f"- Static candidate occurrences found: {counts.candidate_occurrences_found}",
        f"- Unique aggregated candidates: {counts.unique_aggregated_candidates}",
        "",
        "### Initial Retained Static Route Candidates",
        "",
    ]
    if result.candidates:
        for candidate in result.candidates:
            lines.extend(_render_candidate(candidate))
    else:
        lines.append("- None.")
    lines.extend(["", "### Safety Notes", ""])
    lines.extend(f"- {note}" for note in result.safety_notes)
    lines.append("")
    return "\n".join(lines).rstrip()


def _retained_html_sources(
    project_state: ProjectState,
    source_collection: DeepSourceRouteCollectionResult | None,
) -> tuple[tuple[_RetainedSource, ...], dict[str, int]]:
    skipped = {
        "considered": 0,
        "source_limit": 0,
        "duplicate": 0,
        "already_represented": 0,
        "unreadable": 0,
        "oversized": 0,
        "binary": 0,
        "invalid_url": 0,
    }
    manifest = getattr(project_state, "recon_manifest", None)
    if manifest is None:
        return (), skipped
    root = Path(project_state.input_dir).expanduser().resolve()
    collected_source_identities = _collection_source_identities(source_collection)
    pending: list[tuple[tuple[str, str, str], _RetainedSource]] = []
    seen: set[tuple[str, str, str]] = set()

    html_artifacts = sorted(
        (artifact for artifact in manifest.artifacts if artifact.type == "html"),
        key=lambda item: (item.file, item.url or "", item.status_code or 0),
    )
    for index, artifact in enumerate(html_artifacts, start=1):
        skipped["considered"] += 1
        if index > DEEP_RECON_BOUNDS.max_source_files:
            skipped["source_limit"] += 1
            continue
        document_url = _manifest_document_url(artifact)
        if document_url is None:
            skipped["invalid_url"] += 1
            continue
        raw_document_url, safe_document_url = document_url
        path = _safe_manifest_path(root, artifact.file)
        if path is None or path.is_symlink() or not path.is_file():
            skipped["unreadable"] += 1
            continue
        try:
            if path.stat().st_size > DEEP_RECON_BOUNDS.max_body_bytes:
                skipped["oversized"] += 1
                continue
            with path.open("rb") as handle:
                body = handle.read(DEEP_RECON_BOUNDS.max_body_bytes + 1)
        except OSError:
            skipped["unreadable"] += 1
            continue
        if not body or len(body) > DEEP_RECON_BOUNDS.max_body_bytes:
            skipped["oversized"] += 1
            continue
        if _looks_binary(body):
            skipped["binary"] += 1
            continue
        digest = sha256(body).hexdigest()
        observation_key = (artifact.file, raw_document_url, digest)
        if observation_key in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(observation_key)
        if (raw_document_url, digest) in collected_source_identities:
            skipped["already_represented"] += 1
            continue
        source_id = "INITIAL-RETAINED-HTML-" + sha256(
            "\x00".join(observation_key).encode("utf-8")
        ).hexdigest()[:16].upper()
        item = DeepSourceRouteCollectedItem(
            url=raw_document_url,
            method="GET",
            status_code=artifact.status_code if artifact.status_code is not None else 0,
            final_url=raw_document_url,
            headers=(("Content-Type", "text/html"),),
            body_preview="",
            body_sha256=digest,
            body_bytes=len(body),
            elapsed_seconds=0.0,
            source="initial_retained_html",
            reason="manifest_retained_initial_html",
            evidence_ids=(),
            body=body,
        )
        pending.append(
            (
                observation_key,
                _RetainedSource(
                    source_id=source_id,
                    manifest_file=artifact.file,
                    safe_document_url=safe_document_url,
                    source_body_sha256=digest,
                    evidence_ids=(),
                    item=item,
                ),
            )
        )
    return tuple(source for _key, source in sorted(pending)), skipped


def _collection_source_identities(
    source_collection: DeepSourceRouteCollectionResult | None,
) -> set[tuple[str, str]]:
    if source_collection is None:
        return set()
    identities: set[tuple[str, str]] = set()
    for item in source_collection.collected:
        digest = (item.body_sha256 or "").strip().lower()
        if not digest:
            continue
        for raw_url in (item.url, item.final_url):
            value = raw_url.strip()
            if safe_javascript_route_url(value) != "unresolved":
                identities.add((value, digest))
    return identities


def _safe_manifest_path(root: Path, value: str) -> Path | None:
    try:
        candidate = Path(value)
        path = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
        path.relative_to(root)
    except (OSError, ValueError):
        return None
    return path


def _manifest_document_url(
    artifact: ReconManifestArtifact,
) -> tuple[str, str] | None:
    value = (artifact.url or "").strip()
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    safe = safe_javascript_route_url(value)
    return None if safe == "unresolved" else (value, safe)


def _looks_binary(body: bytes) -> bool:
    if b"\x00" in body:
        return True
    sample = body[:1024]
    if not sample:
        return False
    text = sample.decode("utf-8", errors="replace")
    printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
    return printable / len(text) < 0.85


def _build_candidates(
    observations: list[_CandidateObservation],
) -> tuple[DeepInitialRetainedJavaScriptRouteCandidate, ...]:
    grouped: dict[tuple[object, ...], list[_CandidateObservation]] = {}
    for observation in observations:
        grouped.setdefault(_semantic_key(observation.candidate), []).append(observation)
    pending = [_candidate_from_observations(values) for values in grouped.values()]
    ordered = sorted(pending, key=_candidate_sort_key)
    return tuple(
        DeepInitialRetainedJavaScriptRouteCandidate(
            candidate_id=f"DEEP-JS-INITIAL-ROUTE-{index:04d}",
            safe_candidate=candidate.safe_candidate,
            safe_resolved_url=candidate.safe_resolved_url,
            path=candidate.path,
            query_parameter_names=candidate.query_parameter_names,
            source_observations=candidate.source_observations,
            occurrence_count=candidate.occurrence_count,
            interpretation=candidate.interpretation,
        )
        for index, candidate in enumerate(ordered, start=1)
    )


def _semantic_key(candidate: DeepJavaScriptRouteCandidate) -> tuple[object, ...]:
    if candidate.safe_resolved_url:
        return ("resolved", candidate.safe_resolved_url)
    return (
        "unresolved",
        candidate.safe_candidate,
        candidate.resolution_contexts,
        candidate.path,
        candidate.query_parameter_names,
    )


def _candidate_from_observations(
    observations: list[_CandidateObservation],
) -> DeepInitialRetainedJavaScriptRouteCandidate:
    ordered = sorted(observations, key=_candidate_observation_sort_key)
    first = ordered[0].candidate
    source_observations = tuple(
        sorted(
            {
                DeepInitialRetainedJavaScriptRouteSourceObservation(
                    source_role="initial_retained_html",
                    source_id=value.source.source_id,
                    manifest_file=value.source.manifest_file,
                    safe_document_url=safe_javascript_route_url(
                        value.source.safe_document_url
                    ),
                    source_body_sha256=value.source.source_body_sha256,
                    evidence_ids=value.source.evidence_ids,
                    source_selection_reasons=value.candidate.source_selection_reasons,
                    script_types=value.candidate.script_types,
                    candidate_forms=value.candidate.candidate_forms,
                    resolution_contexts=value.candidate.resolution_contexts,
                    occurrence_count=value.candidate.occurrence_count,
                    semantic_contexts=value.candidate.semantic_contexts,
                )
                for value in ordered
            },
            key=_source_observation_sort_key,
        )
    )
    return DeepInitialRetainedJavaScriptRouteCandidate(
        candidate_id="",
        safe_candidate=first.safe_candidate,
        safe_resolved_url=first.safe_resolved_url,
        path=first.path,
        query_parameter_names=first.query_parameter_names,
        source_observations=source_observations,
        occurrence_count=sum(item.occurrence_count for item in source_observations),
        interpretation=(
            "Static route candidate observed in offline analysis of retained initial HTML."
            if first.safe_resolved_url
            else "Relative route candidate retained from initial HTML without assuming browser execution context."
        ),
    )


def _candidate_observation_sort_key(observation: _CandidateObservation) -> tuple[object, ...]:
    candidate = observation.candidate
    source = observation.source
    return (
        candidate.safe_resolved_url or "",
        candidate.safe_candidate,
        source.safe_document_url,
        source.manifest_file,
        source.source_body_sha256,
        source.evidence_ids,
    )


def _source_observation_sort_key(
    observation: DeepInitialRetainedJavaScriptRouteSourceObservation,
) -> tuple[object, ...]:
    return (
        observation.safe_document_url,
        observation.manifest_file,
        observation.source_body_sha256,
        observation.evidence_ids,
        observation.source_id,
        observation.source_selection_reasons,
        observation.script_types,
        observation.candidate_forms,
        observation.resolution_contexts,
        observation.semantic_contexts,
        observation.occurrence_count,
    )


def _candidate_sort_key(
    candidate: DeepInitialRetainedJavaScriptRouteCandidate,
) -> tuple[object, ...]:
    return (
        0 if candidate.safe_resolved_url else 1,
        candidate.safe_resolved_url or candidate.safe_candidate,
        candidate.path,
        candidate.query_parameter_names,
        tuple(item.source_id for item in candidate.source_observations),
    )


def _observation_values(
    observations: tuple[DeepInitialRetainedJavaScriptRouteSourceObservation, ...],
    field_name: str,
) -> tuple[str, ...]:
    return _unique_sorted(
        tuple(
            value
            for observation in observations
            for value in getattr(observation, field_name)
        )
    )


def _unique_sorted(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(value for value in values if value)))


def _render_candidate(candidate: DeepInitialRetainedJavaScriptRouteCandidate) -> list[str]:
    lines = [
        f"#### {candidate.candidate_id} - Initial retained static route candidate",
        "",
        f"- Candidate: `{candidate.safe_candidate}`",
    ]
    if candidate.safe_resolved_url:
        lines.append(f"- Resolved URL: `{candidate.safe_resolved_url}`")
    lines.extend(
        [
            f"- Path: `{candidate.path}`",
            "- Query parameter names: " + _format_values(candidate.query_parameter_names),
            f"- Occurrences: `{candidate.occurrence_count}`",
        ]
    )
    for index, observation in enumerate(candidate.source_observations[:MAX_RENDERED_VALUES], start=1):
        lines.extend(
            [
                f"- Source observation {index}:",
                f"  - Role: `{observation.source_role}`",
                f"  - Manifest file: `{observation.manifest_file}`",
                f"  - Document URL: `{observation.safe_document_url}`",
                f"  - Body SHA-256: `{observation.source_body_sha256}`",
                "  - Evidence: " + _format_values(observation.evidence_ids),
                "  - Semantic contexts: "
                + _format_values(observation.semantic_contexts),
            ]
        )
    lines.extend([f"- Interpretation: {candidate.interpretation}", ""])
    return lines


def _format_values(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    rendered = ", ".join(f"`{value}`" for value in values[:MAX_RENDERED_VALUES])
    remaining = len(values) - MAX_RENDERED_VALUES
    return rendered if remaining <= 0 else f"{rendered}, ... +{remaining} more"
