"""Offline static route analysis of already collected shallow JavaScript.

This module performs one pure analysis pass over retained in-memory shallow
responses. It does not plan or make requests, execute JavaScript, recurse, or
feed extracted candidates back into collection.
"""

from __future__ import annotations

from dataclasses import dataclass

from bugslyce.recon.deep_javascript_route_extraction import (
    CANDIDATE_FORM_ORDER,
    DeepJavaScriptRouteCandidate,
    build_deep_javascript_route_extraction,
    safe_javascript_route_url,
)
from bugslyce.recon.deep_shallow_route_followup import (
    DeepShallowRouteFollowupCollectedItem,
    DeepShallowRouteFollowupResult,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
)


MAX_RENDERED_VALUES = 6
MAX_RENDERED_VALUE_CHARS = 120
SAFETY_NOTES = (
    "This is one offline analysis pass over already collected shallow responses only.",
    "No network request was made or planned by this analysis.",
    "No JavaScript was executed.",
    "No recursive collection occurred.",
    "Extracted static candidates were not automatically requested.",
    "Static candidates are manual-review context, not confirmed endpoints.",
)


@dataclass(frozen=True)
class DeepPostFollowupJavaScriptRouteSourceObservation:
    """One relational shallow-source observation supporting a post candidate."""

    shallow_request_id: str
    upstream_route_candidate_ids: tuple[str, ...]
    safe_requested_url: str
    safe_final_url: str
    source_body_sha256: str
    evidence_ids: tuple[str, ...]
    source_model_kinds: tuple[str, ...]
    source_selection_reasons: tuple[str, ...]
    script_types: tuple[str, ...]
    candidate_forms: tuple[str, ...]
    resolution_contexts: tuple[str, ...]
    occurrence_count: int
    semantic_contexts: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeepPostFollowupJavaScriptRouteCandidate:
    """One aggregated route candidate from retained shallow JavaScript."""

    candidate_id: str
    safe_candidate: str
    observed_safe_candidates: tuple[str, ...]
    safe_resolved_url: str | None
    path: str
    query_parameter_names: tuple[str, ...]
    source_observations: tuple[
        DeepPostFollowupJavaScriptRouteSourceObservation, ...
    ]
    occurrence_count: int
    interpretation: str

    @property
    def candidate_forms(self) -> tuple[str, ...]:
        return _sort_candidate_forms(
            [
                value
                for observation in self.source_observations
                for value in observation.candidate_forms
            ]
        )

    @property
    def resolution_contexts(self) -> tuple[str, ...]:
        return _observation_values(self.source_observations, "resolution_contexts")

    @property
    def semantic_contexts(self) -> tuple[str, ...]:
        return _observation_values(self.source_observations, "semantic_contexts")

    @property
    def shallow_request_ids(self) -> tuple[str, ...]:
        return _unique_sorted(
            [observation.shallow_request_id for observation in self.source_observations]
        )

    @property
    def upstream_route_candidate_ids(self) -> tuple[str, ...]:
        return _observation_values(
            self.source_observations,
            "upstream_route_candidate_ids",
        )

    @property
    def safe_requested_urls(self) -> tuple[str, ...]:
        return _unique_sorted(
            [observation.safe_requested_url for observation in self.source_observations]
        )

    @property
    def safe_final_urls(self) -> tuple[str, ...]:
        return _unique_sorted(
            [observation.safe_final_url for observation in self.source_observations]
        )

    @property
    def source_body_sha256s(self) -> tuple[str, ...]:
        return _unique_sorted(
            [observation.source_body_sha256 for observation in self.source_observations]
        )

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return _observation_values(self.source_observations, "evidence_ids")

    @property
    def source_model_kinds(self) -> tuple[str, ...]:
        return _observation_values(self.source_observations, "source_model_kinds")

    @property
    def source_selection_reasons(self) -> tuple[str, ...]:
        return _observation_values(
            self.source_observations,
            "source_selection_reasons",
        )

    @property
    def script_types(self) -> tuple[str, ...]:
        return _observation_values(self.source_observations, "script_types")


@dataclass(frozen=True)
class DeepPostFollowupJavaScriptRouteExtractionSummaryCounts:
    """Immutable summary counts for the post-follow-up offline pass."""

    shallow_responses_considered: int
    javascript_responses_scanned: int
    non_javascript_responses_skipped: int
    empty_bodies_skipped: int
    candidate_occurrences_found: int
    unique_post_candidates: int
    duplicate_candidate_occurrences_aggregated: int


@dataclass(frozen=True)
class DeepPostFollowupJavaScriptRouteExtractionResult:
    """Pure offline route analysis of retained shallow JavaScript bodies."""

    candidates: tuple[DeepPostFollowupJavaScriptRouteCandidate, ...]
    summary_counts: DeepPostFollowupJavaScriptRouteExtractionSummaryCounts
    safety_notes: tuple[str, ...]


@dataclass(frozen=True)
class _PostCandidateObservation:
    candidate: DeepJavaScriptRouteCandidate
    item: DeepShallowRouteFollowupCollectedItem
    safe_requested_url: str
    safe_final_url: str


def build_deep_post_followup_javascript_route_extraction(
    shallow_followups: DeepShallowRouteFollowupResult,
) -> DeepPostFollowupJavaScriptRouteExtractionResult:
    """Analyse retained shallow JavaScript without creating a network surface."""

    observations: list[_PostCandidateObservation] = []
    javascript_responses_scanned = 0
    non_javascript_responses_skipped = 0
    empty_bodies_skipped = 0
    candidate_occurrences_found = 0

    for item in sorted(shallow_followups.collected, key=_shallow_item_sort_key):
        if not item.body:
            empty_bodies_skipped += 1
            continue
        extraction = build_deep_javascript_route_extraction(
            _source_collection_for_shallow_item(item)
        )
        if extraction.summary_counts.javascript_response_bodies_scanned != 1:
            non_javascript_responses_skipped += 1
            continue
        javascript_responses_scanned += 1
        candidate_occurrences_found += (
            extraction.summary_counts.accepted_static_route_occurrences
        )
        safe_requested_url = safe_javascript_route_url(item.requested_url)
        safe_final_url = safe_javascript_route_url(item.final_url)
        observations.extend(
            _PostCandidateObservation(
                candidate=candidate,
                item=item,
                safe_requested_url=safe_requested_url,
                safe_final_url=safe_final_url,
            )
            for candidate in extraction.candidates
        )

    candidates = _build_post_candidates(observations)
    return DeepPostFollowupJavaScriptRouteExtractionResult(
        candidates=candidates,
        summary_counts=DeepPostFollowupJavaScriptRouteExtractionSummaryCounts(
            shallow_responses_considered=len(shallow_followups.collected),
            javascript_responses_scanned=javascript_responses_scanned,
            non_javascript_responses_skipped=non_javascript_responses_skipped,
            empty_bodies_skipped=empty_bodies_skipped,
            candidate_occurrences_found=candidate_occurrences_found,
            unique_post_candidates=len(candidates),
            duplicate_candidate_occurrences_aggregated=max(
                0,
                candidate_occurrences_found - len(candidates),
            ),
        ),
        safety_notes=SAFETY_NOTES,
    )


def render_deep_post_followup_javascript_route_extraction_markdown(
    result: DeepPostFollowupJavaScriptRouteExtractionResult,
) -> str:
    """Render the standalone post-follow-up analysis for operator review."""

    counts = result.summary_counts
    lines = [
        "## Deep Post-follow-up JavaScript Route Analysis",
        "",
        "This is offline re-analysis of JavaScript bodies already retained by the bounded shallow follow-up stage.",
        "Routes shown here were not automatically requested by this analysis.",
        "",
        "### Summary",
        "",
        f"- Shallow responses considered: {counts.shallow_responses_considered}",
        f"- JavaScript responses scanned: {counts.javascript_responses_scanned}",
        f"- Non-JavaScript responses skipped: {counts.non_javascript_responses_skipped}",
        f"- Empty bodies skipped: {counts.empty_bodies_skipped}",
        f"- Static candidate occurrences found: {counts.candidate_occurrences_found}",
        f"- Unique post-follow-up candidates: {counts.unique_post_candidates}",
        "- Duplicate candidate occurrences aggregated: "
        f"{counts.duplicate_candidate_occurrences_aggregated}",
        "",
        "### Offline Static Route Candidates",
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


def _source_collection_for_shallow_item(
    item: DeepShallowRouteFollowupCollectedItem,
) -> DeepSourceRouteCollectionResult:
    source_item = DeepSourceRouteCollectedItem(
        url=item.final_url,
        method=item.method,
        status_code=item.status_code,
        final_url=item.final_url,
        headers=item.headers,
        body_preview=item.body_preview,
        body_sha256=item.body_sha256,
        body_bytes=item.body_bytes,
        elapsed_seconds=item.elapsed_seconds,
        source="shallow_route_followup",
        reason="post_followup_javascript_analysis",
        evidence_ids=item.evidence_ids,
        body=item.body,
    )
    return DeepSourceRouteCollectionResult(
        collected=(source_item,),
        skipped=(),
        total_considered=1,
        total_collected=1,
        total_skipped=0,
    )


def _build_post_candidates(
    observations: list[_PostCandidateObservation],
) -> tuple[DeepPostFollowupJavaScriptRouteCandidate, ...]:
    grouped: dict[tuple, list[_PostCandidateObservation]] = {}
    for observation in observations:
        grouped.setdefault(_semantic_key(observation.candidate), []).append(observation)

    pending = [
        _candidate_from_observations(values)
        for _key, values in sorted(grouped.items())
    ]
    ordered = sorted(pending, key=_post_candidate_sort_key)
    return tuple(
        DeepPostFollowupJavaScriptRouteCandidate(
            candidate_id=f"DEEP-JS-POST-ROUTE-{index:04d}",
            safe_candidate=candidate.safe_candidate,
            observed_safe_candidates=candidate.observed_safe_candidates,
            safe_resolved_url=candidate.safe_resolved_url,
            path=candidate.path,
            query_parameter_names=candidate.query_parameter_names,
            source_observations=candidate.source_observations,
            occurrence_count=candidate.occurrence_count,
            interpretation=candidate.interpretation,
        )
        for index, candidate in enumerate(ordered, start=1)
    )


def _candidate_from_observations(
    observations: list[_PostCandidateObservation],
) -> DeepPostFollowupJavaScriptRouteCandidate:
    ordered = sorted(observations, key=_observation_sort_key)
    first = ordered[0].candidate
    safe_candidates = _unique_sorted(
        [item.candidate.safe_candidate for item in ordered]
    )
    safe_resolved_urls = _unique_sorted(
        [
            item.candidate.safe_resolved_url
            for item in ordered
            if item.candidate.safe_resolved_url
        ]
    )
    safe_resolved_url = safe_resolved_urls[0] if safe_resolved_urls else None
    source_observations = _source_observations(ordered)
    return DeepPostFollowupJavaScriptRouteCandidate(
        candidate_id="",
        safe_candidate=safe_candidates[0],
        observed_safe_candidates=safe_candidates,
        safe_resolved_url=safe_resolved_url,
        path=first.path,
        query_parameter_names=first.query_parameter_names,
        source_observations=source_observations,
        occurrence_count=sum(
            observation.occurrence_count for observation in source_observations
        ),
        interpretation=(
            "Static route candidate observed during offline re-analysis of retained shallow JavaScript."
            if safe_resolved_url
            else "Relative route candidate retained during offline re-analysis without assuming browser execution context."
        ),
    )


def _source_observations(
    observations: list[_PostCandidateObservation],
) -> tuple[DeepPostFollowupJavaScriptRouteSourceObservation, ...]:
    values = {
        DeepPostFollowupJavaScriptRouteSourceObservation(
            shallow_request_id=observation.item.request_id,
            upstream_route_candidate_ids=tuple(
                sorted(set(observation.item.source_route_candidate_ids))
            ),
            safe_requested_url=observation.safe_requested_url,
            safe_final_url=observation.safe_final_url,
            source_body_sha256=observation.item.body_sha256,
            evidence_ids=tuple(sorted(set(observation.item.evidence_ids))),
            source_model_kinds=tuple(
                sorted(set(observation.item.source_model_kinds))
            ),
            source_selection_reasons=observation.candidate.source_selection_reasons,
            script_types=observation.candidate.script_types,
            candidate_forms=observation.candidate.candidate_forms,
            resolution_contexts=observation.candidate.resolution_contexts,
            occurrence_count=observation.candidate.occurrence_count,
            semantic_contexts=observation.candidate.semantic_contexts,
        )
        for observation in observations
    }
    return tuple(sorted(values, key=_source_observation_sort_key))


def _semantic_key(candidate: DeepJavaScriptRouteCandidate) -> tuple:
    if candidate.safe_resolved_url:
        return ("resolved", candidate.safe_resolved_url)
    return (
        "unresolved",
        candidate.safe_candidate,
        candidate.resolution_contexts,
        candidate.path,
        candidate.query_parameter_names,
    )


def _shallow_item_sort_key(item: DeepShallowRouteFollowupCollectedItem) -> tuple:
    return (
        safe_javascript_route_url(item.final_url),
        safe_javascript_route_url(item.requested_url),
        item.request_id,
        item.method,
        item.status_code,
        tuple(sorted((name.lower(), value) for name, value in item.headers)),
        item.body_sha256,
        item.body_bytes,
        tuple(sorted(item.source_route_candidate_ids)),
        tuple(sorted(item.evidence_ids)),
    )


def _observation_sort_key(observation: _PostCandidateObservation) -> tuple:
    return (
        observation.candidate.safe_resolved_url or "",
        observation.candidate.safe_candidate,
        observation.safe_final_url,
        observation.safe_requested_url,
        observation.item.request_id,
        observation.item.body_sha256,
        tuple(sorted(observation.item.evidence_ids)),
    )


def _post_candidate_sort_key(
    candidate: DeepPostFollowupJavaScriptRouteCandidate,
) -> tuple:
    return (
        0 if candidate.safe_resolved_url else 1,
        candidate.safe_resolved_url or candidate.safe_candidate,
        candidate.path,
        candidate.query_parameter_names,
        candidate.resolution_contexts,
        candidate.shallow_request_ids,
        candidate.evidence_ids,
    )


def _source_observation_sort_key(
    observation: DeepPostFollowupJavaScriptRouteSourceObservation,
) -> tuple:
    return (
        observation.shallow_request_id,
        observation.safe_final_url,
        observation.safe_requested_url,
        observation.source_body_sha256,
        observation.upstream_route_candidate_ids,
        observation.evidence_ids,
        observation.source_model_kinds,
        observation.source_selection_reasons,
        observation.script_types,
        observation.candidate_forms,
        observation.resolution_contexts,
        observation.semantic_contexts,
        observation.occurrence_count,
    )


def _render_candidate(
    candidate: DeepPostFollowupJavaScriptRouteCandidate,
) -> list[str]:
    lines = [
        f"#### {candidate.candidate_id} - Offline static route candidate",
        "",
        f"- Candidate: `{_compact_single(candidate.safe_candidate)}`",
    ]
    if candidate.safe_resolved_url:
        lines.append(f"- Resolved URL: `{_compact_single(candidate.safe_resolved_url)}`")
    lines.extend(
        [
            f"- Path: `{_compact_single(candidate.path)}`",
            "- Observed candidate forms: "
            + _format_compact_values(candidate.observed_safe_candidates),
            "- Query parameter names: "
            + _format_compact_values(candidate.query_parameter_names),
            "- Candidate forms: " + _format_compact_values(candidate.candidate_forms),
            "- Resolution contexts: "
            + _format_compact_values(candidate.resolution_contexts),
            f"- Occurrences: `{candidate.occurrence_count}`",
        ]
    )
    for index, observation in enumerate(
        candidate.source_observations[:MAX_RENDERED_VALUES],
        start=1,
    ):
        lines.extend(_render_source_observation(index, observation))
    remaining = len(candidate.source_observations) - MAX_RENDERED_VALUES
    if remaining > 0:
        lines.append(f"- Supporting source observations: ... +{remaining} more")
    lines.extend([f"- Interpretation: {candidate.interpretation}", ""])
    return lines


def _render_source_observation(
    index: int,
    observation: DeepPostFollowupJavaScriptRouteSourceObservation,
) -> list[str]:
    return [
        f"- Source observation {index}:",
        f"  - Shallow request: `{_compact_single(observation.shallow_request_id)}`",
        "  - Upstream route candidates: "
        + _format_compact_values(observation.upstream_route_candidate_ids),
        f"  - Requested URL: `{_compact_single(observation.safe_requested_url)}`",
        f"  - Final URL: `{_compact_single(observation.safe_final_url)}`",
        f"  - Body SHA-256: `{_compact_single(observation.source_body_sha256)}`",
        "  - Evidence: " + _format_compact_values(observation.evidence_ids),
        "  - Source model kinds: "
        + _format_compact_values(observation.source_model_kinds),
        "  - Source selection: "
        + _format_compact_values(observation.source_selection_reasons),
        "  - Script types: " + _format_compact_values(observation.script_types),
        "  - Candidate forms: "
        + _format_compact_values(observation.candidate_forms),
        "  - Resolution contexts: "
        + _format_compact_values(observation.resolution_contexts),
        "  - Semantic contexts: "
        + _format_compact_values(observation.semantic_contexts),
        f"  - Occurrences: `{observation.occurrence_count}`",
    ]


def _format_compact_values(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    rendered = ", ".join(
        f"`{_compact_single(value)}`" for value in values[:MAX_RENDERED_VALUES]
    )
    remaining = len(values) - MAX_RENDERED_VALUES
    if remaining > 0:
        rendered += f", ... +{remaining} more"
    return rendered


def _compact_single(
    value: str,
    *,
    max_chars: int = MAX_RENDERED_VALUE_CHARS,
) -> str:
    compact = " ".join(str(value).strip().split())
    if len(compact) <= max_chars:
        return compact
    return compact[: max_chars - 24].rstrip() + " ... [truncated]"


def _unique_sorted(values: list[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def _observation_values(
    observations: tuple[DeepPostFollowupJavaScriptRouteSourceObservation, ...],
    field_name: str,
) -> tuple[str, ...]:
    return _unique_sorted(
        [
            value
            for observation in observations
            for value in getattr(observation, field_name)
        ]
    )


def _sort_candidate_forms(values: list[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            set(values),
            key=lambda value: (CANDIDATE_FORM_ORDER.get(value, 99), value),
        )
    )
