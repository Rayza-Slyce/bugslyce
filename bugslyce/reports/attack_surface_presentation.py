"""Human-readable projection of existing retained attack-surface evidence."""

from __future__ import annotations

from dataclasses import dataclass

from bugslyce.recon.deep_http_fingerprint_summary import DeepHttpFingerprintSummary
from bugslyce.recon.deep_response_similarity_review import DeepResponseSimilarityReview
from bugslyce.reports.human_triage import HumanTriageBrief, HumanTriageItem


_JAVASCRIPT_MEDIA_TYPES = frozenset(
    {
        "application/ecmascript",
        "application/javascript",
        "text/ecmascript",
        "text/javascript",
    }
)
_ACCESS_BOUNDARY_STATUSES = frozenset({401, 403})


@dataclass(frozen=True)
class AttackSurfaceHttpMetrics:
    """Counts derived only from retained Deep HTTP fingerprints."""

    retained_responses: int
    successful_responses: int
    blocked_responses: int
    not_found_responses: int
    successful_javascript_resources: int
    successful_non_javascript_url_count: int


@dataclass(frozen=True)
class AttackSurfaceBlockedCoverage:
    """One existing repeated access-boundary response group."""

    group_id: str
    status_codes: tuple[int, ...]
    requested_urls: tuple[str, ...]
    titles: tuple[str, ...]
    fingerprint_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]

    @property
    def response_count(self) -> int:
        return len(self.fingerprint_ids)


@dataclass(frozen=True)
class AttackSurfacePresentation:
    """Presentation-only synthesis retaining exact underlying identities."""

    http_metrics: AttackSurfaceHttpMetrics
    successful_non_javascript_urls: tuple[str, ...]
    worth_reviewing: tuple[HumanTriageItem, ...]
    blocked_coverage: tuple[AttackSurfaceBlockedCoverage, ...]


def build_attack_surface_presentation(
    http_summary: DeepHttpFingerprintSummary,
    similarity_review: DeepResponseSimilarityReview,
    human_triage: HumanTriageBrief,
) -> AttackSurfacePresentation:
    """Build a deterministic human projection without changing evidence semantics."""

    successful = tuple(
        item
        for item in http_summary.fingerprints
        if 200 <= item.status_code <= 299
    )
    javascript = tuple(item for item in successful if _is_javascript(item.content_type))
    non_javascript = tuple(
        item for item in successful if not _is_javascript(item.content_type)
    )
    successful_non_javascript_urls = tuple(
        sorted({item.requested_url for item in non_javascript})
    )
    blocked = tuple(
        AttackSurfaceBlockedCoverage(
            group_id=group.group_id,
            status_codes=group.status_codes,
            requested_urls=group.requested_urls,
            titles=group.titles_observed_in_bounded_previews,
            fingerprint_ids=group.fingerprint_ids,
            evidence_ids=group.evidence_ids,
        )
        for group in similarity_review.groups
        if group.category == "client_error_signature_group"
        and group.status_codes
        and set(group.status_codes).issubset(_ACCESS_BOUNDARY_STATUSES)
    )
    return AttackSurfacePresentation(
        http_metrics=AttackSurfaceHttpMetrics(
            retained_responses=len(http_summary.fingerprints),
            successful_responses=len(successful),
            blocked_responses=sum(
                item.status_code == 403 for item in http_summary.fingerprints
            ),
            not_found_responses=sum(
                item.status_code == 404 for item in http_summary.fingerprints
            ),
            successful_javascript_resources=len(javascript),
            successful_non_javascript_url_count=len(successful_non_javascript_urls),
        ),
        successful_non_javascript_urls=successful_non_javascript_urls,
        worth_reviewing=human_triage.start_here,
        blocked_coverage=tuple(sorted(blocked, key=lambda item: item.group_id)),
    )


def _is_javascript(content_type: str | None) -> bool:
    if not content_type:
        return False
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type in _JAVASCRIPT_MEDIA_TYPES
