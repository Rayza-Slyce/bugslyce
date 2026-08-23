"""Immutable shared operator-brief semantics and deterministic persistence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
from pathlib import Path

from bugslyce.reports.operator_summary import OperatorSummary
from bugslyce.reports.analysis_coverage import (
    AnalysisCoverageExecutionNote,
    AnalysisCoverageOutcome,
    AnalysisCoverageState,
    AnalysisCoverageUnknownReason,
)


OPERATOR_BRIEF_FILENAME = "operator_brief.json"
_OPERATOR_BRIEF_SCHEMA_VERSION = 2
_OPERATOR_BRIEF_GENERATED_BY = "bugslyce.operator_brief"

PRIMARY_THREAD = "primary_thread"
SUPPORTING_CONTEXT = "supporting_context"
DEPRIORITISED_CONTEXT = "deprioritised_context"
EVIDENCE_ONLY = "evidence_only"

_VALID_DISPOSITIONS = frozenset(
    {
        PRIMARY_THREAD,
        SUPPORTING_CONTEXT,
        DEPRIORITISED_CONTEXT,
        EVIDENCE_ONLY,
    }
)


class OperatorBriefSemanticClass(str, Enum):
    OBSERVED = "observed"
    DERIVED = "derived"


class OperatorBriefFactRole(str, Enum):
    DIRECT_EVIDENCE = "direct_evidence"
    RELATIONSHIP_CONTEXT = "relationship_context"


class OperatorBriefFactKind(str, Enum):
    HTTP_RESPONSE = "http_response"
    HTTP_ROUTE = "http_route"
    RESPONSE_EQUIVALENCE = "response_equivalence"
    ROUTE_RELATIONSHIP = "route_relationship"
    FORM = "form"
    PARAMETER = "parameter"
    WORKFLOW = "workflow"
    RETAINED_CONTENT = "retained_content"
    SOURCE_ROBOTS_CLUE = "source_robots_clue"
    SMB_SHARE = "smb_share"
    SERVICE = "service"


class OperatorBriefSubjectKind(str, Enum):
    APPLICATION = "application"
    ACCOUNT_WORKFLOW = "account_workflow"
    CONTENT_SURFACE = "content_surface"
    SMB_SURFACE = "smb_surface"
    SERVICE_SURFACE = "service_surface"
    LEGACY_CANONICAL_LEAD = "legacy_canonical_lead"


class OperatorBriefConflictKind(str, Enum):
    DIFFERING_HTTP_STATUS = "differing_http_status"


class OperatorBriefDispositionReason(str, Enum):
    PRIMARY_SUBJECT = "primary_subject"
    SUPPORTING_RELATIONSHIP = "supporting_relationship"
    LOWER_SPECIFICITY = "lower_specificity"
    EVIDENCE_DETAIL = "evidence_detail"
    LEGACY_PROJECTION = "legacy_projection"


class OperatorBriefLegacyContextKind(str, Enum):
    OBSERVED_FACT_TEXT = "observed_fact_text"
    RELATED_CONTEXT_TEXT = "related_context_text"
    CONFLICT_TEXT = "conflict_text"
    COVERAGE_LIMITATION_TEXT = "coverage_limitation_text"
    UNKNOWN_TEXT = "unknown_text"
    UNATTRIBUTED_SCORE_TEXT = "unattributed_score_text"


def _normalised_text_membership(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} cannot contain blank values.")
    return tuple(sorted(set(values)))


@dataclass(frozen=True, order=True)
class OperatorBriefSourceReference:
    source_kind: str
    source_id: str

    def __post_init__(self) -> None:
        if not self.source_kind.strip() or not self.source_id.strip():
            raise ValueError("Operator Brief source references require kind and ID.")


@dataclass(frozen=True)
class OperatorBriefFact:
    fact_id: str
    kind: OperatorBriefFactKind
    semantic_class: OperatorBriefSemanticClass
    role: OperatorBriefFactRole
    label: str
    summary: str
    endpoints: tuple[str, ...] = ()
    origins: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    artefact_references: tuple[str, ...] = ()
    source_references: tuple[OperatorBriefSourceReference, ...] = ()
    route: str = ""
    parameter_name: str = ""
    form_method: str = ""
    form_action: str = ""
    service: str = ""
    share_name: str = ""
    share_type: str = ""
    body_sha256: str = ""
    http_method: str = ""
    http_status_code: int | None = None

    def __post_init__(self) -> None:
        if not self.fact_id.strip():
            raise ValueError("Operator Brief facts require a fact ID.")
        if not isinstance(self.kind, OperatorBriefFactKind):
            raise ValueError("Operator Brief fact kind is invalid.")
        if not isinstance(self.semantic_class, OperatorBriefSemanticClass):
            raise ValueError("Operator Brief fact semantic class is invalid.")
        if not isinstance(self.role, OperatorBriefFactRole):
            raise ValueError("Operator Brief fact role is invalid.")
        if not isinstance(self.http_method, str):
            raise ValueError("Operator Brief HTTP method must be text.")
        if self.http_status_code is not None and (
            isinstance(self.http_status_code, bool)
            or not isinstance(self.http_status_code, int)
        ):
            raise ValueError("Operator Brief HTTP status must be an integer or null.")
        if (
            self.role is OperatorBriefFactRole.DIRECT_EVIDENCE
            and self.semantic_class is not OperatorBriefSemanticClass.OBSERVED
        ):
            raise ValueError("Operator Brief direct evidence requires observed semantics.")
        if self.kind is OperatorBriefFactKind.RESPONSE_EQUIVALENCE and (
            self.semantic_class is not OperatorBriefSemanticClass.DERIVED
            or self.role is not OperatorBriefFactRole.RELATIONSHIP_CONTEXT
        ):
            raise ValueError(
                "Operator Brief response equivalence requires derived relationship context."
            )
        if self.kind is OperatorBriefFactKind.HTTP_RESPONSE:
            if (
                self.semantic_class is not OperatorBriefSemanticClass.OBSERVED
                or self.role is not OperatorBriefFactRole.DIRECT_EVIDENCE
            ):
                raise ValueError(
                    "Operator Brief HTTP responses require observed direct evidence."
                )
            if not self.http_method.strip():
                raise ValueError("Operator Brief HTTP responses require a method.")
            if self.http_status_code is None:
                raise ValueError("Operator Brief HTTP responses require a status.")
        if not self.label.strip() or not self.summary.strip():
            raise ValueError("Operator Brief facts require a label and summary.")
        if any(not isinstance(value, str) for value in self.endpoints):
            raise ValueError("Operator Brief fact endpoints must be text.")
        if any(
            not isinstance(value, OperatorBriefSourceReference)
            for value in self.source_references
        ):
            raise ValueError("Operator Brief fact source references are invalid.")
        object.__setattr__(
            self,
            "origins",
            _normalised_text_membership(self.origins, "Operator Brief fact origins"),
        )
        object.__setattr__(
            self,
            "evidence_ids",
            _normalised_text_membership(
                self.evidence_ids, "Operator Brief fact evidence IDs"
            ),
        )
        object.__setattr__(
            self,
            "artefact_references",
            _normalised_text_membership(
                self.artefact_references, "Operator Brief fact artefact references"
            ),
        )
        object.__setattr__(
            self,
            "source_references",
            tuple(sorted(set(self.source_references))),
        )


@dataclass(frozen=True)
class OperatorBriefConflictObservation:
    observation_id: str
    endpoint: str
    method: str
    status_code: int
    collection_stage: str
    evidence_ids: tuple[str, ...] = ()
    artefact_references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (self.observation_id, self.endpoint, self.method, self.collection_stage)
        ):
            raise ValueError("Operator Brief conflict observations require identities.")
        if isinstance(self.status_code, bool) or not isinstance(self.status_code, int):
            raise ValueError("Operator Brief conflict status must be an integer.")
        object.__setattr__(
            self,
            "evidence_ids",
            _normalised_text_membership(
                self.evidence_ids, "Operator Brief conflict evidence IDs"
            ),
        )
        object.__setattr__(
            self,
            "artefact_references",
            _normalised_text_membership(
                self.artefact_references,
                "Operator Brief conflict artefact references",
            ),
        )


@dataclass(frozen=True)
class OperatorBriefConflict:
    conflict_id: str
    kind: OperatorBriefConflictKind
    subject_endpoint: str
    observations: tuple[OperatorBriefConflictObservation, ...]
    summary: str

    def __post_init__(self) -> None:
        if not self.conflict_id.strip() or not self.subject_endpoint.strip():
            raise ValueError("Operator Brief conflicts require an ID and subject.")
        if not isinstance(self.kind, OperatorBriefConflictKind):
            raise ValueError("Operator Brief conflict kind is invalid.")
        if not self.summary.strip():
            raise ValueError("Operator Brief conflicts require a summary.")
        if any(
            not isinstance(item, OperatorBriefConflictObservation)
            for item in self.observations
        ):
            raise ValueError("Operator Brief conflict observations are invalid.")
        observation_ids = {item.observation_id for item in self.observations}
        if len(observation_ids) != len(self.observations):
            raise ValueError("Operator Brief conflicts contain duplicate observation IDs.")
        if self.kind is OperatorBriefConflictKind.DIFFERING_HTTP_STATUS:
            if len(self.observations) < 2:
                raise ValueError(
                    "Differing HTTP status conflicts require multiple observations."
                )
            if len({item.status_code for item in self.observations}) < 2:
                raise ValueError(
                    "Differing HTTP status conflicts require different status codes."
                )
            if any(item.endpoint != self.subject_endpoint for item in self.observations):
                raise ValueError(
                    "Differing HTTP status observations must match the subject endpoint."
                )


@dataclass(frozen=True)
class OperatorBriefCoverageLimitation:
    limitation_id: str
    capability: str
    source_role: str
    source_id: str
    state: AnalysisCoverageState
    outcome: AnalysisCoverageOutcome | None
    unknown_reason: AnalysisCoverageUnknownReason | None
    execution_note: AnalysisCoverageExecutionNote | None
    summary: str

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (
                self.limitation_id,
                self.capability,
                self.source_role,
                self.source_id,
                self.summary,
            )
        ):
            raise ValueError("Operator Brief coverage limitations require scoped identities.")
        if not isinstance(self.state, AnalysisCoverageState):
            raise ValueError("Operator Brief coverage state is invalid.")
        if self.outcome is not None and not isinstance(
            self.outcome, AnalysisCoverageOutcome
        ):
            raise ValueError("Operator Brief coverage outcome is invalid.")
        if self.unknown_reason is not None and not isinstance(
            self.unknown_reason, AnalysisCoverageUnknownReason
        ):
            raise ValueError("Operator Brief coverage unknown reason is invalid.")
        if self.execution_note is not None and not isinstance(
            self.execution_note, AnalysisCoverageExecutionNote
        ):
            raise ValueError("Operator Brief coverage execution note is invalid.")
        valid_outcomes = {
            AnalysisCoverageState.ANALYSED: {
                AnalysisCoverageOutcome.FINDING_PRESENT,
                AnalysisCoverageOutcome.NO_FINDING,
            },
            AnalysisCoverageState.NOT_RUN: {
                AnalysisCoverageOutcome.UNSUPPORTED,
                AnalysisCoverageOutcome.BOUNDED_SKIPPED,
                AnalysisCoverageOutcome.NOT_COLLECTED,
                AnalysisCoverageOutcome.NO_OP_NOT_APPLICABLE,
            },
            AnalysisCoverageState.INCOMPLETE: {
                AnalysisCoverageOutcome.PARTIAL_FAILED,
            },
            AnalysisCoverageState.UNKNOWN: {None},
        }
        if self.outcome not in valid_outcomes[self.state]:
            raise ValueError("Operator Brief coverage state/outcome is invalid.")
        if (
            self.state is AnalysisCoverageState.UNKNOWN
            and self.unknown_reason is None
        ):
            raise ValueError("Unknown coverage requires an unknown reason.")
        if self.unknown_reason is not None and self.state is not AnalysisCoverageState.UNKNOWN:
            raise ValueError("Operator Brief coverage unknown reasons require UNKNOWN state.")
        if self.execution_note is not None and self.state is not AnalysisCoverageState.ANALYSED:
            raise ValueError("Operator Brief coverage execution notes require ANALYSED state.")


@dataclass(frozen=True)
class OperatorBriefSourceRanking:
    source_lead_id: str
    rank: int
    score: int
    signal: str

    def __post_init__(self) -> None:
        if not self.source_lead_id.strip() or not self.signal.strip():
            raise ValueError("Operator Brief source rankings require lead ID and signal.")
        if isinstance(self.rank, bool) or not isinstance(self.rank, int) or self.rank < 1:
            raise ValueError("Operator Brief source ranking rank must be positive.")
        if isinstance(self.score, bool) or not isinstance(self.score, int):
            raise ValueError("Operator Brief source ranking score must be an integer.")


@dataclass(frozen=True)
class OperatorBriefLegacyContext:
    kind: OperatorBriefLegacyContextKind
    text: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, OperatorBriefLegacyContextKind):
            raise ValueError("Operator Brief legacy context kind is invalid.")
        if not self.text.strip():
            raise ValueError("Operator Brief legacy context cannot be blank.")


@dataclass(frozen=True, init=False)
class OperatorBriefThread:
    """One immutable operator-facing investigation subject."""

    thread_id: str
    identity_key: str
    subject_kind: OperatorBriefSubjectKind
    title: str
    rank: int
    signal: str
    source_lead_ids: tuple[str, ...]
    endpoints: tuple[str, ...]
    origins: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    why_review: str
    next_review_step: str
    facts: tuple[OperatorBriefFact, ...] = ()
    conflicts: tuple[OperatorBriefConflict, ...] = ()
    coverage_limitations: tuple[OperatorBriefCoverageLimitation, ...] = ()
    source_rankings: tuple[OperatorBriefSourceRanking, ...] = ()
    legacy_context: tuple[OperatorBriefLegacyContext, ...] = ()
    source_artefacts: tuple[str, ...] = ()

    def __init__(
        self,
        thread_id: str,
        title: str,
        rank: int,
        signal: str,
        source_lead_ids: tuple[str, ...],
        endpoints: tuple[str, ...],
        evidence_ids: tuple[str, ...],
        why_review: str,
        next_review_step: str,
        *,
        identity_key: str = "",
        subject_kind: OperatorBriefSubjectKind = (
            OperatorBriefSubjectKind.LEGACY_CANONICAL_LEAD
        ),
        origins: tuple[str, ...] = (),
        facts: tuple[OperatorBriefFact, ...] = (),
        conflicts: tuple[OperatorBriefConflict, ...] | tuple[str, ...] = (),
        coverage_limitations: (
            tuple[OperatorBriefCoverageLimitation, ...] | tuple[str, ...]
        ) = (),
        source_rankings: tuple[OperatorBriefSourceRanking, ...] = (),
        legacy_context: tuple[OperatorBriefLegacyContext, ...] = (),
        source_artefacts: tuple[str, ...] = (),
        score: int | None = None,
        observed_facts: tuple[str, ...] = (),
        related_context: tuple[str, ...] = (),
        unknowns: tuple[str, ...] = (),
    ) -> None:
        """Build the current model while accepting the R3A constructor shape."""

        if any(
            not isinstance(item, (OperatorBriefConflict, str))
            for item in conflicts
        ):
            raise ValueError("Operator Brief thread conflicts are invalid.")
        if any(
            not isinstance(item, (OperatorBriefCoverageLimitation, str))
            for item in coverage_limitations
        ):
            raise ValueError("Operator Brief thread coverage limitations are invalid.")
        if score is not None and (
            isinstance(score, bool) or not isinstance(score, int)
        ):
            raise ValueError("Legacy Operator Brief thread score must be an integer.")
        structured_conflicts = tuple(
            item for item in conflicts if isinstance(item, OperatorBriefConflict)
        )
        structured_limitations = tuple(
            item
            for item in coverage_limitations
            if isinstance(item, OperatorBriefCoverageLimitation)
        )
        migrated_context = tuple(legacy_context) + tuple(
            OperatorBriefLegacyContext(kind=kind, text=text)
            for values, kind in (
                (observed_facts, OperatorBriefLegacyContextKind.OBSERVED_FACT_TEXT),
                (related_context, OperatorBriefLegacyContextKind.RELATED_CONTEXT_TEXT),
                (
                    tuple(item for item in conflicts if isinstance(item, str)),
                    OperatorBriefLegacyContextKind.CONFLICT_TEXT,
                ),
                (
                    tuple(
                        item
                        for item in coverage_limitations
                        if isinstance(item, str)
                    ),
                    OperatorBriefLegacyContextKind.COVERAGE_LIMITATION_TEXT,
                ),
                (unknowns, OperatorBriefLegacyContextKind.UNKNOWN_TEXT),
            )
            for text in values
        )
        if score is not None and len(source_lead_ids) != 1:
            migrated_context += (
                OperatorBriefLegacyContext(
                    kind=OperatorBriefLegacyContextKind.UNATTRIBUTED_SCORE_TEXT,
                    text=str(score),
                ),
            )
        rankings = tuple(source_rankings)
        if not rankings and len(source_lead_ids) == 1 and score is not None:
            rankings = (
                OperatorBriefSourceRanking(
                    source_lead_id=source_lead_ids[0],
                    rank=rank,
                    score=score,
                    signal=signal,
                ),
            )

        object.__setattr__(self, "thread_id", thread_id)
        object.__setattr__(
            self,
            "identity_key",
            identity_key
            or "legacy_canonical_lead:"
            + ("|".join(source_lead_ids) or thread_id),
        )
        object.__setattr__(self, "subject_kind", subject_kind)
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "rank", rank)
        object.__setattr__(self, "signal", signal)
        object.__setattr__(self, "source_lead_ids", tuple(source_lead_ids))
        object.__setattr__(self, "endpoints", tuple(endpoints))
        object.__setattr__(self, "origins", tuple(origins))
        object.__setattr__(self, "evidence_ids", tuple(evidence_ids))
        object.__setattr__(self, "why_review", why_review)
        object.__setattr__(self, "next_review_step", next_review_step)
        object.__setattr__(self, "facts", tuple(facts))
        object.__setattr__(self, "conflicts", structured_conflicts)
        object.__setattr__(self, "coverage_limitations", structured_limitations)
        object.__setattr__(self, "source_rankings", rankings)
        object.__setattr__(self, "legacy_context", migrated_context)
        object.__setattr__(self, "source_artefacts", tuple(source_artefacts))
        self.__post_init__()

    def __post_init__(self) -> None:
        if not self.thread_id.strip():
            raise ValueError("Operator Brief threads require a thread ID.")
        if not self.identity_key.strip():
            raise ValueError("Operator Brief threads require an identity key.")
        if not isinstance(self.subject_kind, OperatorBriefSubjectKind):
            raise ValueError("Operator Brief thread subject kind is invalid.")
        if not self.title.strip():
            raise ValueError("Operator Brief threads require a title.")
        if isinstance(self.rank, bool) or not isinstance(self.rank, int) or self.rank < 1:
            raise ValueError("Operator Brief thread rank must be a positive integer.")
        if not self.signal.strip():
            raise ValueError("Operator Brief threads require a signal.")
        if any(not value.strip() for value in self.source_lead_ids):
            raise ValueError("Operator Brief source lead IDs cannot be blank.")
        if any(not isinstance(item, OperatorBriefFact) for item in self.facts):
            raise ValueError("Operator Brief thread facts are invalid.")
        if any(
            not isinstance(item, OperatorBriefConflict) for item in self.conflicts
        ):
            raise ValueError("Operator Brief thread conflicts are invalid.")
        if any(
            not isinstance(item, OperatorBriefCoverageLimitation)
            for item in self.coverage_limitations
        ):
            raise ValueError("Operator Brief thread coverage limitations are invalid.")
        if any(
            not isinstance(item, OperatorBriefSourceRanking)
            for item in self.source_rankings
        ):
            raise ValueError("Operator Brief thread source rankings are invalid.")
        if any(
            not isinstance(item, OperatorBriefLegacyContext)
            for item in self.legacy_context
        ):
            raise ValueError("Operator Brief thread legacy context is invalid.")
        fact_ids = {item.fact_id for item in self.facts}
        if len(fact_ids) != len(self.facts):
            raise ValueError("Operator Brief threads contain duplicate fact IDs.")
        conflict_ids = {item.conflict_id for item in self.conflicts}
        if len(conflict_ids) != len(self.conflicts):
            raise ValueError("Operator Brief threads contain duplicate conflict IDs.")
        limitation_ids = {item.limitation_id for item in self.coverage_limitations}
        if len(limitation_ids) != len(self.coverage_limitations):
            raise ValueError(
                "Operator Brief threads contain duplicate coverage limitation IDs."
            )
        ranking_ids = {item.source_lead_id for item in self.source_rankings}
        if len(ranking_ids) != len(self.source_rankings):
            raise ValueError("Operator Brief threads contain duplicate source rankings.")
        if not ranking_ids.issubset(set(self.source_lead_ids)):
            raise ValueError(
                "Operator Brief source rankings must reference source lead IDs."
            )

    @property
    def score(self) -> int | None:
        """Legacy one-for-one projection access without an aggregate model field."""

        if len(self.source_rankings) == 1:
            return self.source_rankings[0].score
        return None

    @property
    def observed_facts(self) -> tuple[str, ...]:
        return tuple(
            item.text
            for item in self.legacy_context
            if item.kind is OperatorBriefLegacyContextKind.OBSERVED_FACT_TEXT
        )

    @property
    def related_context(self) -> tuple[str, ...]:
        return tuple(
            item.text
            for item in self.legacy_context
            if item.kind is OperatorBriefLegacyContextKind.RELATED_CONTEXT_TEXT
        )

    @property
    def unknowns(self) -> tuple[str, ...]:
        return tuple(
            item.text
            for item in self.legacy_context
            if item.kind is OperatorBriefLegacyContextKind.UNKNOWN_TEXT
        )


@dataclass(frozen=True)
class OperatorBriefDisposition:
    """Auditable disposition of one existing operator-facing interpretation."""

    source_kind: str
    source_id: str
    disposition: str
    thread_id: str = ""
    reason_code: OperatorBriefDispositionReason = (
        OperatorBriefDispositionReason.LEGACY_PROJECTION
    )
    represented_fact_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.source_kind.strip():
            raise ValueError("Operator Brief dispositions require a source kind.")
        if not self.source_id.strip():
            raise ValueError("Operator Brief dispositions require a source ID.")
        if self.disposition not in _VALID_DISPOSITIONS:
            raise ValueError("Operator Brief disposition is invalid.")
        if not isinstance(self.reason_code, OperatorBriefDispositionReason):
            raise ValueError("Operator Brief disposition reason is invalid.")
        object.__setattr__(
            self,
            "represented_fact_ids",
            _normalised_text_membership(
                self.represented_fact_ids,
                "Operator Brief represented fact IDs",
            ),
        )
        if self.disposition in {PRIMARY_THREAD, SUPPORTING_CONTEXT} and not (
            self.thread_id.strip()
        ):
            raise ValueError(
                "Primary-thread and supporting-context dispositions require a thread ID."
            )


@dataclass(frozen=True)
class OperatorBriefView:
    """Shared semantic Operator Brief consumed by report presentation paths."""

    threads: tuple[OperatorBriefThread, ...]
    dispositions: tuple[OperatorBriefDisposition, ...]

    def __post_init__(self) -> None:
        thread_ids = {thread.thread_id for thread in self.threads}
        if len(thread_ids) != len(self.threads):
            raise ValueError("Operator Brief contains duplicate thread IDs.")

        identity_keys = {thread.identity_key for thread in self.threads}
        if len(identity_keys) != len(self.threads):
            raise ValueError("Operator Brief contains duplicate semantic identity keys.")

        disposition_sources = {
            (item.source_kind, item.source_id)
            for item in self.dispositions
        }
        if len(disposition_sources) != len(self.dispositions):
            raise ValueError("Operator Brief contains duplicate disposition sources.")

        if any(
            item.thread_id and item.thread_id not in thread_ids
            for item in self.dispositions
        ):
            raise ValueError("Operator Brief disposition references an unknown thread ID.")

        facts_by_thread = {
            thread.thread_id: {fact.fact_id for fact in thread.facts}
            for thread in self.threads
        }
        if any(
            fact_id not in facts_by_thread.get(item.thread_id, set())
            for item in self.dispositions
            for fact_id in item.represented_fact_ids
        ):
            raise ValueError("Operator Brief disposition references an unknown fact ID.")


def build_operator_brief_view(
    operator_summary: OperatorSummary,
) -> OperatorBriefView:
    """Project current canonical leads one-for-one without changing semantics."""

    threads: list[OperatorBriefThread] = []
    dispositions: list[OperatorBriefDisposition] = []

    for lead in operator_summary.ranked_leads:
        if not lead.lead_id.strip():
            raise ValueError(
                "Canonical operator-summary leads require an ID before "
                "Operator Brief projection."
            )

        thread_id = _thread_id_for_source_lead(lead.lead_id)
        thread = OperatorBriefThread(
            thread_id=thread_id,
            identity_key=f"operator_summary_lead:{lead.lead_id}",
            subject_kind=OperatorBriefSubjectKind.LEGACY_CANONICAL_LEAD,
            title=lead.title,
            rank=lead.rank,
            signal=lead.signal,
            source_lead_ids=(lead.lead_id,),
            endpoints=tuple(lead.endpoints),
            origins=(),
            evidence_ids=tuple(lead.evidence_ids),
            why_review=lead.why,
            next_review_step=lead.next_action,
            source_rankings=(
                OperatorBriefSourceRanking(
                    source_lead_id=lead.lead_id,
                    rank=lead.rank,
                    score=lead.score,
                    signal=lead.signal,
                ),
            ),
        )
        threads.append(thread)
        dispositions.append(
            OperatorBriefDisposition(
                source_kind="operator_summary_lead",
                source_id=lead.lead_id,
                disposition=PRIMARY_THREAD,
                thread_id=thread_id,
                reason_code=OperatorBriefDispositionReason.PRIMARY_SUBJECT,
            )
        )

    return OperatorBriefView(
        threads=tuple(threads),
        dispositions=tuple(dispositions),
    )


def write_operator_brief_artifact(
    root: Path,
    brief: OperatorBriefView,
) -> Path:
    """Persist one exact Operator Brief deterministically."""

    if not isinstance(brief, OperatorBriefView):
        raise TypeError("Operator Brief persistence requires an OperatorBriefView.")

    payload = {
        "schema_version": _OPERATOR_BRIEF_SCHEMA_VERSION,
        "generated_by": _OPERATOR_BRIEF_GENERATED_BY,
        "threads": [_thread_to_dict(thread) for thread in brief.threads],
        "dispositions": [
            _disposition_to_dict(disposition)
            for disposition in brief.dispositions
        ],
    }

    root.mkdir(parents=True, exist_ok=True)
    path = root / OPERATOR_BRIEF_FILENAME

    if path.is_symlink():
        raise ValueError(
            f"structured artefact must be a regular file: {OPERATOR_BRIEF_FILENAME}"
        )
    if path.exists() and not path.is_file():
        raise ValueError(
            f"structured artefact must be a regular file: {OPERATOR_BRIEF_FILENAME}"
        )

    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def load_operator_brief_artifact(
    root: Path,
) -> OperatorBriefView | None:
    """Load a persisted Operator Brief, or None for legacy absence."""

    path = root / OPERATOR_BRIEF_FILENAME

    if path.is_symlink():
        raise ValueError(
            f"structured artefact must be a regular file: {OPERATOR_BRIEF_FILENAME}"
        )
    if not path.exists():
        return None
    if not path.is_file():
        raise ValueError(
            f"structured artefact must be a regular file: {OPERATOR_BRIEF_FILENAME}"
        )

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"could not parse {OPERATOR_BRIEF_FILENAME}: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise ValueError(
            f"{OPERATOR_BRIEF_FILENAME} must contain a JSON object"
        )

    schema_version = payload.get("schema_version")
    if type(schema_version) is not int or schema_version not in {1, 2}:
        raise ValueError(
            f"{OPERATOR_BRIEF_FILENAME} has an unsupported schema_version"
        )

    if payload.get("generated_by") != _OPERATOR_BRIEF_GENERATED_BY:
        raise ValueError(
            f"{OPERATOR_BRIEF_FILENAME} has an invalid generated_by value"
        )

    if schema_version == 1:
        return _load_schema_v1(payload)
    return _load_schema_v2(payload)


def _load_schema_v2(payload: dict[str, object]) -> OperatorBriefView:
    raw_threads = payload.get("threads")
    if not isinstance(raw_threads, list):
        raise ValueError(
            f"{OPERATOR_BRIEF_FILENAME} field 'threads' must be a list"
        )

    raw_dispositions = payload.get("dispositions")
    if not isinstance(raw_dispositions, list):
        raise ValueError(
            f"{OPERATOR_BRIEF_FILENAME} field 'dispositions' must be a list"
        )

    threads = tuple(
        _thread_v2_from_dict(value, index)
        for index, value in enumerate(raw_threads)
    )
    dispositions = tuple(
        _disposition_v2_from_dict(value, index)
        for index, value in enumerate(raw_dispositions)
    )

    return OperatorBriefView(
        threads=threads,
        dispositions=dispositions,
    )


def _load_schema_v1(payload: dict[str, object]) -> OperatorBriefView:
    raw_threads = payload.get("threads")
    if not isinstance(raw_threads, list):
        raise ValueError(
            f"{OPERATOR_BRIEF_FILENAME} field 'threads' must be a list"
        )
    raw_dispositions = payload.get("dispositions")
    if not isinstance(raw_dispositions, list):
        raise ValueError(
            f"{OPERATOR_BRIEF_FILENAME} field 'dispositions' must be a list"
        )
    return OperatorBriefView(
        threads=tuple(
            _thread_v1_from_dict(value, index)
            for index, value in enumerate(raw_threads)
        ),
        dispositions=tuple(
            _disposition_v1_from_dict(value, index)
            for index, value in enumerate(raw_dispositions)
        ),
    )


def _thread_id_for_source_lead(lead_id: str) -> str:
    identity = {
        "source_kind": "operator_summary_lead",
        "source_ids": [lead_id],
    }
    digest = sha256(
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()[:16].upper()
    return f"THREAD-{digest}"


def _thread_to_dict(
    thread: OperatorBriefThread,
) -> dict[str, object]:
    return {
        "thread_id": thread.thread_id,
        "identity_key": thread.identity_key,
        "subject_kind": thread.subject_kind.value,
        "title": thread.title,
        "rank": thread.rank,
        "signal": thread.signal,
        "source_lead_ids": list(thread.source_lead_ids),
        "endpoints": list(thread.endpoints),
        "origins": list(thread.origins),
        "evidence_ids": list(thread.evidence_ids),
        "why_review": thread.why_review,
        "next_review_step": thread.next_review_step,
        "facts": [_fact_to_dict(item) for item in thread.facts],
        "conflicts": [_conflict_to_dict(item) for item in thread.conflicts],
        "coverage_limitations": [
            _coverage_limitation_to_dict(item)
            for item in thread.coverage_limitations
        ],
        "source_rankings": [
            _source_ranking_to_dict(item) for item in thread.source_rankings
        ],
        "legacy_context": [
            {"kind": item.kind.value, "text": item.text}
            for item in thread.legacy_context
        ],
        "source_artefacts": list(thread.source_artefacts),
    }


def _disposition_to_dict(
    disposition: OperatorBriefDisposition,
) -> dict[str, object]:
    return {
        "source_kind": disposition.source_kind,
        "source_id": disposition.source_id,
        "disposition": disposition.disposition,
        "thread_id": disposition.thread_id,
        "reason_code": disposition.reason_code.value,
        "represented_fact_ids": list(disposition.represented_fact_ids),
    }


def _fact_to_dict(fact: OperatorBriefFact) -> dict[str, object]:
    return {
        "fact_id": fact.fact_id,
        "kind": fact.kind.value,
        "semantic_class": fact.semantic_class.value,
        "role": fact.role.value,
        "label": fact.label,
        "summary": fact.summary,
        "endpoints": list(fact.endpoints),
        "origins": list(fact.origins),
        "evidence_ids": list(fact.evidence_ids),
        "artefact_references": list(fact.artefact_references),
        "source_references": [
            {"source_kind": item.source_kind, "source_id": item.source_id}
            for item in fact.source_references
        ],
        "route": fact.route,
        "parameter_name": fact.parameter_name,
        "form_method": fact.form_method,
        "form_action": fact.form_action,
        "service": fact.service,
        "share_name": fact.share_name,
        "share_type": fact.share_type,
        "body_sha256": fact.body_sha256,
        "http_method": fact.http_method,
        "http_status_code": fact.http_status_code,
    }


def _conflict_to_dict(conflict: OperatorBriefConflict) -> dict[str, object]:
    return {
        "conflict_id": conflict.conflict_id,
        "kind": conflict.kind.value,
        "subject_endpoint": conflict.subject_endpoint,
        "observations": [
            {
                "observation_id": item.observation_id,
                "endpoint": item.endpoint,
                "method": item.method,
                "status_code": item.status_code,
                "collection_stage": item.collection_stage,
                "evidence_ids": list(item.evidence_ids),
                "artefact_references": list(item.artefact_references),
            }
            for item in conflict.observations
        ],
        "summary": conflict.summary,
    }


def _coverage_limitation_to_dict(
    limitation: OperatorBriefCoverageLimitation,
) -> dict[str, object]:
    return {
        "limitation_id": limitation.limitation_id,
        "capability": limitation.capability,
        "source_role": limitation.source_role,
        "source_id": limitation.source_id,
        "state": limitation.state.value,
        "outcome": limitation.outcome.value if limitation.outcome else None,
        "unknown_reason": (
            limitation.unknown_reason.value if limitation.unknown_reason else None
        ),
        "execution_note": (
            limitation.execution_note.value if limitation.execution_note else None
        ),
        "summary": limitation.summary,
    }


def _source_ranking_to_dict(
    ranking: OperatorBriefSourceRanking,
) -> dict[str, object]:
    return {
        "source_lead_id": ranking.source_lead_id,
        "rank": ranking.rank,
        "score": ranking.score,
        "signal": ranking.signal,
    }


def _thread_v2_from_dict(
    value: object,
    index: int,
) -> OperatorBriefThread:
    label = f"{OPERATOR_BRIEF_FILENAME} threads[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")

    try:
        return OperatorBriefThread(
            thread_id=_text_field(value, "thread_id", label),
            identity_key=_text_field(value, "identity_key", label),
            subject_kind=_enum_field(
                value, "subject_kind", label, OperatorBriefSubjectKind
            ),
            title=_text_field(value, "title", label),
            rank=_int_field(value, "rank", label),
            signal=_text_field(value, "signal", label),
            source_lead_ids=_text_tuple_field(
                value,
                "source_lead_ids",
                label,
            ),
            endpoints=_text_tuple_field(value, "endpoints", label),
            origins=_text_tuple_field(value, "origins", label),
            evidence_ids=_text_tuple_field(
                value,
                "evidence_ids",
                label,
            ),
            why_review=_text_field(value, "why_review", label),
            next_review_step=_text_field(
                value,
                "next_review_step",
                label,
            ),
            facts=tuple(
                _fact_from_dict(item, f"{label}.facts[{item_index}]")
                for item_index, item in enumerate(
                    _list_field(value, "facts", label)
                )
            ),
            conflicts=tuple(
                _conflict_from_dict(item, f"{label}.conflicts[{item_index}]")
                for item_index, item in enumerate(
                    _list_field(value, "conflicts", label)
                )
            ),
            coverage_limitations=tuple(
                _coverage_limitation_from_dict(
                    item, f"{label}.coverage_limitations[{item_index}]"
                )
                for item_index, item in enumerate(
                    _list_field(value, "coverage_limitations", label)
                )
            ),
            source_rankings=tuple(
                _source_ranking_from_dict(
                    item, f"{label}.source_rankings[{item_index}]"
                )
                for item_index, item in enumerate(
                    _list_field(value, "source_rankings", label)
                )
            ),
            legacy_context=tuple(
                _legacy_context_from_dict(
                    item, f"{label}.legacy_context[{item_index}]"
                )
                for item_index, item in enumerate(
                    _list_field(value, "legacy_context", label)
                )
            ),
            source_artefacts=_text_tuple_field(
                value,
                "source_artefacts",
                label,
            ),
        )
    except ValueError as exc:
        raise ValueError(f"{label} is invalid: {exc}") from exc


def _disposition_v2_from_dict(
    value: object,
    index: int,
) -> OperatorBriefDisposition:
    label = f"{OPERATOR_BRIEF_FILENAME} dispositions[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")

    try:
        return OperatorBriefDisposition(
            source_kind=_text_field(value, "source_kind", label),
            source_id=_text_field(value, "source_id", label),
            disposition=_text_field(value, "disposition", label),
            thread_id=_text_field(value, "thread_id", label),
            reason_code=_enum_field(
                value,
                "reason_code",
                label,
                OperatorBriefDispositionReason,
            ),
            represented_fact_ids=_text_tuple_field(
                value, "represented_fact_ids", label
            ),
        )
    except ValueError as exc:
        raise ValueError(f"{label} is invalid: {exc}") from exc


def _thread_v1_from_dict(value: object, index: int) -> OperatorBriefThread:
    label = f"{OPERATOR_BRIEF_FILENAME} threads[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    try:
        source_lead_ids = _text_tuple_field(value, "source_lead_ids", label)
        rank = _int_field(value, "rank", label)
        score = _int_field(value, "score", label)
        signal = _text_field(value, "signal", label)
        legacy_context = _legacy_context_from_v1(value, label)
        if len(source_lead_ids) != 1:
            legacy_context += (
                OperatorBriefLegacyContext(
                    kind=OperatorBriefLegacyContextKind.UNATTRIBUTED_SCORE_TEXT,
                    text=str(score),
                ),
            )
        return OperatorBriefThread(
            thread_id=_text_field(value, "thread_id", label),
            identity_key=(
                "legacy_canonical_lead:"
                + ("|".join(source_lead_ids) or _text_field(value, "thread_id", label))
            ),
            subject_kind=OperatorBriefSubjectKind.LEGACY_CANONICAL_LEAD,
            title=_text_field(value, "title", label),
            rank=rank,
            signal=signal,
            source_lead_ids=source_lead_ids,
            endpoints=_text_tuple_field(value, "endpoints", label),
            origins=(),
            evidence_ids=_text_tuple_field(value, "evidence_ids", label),
            why_review=_text_field(value, "why_review", label),
            next_review_step=_text_field(value, "next_review_step", label),
            facts=(),
            conflicts=(),
            coverage_limitations=(),
            source_rankings=(
                (
                    OperatorBriefSourceRanking(
                        source_lead_id=source_lead_ids[0],
                        rank=rank,
                        score=score,
                        signal=signal,
                    ),
                )
                if len(source_lead_ids) == 1
                else ()
            ),
            legacy_context=legacy_context,
            source_artefacts=_text_tuple_field(value, "source_artefacts", label),
        )
    except ValueError as exc:
        raise ValueError(f"{label} is invalid: {exc}") from exc


def _disposition_v1_from_dict(
    value: object,
    index: int,
) -> OperatorBriefDisposition:
    label = f"{OPERATOR_BRIEF_FILENAME} dispositions[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    try:
        return OperatorBriefDisposition(
            source_kind=_text_field(value, "source_kind", label),
            source_id=_text_field(value, "source_id", label),
            disposition=_text_field(value, "disposition", label),
            thread_id=_text_field(value, "thread_id", label),
            reason_code=OperatorBriefDispositionReason.LEGACY_PROJECTION,
            represented_fact_ids=(),
        )
    except ValueError as exc:
        raise ValueError(f"{label} is invalid: {exc}") from exc


def _fact_from_dict(value: object, label: str) -> OperatorBriefFact:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return OperatorBriefFact(
        fact_id=_text_field(value, "fact_id", label),
        kind=_enum_field(value, "kind", label, OperatorBriefFactKind),
        semantic_class=_enum_field(
            value, "semantic_class", label, OperatorBriefSemanticClass
        ),
        role=_enum_field(value, "role", label, OperatorBriefFactRole),
        label=_text_field(value, "label", label),
        summary=_text_field(value, "summary", label),
        endpoints=_text_tuple_field(value, "endpoints", label),
        origins=_text_tuple_field(value, "origins", label),
        evidence_ids=_text_tuple_field(value, "evidence_ids", label),
        artefact_references=_text_tuple_field(
            value, "artefact_references", label
        ),
        source_references=tuple(
            _source_reference_from_dict(
                item, f"{label}.source_references[{item_index}]"
            )
            for item_index, item in enumerate(
                _list_field(value, "source_references", label)
            )
        ),
        route=_text_field(value, "route", label),
        parameter_name=_text_field(value, "parameter_name", label),
        form_method=_text_field(value, "form_method", label),
        form_action=_text_field(value, "form_action", label),
        service=_text_field(value, "service", label),
        share_name=_text_field(value, "share_name", label),
        share_type=_text_field(value, "share_type", label),
        body_sha256=_text_field(value, "body_sha256", label),
        http_method=_optional_text_field(value, "http_method", label, default=""),
        http_status_code=_optional_int_field(value, "http_status_code", label),
    )


def _source_reference_from_dict(
    value: object,
    label: str,
) -> OperatorBriefSourceReference:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return OperatorBriefSourceReference(
        source_kind=_text_field(value, "source_kind", label),
        source_id=_text_field(value, "source_id", label),
    )


def _conflict_from_dict(value: object, label: str) -> OperatorBriefConflict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return OperatorBriefConflict(
        conflict_id=_text_field(value, "conflict_id", label),
        kind=_enum_field(value, "kind", label, OperatorBriefConflictKind),
        subject_endpoint=_text_field(value, "subject_endpoint", label),
        observations=tuple(
            _conflict_observation_from_dict(
                item, f"{label}.observations[{item_index}]"
            )
            for item_index, item in enumerate(
                _list_field(value, "observations", label)
            )
        ),
        summary=_text_field(value, "summary", label),
    )


def _conflict_observation_from_dict(
    value: object,
    label: str,
) -> OperatorBriefConflictObservation:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return OperatorBriefConflictObservation(
        observation_id=_text_field(value, "observation_id", label),
        endpoint=_text_field(value, "endpoint", label),
        method=_text_field(value, "method", label),
        status_code=_int_field(value, "status_code", label),
        collection_stage=_text_field(value, "collection_stage", label),
        evidence_ids=_text_tuple_field(value, "evidence_ids", label),
        artefact_references=_text_tuple_field(
            value, "artefact_references", label
        ),
    )


def _coverage_limitation_from_dict(
    value: object,
    label: str,
) -> OperatorBriefCoverageLimitation:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return OperatorBriefCoverageLimitation(
        limitation_id=_text_field(value, "limitation_id", label),
        capability=_text_field(value, "capability", label),
        source_role=_text_field(value, "source_role", label),
        source_id=_text_field(value, "source_id", label),
        state=_enum_field(value, "state", label, AnalysisCoverageState),
        outcome=_optional_enum_field(
            value, "outcome", label, AnalysisCoverageOutcome
        ),
        unknown_reason=_optional_enum_field(
            value, "unknown_reason", label, AnalysisCoverageUnknownReason
        ),
        execution_note=_optional_enum_field(
            value, "execution_note", label, AnalysisCoverageExecutionNote
        ),
        summary=_text_field(value, "summary", label),
    )


def _source_ranking_from_dict(
    value: object,
    label: str,
) -> OperatorBriefSourceRanking:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return OperatorBriefSourceRanking(
        source_lead_id=_text_field(value, "source_lead_id", label),
        rank=_int_field(value, "rank", label),
        score=_int_field(value, "score", label),
        signal=_text_field(value, "signal", label),
    )


def _legacy_context_from_dict(
    value: object,
    label: str,
) -> OperatorBriefLegacyContext:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return OperatorBriefLegacyContext(
        kind=_enum_field(value, "kind", label, OperatorBriefLegacyContextKind),
        text=_text_field(value, "text", label),
    )


def _legacy_context_from_v1(
    value: dict[str, object],
    label: str,
) -> tuple[OperatorBriefLegacyContext, ...]:
    mappings = (
        ("observed_facts", OperatorBriefLegacyContextKind.OBSERVED_FACT_TEXT),
        ("related_context", OperatorBriefLegacyContextKind.RELATED_CONTEXT_TEXT),
        ("conflicts", OperatorBriefLegacyContextKind.CONFLICT_TEXT),
        (
            "coverage_limitations",
            OperatorBriefLegacyContextKind.COVERAGE_LIMITATION_TEXT,
        ),
        ("unknowns", OperatorBriefLegacyContextKind.UNKNOWN_TEXT),
    )
    return tuple(
        OperatorBriefLegacyContext(kind=kind, text=text)
        for key, kind in mappings
        for text in _text_tuple_field(value, key, label)
    )


def _list_field(
    value: dict[str, object],
    key: str,
    label: str,
) -> list[object]:
    field = value.get(key)
    if not isinstance(field, list):
        raise ValueError(f"{label}.{key} must be a list")
    return field


def _enum_field(value, key, label, enum_type):
    field = _text_field(value, key, label)
    try:
        return enum_type(field)
    except ValueError as exc:
        raise ValueError(f"{label}.{key} is invalid") from exc


def _optional_enum_field(value, key, label, enum_type):
    field = value.get(key)
    if field is None:
        return None
    if not isinstance(field, str):
        raise ValueError(f"{label}.{key} must be text or null")
    try:
        return enum_type(field)
    except ValueError as exc:
        raise ValueError(f"{label}.{key} is invalid") from exc


def _text_field(
    value: dict[str, object],
    key: str,
    label: str,
) -> str:
    field = value.get(key)
    if not isinstance(field, str):
        raise ValueError(f"{label}.{key} must be text")
    return field


def _optional_text_field(
    value: dict[str, object],
    key: str,
    label: str,
    *,
    default: str,
) -> str:
    if key not in value:
        return default
    return _text_field(value, key, label)


def _int_field(
    value: dict[str, object],
    key: str,
    label: str,
) -> int:
    field = value.get(key)
    if isinstance(field, bool) or not isinstance(field, int):
        raise ValueError(f"{label}.{key} must be an integer")
    return field


def _optional_int_field(
    value: dict[str, object],
    key: str,
    label: str,
) -> int | None:
    if key not in value or value[key] is None:
        return None
    return _int_field(value, key, label)


def _text_tuple_field(
    value: dict[str, object],
    key: str,
    label: str,
) -> tuple[str, ...]:
    field = value.get(key)
    if not isinstance(field, list):
        raise ValueError(f"{label}.{key} must be a list")
    if any(not isinstance(item, str) for item in field):
        raise ValueError(f"{label}.{key} must contain text values")
    return tuple(field)


def retire_operator_brief_artifact(root: Path) -> None:
    """Remove a stale Operator Brief while refusing unsafe path types."""

    path = root / OPERATOR_BRIEF_FILENAME

    if path.is_symlink():
        raise ValueError(
            f"structured artefact must be a regular file: {OPERATOR_BRIEF_FILENAME}"
        )
    if not path.exists():
        return
    if not path.is_file():
        raise ValueError(
            f"structured artefact must be a regular file: {OPERATOR_BRIEF_FILENAME}"
        )

    path.unlink()
