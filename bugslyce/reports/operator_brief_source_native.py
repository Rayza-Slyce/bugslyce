"""Pure composition of source-native interpretations for Operator Brief policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import re
from urllib.parse import urlsplit

from bugslyce.core.models import HTTPArtifact
from bugslyce.recon.deep_http_fingerprint_summary import (
    DeepHttpFingerprintSummary,
    DeepHttpResponseFingerprint,
)
from bugslyce.recon.deep_response_similarity_review import (
    DeepResponseSimilarityGroup,
    DeepResponseSimilarityReview,
)
from bugslyce.recon.deep_source_route_collection_review import (
    DeepSourceRouteCollectionReviewSummary,
    DeepSourceRouteReviewLead,
)
from bugslyce.recon.deep_successful_content import (
    SuccessfulDeepContentReview,
    directory_listing_title,
)
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.reports.artifact_classifier import (
    LIKELY_SIGNAL,
    classify_encoded_artifact,
)
from bugslyce.reports.operator_brief import (
    OperatorBriefFact,
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSourceReference,
    OperatorBriefSubjectKind,
)
from bugslyce.reports.operator_brief_thread_policy import (
    OperatorBriefThreadEvidenceBasis,
    OperatorBriefThreadMateriality,
    OperatorBriefThreadPolicySubject,
    OperatorBriefThreadPolicySubjectReference,
    OperatorBriefThreadSpecificity,
)
from bugslyce.triage.workflow_leads import (
    WorkflowAccountObservation,
    WorkflowAccountRetention,
    WorkflowLead,
    WorkflowObjectReferenceRetention,
)


class OperatorBriefSourceNativeFamily(str, Enum):
    STRUCTURED_CONFIGURATION_BODY = "structured_configuration_body"
    STRUCTURED_JSON_ROUTES = "structured_json_routes"
    DIRECTORY_LISTING_RESPONSE = "directory_listing_response"
    DISTINCTIVE_ACCESS_BOUNDARY_RESPONSE = "distinctive_access_boundary_response"
    CREDENTIAL_LIKE_ARTIFACT_REVIEW = "credential_like_artifact_review"
    ACCOUNT_WORKFLOW = "account_workflow"
    OBJECT_REFERENCE_SURFACE = "object_reference_surface"
    ENCODED_OR_HIDDEN_ARTIFACT = "encoded_or_hidden_artifact"


class OperatorBriefAccessBoundarySignalKind(str, Enum):
    WWW_AUTHENTICATE = "www_authenticate"
    EXPLICIT_AUTHENTICATION_TITLE = "explicit_authentication_title"


class OperatorBriefCredentialIndicatorClass(str, Enum):
    SENSITIVE_ASSIGNMENT = "sensitive_assignment"


def _canonical_strings(values) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value.strip()
                for value in values
                if isinstance(value, str) and value.strip()
            }
        )
    )


def _ordered_strings(values) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        compact = value.strip()
        if compact and compact not in result:
            result.append(compact)
    return tuple(result)


def _canonical_url(value: str | None) -> str:
    compact = value.strip() if isinstance(value, str) else ""
    if not compact:
        return ""
    try:
        parsed = urlsplit(compact)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except (TypeError, ValueError):
        return ""
    if scheme not in {"http", "https"} or not hostname:
        return ""
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    authority = host if port in {None, default_port} else f"{host}:{port}"
    path = parsed.path or "/"
    return f"{scheme}://{authority}{path}"


def _canonical_urls(values) -> tuple[str, ...]:
    return _canonical_strings(
        canonical for value in values if (canonical := _canonical_url(value))
    )


def _origins(values: tuple[str, ...]) -> tuple[str, ...]:
    return _canonical_strings(
        origin.origin_url
        for value in values
        if (origin := http_origin_from_url(value)) is not None
    )


@dataclass(frozen=True)
class OperatorBriefStructuredDisclosureInterpretation:
    category: str
    source_url: str
    final_url: str
    body_sha256: str
    disclosed_routes: tuple[str, ...] = ()
    redacted_excerpt_lines: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_url", _canonical_url(self.source_url))
        object.__setattr__(self, "final_url", _canonical_url(self.final_url))
        object.__setattr__(self, "disclosed_routes", _canonical_strings(self.disclosed_routes))
        object.__setattr__(
            self,
            "redacted_excerpt_lines",
            _ordered_strings(self.redacted_excerpt_lines),
        )


@dataclass(frozen=True)
class OperatorBriefDirectoryListingInterpretation:
    canonical_url: str
    requested_urls: tuple[str, ...]
    status_code: int
    content_type: str | None
    body_sha256: str
    listing_path: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "canonical_url", _canonical_url(self.canonical_url))
        object.__setattr__(self, "requested_urls", _canonical_urls(self.requested_urls))


@dataclass(frozen=True)
class OperatorBriefAccessBoundaryInterpretation:
    fingerprint_id: str
    requested_url: str
    final_url: str
    method: str
    status_code: int
    body_sha256: str
    signal_kinds: tuple[OperatorBriefAccessBoundarySignalKind, ...]
    contrast_category: str
    comparison_endpoints: tuple[str, ...]
    comparison_statuses: tuple[int, ...]
    member_count: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "requested_url", _canonical_url(self.requested_url))
        object.__setattr__(self, "final_url", _canonical_url(self.final_url))
        object.__setattr__(self, "method", self.method.strip().upper())
        object.__setattr__(
            self,
            "signal_kinds",
            tuple(sorted(set(self.signal_kinds), key=lambda item: item.value)),
        )
        object.__setattr__(
            self,
            "comparison_endpoints",
            _canonical_urls(self.comparison_endpoints),
        )
        object.__setattr__(
            self,
            "comparison_statuses",
            tuple(sorted(set(self.comparison_statuses))),
        )


@dataclass(frozen=True)
class OperatorBriefCredentialInterpretation:
    source_url: str
    artefact_types: tuple[str, ...]
    assignment_labels: tuple[str, ...]
    indicator_classes: tuple[OperatorBriefCredentialIndicatorClass, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_url", _canonical_url(self.source_url))
        object.__setattr__(self, "artefact_types", _canonical_strings(self.artefact_types))
        object.__setattr__(
            self,
            "assignment_labels",
            _canonical_strings(self.assignment_labels),
        )
        object.__setattr__(
            self,
            "indicator_classes",
            tuple(sorted(set(self.indicator_classes), key=lambda item: item.value)),
        )


@dataclass(frozen=True)
class OperatorBriefAccountWorkflowInterpretation:
    origin: str
    covered_urls: tuple[str, ...]
    observations: tuple[WorkflowAccountObservation, ...]

    def __post_init__(self) -> None:
        retention = WorkflowAccountRetention(self.origin, self.observations)
        object.__setattr__(self, "origin", retention.origin)
        object.__setattr__(self, "covered_urls", _canonical_urls(self.covered_urls))
        object.__setattr__(self, "observations", retention.observations)


@dataclass(frozen=True)
class OperatorBriefObjectReferenceInterpretation:
    origin: str
    covered_urls: tuple[str, ...]
    parameter_names: tuple[str, ...]

    def __post_init__(self) -> None:
        retention = WorkflowObjectReferenceRetention(self.origin, self.parameter_names)
        object.__setattr__(self, "origin", retention.origin)
        object.__setattr__(self, "covered_urls", _canonical_urls(self.covered_urls))
        object.__setattr__(self, "parameter_names", retention.parameter_names)


@dataclass(frozen=True)
class OperatorBriefEncodedArtifactInterpretation:
    classification_category: str
    source_url: str
    artefact_type: str
    value_sha256: str
    value_length: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_url", _canonical_url(self.source_url))


OperatorBriefSourceNativeInterpretation = (
    OperatorBriefStructuredDisclosureInterpretation
    | OperatorBriefDirectoryListingInterpretation
    | OperatorBriefAccessBoundaryInterpretation
    | OperatorBriefCredentialInterpretation
    | OperatorBriefAccountWorkflowInterpretation
    | OperatorBriefObjectReferenceInterpretation
    | OperatorBriefEncodedArtifactInterpretation
)


@dataclass(frozen=True)
class OperatorBriefSourceNativeSubject:
    subject_id: str
    family: OperatorBriefSourceNativeFamily
    policy_subject: OperatorBriefThreadPolicySubject
    endpoints: tuple[str, ...]
    origins: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]
    interpretation: OperatorBriefSourceNativeInterpretation

    def __post_init__(self) -> None:
        object.__setattr__(self, "endpoints", _canonical_urls(self.endpoints))
        object.__setattr__(self, "origins", _canonical_strings(self.origins))
        object.__setattr__(self, "evidence_ids", _canonical_strings(self.evidence_ids))
        object.__setattr__(
            self,
            "artefact_references",
            _canonical_strings(self.artefact_references),
        )
        object.__setattr__(
            self,
            "source_references",
            tuple(sorted(set(self.source_references))),
        )


@dataclass(frozen=True)
class OperatorBriefSourceNativeComposition:
    subjects: tuple[OperatorBriefSourceNativeSubject, ...]

    def __post_init__(self) -> None:
        if any(not isinstance(item, OperatorBriefSourceNativeSubject) for item in self.subjects):
            raise ValueError("Source-native composition subjects are invalid.")
        policy_keys = [item.policy_subject.policy_key for item in self.subjects]
        semantic_keys = [item.policy_subject.semantic_subject_key for item in self.subjects]
        if len(set(policy_keys)) != len(policy_keys):
            raise ValueError("Source-native composition contains duplicate policy keys.")
        if len(set(semantic_keys)) != len(semantic_keys):
            raise ValueError("Source-native composition contains duplicate semantic identities.")
        object.__setattr__(
            self,
            "subjects",
            tuple(sorted(self.subjects, key=lambda item: item.policy_subject.policy_key)),
        )

    @property
    def policy_subjects(self) -> tuple[OperatorBriefThreadPolicySubject, ...]:
        return tuple(item.policy_subject for item in self.subjects)


@dataclass(frozen=True)
class _SourceRecord:
    family: OperatorBriefSourceNativeFamily
    subject_kind: OperatorBriefSubjectKind
    identity_payload: object
    endpoints: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    artefact_references: tuple[str, ...]
    source_references: tuple[OperatorBriefSourceReference, ...]
    interpretation: OperatorBriefSourceNativeInterpretation
    matcher: str = "none"
    match_routes: tuple[str, ...] = ()
    match_body_sha256: str = ""
    match_status: int | None = None
    match_source_reference: OperatorBriefSourceReference | None = None


_FAMILY_KINDS = {
    OperatorBriefSourceNativeFamily.STRUCTURED_CONFIGURATION_BODY:
        OperatorBriefSubjectKind.CONTENT_SURFACE,
    OperatorBriefSourceNativeFamily.STRUCTURED_JSON_ROUTES:
        OperatorBriefSubjectKind.CONTENT_SURFACE,
    OperatorBriefSourceNativeFamily.DIRECTORY_LISTING_RESPONSE:
        OperatorBriefSubjectKind.CONTENT_SURFACE,
    OperatorBriefSourceNativeFamily.DISTINCTIVE_ACCESS_BOUNDARY_RESPONSE:
        OperatorBriefSubjectKind.CONTENT_SURFACE,
    OperatorBriefSourceNativeFamily.CREDENTIAL_LIKE_ARTIFACT_REVIEW:
        OperatorBriefSubjectKind.CONTENT_SURFACE,
    OperatorBriefSourceNativeFamily.ACCOUNT_WORKFLOW:
        OperatorBriefSubjectKind.ACCOUNT_WORKFLOW,
    OperatorBriefSourceNativeFamily.OBJECT_REFERENCE_SURFACE:
        OperatorBriefSubjectKind.CONTENT_SURFACE,
    OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT:
        OperatorBriefSubjectKind.CONTENT_SURFACE,
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _identity_digest(family: OperatorBriefSourceNativeFamily, payload: object) -> str:
    value = {"family": family.value, "identity": payload}
    return sha256(_canonical_json(value).encode("utf-8")).hexdigest()[:16]


def _policy_key(subject_kind: OperatorBriefSubjectKind, semantic_key: str) -> str:
    payload = {
        "semantic_subject_key": semantic_key,
        "subject_kind": subject_kind.value,
    }
    digest = sha256(_canonical_json(payload).encode("utf-8")).hexdigest()[:16]
    return f"POLICY-{digest.upper()}"


def _direct_http_facts(subject: OperatorBriefThreadPolicySubject) -> tuple[OperatorBriefFact, ...]:
    return tuple(
        fact
        for fact in subject.facts
        if fact.kind is OperatorBriefFactKind.HTTP_RESPONSE
        and fact.role is OperatorBriefFactRole.DIRECT_EVIDENCE
    )


def _fact_locators(fact: OperatorBriefFact) -> frozenset[str]:
    return frozenset(value for value in (fact.route, *fact.endpoints) if value)


def _application_matches(
    record: _SourceRecord,
    subject: OperatorBriefThreadPolicySubject,
) -> bool:
    facts = _direct_http_facts(subject)
    if record.matcher == "route_hash":
        routes = set(record.match_routes)
        return any(
            bool(routes & _fact_locators(fact))
            and fact.body_sha256 == record.match_body_sha256
            for fact in facts
        )
    if record.matcher == "listing":
        routes = set(record.match_routes)
        return any(
            bool(routes & _fact_locators(fact))
            and fact.body_sha256 == record.match_body_sha256
            and fact.http_status_code == record.match_status
            for fact in facts
        )
    if record.matcher == "source_reference":
        reference = record.match_source_reference
        return reference is not None and any(
            reference in fact.source_references for fact in subject.facts
            if fact.role is OperatorBriefFactRole.DIRECT_EVIDENCE
        )
    if record.matcher == "endpoint":
        routes = set(record.match_routes)
        return any(bool(routes & _fact_locators(fact)) for fact in facts)
    return False


def _subject_from_record(
    record: _SourceRecord,
    normalized_policy_subjects: tuple[OperatorBriefThreadPolicySubject, ...],
) -> OperatorBriefSourceNativeSubject:
    digest = _identity_digest(record.family, record.identity_payload)
    semantic_key = f"source-native:{record.family.value}:{digest}"
    matching = tuple(
        subject
        for subject in normalized_policy_subjects
        if subject.subject_kind is OperatorBriefSubjectKind.APPLICATION
        and subject.semantic_subject_key is not None
        and _application_matches(record, subject)
    )
    association = None
    if len(matching) == 1:
        association = OperatorBriefThreadPolicySubjectReference(
            subject_kind=OperatorBriefSubjectKind.APPLICATION,
            semantic_subject_key=matching[0].semantic_subject_key,
        )
    associated = association is not None
    policy_subject = OperatorBriefThreadPolicySubject(
        policy_key=_policy_key(record.subject_kind, semantic_key),
        semantic_subject_key=semantic_key,
        subject_kind=record.subject_kind,
        materiality=(
            OperatorBriefThreadMateriality.CONTEXT
            if associated
            else OperatorBriefThreadMateriality.MATERIAL
        ),
        specificity=OperatorBriefThreadSpecificity.SPECIFIC,
        evidence_basis=OperatorBriefThreadEvidenceBasis.LEGACY,
        independent=not associated,
        associated_subject_reference=association,
    )
    endpoints = _canonical_urls(record.endpoints)
    return OperatorBriefSourceNativeSubject(
        subject_id=f"SOURCE-NATIVE-{digest.upper()}",
        family=record.family,
        policy_subject=policy_subject,
        endpoints=endpoints,
        origins=_origins(endpoints),
        evidence_ids=record.evidence_ids,
        artefact_references=record.artefact_references,
        source_references=record.source_references,
        interpretation=record.interpretation,
    )


def _disclosure_records(
    summary: DeepSourceRouteCollectionReviewSummary,
) -> tuple[_SourceRecord, ...]:
    admitted = {
        "structured_configuration_body":
            OperatorBriefSourceNativeFamily.STRUCTURED_CONFIGURATION_BODY,
        "structured_json_routes":
            OperatorBriefSourceNativeFamily.STRUCTURED_JSON_ROUTES,
    }
    grouped: dict[str, list[DeepSourceRouteReviewLead]] = {}
    details: dict[str, tuple[OperatorBriefSourceNativeFamily, str, str, str]] = {}
    for lead in summary.review_leads:
        family = admitted.get(lead.category)
        if family is None:
            continue
        if len(lead.urls) != 1 or len(lead.final_urls) != 1 or not lead.source_body_sha256:
            raise ValueError("Structured disclosure authority requires one source and final URL.")
        source_url = _canonical_url(lead.urls[0])
        final_url = _canonical_url(lead.final_urls[0])
        if not source_url or not final_url:
            raise ValueError("Structured disclosure authority contains an invalid URL.")
        identity = {
            "category": lead.category,
            "source_url": source_url,
            "final_url": final_url,
            "body_sha256": lead.source_body_sha256,
        }
        key = _canonical_json({"family": family.value, **identity})
        grouped.setdefault(key, []).append(lead)
        details[key] = (family, source_url, final_url, lead.source_body_sha256)

    records = []
    for key in sorted(grouped):
        leads = sorted(
            grouped[key],
            key=lambda item: (
                item.observed_values,
                item.evidence_excerpt,
                item.evidence_ids,
            ),
        )
        family, source_url, final_url, body_sha = details[key]
        routes = _canonical_strings(
            value for lead in leads for value in lead.observed_values
        )
        excerpts = _ordered_strings(
            value for lead in leads for value in lead.evidence_excerpt
        )
        evidence_ids = _canonical_strings(
            value for lead in leads for value in lead.evidence_ids
        )
        interpretation = OperatorBriefStructuredDisclosureInterpretation(
            category=family.value,
            source_url=source_url,
            final_url=final_url,
            body_sha256=body_sha,
            disclosed_routes=routes,
            redacted_excerpt_lines=excerpts,
        )
        records.append(
            _SourceRecord(
                family=family,
                subject_kind=_FAMILY_KINDS[family],
                identity_payload={
                    "category": family.value,
                    "source_url": source_url,
                    "final_url": final_url,
                    "body_sha256": body_sha,
                },
                endpoints=(source_url, final_url),
                evidence_ids=evidence_ids,
                artefact_references=(),
                source_references=(),
                interpretation=interpretation,
                matcher="route_hash",
                match_routes=(source_url, final_url),
                match_body_sha256=body_sha,
            )
        )
    return tuple(records)


def _listing_path(review: SuccessfulDeepContentReview) -> str:
    path = urlsplit(review.canonical_url).path or "/"
    return path.rstrip("/") or "/"


def _listing_records(
    reviews: tuple[SuccessfulDeepContentReview, ...],
) -> tuple[_SourceRecord, ...]:
    grouped: dict[str, list[SuccessfulDeepContentReview]] = {}
    details: dict[str, tuple[str, tuple[str, ...], int, str]] = {}
    for review in reviews:
        if directory_listing_title(review) is None:
            continue
        canonical_url = _canonical_url(review.canonical_url)
        requested_urls = _canonical_urls(review.requested_urls)
        identity = {
            "canonical_url": canonical_url,
            "requested_urls": requested_urls,
            "status_code": review.status_code,
            "body_sha256": review.body_sha256,
        }
        key = _canonical_json(identity)
        grouped.setdefault(key, []).append(review)
        details[key] = (
            canonical_url,
            requested_urls,
            review.status_code,
            review.body_sha256,
        )
    family = OperatorBriefSourceNativeFamily.DIRECTORY_LISTING_RESPONSE
    records = []
    for key in sorted(grouped):
        items = grouped[key]
        canonical_url, requested_urls, status, body_sha = details[key]
        representative = min(
            items,
            key=lambda item: (item.content_type or "", item.review_id),
        )
        endpoints = _canonical_urls((canonical_url, *requested_urls))
        records.append(
            _SourceRecord(
                family=family,
                subject_kind=_FAMILY_KINDS[family],
                identity_payload=json.loads(key),
                endpoints=endpoints,
                evidence_ids=_canonical_strings(
                    value for item in items for value in item.evidence_ids
                ),
                artefact_references=_canonical_strings(
                    value for item in items for value in item.artefact_references
                ),
                source_references=(),
                interpretation=OperatorBriefDirectoryListingInterpretation(
                    canonical_url=canonical_url,
                    requested_urls=requested_urls,
                    status_code=status,
                    content_type=representative.content_type,
                    body_sha256=body_sha,
                    listing_path=_listing_path(representative),
                ),
                matcher="listing",
                match_routes=endpoints,
                match_body_sha256=body_sha,
                match_status=status,
            )
        )
    return tuple(records)


_AUTH_TITLE_PHRASES = (
    "authorization header",
    "authorisation header",
    "authentication required",
    "authentication failed",
    "not authenticated",
    "credentials required",
    "credential required",
    "token required",
    "token missing",
    "missing token",
    "login required",
    "sign in required",
    "permission denied",
    "insufficient permission",
    "insufficient privilege",
    "not authorised",
    "not authorized",
)


def _access_signal_kinds(
    fingerprint: DeepHttpResponseFingerprint,
) -> tuple[OperatorBriefAccessBoundarySignalKind, ...]:
    values = []
    if any(
        header.name.strip().casefold() == "www-authenticate"
        for header in fingerprint.interesting_headers
    ):
        values.append(OperatorBriefAccessBoundarySignalKind.WWW_AUTHENTICATE)
    title = (fingerprint.title_observed_in_bounded_preview or "").casefold()
    if any(phrase in title for phrase in _AUTH_TITLE_PHRASES):
        values.append(
            OperatorBriefAccessBoundarySignalKind.EXPLICIT_AUTHENTICATION_TITLE
        )
    return tuple(values)


def _access_group(
    fingerprint: DeepHttpResponseFingerprint,
    groups: tuple[DeepResponseSimilarityGroup, ...],
) -> DeepResponseSimilarityGroup | None:
    explicit = [
        group for group in groups if fingerprint.fingerprint_id in group.fingerprint_ids
    ]
    if explicit:
        return min(explicit, key=lambda item: (-item.member_count, item.category, item.group_id))
    origin = http_origin_from_url(fingerprint.requested_url)
    eligible_categories = {
        "exact_body_hash_group",
        "request_reflecting_template_group",
        "candidate_default_template_group",
        "client_error_signature_group",
        "response_signature_group",
    }
    eligible = [
        group
        for group in groups
        if origin is not None
        and group.category in eligible_categories
        and group.member_count >= 3
        and fingerprint.status_code not in group.status_codes
        and len(
            {
                url
                for url in group.requested_urls
                if http_origin_from_url(url) == origin
            }
        )
        >= 3
    ]
    return (
        min(eligible, key=lambda item: (-item.member_count, item.category, item.group_id))
        if eligible
        else None
    )


def _access_records(
    summary: DeepHttpFingerprintSummary,
    review: DeepResponseSimilarityReview,
) -> tuple[_SourceRecord, ...]:
    family = OperatorBriefSourceNativeFamily.DISTINCTIVE_ACCESS_BOUNDARY_RESPONSE
    records = []
    for fingerprint in sorted(summary.fingerprints, key=lambda item: item.fingerprint_id):
        signals = _access_signal_kinds(fingerprint)
        group = _access_group(fingerprint, review.groups)
        if (
            fingerprint.status_code not in {401, 403}
            or not fingerprint.evidence_ids
            or fingerprint.body_empty
            or not signals
            or group is None
        ):
            continue
        requested_url = _canonical_url(fingerprint.requested_url)
        final_url = _canonical_url(fingerprint.final_url)
        identity = {
            "requested_url": requested_url,
            "final_url": final_url,
            "method": fingerprint.method.strip().upper(),
            "status_code": fingerprint.status_code,
            "body_sha256": fingerprint.body_sha256,
        }
        source_reference = OperatorBriefSourceReference(
            source_kind="deep_http_fingerprint",
            source_id=fingerprint.fingerprint_id,
        )
        endpoints = _canonical_urls((requested_url, final_url))
        records.append(
            _SourceRecord(
                family=family,
                subject_kind=_FAMILY_KINDS[family],
                identity_payload=identity,
                endpoints=endpoints,
                evidence_ids=_canonical_strings(
                    (*fingerprint.evidence_ids, *group.evidence_ids)
                ),
                artefact_references=(),
                source_references=(source_reference,),
                interpretation=OperatorBriefAccessBoundaryInterpretation(
                    fingerprint_id=fingerprint.fingerprint_id,
                    requested_url=requested_url,
                    final_url=final_url,
                    method=fingerprint.method,
                    status_code=fingerprint.status_code,
                    body_sha256=fingerprint.body_sha256,
                    signal_kinds=signals,
                    contrast_category=group.category,
                    comparison_endpoints=group.requested_urls,
                    comparison_statuses=group.status_codes,
                    member_count=group.member_count,
                ),
                matcher="source_reference",
                match_source_reference=source_reference,
            )
        )
    return tuple(records)


_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<label>"
    r"api[_ -]?key|database[_ -]?(?:user|password)|db[_ -]?(?:user|password)|"
    r"password|passwd|pwd|secret|token|username|user"
    r")\b\s*[:=]\s*['\"]?(?P<value>[A-Za-z0-9._~+/=-]{3,})"
)
_SECRET_LABELS = {
    "api_key",
    "db_password",
    "database_password",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
}
_USERNAME_LABELS = {"user", "username", "db_user", "database_user"}
_SUPPORTING_KEYWORDS = {"password", "secret"}


def _assignment_labels(artifact: HTTPArtifact) -> tuple[str, ...]:
    if artifact.artifact_type != "html_comment":
        return ()
    labels = []
    for match in _ASSIGNMENT.finditer(artifact.value):
        label = re.sub(r"[^a-z0-9]+", "_", match.group("label").lower()).strip("_")
        value = match.group("value").strip("'\"")
        if label in _SECRET_LABELS and len(value) >= 10:
            labels.append(label)
        elif (
            label in _USERNAME_LABELS
            and 4 <= len(value) <= 64
            and re.fullmatch(r"[A-Za-z0-9._-]+", value)
        ):
            labels.append(label)
    return _canonical_strings(labels)


def _credential_records(artifacts: tuple[HTTPArtifact, ...]) -> tuple[_SourceRecord, ...]:
    all_by_url: dict[str, list[HTTPArtifact]] = {}
    qualifying: dict[str, list[tuple[HTTPArtifact, tuple[str, ...]]]] = {}
    for artifact in artifacts:
        source_url = _canonical_url(artifact.url)
        if not source_url:
            continue
        all_by_url.setdefault(source_url, []).append(artifact)
        labels = _assignment_labels(artifact)
        if labels and artifact.evidence_ids:
            qualifying.setdefault(source_url, []).append((artifact, labels))
    family = OperatorBriefSourceNativeFamily.CREDENTIAL_LIKE_ARTIFACT_REVIEW
    records = []
    for source_url in sorted(qualifying):
        primary = qualifying[source_url]
        supporting = [
            artifact
            for artifact in all_by_url[source_url]
            if artifact.artifact_type == "keyword_hit"
            and artifact.value.strip().casefold() in _SUPPORTING_KEYWORDS
            and artifact.evidence_ids
        ]
        grouped_artifacts = [artifact for artifact, _labels in primary] + supporting
        labels = _canonical_strings(
            label for _artifact, item_labels in primary for label in item_labels
        )
        records.append(
            _SourceRecord(
                family=family,
                subject_kind=_FAMILY_KINDS[family],
                identity_payload={"category": family.value, "source_url": source_url},
                endpoints=(source_url,),
                evidence_ids=_canonical_strings(
                    value
                    for artifact in grouped_artifacts
                    for value in artifact.evidence_ids
                ),
                artefact_references=_canonical_strings(
                    artifact.source_file for artifact in grouped_artifacts
                ),
                source_references=(),
                interpretation=OperatorBriefCredentialInterpretation(
                    source_url=source_url,
                    artefact_types=_canonical_strings(
                        artifact.artifact_type for artifact in grouped_artifacts
                    ),
                    assignment_labels=labels,
                    indicator_classes=(
                        OperatorBriefCredentialIndicatorClass.SENSITIVE_ASSIGNMENT,
                    ),
                ),
                matcher="endpoint",
                match_routes=(source_url,),
            )
        )
    return tuple(records)


def _observation_identity(observation: WorkflowAccountObservation) -> tuple[object, ...]:
    return (
        observation.kind,
        observation.url,
        observation.redirect_target_url,
        observation.methods,
        observation.field_names,
    )


def _account_records(leads: tuple[WorkflowLead, ...]) -> tuple[_SourceRecord, ...]:
    grouped: dict[str, list[WorkflowLead]] = {}
    for lead in leads:
        if lead.category == "account_workflow" and isinstance(
            lead.retention, WorkflowAccountRetention
        ):
            grouped.setdefault(lead.retention.origin, []).append(lead)
    family = OperatorBriefSourceNativeFamily.ACCOUNT_WORKFLOW
    records = []
    for origin in sorted(grouped):
        items = grouped[origin]
        observations: dict[tuple[object, ...], list[WorkflowAccountObservation]] = {}
        for lead in items:
            assert isinstance(lead.retention, WorkflowAccountRetention)
            for observation in lead.retention.observations:
                observations.setdefault(_observation_identity(observation), []).append(
                    observation
                )
        merged_observations = []
        for key in sorted(observations, key=lambda value: tuple(str(item) for item in value)):
            values = observations[key]
            representative = values[0]
            merged_observations.append(
                WorkflowAccountObservation(
                    kind=representative.kind,
                    url=representative.url,
                    evidence_ids=_canonical_strings(
                        evidence_id
                        for item in values
                        for evidence_id in item.evidence_ids
                    ),
                    methods=representative.methods,
                    field_names=representative.field_names,
                    redirect_target_url=representative.redirect_target_url,
                )
            )
        covered_urls = _canonical_urls(
            value for lead in items for value in lead.covered_urls
        )
        records.append(
            _SourceRecord(
                family=family,
                subject_kind=_FAMILY_KINDS[family],
                identity_payload={"category": family.value, "origin": origin},
                endpoints=covered_urls,
                evidence_ids=_canonical_strings(
                    value for lead in items for value in lead.evidence_ids
                ),
                artefact_references=(),
                source_references=(),
                interpretation=OperatorBriefAccountWorkflowInterpretation(
                    origin=origin,
                    covered_urls=covered_urls,
                    observations=tuple(merged_observations),
                ),
            )
        )
    return tuple(records)


def _object_records(leads: tuple[WorkflowLead, ...]) -> tuple[_SourceRecord, ...]:
    grouped: dict[str, list[WorkflowLead]] = {}
    for lead in leads:
        if lead.category == "object_reference_surface" and isinstance(
            lead.retention, WorkflowObjectReferenceRetention
        ):
            grouped.setdefault(lead.retention.origin, []).append(lead)
    family = OperatorBriefSourceNativeFamily.OBJECT_REFERENCE_SURFACE
    records = []
    for origin in sorted(grouped):
        items = grouped[origin]
        covered_urls = _canonical_urls(
            value for lead in items for value in lead.covered_urls
        )
        parameter_names = _canonical_strings(
            name
            for lead in items
            if isinstance(lead.retention, WorkflowObjectReferenceRetention)
            for name in lead.retention.parameter_names
        )
        records.append(
            _SourceRecord(
                family=family,
                subject_kind=_FAMILY_KINDS[family],
                identity_payload={"category": family.value, "origin": origin},
                endpoints=covered_urls,
                evidence_ids=_canonical_strings(
                    value for lead in items for value in lead.evidence_ids
                ),
                artefact_references=(),
                source_references=(),
                interpretation=OperatorBriefObjectReferenceInterpretation(
                    origin=origin,
                    covered_urls=covered_urls,
                    parameter_names=parameter_names,
                ),
            )
        )
    return tuple(records)


def _encoded_records(artifacts: tuple[HTTPArtifact, ...]) -> tuple[_SourceRecord, ...]:
    grouped: dict[str, list[HTTPArtifact]] = {}
    details: dict[str, tuple[str, str, str, str]] = {}
    for artifact in artifacts:
        classification = classify_encoded_artifact(artifact)
        if classification.category != LIKELY_SIGNAL:
            continue
        if (
            artifact.artifact_type not in {"encoded_like_artifact", "hidden_element"}
            and "encoded_or_hidden_artifact" not in artifact.tags
        ):
            continue
        source_url = _canonical_url(artifact.url)
        source_locator = source_url or artifact.source_file.strip()
        value_sha = sha256(artifact.value.encode("utf-8")).hexdigest()
        identity = {
            "source_locator": source_locator,
            "artefact_type": artifact.artifact_type,
            "value_sha256": value_sha,
        }
        key = _canonical_json(identity)
        grouped.setdefault(key, []).append(artifact)
        details[key] = (
            source_url,
            source_locator,
            artifact.artifact_type,
            value_sha,
        )
    family = OperatorBriefSourceNativeFamily.ENCODED_OR_HIDDEN_ARTIFACT
    records = []
    for key in sorted(grouped):
        items = grouped[key]
        source_url, source_locator, artefact_type, value_sha = details[key]
        representative = min(items, key=lambda item: item.value)
        endpoints = (source_url,) if source_url else ()
        records.append(
            _SourceRecord(
                family=family,
                subject_kind=_FAMILY_KINDS[family],
                identity_payload={
                    "source_locator": source_locator,
                    "artefact_type": artefact_type,
                    "value_sha256": value_sha,
                },
                endpoints=endpoints,
                evidence_ids=_canonical_strings(
                    value for item in items for value in item.evidence_ids
                ),
                artefact_references=_canonical_strings(
                    item.source_file for item in items
                ),
                source_references=(),
                interpretation=OperatorBriefEncodedArtifactInterpretation(
                    classification_category=LIKELY_SIGNAL,
                    source_url=source_url,
                    artefact_type=artefact_type,
                    value_sha256=value_sha,
                    value_length=len(representative.value),
                ),
                matcher="endpoint" if source_url else "none",
                match_routes=endpoints,
            )
        )
    return tuple(records)


def compose_operator_brief_source_native(
    *,
    deep_source_route_review: DeepSourceRouteCollectionReviewSummary,
    successful_content_reviews: tuple[SuccessfulDeepContentReview, ...],
    deep_http_fingerprints: DeepHttpFingerprintSummary,
    deep_response_similarity: DeepResponseSimilarityReview,
    http_artifacts: tuple[HTTPArtifact, ...],
    workflow_leads: tuple[WorkflowLead, ...],
    normalized_policy_subjects: tuple[OperatorBriefThreadPolicySubject, ...],
) -> OperatorBriefSourceNativeComposition:
    """Compose typed source-native interpretations and their policy projections."""

    if not isinstance(deep_source_route_review, DeepSourceRouteCollectionReviewSummary):
        raise TypeError("deep_source_route_review has an invalid type.")
    if not isinstance(deep_http_fingerprints, DeepHttpFingerprintSummary):
        raise TypeError("deep_http_fingerprints has an invalid type.")
    if not isinstance(deep_response_similarity, DeepResponseSimilarityReview):
        raise TypeError("deep_response_similarity has an invalid type.")
    typed_tuples = (
        (successful_content_reviews, SuccessfulDeepContentReview, "successful_content_reviews"),
        (http_artifacts, HTTPArtifact, "http_artifacts"),
        (workflow_leads, WorkflowLead, "workflow_leads"),
        (
            normalized_policy_subjects,
            OperatorBriefThreadPolicySubject,
            "normalized_policy_subjects",
        ),
    )
    for values, item_type, name in typed_tuples:
        if not isinstance(values, tuple) or any(
            not isinstance(item, item_type) for item in values
        ):
            raise TypeError(f"{name} has an invalid type.")

    records = (
        *_disclosure_records(deep_source_route_review),
        *_listing_records(successful_content_reviews),
        *_access_records(deep_http_fingerprints, deep_response_similarity),
        *_credential_records(http_artifacts),
        *_account_records(workflow_leads),
        *_object_records(workflow_leads),
        *_encoded_records(http_artifacts),
    )
    subjects = tuple(
        _subject_from_record(record, normalized_policy_subjects)
        for record in records
    )
    return OperatorBriefSourceNativeComposition(subjects=subjects)
