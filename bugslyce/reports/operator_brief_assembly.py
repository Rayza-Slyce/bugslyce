"""Pure final Stage 5 composition of Operator Brief semantic owners."""

from __future__ import annotations

from dataclasses import dataclass

from bugslyce.reports.operator_brief_http import OperatorBriefHttpComposition
from bugslyce.reports.operator_brief_multi_family_assembly import (
    assemble_operator_brief_policy_subjects,
)
from bugslyce.reports.operator_brief_network import OperatorBriefNetworkComposition
from bugslyce.reports.operator_brief_source_native import (
    OperatorBriefSourceNativeComposition,
)
from bugslyce.reports.operator_brief_thread_policy import (
    OperatorBriefThreadPolicyResult,
    OperatorBriefThreadPolicySubject,
    apply_operator_brief_thread_policy,
)
from bugslyce.reports.operator_brief_web_context import (
    OperatorBriefWebContextComposition,
)


@dataclass(frozen=True)
class OperatorBriefComposition:
    """Original Stage 5 compositions and their closed thread-policy result."""

    http: OperatorBriefHttpComposition
    network: OperatorBriefNetworkComposition
    web_context: OperatorBriefWebContextComposition
    source_native: OperatorBriefSourceNativeComposition
    thread_policy_result: OperatorBriefThreadPolicyResult

    @property
    def policy_subjects(self) -> tuple[OperatorBriefThreadPolicySubject, ...]:
        """Expose the closed policy result's canonical subject tuple directly."""

        return self.thread_policy_result.subjects


def _cross_source_union(
    normalized_subjects: tuple[OperatorBriefThreadPolicySubject, ...],
    source_native_subjects: tuple[OperatorBriefThreadPolicySubject, ...],
) -> tuple[OperatorBriefThreadPolicySubject, ...]:
    normalized_keys = {item.policy_key for item in normalized_subjects}
    source_native_keys = {item.policy_key for item in source_native_subjects}
    if normalized_keys & source_native_keys:
        raise ValueError("Final Operator Brief assembly contains duplicate policy keys.")

    normalized_identities = {
        (item.subject_kind, item.semantic_subject_key)
        for item in normalized_subjects
        if item.semantic_subject_key is not None
    }
    source_native_identities = {
        (item.subject_kind, item.semantic_subject_key)
        for item in source_native_subjects
        if item.semantic_subject_key is not None
    }
    if normalized_identities & source_native_identities:
        raise ValueError(
            "Final Operator Brief assembly contains duplicate semantic identities."
        )

    return tuple(sorted((*normalized_subjects, *source_native_subjects), key=lambda item: item.policy_key))


def assemble_operator_brief(
    *,
    http: OperatorBriefHttpComposition,
    network: OperatorBriefNetworkComposition,
    web_context: OperatorBriefWebContextComposition,
    source_native: OperatorBriefSourceNativeComposition,
) -> OperatorBriefComposition:
    """Compose closed normalized, source-native, and policy owners without I/O."""

    if not isinstance(http, OperatorBriefHttpComposition):
        raise TypeError("Operator Brief assembly requires an HTTP composition.")
    if not isinstance(network, OperatorBriefNetworkComposition):
        raise TypeError("Operator Brief assembly requires a network composition.")
    if not isinstance(web_context, OperatorBriefWebContextComposition):
        raise TypeError("Operator Brief assembly requires a web-context composition.")
    if not isinstance(source_native, OperatorBriefSourceNativeComposition):
        raise TypeError("Operator Brief assembly requires a source-native composition.")

    normalized_subjects = assemble_operator_brief_policy_subjects(
        http=http,
        network=network,
        web_context=web_context,
    )
    subjects = _cross_source_union(normalized_subjects, source_native.policy_subjects)
    return OperatorBriefComposition(
        http=http,
        network=network,
        web_context=web_context,
        source_native=source_native,
        thread_policy_result=apply_operator_brief_thread_policy(subjects),
    )
