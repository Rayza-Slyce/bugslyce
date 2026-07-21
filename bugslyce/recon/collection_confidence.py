"""Deterministic collection-confidence notices from retained structured evidence."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import json
from pathlib import Path
import re

from bugslyce.core.models import ProjectState
from bugslyce.recon.deep_source_route_collection_export import (
    DEEP_SOURCE_ROUTE_COLLECTION_JSON,
    load_deep_source_route_collection_result,
)


INTENTIONALLY_BOUNDED = "intentionally_bounded"
PARTIAL_OR_DEGRADED = "partial_or_degraded"
FAILED = "failed"
SKIPPED_OR_UNAVAILABLE = "skipped_or_unavailable"
UNKNOWN_LEGACY_STATE = "unknown_legacy_state"

_CATEGORY_ORDER = {
    FAILED: 0,
    PARTIAL_OR_DEGRADED: 1,
    SKIPPED_OR_UNAVAILABLE: 2,
    INTENTIONALLY_BOUNDED: 3,
    UNKNOWN_LEGACY_STATE: 4,
}
_BOUNDED_CONTENT_PROFILES = (
    "deep-bounded-core",
    "standard-bounded-core",
    "lab-root-tiny",
)
_FOLLOWUP_CAP = re.compile(
    r"^Discovered-path follow-up capped at (?P<count>[1-9][0-9]*) URLs?\.$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CollectionConfidenceNotice:
    """One immutable evidence-led collection confidence statement."""

    notice_id: str
    category: str
    title: str
    direct_fact: str
    operator_implication: str
    stage_or_tool: str
    evidence_ids: tuple[str, ...] = ()
    artefact_references: tuple[str, ...] = ()
    counts: tuple[tuple[str, int], ...] = ()


def build_collection_confidence_notices(
    project_state: ProjectState,
    *,
    source_collection: object | None = None,
    pipeline_steps: Iterable[object] = (),
    command_results: Iterable[object] = (),
    legacy_status_unknown: bool = False,
) -> tuple[CollectionConfidenceNotice, ...]:
    """Build stable notices without inferring collection state from report prose."""

    notices: list[CollectionConfidenceNotice] = []
    content_notice = _bounded_content_notice(project_state)
    if content_notice is not None:
        notices.append(content_notice)
    deep_notice = _bounded_deep_notice(source_collection)
    if deep_notice is not None:
        notices.append(deep_notice)
    notices.extend(_structured_warning_notices(project_state))
    notices.extend(_pipeline_step_notices(pipeline_steps))
    notices.extend(_command_result_notices(command_results))
    if legacy_status_unknown:
        notices.append(
            CollectionConfidenceNotice(
                notice_id="CONFIDENCE-UNKNOWN-LEGACY",
                category=UNKNOWN_LEGACY_STATE,
                title="Collection status is unknown for legacy evidence",
                direct_fact=(
                    "The retained legacy project does not establish current collection "
                    "status."
                ),
                operator_implication=(
                    "Do not infer successful or exhaustive collection from the available "
                    "legacy files."
                ),
                stage_or_tool="legacy_project_state",
                artefact_references=("project_state.json",),
            )
        )
    return _dedupe_and_sort(notices)


def build_collection_confidence_notices_from_project(
    project_state: ProjectState,
    input_dir: Path,
    *,
    source_collection: object | None = None,
) -> tuple[CollectionConfidenceNotice, ...]:
    """Build notices from current local structured metadata only."""

    root = input_dir.expanduser().resolve()
    if source_collection is None:
        collection_path = root / DEEP_SOURCE_ROUTE_COLLECTION_JSON
        if collection_path.is_file() and not collection_path.is_symlink():
            try:
                source_collection = load_deep_source_route_collection_result(
                    collection_path
                )
            except (OSError, UnicodeError, ValueError):
                source_collection = None
    pipeline = _load_optional_object(root / "project_pipeline.json")
    pipeline_steps = pipeline.get("steps", ()) if pipeline is not None else ()
    if not isinstance(pipeline_steps, list):
        pipeline_steps = ()
    command_results: list[dict[str, object]] = []
    for path in sorted(root.glob("recon_execution*.json")):
        payload = _load_optional_object(path)
        if payload is None:
            continue
        raw_results = payload.get("command_results", ())
        if not isinstance(raw_results, list):
            continue
        for raw_result in raw_results:
            if not isinstance(raw_result, dict):
                continue
            command_results.append({**raw_result, "confidence_artifact": path.name})
    return build_collection_confidence_notices(
        project_state,
        source_collection=source_collection,
        pipeline_steps=pipeline_steps,
        command_results=command_results,
    )


def render_collection_confidence_markdown(
    notices: tuple[CollectionConfidenceNotice, ...],
) -> str | None:
    """Render the compact primary report section."""

    if not notices:
        return None
    lines = [
        "## Collection Confidence",
        "",
        "Absence of a notice does not prove exhaustive coverage.",
        "",
    ]
    for notice in notices:
        lines.extend(
            [
                f"### {notice.notice_id}: {notice.title}",
                "",
                f"- Category: `{notice.category}`",
                f"- Direct fact: {notice.direct_fact}",
                f"- Operator implication: {notice.operator_implication}",
                f"- Stage/tool: `{notice.stage_or_tool}`",
            ]
        )
        if notice.counts:
            lines.append(
                "- Counts: "
                + "; ".join(f"{name} `{count}`" for name, count in notice.counts)
            )
        lines.extend(
            [
                "- Evidence: " + _render_values(notice.evidence_ids),
                "- Retained artefact: " + _render_values(notice.artefact_references),
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_collection_confidence_runbook(
    notices: tuple[CollectionConfidenceNotice, ...],
) -> str | None:
    """Render offline review guidance from the same notice model."""

    if not notices:
        return None
    lines = [
        "## Collection Confidence Review",
        "",
        "Review these retained collection limitations before interpreting negative results.",
        "Absence of a notice does not prove exhaustive coverage.",
        "",
    ]
    for notice in notices:
        lines.extend(
            [
                f"### {notice.notice_id}: {notice.title}",
                "",
                f"- Category: `{notice.category}`",
                f"- Direct fact: {notice.direct_fact}",
                f"- What remains unknown: {notice.operator_implication}",
                "- Evidence: " + _render_values(notice.evidence_ids),
                "- Retained artefact: " + _render_values(notice.artefact_references),
                "- Offline action: inspect the retained artefact and decide whether "
                "additional authorised collection is warranted later; do not infer a "
                "negative result and do not re-contact the target from this runbook.",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _bounded_content_notice(
    project_state: ProjectState,
) -> CollectionConfidenceNotice | None:
    manifest = getattr(project_state, "recon_manifest", None)
    artifacts = getattr(manifest, "artifacts", ()) if manifest is not None else ()
    profile = next(
        (
            candidate
            for artifact in artifacts
            for candidate in _BOUNDED_CONTENT_PROFILES
            if getattr(artifact, "type", "") == "gobuster"
            and candidate in Path(getattr(artifact, "file", "")).name
        ),
        None,
    )
    if profile is None:
        return None
    evidence_ids = tuple(
        sorted(
            {
                evidence.id
                for evidence in getattr(project_state, "evidence", ())
                if Path(evidence.source_file).name
                in {
                    Path(getattr(artifact, "file", "")).name
                    for artifact in artifacts
                    if getattr(artifact, "type", "") == "gobuster"
                }
            }
        )
    )
    return CollectionConfidenceNotice(
        notice_id="CONFIDENCE-BOUNDED-CONTENT-DISCOVERY",
        category=INTENTIONALLY_BOUNDED,
        title="Intentionally bounded content discovery",
        direct_fact=f"Content discovery used the structured `{profile}` profile.",
        operator_implication=(
            "The configured discovery scope was not exhaustive; routes outside its "
            "selected bounded inputs were not tested by this stage."
        ),
        stage_or_tool="content_discovery",
        evidence_ids=evidence_ids,
        artefact_references=("recon_manifest.json",),
    )


def _bounded_deep_notice(
    source_collection: object | None,
) -> CollectionConfidenceNotice | None:
    if source_collection is None:
        return None
    values = tuple(
        getattr(source_collection, name, None)
        for name in ("total_considered", "total_collected", "total_skipped")
    )
    if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
        return None
    considered, collected, skipped = values
    evidence_ids = tuple(
        sorted(
            {
                evidence_id
                for item in (
                    *tuple(getattr(source_collection, "collected", ())),
                    *tuple(getattr(source_collection, "skipped", ())),
                )
                for evidence_id in tuple(getattr(item, "evidence_ids", ()))
                if isinstance(evidence_id, str) and evidence_id.strip()
            }
        )
    )
    return CollectionConfidenceNotice(
        notice_id="CONFIDENCE-DEEP-SOURCE-ROUTES",
        category=INTENTIONALLY_BOUNDED,
        title="Intentionally bounded Deep source-route collection",
        direct_fact=(
            f"Deep source-route collection considered {considered} requests, collected "
            f"{collected}, and intentionally skipped {skipped} under its bounded policy."
        ),
        operator_implication=(
            "Review covers only policy-allowed retained requests; skipped or unconsidered "
            "routes remain unknown."
        ),
        stage_or_tool="deep_source_route_collection",
        evidence_ids=evidence_ids,
        artefact_references=("deep_source_route_collection.json",),
        counts=(
            ("considered", considered),
            ("collected", collected),
            ("skipped", skipped),
        ),
    )


def _structured_warning_notices(
    project_state: ProjectState,
) -> tuple[CollectionConfidenceNotice, ...]:
    notices = []
    for warning in getattr(project_state, "warnings", ()):
        match = _FOLLOWUP_CAP.fullmatch(str(warning).strip())
        if match is None:
            continue
        count = int(match.group("count"))
        notices.append(
            CollectionConfidenceNotice(
                notice_id="CONFIDENCE-DEGRADED-PATH-FOLLOWUP-CAP",
                category=PARTIAL_OR_DEGRADED,
                title="Eligible path follow-up was capped",
                direct_fact=(
                    f"Structured collection metadata records a cap of {count} URLs."
                ),
                operator_implication=(
                    "Eligible routes beyond the cap may not have follow-up response evidence."
                ),
                stage_or_tool="path_followup",
                artefact_references=("project_state.json",),
                counts=(("cap", count),),
            )
        )
    return tuple(notices)


def _pipeline_step_notices(
    pipeline_steps: Iterable[object],
) -> tuple[CollectionConfidenceNotice, ...]:
    notices = []
    for step in pipeline_steps:
        status = str(_field(step, "status") or "").strip().lower()
        if status not in {"failed", "skipped", "unavailable"}:
            continue
        step_id = str(_field(step, "step_id") or "unknown-stage").strip()
        name = str(_field(step, "name") or step_id).strip()
        message = str(
            _field(step, "message") or "No additional reason was recorded."
        ).strip()
        unavailable = status == "unavailable" or "unavailable" in message.lower()
        category = FAILED if status == "failed" else SKIPPED_OR_UNAVAILABLE
        notices.append(
            CollectionConfidenceNotice(
                notice_id=f"CONFIDENCE-STAGE-{_identifier(step_id)}",
                category=category,
                title=(
                    f"Collection stage unavailable: {name}"
                    if unavailable
                    else f"Collection stage {status}: {name}"
                ),
                direct_fact=(
                    f"Pipeline stage `{step_id}` recorded status `{status}`: {message}"
                ),
                operator_implication=(
                    "No result should be inferred for this stage from absent evidence."
                ),
                stage_or_tool=str(_field(step, "command_kind") or step_id),
                artefact_references=("project_pipeline.json",),
            )
        )
    return tuple(notices)


def _command_result_notices(
    command_results: Iterable[object],
) -> tuple[CollectionConfidenceNotice, ...]:
    notices = []
    for result in command_results:
        exit_code = _field(result, "exit_code")
        error = _field(result, "error")
        executed = _field(result, "executed")
        command_id = str(_field(result, "command_id") or "unknown-command").strip()
        tool = str(_field(result, "tool") or "unknown-tool").strip()
        artefact = str(
            _field(result, "confidence_artifact") or "recon_execution.json"
        )
        if executed is False:
            notices.append(
                CollectionConfidenceNotice(
                    notice_id=f"CONFIDENCE-COMMAND-{_identifier(command_id)}",
                    category=SKIPPED_OR_UNAVAILABLE,
                    title=f"Collection command was not attempted: {command_id}",
                    direct_fact=(
                        f"Structured execution metadata records `{command_id}` as not "
                        "executed."
                    ),
                    operator_implication=(
                        "No result should be inferred from this unexecuted command."
                    ),
                    stage_or_tool=tool,
                    artefact_references=(artefact,),
                )
            )
            continue
        if (exit_code in {0, None}) and not error:
            continue
        reason = str(error).strip() if error else f"exit code {exit_code}"
        notices.append(
            CollectionConfidenceNotice(
                notice_id=f"CONFIDENCE-COMMAND-{_identifier(command_id)}",
                category=FAILED,
                title=f"Collection command failed: {command_id}",
                direct_fact=f"The `{tool}` command `{command_id}` failed with {reason}.",
                operator_implication=(
                    "Expected evidence from this command may be absent; do not infer a "
                    "negative result."
                ),
                stage_or_tool=tool,
                artefact_references=(artefact,),
            )
        )
    return tuple(notices)


def _dedupe_and_sort(
    notices: Iterable[CollectionConfidenceNotice],
) -> tuple[CollectionConfidenceNotice, ...]:
    merged: dict[str, CollectionConfidenceNotice] = {}
    for notice in notices:
        existing = merged.get(notice.notice_id)
        if existing is None:
            merged[notice.notice_id] = notice
            continue
        merged[notice.notice_id] = CollectionConfidenceNotice(
            notice_id=existing.notice_id,
            category=existing.category,
            title=existing.title,
            direct_fact=existing.direct_fact,
            operator_implication=existing.operator_implication,
            stage_or_tool=existing.stage_or_tool,
            evidence_ids=tuple(sorted({*existing.evidence_ids, *notice.evidence_ids})),
            artefact_references=tuple(
                sorted({*existing.artefact_references, *notice.artefact_references})
            ),
            counts=tuple(sorted({*existing.counts, *notice.counts})),
        )
    return tuple(
        sorted(
            merged.values(),
            key=lambda notice: (
                _CATEGORY_ORDER.get(notice.category, 99),
                notice.notice_id,
            ),
        )
    )


def _field(item: object, name: str) -> object:
    return item.get(name) if isinstance(item, dict) else getattr(item, name, None)


def _identifier(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "-", value.upper()).strip("-") or "UNKNOWN"


def _render_values(values: tuple[str, ...]) -> str:
    return ", ".join(f"`{value}`" for value in values) if values else "none recorded"


def _load_optional_object(path: Path) -> dict[str, object] | None:
    if not path.is_file() or path.is_symlink():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None
