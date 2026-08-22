"""Adapt manifest-retained HTML files into normalized HTTP evidence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
from pathlib import Path
import stat

from bugslyce.core.models import ReconManifest
from bugslyce.recon.http_origin import http_origin_from_url
from bugslyce.recon.http_route_relationships import canonical_relationship_url
from bugslyce.reports.operator_brief import OperatorBriefSourceReference
from bugslyce.reports.operator_brief_http import (
    OperatorBriefHttpCompositionInput,
    OperatorBriefHttpRetainedBodyObservation,
    build_operator_brief_http_exact_equivalence,
    build_operator_brief_http_retained_body_observation,
    combine_operator_brief_http_inputs,
)


_SOURCE_KIND = "manifest_retained_html"


class OperatorBriefHttpRetainedManifestRejectionReason(str, Enum):
    UNSAFE_PATH = "unsafe_path"
    SYMLINK = "symlink"
    MISSING_FILE = "missing_file"
    NON_REGULAR_FILE = "non_regular_file"
    OVERSIZED_FILE = "oversized_file"
    INVALID_URL = "invalid_url"
    READ_ERROR = "read_error"


@dataclass(frozen=True)
class OperatorBriefHttpRetainedManifestRejection:
    artefact_reference: str
    manifest_url: str | None
    reason: OperatorBriefHttpRetainedManifestRejectionReason


@dataclass(frozen=True)
class OperatorBriefHttpRetainedManifestResult:
    inputs: OperatorBriefHttpCompositionInput
    rejections: tuple[OperatorBriefHttpRetainedManifestRejection, ...]


def _safe_retained_file(
    root: Path,
    artefact_reference: str,
) -> tuple[Path | None, OperatorBriefHttpRetainedManifestRejectionReason | None]:
    relative = Path(artefact_reference)
    if (
        not artefact_reference
        or not relative.parts
        or "\x00" in artefact_reference
        or relative.is_absolute()
        or ".." in relative.parts
    ):
        return None, OperatorBriefHttpRetainedManifestRejectionReason.UNSAFE_PATH

    candidate = root
    for index, component in enumerate(relative.parts):
        candidate /= component
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            return (
                None,
                OperatorBriefHttpRetainedManifestRejectionReason.MISSING_FILE,
            )
        except OSError:
            return None, OperatorBriefHttpRetainedManifestRejectionReason.READ_ERROR
        if stat.S_ISLNK(metadata.st_mode):
            return None, OperatorBriefHttpRetainedManifestRejectionReason.SYMLINK
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            return (
                None,
                OperatorBriefHttpRetainedManifestRejectionReason.NON_REGULAR_FILE,
            )

    try:
        candidate.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return None, OperatorBriefHttpRetainedManifestRejectionReason.UNSAFE_PATH
    if not stat.S_ISREG(metadata.st_mode):
        return (
            None,
            OperatorBriefHttpRetainedManifestRejectionReason.NON_REGULAR_FILE,
        )
    return candidate, None


def _rejection(
    artefact_reference: str,
    manifest_url: str | None,
    reason: OperatorBriefHttpRetainedManifestRejectionReason,
) -> OperatorBriefHttpRetainedManifestRejection:
    return OperatorBriefHttpRetainedManifestRejection(
        artefact_reference=artefact_reference,
        manifest_url=manifest_url,
        reason=reason,
    )


def _read_retained_file(
    path: Path,
    maximum_body_bytes: int,
) -> tuple[bytes | None, OperatorBriefHttpRetainedManifestRejectionReason | None]:
    try:
        with path.open("rb") as handle:
            body = handle.read(maximum_body_bytes + 1)
    except OSError:
        return None, OperatorBriefHttpRetainedManifestRejectionReason.READ_ERROR
    if len(body) > maximum_body_bytes:
        return (
            None,
            OperatorBriefHttpRetainedManifestRejectionReason.OVERSIZED_FILE,
        )
    return body, None


def _stable_id(prefix: str, values: tuple[str, ...]) -> str:
    payload = json.dumps(values, ensure_ascii=True, separators=(",", ":"))
    return f"{prefix}-{sha256(payload.encode('utf-8')).hexdigest()[:24]}"


def _add_retained_equalities(
    inputs: OperatorBriefHttpCompositionInput,
) -> OperatorBriefHttpCompositionInput:
    groups: dict[tuple[str, int], list[str]] = {}
    for item in inputs.retained_content:
        if item.body_empty:
            continue
        groups.setdefault((item.body_sha256, item.body_bytes), []).append(
            item.observation_id
        )

    relationships = []
    for (body_digest, body_bytes), member_ids in sorted(groups.items()):
        members = tuple(sorted(set(member_ids)))
        if len(members) < 2:
            continue
        authority_id = _stable_id(
            "RETAINED-EXACT",
            (body_digest, str(body_bytes), *members),
        )
        relationships.append(
            build_operator_brief_http_exact_equivalence(
                body_sha256=body_digest,
                observation_ids=members,
                authority_references=(
                    OperatorBriefSourceReference(
                        source_kind="retained_body_exact_hash",
                        source_id=authority_id,
                    ),
                ),
            )
        )

    if not relationships:
        return inputs
    return combine_operator_brief_http_inputs(
        inputs,
        OperatorBriefHttpCompositionInput(
            observations=(),
            exact_equivalences=tuple(relationships),
            retained_content=(),
        ),
    )


def build_operator_brief_http_inputs_from_retained_manifest_html(
    manifest: ReconManifest,
    project_root: Path,
    *,
    maximum_body_bytes: int,
) -> OperatorBriefHttpRetainedManifestResult:
    """Adapt manifest-retained HTML into normalized partial HTTP evidence."""

    if isinstance(maximum_body_bytes, bool) or not isinstance(
        maximum_body_bytes, int
    ):
        raise TypeError("maximum_body_bytes must be an integer.")
    if maximum_body_bytes <= 0:
        raise ValueError("maximum_body_bytes must be positive.")
    root = Path(project_root)
    if not root.exists() or not root.is_dir():
        raise ValueError("project_root must identify an existing directory.")

    rejections: list[OperatorBriefHttpRetainedManifestRejection] = []
    retained_content: list[OperatorBriefHttpRetainedBodyObservation] = []
    for artefact in manifest.artifacts:
        if artefact.type != "html":
            continue
        canonical_endpoint = canonical_relationship_url(artefact.url)
        if (
            not canonical_endpoint
            or http_origin_from_url(canonical_endpoint) is None
        ):
            rejections.append(
                _rejection(
                    artefact.file,
                    artefact.url,
                    OperatorBriefHttpRetainedManifestRejectionReason.INVALID_URL,
                )
            )
            continue

        path, reason = _safe_retained_file(root, artefact.file)
        body = None
        if reason is None:
            body, reason = _read_retained_file(path, maximum_body_bytes)
        if reason is not None:
            rejections.append(_rejection(artefact.file, artefact.url, reason))
            continue

        body_digest = sha256(body).hexdigest()
        retained_content.append(
            build_operator_brief_http_retained_body_observation(
                source_kind=_SOURCE_KIND,
                source_id=_stable_id(
                    "MANIFEST-HTML",
                    (
                        canonical_endpoint,
                        artefact.file,
                        body_digest,
                        str(len(body)),
                    ),
                ),
                endpoint=canonical_endpoint,
                body_sha256=body_digest,
                body_bytes=len(body),
                evidence_ids=(),
                artefact_references=(artefact.file,),
            )
        )

    inputs = combine_operator_brief_http_inputs(
        *(
            OperatorBriefHttpCompositionInput(
                observations=(),
                exact_equivalences=(),
                retained_content=(item,),
            )
            for item in retained_content
        )
    )
    inputs = _add_retained_equalities(inputs)
    return OperatorBriefHttpRetainedManifestResult(
        inputs=inputs,
        rejections=tuple(
            sorted(
                set(rejections),
                key=lambda item: (
                    item.artefact_reference,
                    item.manifest_url or "",
                    item.reason.value,
                ),
            )
        ),
    )
