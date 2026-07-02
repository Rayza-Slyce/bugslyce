"""Parser for saved robots.txt files."""

from __future__ import annotations

from pathlib import Path
import warnings

from bugslyce.core.models import HTTPArtifact


MAX_ROBOTS_VALUE_LENGTH = 160
GENERIC_ROBOTS_VALUES = {
    "*",
    "/",
    "user-agent",
    "user-agent: *",
    "allow: /",
    "disallow:",
}
HTML_ERROR_MARKERS = ("<!doctype html", "<html", "<body", "<head", "<title")


def parse_robots(path: Path, url: str = "") -> list[HTTPArtifact]:
    """Parse saved robots.txt content into local HTTP artefacts."""

    if not path.exists():
        warnings.warn(f"Robots file does not exist: {path}", RuntimeWarning, stacklevel=2)
        return []

    artifacts: list[HTTPArtifact] = [
        HTTPArtifact(url=url, artifact_type="robots", value=str(path), source_file=str(path), evidence_ids=[], tags=[])
    ]
    text = path.read_text(encoding="utf-8", errors="replace")
    if _looks_like_html_error(text):
        return artifacts
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" in stripped:
            parsed = _parse_directive(stripped)
            if parsed is None:
                continue
            artifact_type, value = parsed
        else:
            value = _body_value(stripped)
            if value is None:
                continue
            artifact_type = "robots_value"
        artifacts.append(
            HTTPArtifact(
                url=url,
                artifact_type=artifact_type,
                value=value,
                source_file=str(path),
                evidence_ids=[],
                tags=[],
            )
        )
    return artifacts


def _parse_directive(line: str) -> tuple[str, str] | None:
    name, value = line.split(":", 1)
    directive = name.strip().lower()
    value = value.strip()
    if directive == "user-agent":
        artifact_type = "unusual_user_agent" if value and value != "*" else "user_agent"
    elif directive == "allow":
        artifact_type = "allow_rule"
    elif directive == "disallow":
        artifact_type = "disallow_rule"
    elif directive == "sitemap":
        artifact_type = "sitemap_rule"
    else:
        return None
    if artifact_type in {"allow_rule", "disallow_rule"} and not value:
        return None
    return artifact_type, value


def _body_value(line: str) -> str | None:
    value = " ".join(line.split())
    if not value or len(value) > MAX_ROBOTS_VALUE_LENGTH:
        return None
    lowered = value.lower()
    if lowered in GENERIC_ROBOTS_VALUES:
        return None
    if "\x00" in value or "\ufffd" in value:
        return None
    if lowered.startswith(HTML_ERROR_MARKERS) or "<" in value or ">" in value:
        return None
    return value


def _looks_like_html_error(text: str) -> bool:
    preview = text.lstrip()[:500].lower()
    return any(marker in preview for marker in HTML_ERROR_MARKERS)
