"""Parser for saved robots.txt files."""

from __future__ import annotations

from pathlib import Path
import warnings

from bugslyce.core.models import HTTPArtifact


def parse_robots(path: Path, url: str = "") -> list[HTTPArtifact]:
    """Parse user-agent, allow, and disallow directives as artifacts."""

    if not path.exists():
        warnings.warn(f"Robots file does not exist: {path}", RuntimeWarning, stacklevel=2)
        return []

    artifacts: list[HTTPArtifact] = [
        HTTPArtifact(url=url, artifact_type="robots", value=str(path), source_file=str(path), evidence_ids=[], tags=[])
    ]
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        name, value = stripped.split(":", 1)
        directive = name.strip().lower()
        value = value.strip()
        if directive == "user-agent":
            artifact_type = "unusual_user_agent" if value and value != "*" else "user_agent"
        elif directive == "allow":
            artifact_type = "allow_rule"
        elif directive == "disallow":
            artifact_type = "disallow_rule"
        else:
            continue
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
