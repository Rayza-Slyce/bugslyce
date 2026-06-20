"""Project-state to ArtefactSource mapper tests."""

from __future__ import annotations

import inspect

from bugslyce.core.models import (
    Evidence,
    HTTPArtifact,
    ProjectState,
)
from bugslyce.recon.interpretation_sources import (
    artefact_sources_from_project_state,
)
from bugslyce.recon.modes import get_recon_mode
from bugslyce.reports.markdown import render_markdown_report


def test_empty_project_state_returns_no_sources() -> None:
    state = _project_state()

    assert artefact_sources_from_project_state(state) == ()


def test_robots_text_already_present_becomes_robots_source() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file="/tmp/robots-80.txt",
                evidence_ids=["EVID-ART-0001"],
                tags=["robots_artifact"],
            )
        ]
    )

    source = artefact_sources_from_project_state(state)[0]

    assert source.source_id == "EVID-ART-0001"
    assert source.source_kind == "robots_txt"
    assert source.source_label == "http://example.test/robots.txt"
    assert source.url == "http://example.test/robots.txt"
    assert source.path == "/tmp/robots-80.txt"
    assert source.port == 80
    assert source.service == "http"
    assert source.field_name == "disallow_rule"
    assert source.text == "Disallow: /admin"


def test_homepage_html_artifact_becomes_html_source() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="https://example.test/",
                artifact_type="html_comment",
                value="flag clue is in the source",
                source_file="/tmp/homepage-443.html",
                evidence_ids=["EVID-ART-0002"],
                tags=[],
            )
        ]
    )

    source = artefact_sources_from_project_state(state)[0]

    assert source.source_kind == "html"
    assert source.url == "https://example.test/"
    assert source.port == 443
    assert source.service == "https"
    assert source.field_name == "html_comment"
    assert source.text == "<!-- flag clue is in the source -->"


def test_missing_or_empty_source_file_does_not_crash_when_metadata_is_sufficient() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file=None,  # type: ignore[arg-type]
                evidence_ids=["EVID-ART-ROBOTS"],
                tags=[],
            ),
            HTTPArtifact(
                url="https://example.test/",
                artifact_type="html_comment",
                value="secret clue",
                source_file="",
                evidence_ids=["EVID-ART-HTML"],
                tags=[],
            ),
        ]
    )

    sources = artefact_sources_from_project_state(state)

    assert [source.source_id for source in sources] == [
        "EVID-ART-ROBOTS",
        "EVID-ART-HTML",
    ]
    assert [source.source_kind for source in sources] == ["robots_txt", "html"]
    assert [source.path for source in sources] == [None, None]
    assert sources[0].source_label == "http://example.test/robots.txt"
    assert sources[1].source_label == "https://example.test/"


def test_selected_generic_text_body_becomes_response_body_source() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/api/status",
                artifact_type="text_body",
                value='{"status":"ok","secret":"L2hpZGRlbi9mbGFn"}',
                source_file="/tmp/body-fetch-status.txt",
                evidence_ids=["EVID-ART-0003"],
                tags=[],
            )
        ]
    )

    source = artefact_sources_from_project_state(state)[0]

    assert source.source_kind == "response_body"
    assert source.url == "http://example.test/api/status"
    assert source.path == "/tmp/body-fetch-status.txt"
    assert source.field_name == "text_body"
    assert "L2hpZGRlbi9mbGFn" in source.text


def test_notes_evidence_becomes_notes_source() -> None:
    state = _project_state(
        evidence=[
            Evidence(
                id="EVID-NOTE-0001",
                source_file="/tmp/notes.md",
                evidence_type="note",
                value="Operator note: possible clue abcdefabcdefabcdefabcdefabcdefab",
                context={"item_number": 1},
            )
        ]
    )

    source = artefact_sources_from_project_state(state)[0]

    assert source.source_id == "EVID-NOTE-0001"
    assert source.source_kind == "notes"
    assert source.source_label == "/tmp/notes.md"
    assert source.path == "/tmp/notes.md"
    assert source.field_name == "note"
    assert "possible clue" in source.text


def test_empty_whitespace_and_binary_content_are_ignored() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="   \n\t",
                source_file="empty.html",
                evidence_ids=["EVID-ART-EMPTY"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/blob",
                artifact_type="text_body",
                value="abc\x00def",
                source_file="blob.bin",
                evidence_ids=["EVID-ART-BIN"],
                tags=[],
            ),
        ]
    )

    assert artefact_sources_from_project_state(state) == ()


def test_duplicate_sources_are_deduplicated_deterministically() -> None:
    artifact = HTTPArtifact(
        url="http://example.test/",
        artifact_type="html_comment",
        value="secret clue",
        source_file="homepage.html",
        evidence_ids=["EVID-ART-0004"],
        tags=[],
    )
    state = _project_state(http_artifacts=[artifact, artifact])

    sources = artefact_sources_from_project_state(state)

    assert len(sources) == 1
    assert sources[0].source_id == "EVID-ART-0004"


def test_source_ordering_is_stable() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-0001"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="secret clue",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-0002"],
                tags=[],
            ),
        ],
        evidence=[
            Evidence(
                id="EVID-NOTE-0001",
                source_file="notes.md",
                evidence_type="note",
                value="note clue",
                context={},
            )
        ],
    )

    sources = artefact_sources_from_project_state(state)

    assert [source.source_id for source in sources] == [
        "EVID-ART-0001",
        "EVID-ART-0002",
        "EVID-NOTE-0001",
    ]


def test_body_text_is_bounded_without_changing_original_artifact() -> None:
    value = "A" * 80
    artifact = HTTPArtifact(
        url="http://example.test/body",
        artifact_type="text_body",
        value=value,
        source_file="body.txt",
        evidence_ids=["EVID-ART-LONG"],
        tags=[],
    )
    state = _project_state(http_artifacts=[artifact])

    source = artefact_sources_from_project_state(state, max_source_chars=20)[0]

    assert source.text == "A" * 17 + "..."
    assert artifact.value == value


def test_mapper_does_not_call_interpretation_collector() -> None:
    import bugslyce.recon.interpretation_sources as module

    source = inspect.getsource(module)

    assert "collect_interpretation_from_sources" not in source
    assert "interpretation_collection" not in source


def test_current_report_generation_remains_unchanged_by_default() -> None:
    state = _project_state()

    report = render_markdown_report(state, [])

    assert "## Manual Review Leads" not in report


def test_standard_and_deep_remain_unavailable() -> None:
    assert not get_recon_mode("standard").is_available
    assert not get_recon_mode("deep").is_available


def _project_state(
    *,
    http_artifacts: list[HTTPArtifact] | None = None,
    evidence: list[Evidence] | None = None,
) -> ProjectState:
    return ProjectState(
        project_name="mapper-test",
        input_dir="/tmp/mapper-test",
        processed_files=[],
        scope_summary="No scope file parsed.",
        assets=[],
        http_services=[],
        endpoints=[],
        port_services=[],
        http_artifacts=http_artifacts or [],
        discovered_paths=[],
        recon_summary=None,
        recon_manifest=None,
        evidence=evidence or [],
        warnings=[],
        generated_at="2026-06-20T00:00:00Z",
    )
