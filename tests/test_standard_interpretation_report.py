"""Internal Standard interpretation report helper tests."""

from __future__ import annotations

from copy import deepcopy
import inspect

import pytest

from bugslyce.core.models import (
    Candidate,
    DiscoveredPath,
    Evidence,
    HTTPArtifact,
    HTTPService,
    ProjectState,
)
from bugslyce.recon.modes import get_recon_mode
from bugslyce.reports.markdown import render_markdown_report
from bugslyce.reports.standard_interpretation import (
    StandardInterpretationReport,
    render_standard_interpretation_report,
)


def test_helper_returns_report_dataclass_with_markdown_and_metadata() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-ROBOTS"],
                tags=[],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])

    assert isinstance(report, StandardInterpretationReport)
    assert report.markdown.startswith("# BugSlyce Recon Pack")
    assert report.sources_analyzed == 1
    assert report.review_lead_count == 1
    assert report.interpretation_assembly.sources_analyzed == 1
    assert report.human_triage_brief_markdown is not None
    assert report.manual_review_leads_markdown is not None
    assert report.investigation_threads_markdown is not None
    assert report.route_source_review_markdown is not None
    assert report.readable_evidence_cards_markdown is not None


def test_helper_places_standard_sections_after_operator_summary_before_scope() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-ROBOTS"],
                tags=[],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])

    assert "## Human Triage Brief" in report.markdown
    assert "## Manual Review Leads" in report.markdown
    assert "## Investigation Threads" in report.markdown
    assert "## Offline Route/Source Review" in report.markdown
    assert "## Readable Evidence Cards" in report.markdown
    assert report.markdown.index("## Operator Summary") < report.markdown.index(
        "## Human Triage Brief"
    )
    assert report.markdown.index("## Human Triage Brief") < report.markdown.index(
        "## Manual Review Leads"
    )
    assert report.markdown.index("## Manual Review Leads") < report.markdown.index(
        "## Investigation Threads"
    )
    assert report.markdown.index("## Investigation Threads") < report.markdown.index(
        "## Offline Route/Source Review"
    )
    assert report.markdown.index("## Offline Route/Source Review") < report.markdown.index(
        "## Readable Evidence Cards"
    )
    assert report.markdown.index("## Readable Evidence Cards") < report.markdown.index(
        "## Scope Summary"
    )
    assert "LEAD-0001" in report.markdown
    assert "not proof of vulnerability" in report.markdown


@pytest.mark.parametrize(
    ("context", "expected"),
    [
        (
            "unknown",
            "This is a manual review signal only. Do not assume exploitability",
        ),
        (
            "ctf_lab",
            "In a CTF or learning-lab context, this may be part of an intended review trail.",
        ),
        (
            "bug_bounty",
            "In a bug bounty context, treat this as low-confidence metadata",
        ),
        (
            "internal_authorised",
            "In an internal authorised assessment, review this against approved scope",
        ),
    ],
)
def test_standard_report_includes_engagement_aware_wording(
    context: str,
    expected: str,
) -> None:
    state = _project_state(
        engagement_context=context,
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-ROBOTS"],
                tags=[],
            )
        ],
    )

    report = render_standard_interpretation_report(state, [])

    assert expected in report.markdown
    assert "## Manual Review Leads" in report.markdown
    assert "## Investigation Threads" in report.markdown
    assert "## Offline Route/Source Review" in report.markdown
    assert "LEAD-0001" in report.markdown


def test_robots_artifact_renders_robots_review_lead() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-ROBOTS"],
                tags=[],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])

    assert "- Category: robots" in report.markdown
    assert "- Field: disallow" in report.markdown
    assert "Disallowed path contains high-signal wording. Manual review recommended." in report.markdown


def test_standard_report_ignores_local_robots_paths_but_keeps_unusual_user_agent_hash() -> None:
    local_path = "/home/user/bugslyce-output/demo/robots-10.10.10.10-80.txt"
    user_agent = "a18672860d0510e5ab6699730763b250"
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="robots",
                value=local_path,
                source_file=local_path,
                evidence_ids=["EVID-ART-ROBOTS-FILE"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="unusual_user_agent",
                value=user_agent,
                source_file=local_path,
                evidence_ids=["EVID-ART-UA"],
                tags=[],
            ),
        ]
    )

    report = render_standard_interpretation_report(state, [])
    manual_section = report.markdown.split("## Manual Review Leads", 1)[1].split(
        "## Scope Summary",
        1,
    )[0]

    assert "## Manual Review Leads" in report.markdown
    assert local_path not in manual_section
    assert "Unknown or non-standard robots directive preserved for review." not in manual_section
    assert user_agent in manual_section
    assert manual_section.count("### LEAD-") == 1
    assert "Robots.txt contains an unusual hash-shaped User-Agent value." in manual_section
    assert "Robots directive contains possible encoded or hash-shaped artefacts." not in manual_section
    assert "possible_md5_shape" in manual_section
    assert "Unusual robots User-Agent value detected." not in manual_section
    assert "CTF" not in manual_section
    explanation_line = next(
        line for line in manual_section.splitlines() if line.startswith("- Explanation:")
    )
    assert explanation_line.lower().count("not proof") == 1
    assert "Treat this as a review lead, not proof of vulnerability." not in explanation_line
    assert "Correlate the value with other collected evidence before escalating." in manual_section
    assert "Do not brute force or attempt authentication based on robots.txt alone." in manual_section


def test_html_source_artifact_renders_html_source_review_lead() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="flag clue is in the source",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-HTML"],
                tags=[],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])

    assert "- Category: html_source" in report.markdown
    assert "- Item type: html_comment" in report.markdown
    assert "HTML comment contains clue-like wording." in report.markdown


def test_standard_report_does_not_render_synthetic_hidden_wrapper_lead() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="hidden_element",
                value="p",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-HIDDEN"],
                tags=[],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])
    manual_section = report.markdown.split("## Manual Review Leads", 1)[1].split(
        "## Scope Summary",
        1,
    )[0]

    assert "## Manual Review Leads" in report.markdown
    assert "<div hidden>" not in manual_section
    assert "Hidden HTML element contains high-signal text." not in manual_section
    assert "No interpretation review leads were generated" in manual_section


def test_standard_report_keeps_genuinely_separate_robots_leads() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="unusual_user_agent",
                value="WeirdCrawler",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-UA"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-DISALLOW"],
                tags=[],
            ),
        ]
    )

    report = render_standard_interpretation_report(state, [])
    manual_section = report.markdown.split("## Manual Review Leads", 1)[1].split(
        "## Scope Summary",
        1,
    )[0]

    assert manual_section.count("### LEAD-") == 2
    assert "Unusual robots User-Agent value detected." in manual_section
    assert "Disallowed path contains high-signal wording. Manual review recommended." in (
        manual_section
    )
    assert "Robots.txt contains an unusual hash-shaped User-Agent value." not in (
        manual_section
    )


def test_generic_encoded_body_renders_transform_review_lead() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/api/status",
                artifact_type="text_body",
                value='{"secret":"L2hpZGRlbi9mbGFn"}',
                source_file="body.txt",
                evidence_ids=["EVID-ART-TEXT"],
                tags=[],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])

    assert "- Category: artefact" in report.markdown
    assert "Possible encoded or transformed artefact detected." in report.markdown
    assert "- Decoded/derived preview: `/hidden/flag`" in report.markdown


def test_standard_report_includes_investigation_threads_for_hidden_paths() -> None:
    state = _project_state(
        discovered_paths=[
            DiscoveredPath(
                url="http://example.test/hidden",
                status_code=200,
                content_length=42,
                redirect_location=None,
                source="gobuster",
                evidence_ids=["EVID-PATH-HIDDEN"],
                tags=[],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])

    assert report.investigation_thread_count == 1
    assert "## Investigation Threads" in report.markdown
    assert "THREAD-0001: Discovered hidden-path review" in report.markdown
    assert "`EVID-PATH-HIDDEN`" in report.markdown


def test_empty_project_state_renders_safe_empty_manual_review_section() -> None:
    state = _project_state()

    report = render_standard_interpretation_report(state, [])

    assert "## Manual Review Leads" in report.markdown
    assert "## Investigation Threads" in report.markdown
    assert "No interpretation review leads were generated from the provided evidence." in report.markdown
    assert "No investigation threads were generated from the provided evidence." in report.markdown
    assert "No vulnerabilities found" not in report.markdown
    assert "target is clean" not in report.markdown.lower()


def test_default_report_rendering_still_omits_manual_review_leads() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-ROBOTS"],
                tags=[],
            )
        ]
    )

    markdown = render_markdown_report(state, [])

    assert "## Manual Review Leads" not in markdown
    assert "## Investigation Threads" not in markdown
    assert "## Offline Route/Source Review" not in markdown
    assert "## Human Triage Brief" not in markdown
    assert "## Readable Evidence Cards" not in markdown


def test_standard_report_includes_human_triage_brief_and_cards_before_raw_tables() -> None:
    state = _project_state(
        http_services=[
            HTTPService(
                url="http://example.test:8080/",
                hostname="example.test",
                status_code=200,
                title="Example app",
                technologies=[],
                content_length=100,
                evidence_ids=["EVID-HTTP-8080"],
                tags=[],
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url="http://example.test/login",
                status_code=200,
                content_length=42,
                redirect_location=None,
                source="gobuster",
                evidence_ids=["EVID-PATH-LOGIN"],
                tags=[],
            )
        ],
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Token-like review value: dG9rZW4tdmFsdWU=",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-COMMENT"],
                tags=[],
            )
        ],
    )

    report = render_standard_interpretation_report(state, [])

    assert "## Human Triage Brief" in report.markdown
    assert "### Start Here" in report.markdown
    assert "### Evidence Values Worth Noting" in report.markdown
    assert "### Review Next" in report.markdown
    assert "### Ignore For Now" in report.markdown
    assert "### Raw Evidence Pointers" in report.markdown
    assert "## Readable Evidence Cards" in report.markdown
    assert "- URL: `http://example.test/login`" in report.markdown
    assert "- Signal:" in report.markdown
    assert "- Why it matters:" in report.markdown
    assert "- Suggested manual action:" in report.markdown
    assert "- Evidence: `EVID-PATH-LOGIN`" in report.markdown
    assert report.markdown.index("## Human Triage Brief") < report.markdown.index(
        "### Discovered Paths"
    )
    assert report.markdown.index("## Readable Evidence Cards") < report.markdown.index(
        "### Discovered Paths"
    )
    human_section = report.markdown.split("## Human Triage Brief", 1)[1].split(
        "## Manual Review Leads",
        1,
    )[0]
    assert "vulnerable" not in human_section.lower()
    assert "flag" not in human_section.lower()
    assert "brute force" not in human_section.lower()
    assert "payload injection" not in human_section.lower()


def test_standard_report_promotes_robots_body_value_in_human_triage() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="robots_value",
                value="Wubbalubbadubdub",
                source_file="robots-example.txt",
                evidence_ids=["EVID-ART-ROBOTS-VALUE"],
                tags=["robots_artifact"],
            )
        ]
    )

    report = render_standard_interpretation_report(state, [])

    human_section = report.markdown.split("## Human Triage Brief", 1)[1].split(
        "## Manual Review Leads",
        1,
    )[0]
    cards_section = report.markdown.split("## Readable Evidence Cards", 1)[1].split(
        "## Scope Summary",
        1,
    )[0]

    assert "robots.txt clue-like value observed" in human_section
    assert "Wubbalubbadubdub" in human_section
    assert "### robots.txt clue-like value observed" in cards_section
    assert "- Signal: robots value" in cards_section
    assert "- Value preview: `Wubbalubbadubdub`" in cards_section
    assert "valid credential" not in human_section.lower()
    assert "probably the password" not in human_section.lower()


def test_helper_does_not_mutate_project_state_or_candidates() -> None:
    state = _project_state(
        evidence=[
            Evidence(
                id="EVID-NOTE-0001",
                source_file="notes.md",
                evidence_type="note",
                value="Operator note: secret L2hpZGRlbi9mbGFn",
                context={"item_number": 1},
            )
        ]
    )
    candidates = [
        Candidate(
            id="CAND-0001",
            candidate_type="manual_context",
            title="Manual context",
            priority="low",
            rationale="Context only.",
            affected_assets=[],
            affected_endpoints=[],
            evidence_ids=["EVID-NOTE-0001"],
            suggested_manual_validation=["Review manually."],
            kill_switch_guidance=None,
        )
    ]
    state_before = deepcopy(state)
    candidates_before = deepcopy(candidates)

    render_standard_interpretation_report(state, candidates)

    assert state == state_before
    assert candidates == candidates_before


def test_helper_does_not_call_write_project_outputs() -> None:
    import bugslyce.reports.standard_interpretation as module

    source = inspect.getsource(module)

    assert "write_project_outputs" not in source


def test_quick_and_standard_available_deep_unavailable() -> None:
    assert get_recon_mode("quick").internal_profile == "lab-safe-tiny"
    assert get_recon_mode("quick").is_available
    assert get_recon_mode("standard").internal_profile == "standard-bounded"
    assert get_recon_mode("standard").is_available
    assert not get_recon_mode("deep").is_available


def _project_state(
    *,
    http_artifacts: list[HTTPArtifact] | None = None,
    evidence: list[Evidence] | None = None,
    discovered_paths: list[DiscoveredPath] | None = None,
    http_services: list[HTTPService] | None = None,
    engagement_context: str = "unknown",
) -> ProjectState:
    return ProjectState(
        project_name="standard-report-test",
        input_dir="/tmp/standard-report-test",
        processed_files=[],
        scope_summary="No scope file parsed.",
        assets=[],
        http_services=http_services or [],
        endpoints=[],
        port_services=[],
        http_artifacts=http_artifacts or [],
        discovered_paths=discovered_paths or [],
        recon_summary=None,
        recon_manifest=None,
        evidence=evidence or [],
        warnings=[],
        generated_at="2026-06-21T00:00:00Z",
        engagement_context=engagement_context,
    )
