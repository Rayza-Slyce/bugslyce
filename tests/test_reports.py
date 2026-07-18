"""Tests for deterministic report and JSON export generation."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

from bugslyce.core.models import DiscoveredPath, Endpoint, HTTPArtifact
from bugslyce.core.project import build_project_state
from bugslyce.reports.human_triage import (
    build_human_triage_brief,
    render_human_triage_brief_markdown,
)
from bugslyce.reports.markdown import (
    export_project_state_json,
    format_endpoint_list,
    format_evidence_ids,
    render_markdown_report,
    write_project_outputs,
)
from bugslyce.triage.candidates import generate_candidates


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def _basic_saas_report() -> tuple[str, object, object]:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)
    return render_markdown_report(state, candidates), state, candidates


def test_markdown_report_renders_for_basic_saas() -> None:
    report, _state, _candidates = _basic_saas_report()

    assert report.startswith("# BugSlyce Recon Pack")
    assert "basic_saas" in report
    assert f"Generated at: `{_state.generated_at}`" in report
    assert "- Engagement context: Unknown / not specified" in report


def test_report_includes_project_engagement_context(tmp_path: Path) -> None:
    input_dir = tmp_path / "project"
    input_dir.mkdir()
    (input_dir / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n* 10.10.10.10\n",
        encoding="utf-8",
    )
    (input_dir / "bugslyce_project.json").write_text(
        json.dumps({"engagement_context": "bug_bounty"}),
        encoding="utf-8",
    )

    state = build_project_state(input_dir)
    report = render_markdown_report(state, [])

    assert state.engagement_context == "bug_bounty"
    assert "- Engagement context: Bug bounty" in report


def test_markdown_report_includes_required_sections() -> None:
    report, _state, _candidates = _basic_saas_report()

    required_sections = [
        "## Operator Summary",
        "### Review First",
        "### Low-Signal / Avoid Rabbit Holes",
        "### Current Coverage",
        "## Scope Summary",
        "## Input Files Processed",
        "## Asset Inventory",
        "## Live HTTP Services",
        "## Attack Surface Summary",
        "## Manual Review Queue",
        "## Evidence Summary",
        "### Raw Evidence References",
        "## Operator Notes / Context",
        "## Safe Next Steps",
        "## Kill-switch / Rabbit-hole Warnings",
        "## Unknowns / Requires Manual Validation",
    ]

    for section in required_sections:
        assert section in report


def test_operator_summary_appears_before_scope_summary() -> None:
    report, _state, _candidates = _basic_saas_report()

    assert report.index("## Operator Summary") < report.index("## Scope Summary")


def test_default_report_does_not_include_manual_review_leads_section() -> None:
    report, _state, _candidates = _basic_saas_report()

    assert "## Manual Review Leads" not in report
    assert "## Human Triage Brief" not in report
    assert "## Readable Evidence Cards" not in report


def test_report_can_include_prerendered_human_triage_and_cards_sections() -> None:
    _report, state, candidates = _basic_saas_report()
    brief_section = "\n".join(
        [
            "## Human Triage Brief",
            "",
            "This brief contains manual review prompts, not confirmed findings.",
        ]
    )
    cards_section = "\n".join(
        [
            "## Readable Evidence Cards",
            "",
            "### HTTP service",
            "",
            "- URL: `http://example.test/`",
            "- Signal: Primary web surface",
            "- Why it matters: Main HTTP service for manual review.",
            "- Suggested manual action: Review collected evidence.",
            "- Evidence: `EVID-HTTP-0001`",
        ]
    )

    report = render_markdown_report(
        state,
        candidates,
        human_triage_brief_markdown=brief_section,
        readable_evidence_cards_markdown=cards_section,
    )

    assert "## Human Triage Brief" in report
    assert "## Readable Evidence Cards" in report
    assert report.index("## Operator Summary") < report.index("## Human Triage Brief")
    assert report.index("## Human Triage Brief") < report.index("## Scope Summary")
    assert report.index("## Readable Evidence Cards") < report.index("## Scope Summary")


def test_report_can_include_prerendered_manual_review_leads_section() -> None:
    _report, state, candidates = _basic_saas_report()
    manual_review_section = "\n".join(
        [
            "## Manual Review Leads",
            "",
            (
                "These leads are derived from collected evidence and should be "
                "treated as manual review prompts, not proof of vulnerability."
            ),
            "",
            "### LEAD-0042: Possible encoded or transformed artefact detected.",
            "",
            "- Priority: high",
            "- Category: artefact",
            "- Source: homepage; kind=html; url=http://example.test/",
            "- Raw value: `L2hpZGRlbi9mbGFn`",
            "- Decoded/derived preview: `/hidden/flag`",
            "- Explanation: Derived previews are advisory and may be incorrect.",
            "- Suggested manual validation:",
            "  - Validate locally before treating this as evidence.",
        ]
    )

    report = render_markdown_report(
        state,
        candidates,
        manual_review_leads_markdown=manual_review_section,
    )

    assert "## Manual Review Leads" in report
    assert "### LEAD-0042: Possible encoded or transformed artefact detected." in report
    assert "- Raw value: `L2hpZGRlbi9mbGFn`" in report
    assert "- Decoded/derived preview: `/hidden/flag`" in report
    assert "Validate locally before treating this as evidence." in report
    assert report.index("## Operator Summary") < report.index("## Manual Review Leads")
    assert report.index("## Manual Review Leads") < report.index("## Scope Summary")


def test_report_ignores_whitespace_only_manual_review_section() -> None:
    _report, state, candidates = _basic_saas_report()

    report = render_markdown_report(
        state,
        candidates,
        manual_review_leads_markdown=" \n\t\n ",
    )

    assert "## Manual Review Leads" not in report
    assert report.index("## Operator Summary") < report.index("## Scope Summary")


def test_deep_recon_markdown_omission_none_empty_and_whitespace_are_unchanged() -> None:
    baseline, state, candidates = _basic_saas_report()

    assert render_markdown_report(state, candidates) == baseline
    assert render_markdown_report(state, candidates, deep_recon_markdown=None) == baseline
    assert render_markdown_report(state, candidates, deep_recon_markdown="") == baseline
    assert render_markdown_report(state, candidates, deep_recon_markdown="   \n\t") == baseline


def test_report_inserts_deep_recon_markdown_once_as_opaque_block() -> None:
    _report, state, candidates = _basic_saas_report()
    deep_markdown = "\n".join(
        [
            "## Deep HTML Route Extraction",
            "",
            "- Preserved bullet",
            "",
            "```text",
            "literal fenced content",
            "```",
        ]
    )
    caller_value = f"\n\t{deep_markdown}\n\n"

    report = render_markdown_report(
        state,
        candidates,
        deep_recon_markdown=caller_value,
    )

    assert caller_value == f"\n\t{deep_markdown}\n\n"
    assert report.count("## Deep HTML Route Extraction") == 1
    assert "- Preserved bullet" in report
    assert "```text\nliteral fenced content\n```" in report
    assert "## Deep Recon\n" not in report
    assert report.index("## Operator Summary") < report.index("## Deep HTML Route Extraction")
    assert report.index("## Deep HTML Route Extraction") < report.index("## Scope Summary")


def test_deep_recon_markdown_follows_manual_review_leads_when_both_are_present() -> None:
    _report, state, candidates = _basic_saas_report()
    manual_review_section = "\n".join(
        [
            "## Manual Review Leads",
            "",
            "Manual review prompt.",
        ]
    )
    deep_markdown = "\n".join(
        [
            "## Deep Parameter Inventory",
            "",
            "Already-rendered Deep block.",
        ]
    )

    report = render_markdown_report(
        state,
        candidates,
        manual_review_leads_markdown=manual_review_section,
        deep_recon_markdown=deep_markdown,
    )

    assert report.index("## Operator Summary") < report.index("## Manual Review Leads")
    assert report.index("## Manual Review Leads") < report.index("## Deep Parameter Inventory")
    assert report.index("## Deep Parameter Inventory") < report.index("## Scope Summary")
    assert report.count("Already-rendered Deep block.") == 1


def test_deep_recon_markdown_preserves_existing_trailing_newline_convention() -> None:
    _report, state, candidates = _basic_saas_report()

    report = render_markdown_report(
        state,
        candidates,
        deep_recon_markdown="## Deep Collection Review\n\nOpaque block.",
    )

    assert report.endswith("\n")
    assert not report.endswith("\n\n")


def test_report_module_does_not_import_deep_implementation_modules() -> None:
    source = Path(__file__).resolve().parents[1] / "bugslyce" / "reports" / "markdown.py"
    content = source.read_text(encoding="utf-8")

    for forbidden in (
        "deep_collection_review_bundle",
        "deep_http_fingerprint_summary",
        "deep_redirect_auth_flow_review",
        "deep_response_similarity_review",
        "deep_html_route_extraction",
        "deep_javascript_route_extraction",
        "deep_shallow_route_followup",
        "deep_form_inventory",
        "deep_parameter_inventory",
    ):
        assert forbidden not in content


def test_manual_review_section_contract_avoids_confirmed_issue_wording() -> None:
    _report, state, candidates = _basic_saas_report()
    manual_review_section = "\n".join(
        [
            "## Manual Review Leads",
            "",
            "These are review prompts, not proof of vulnerability.",
            "",
            "### LEAD-0001: Possible hash candidate detected.",
            "",
            "- Category: artefact",
            "- Explanation: Shape alone does not confirm the hash type.",
        ]
    )

    report = render_markdown_report(
        state,
        candidates,
        manual_review_leads_markdown=manual_review_section,
    )
    inserted = report.split("## Manual Review Leads", 1)[1].split("## Scope Summary", 1)[0].lower()

    assert "vulnerabilities" not in inserted
    assert "confirmed findings" not in inserted
    assert "confirmed issues" not in inserted
    assert "exploits" not in inserted
    assert "credentials" not in inserted
    assert "secrets found" not in inserted


def test_markdown_report_includes_candidate_and_evidence_ids() -> None:
    report, _state, _candidates = _basic_saas_report()

    assert "CAND-0001" in report
    assert "EVID-HOST-0001" in report
    assert "EVID-URL-0001" in report


def test_markdown_report_includes_priority_queue_and_kill_switch_warnings() -> None:
    report, _state, _candidates = _basic_saas_report()

    assert "### high" in report
    assert "### medium" in report
    assert "### low" in report
    assert "### kill_switch" in report
    assert "Kill-switch guidance" in report


def test_project_state_json_export_is_valid_and_complete() -> None:
    _report, state, candidates = _basic_saas_report()

    exported = json.loads(export_project_state_json(state, candidates))

    assert "project_state" in exported
    assert "candidates" in exported
    assert exported["project_state"]["assets"]
    assert exported["project_state"]["endpoints"]
    assert exported["project_state"]["evidence"]
    assert exported["candidates"]
    assert exported["candidates"][0]["id"].startswith("CAND-")


def test_write_project_outputs_to_temp_directory(tmp_path: Path) -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    report_path, json_path = write_project_outputs(state, candidates, tmp_path / "bugslyce-output")

    assert report_path == tmp_path / "bugslyce-output" / "report.md"
    assert json_path == tmp_path / "bugslyce-output" / "project_state.json"
    assert report_path.exists()
    assert json_path.exists()
    assert "# BugSlyce Recon Pack" in report_path.read_text(encoding="utf-8")
    assert json.loads(json_path.read_text(encoding="utf-8"))["candidates"]


def test_long_evidence_lists_are_compacted_in_markdown_tables() -> None:
    report, state, _candidates = _basic_saas_report()
    app_asset = next(asset for asset in state.assets if asset.hostname == "app.example-bounty.test")
    expected_compact = format_evidence_ids(app_asset.evidence_ids)

    assert len(app_asset.evidence_ids) > 4
    assert "... +" in expected_compact
    assert expected_compact in report


def test_json_export_preserves_full_evidence_ids() -> None:
    _report, state, candidates = _basic_saas_report()
    app_asset = next(asset for asset in state.assets if asset.hostname == "app.example-bounty.test")
    exported = json.loads(export_project_state_json(state, candidates))
    exported_app = next(
        asset
        for asset in exported["project_state"]["assets"]
        if asset["hostname"] == "app.example-bounty.test"
    )

    assert exported_app["evidence_ids"] == app_asset.evidence_ids
    assert len(exported_app["evidence_ids"]) > 4


def test_report_candidate_endpoint_lists_are_compacted_but_json_preserves_full_detail() -> None:
    report, _state, candidates = _basic_saas_report()
    auth_candidate = next(
        candidate
        for candidate in candidates
        if candidate.candidate_type == "auth_surface"
        and candidate.affected_assets == ["app.example-bounty.test"]
    )
    expected_compact = format_endpoint_list(auth_candidate.affected_endpoints)
    exported = json.loads(export_project_state_json(_state, candidates))
    exported_auth = next(
        candidate
        for candidate in exported["candidates"]
        if candidate["id"] == auth_candidate.id
    )

    assert len(auth_candidate.affected_endpoints) > 4
    assert "... +" in expected_compact
    assert expected_compact in report
    assert exported_auth["affected_endpoints"] == auth_candidate.affected_endpoints


def test_report_renders_ip_assets() -> None:
    state = build_project_state(FIXTURES_ROOT / "local_lab_ip")
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)

    assert "10.10.10.10" in report
    assert "http://10.10.10.10/login" in report
    assert "CAND-" in report


def test_scope_policy_text_is_not_rendered_as_assets_or_candidates(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text(
        "\n".join(
            [
                "# Scope Policy Check",
                "",
                "## In Scope",
                "",
                "* 127.0.0.1",
                "",
                "## Out of Scope",
                "",
                "* Scanners",
                "* Content discovery",
                "* Brute force",
                "* Exploitation",
            ]
        ),
        encoding="utf-8",
    )
    state = build_project_state(tmp_path)
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)
    asset_inventory = report.split("## Asset Inventory", 1)[1].split("## Live HTTP Services", 1)[0]
    manual_queue = report.split("## Manual Review Queue", 1)[1].split("## Evidence Summary", 1)[0]

    assert "127.0.0.1" in asset_inventory
    assert "scanners" not in asset_inventory.lower()
    assert "exploitation" not in asset_inventory.lower()
    assert "scope review before testing scanners" not in manual_queue.lower()
    assert "scope review before testing exploitation" not in manual_queue.lower()


def test_operator_notes_are_context_not_queue_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_recon_pack")
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)

    assert "## Operator Notes / Context" in report
    assert "Notes are context only" in report
    assert "manual_note_review" not in report
    assert all(candidate.candidate_type != "manual_note_review" for candidate in candidates)


def test_lab_recon_pack_report_uses_evidence_first_sections() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_recon_pack")
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)

    assert "# BugSlyce Recon Pack" in report
    assert "## Attack Surface Summary" in report
    assert "## Manual Review Queue" in report
    assert "High-port HTTP services" in report
    assert "Robots artefacts" in report


def test_raw_recon_pack_report_includes_structured_evidence_sections() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_raw_recon_pack")
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)

    assert "# BugSlyce Recon Pack" in report
    assert "## Recon Manifest" in report
    assert "Schema version: `1.0`" in report
    assert "Artefact count: 14" in report
    assert "### Port Services" in report
    assert "### Discovered Paths" in report
    assert "### HTTP Artefacts" in report
    assert "### Raw Evidence References" in report


def test_report_workflow_summary_preserves_duplicate_path_evidence(
    tmp_path: Path,
) -> None:
    source = FIXTURES_ROOT / "lab_raw_recon_pack"
    for path in source.iterdir():
        if path.is_file():
            (tmp_path / path.name).write_bytes(path.read_bytes())
    manifest_path = tmp_path / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["profile"] = (
        "lab-tcp-full-plus-services-plus-http-metadata-plus-path-followup-"
        "plus-content-discovery-plus-content-followup-plus-body-fetch-"
        "plus-content-discovery"
    )
    duplicate_file = tmp_path / "gobuster-tiny-10.10.10.10-80-root.txt"
    duplicate_file.write_text(
        "hidden (Status: 301) [Size: 169] "
        "[--> http://10.10.10.10/hidden/]\n",
        encoding="utf-8",
    )
    manifest["artifacts"].append(
        {
            "type": "gobuster",
            "file": duplicate_file.name,
            "base_url": "http://10.10.10.10/",
            "description": "Approved lab-root-tiny root discovery",
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    state = build_project_state(tmp_path)
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)
    workflow = report.split("## Workflow / Provenance Summary", 1)[1].split(
        "## Input Files Processed",
        1,
    )[0]
    path_table = report.split("### Discovered Paths", 1)[1].split(
        "### HTTP Artefacts",
        1,
    )[0]
    raw_count = len(state.discovered_paths)
    unique_count = len({record.url for record in state.discovered_paths})

    assert "Base discovery profile: `lab-tcp-full`" in workflow
    assert "Content discovery profiles detected: `lab-root-tiny`, `lab-root-light`" in workflow
    assert f"Raw discovered path evidence rows: {raw_count}" in workflow
    assert f"Unique discovered paths: {unique_count}" in workflow
    assert f"Duplicate path rows retained for auditability: {raw_count - unique_count}" in workflow
    assert report.count("http://10.10.10.10/hidden/") >= 2
    assert "Repeated URLs may appear" in path_table
    assert "EVID-PATH-" in path_table
    assert "## Operator Summary" in report
    assert manifest["profile"] in report


def test_report_workflow_summary_detects_standard_bounded_core_profile(
    tmp_path: Path,
) -> None:
    source = FIXTURES_ROOT / "lab_raw_recon_pack"
    for path in source.iterdir():
        if path.is_file():
            (tmp_path / path.name).write_bytes(path.read_bytes())
    manifest_path = tmp_path / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"] = [
        artifact
        for artifact in manifest["artifacts"]
        if not artifact.get("file", "").startswith("gobuster-")
    ]
    bounded_file = tmp_path / "gobuster-standard-bounded-core-10.10.10.10-80-root.txt"
    bounded_file.write_text("login.php (Status: 200) [Size: 456]\n", encoding="utf-8")
    manifest["artifacts"].append(
        {
            "type": "gobuster",
            "file": bounded_file.name,
            "base_url": "http://10.10.10.10/",
            "description": "Bounded Standard content discovery",
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    state = build_project_state(tmp_path)
    report = render_markdown_report(state, generate_candidates(state))
    workflow = report.split("## Workflow / Provenance Summary", 1)[1].split(
        "## Input Files Processed",
        1,
    )[0]

    assert state.recon_manifest is not None
    assert "standard-bounded-core" in workflow
    assert "Content discovery profiles detected: `standard-bounded-core`" in workflow
    assert "lab-root-light" not in workflow


def test_operator_summary_prioritises_services_and_separates_noise() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_raw_recon_pack")
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)
    summary = report.split("## Operator Summary", 1)[1].split("## Scope Summary", 1)[0]
    review_first = summary.split("### Review First", 1)[1].split(
        "### Low-Signal / Avoid Rabbit Holes",
        1,
    )[0]
    low_signal = summary.split("### Low-Signal / Avoid Rabbit Holes", 1)[1].split(
        "### Current Coverage",
        1,
    )[0]

    assert "High-port HTTP service review" in review_first
    assert "Multiple HTTP services review" in review_first
    assert "Unusual robots user-agent context" in review_first
    assert "SSH service context on 2222/tcp" in review_first
    assert "Static assets" not in review_first
    assert "404/dead paths" not in review_first
    assert "Static assets" in low_signal
    assert "404/dead paths" in low_signal
    assert "EVID-" in summary
    assert "vulnerable" not in summary.lower()
    assert "exploitable" not in summary.lower()
    assert "confirmed issue" not in summary.lower()


def test_operator_summary_promotes_generic_body_fetched_200_path(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (tmp_path / "curl-headers-content-followup-portal.txt").write_text(
        "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 80\n",
        encoding="utf-8",
    )
    (tmp_path / "body-fetch-10.10.10.10-80-portal.html").write_text(
        "<html><head><title>Operator Portal</title></head>"
        "<body><a href=\"/dashboard\">Dashboard</a></body></html>",
        encoding="utf-8",
    )
    (tmp_path / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "scope_file": "scope.md",
                "profile": "lab-root-tiny-plus-content-followup-plus-body-fetch",
                "artifacts": [
                    {
                        "type": "http_headers",
                        "file": "curl-headers-content-followup-portal.txt",
                        "url": "http://10.10.10.10/portal/",
                        "description": (
                            "Bounded header request for content-discovery result follow-up"
                        ),
                    },
                    {
                        "type": "html",
                        "file": "body-fetch-10.10.10.10-80-portal.html",
                        "url": "http://10.10.10.10/portal/",
                        "description": (
                            "Bounded body request for selected high-signal "
                            "content-discovery follow-up path"
                        ),
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    state = build_project_state(tmp_path)
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)
    review_first = report.split("### Review First", 1)[1].split(
        "### Low-Signal / Avoid Rabbit Holes",
        1,
    )[0]

    assert "Fetched application page: /portal/" in review_first
    assert 'saved page title "Operator Portal"' in review_first
    assert "http://10.10.10.10/portal/" in review_first
    assert "EVID-HEADER-" in review_first
    assert "EVID-ART-" in review_first
    assert "Signal: `medium`" in review_first


def test_operator_summary_treats_documentation_encoded_match_as_noise() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_raw_recon_pack")
    state = replace(
        state,
        http_artifacts=[
            *state.http_artifacts,
            HTTPArtifact(
                url="http://10.10.10.10:65524/",
                artifact_type="encoded_like_artifact",
                value="/usr/share/doc/apache2/README.Debian.gz",
                source_file="homepage-65524.html",
                evidence_ids=["EVID-ART-NOISE"],
                tags=["encoded_or_hidden_artifact"],
            ),
        ],
    )
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)
    review_first = report.split("### Review First", 1)[1].split(
        "### Low-Signal / Avoid Rabbit Holes",
        1,
    )[0]
    low_signal = report.split("### Low-Signal / Avoid Rabbit Holes", 1)[1].split(
        "### Current Coverage",
        1,
    )[0]

    assert "EVID-ART-NOISE" not in review_first
    assert "Encoded detector likely-noise matches" in low_signal
    assert "EVID-ART-NOISE" in low_signal


def test_operator_summary_promotes_credential_like_homepage_artifacts() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_raw_recon_pack")
    pickle_artifacts = [
        HTTPArtifact(
            url="http://10.81.143.79/",
            artifact_type="page_title",
            value="Rick is sup4r cool",
            source_file="homepage-pickle.html",
            evidence_ids=["EVID-ART-TITLE"],
            tags=[],
        ),
        HTTPArtifact(
            url="http://10.81.143.79/",
            artifact_type="html_comment",
            value="DB_USER=appuser DB_PASSWORD=correct-horse-battery-staple",
            source_file="homepage-pickle.html",
            evidence_ids=["EVID-ART-USER"],
            tags=[],
        ),
        HTTPArtifact(
            url="http://10.81.143.79/",
            artifact_type="keyword_hit",
            value="password",
            source_file="homepage-pickle.html",
            evidence_ids=["EVID-ART-PASS"],
            tags=[],
        ),
        HTTPArtifact(
            url="http://10.81.143.79/",
            artifact_type="keyword_hit",
            value="secret",
            source_file="homepage-pickle.html",
            evidence_ids=["EVID-ART-SECRET"],
            tags=[],
        ),
    ]
    state = replace(state, http_artifacts=[*state.http_artifacts, *pickle_artifacts])
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)
    review_first = report.split("### Review First", 1)[1].split(
        "### Low-Signal / Avoid Rabbit Holes",
        1,
    )[0]
    manual_queue = report.split("## Manual Review Queue", 1)[1]

    first_item = review_first.strip().split("\n", 1)[0]
    assert "Credential-like artefact review in homepage HTML" in first_item
    assert "EVID-ART-USER" in review_first
    assert "EVID-ART-PASS" in review_first
    assert "EVID-ART-SECRET" in review_first
    assert "Signal: `high`" in review_first
    assert "Do not submit forms, brute force" in review_first
    assert "valid without explicit authorisation" in review_first
    assert "Static assets" not in first_item
    assert "SSH service context" not in first_item

    credential_candidate = next(
        candidate
        for candidate in candidates
        if candidate.candidate_type == "credential_like_artifact_review"
        and candidate.affected_endpoints == ["http://10.81.143.79/"]
    )
    assert credential_candidate.priority == "high"
    assert credential_candidate.evidence_ids == [
        "EVID-ART-USER",
        "EVID-ART-PASS",
        "EVID-ART-SECRET",
    ]
    assert f"#### {credential_candidate.id}" in manual_queue
    assert "Candidate type: `credential_like_artifact_review`" in manual_queue
    assert "Do not brute force." in manual_queue
    assert "Do not attempt authentication unless explicitly authorised." in manual_queue


def test_primary_report_plain_forbidden_route_owned_by_operator_summary() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    url = "https://app.example-bounty.test/admin"
    state = replace(
        state,
        endpoints=[
            Endpoint(
                url=url,
                hostname="app.example-bounty.test",
                path="/admin",
                query_params=[],
                evidence_ids=["EVID-PATH-ADMIN403"],
                tags=[],
            ),
        ],
        discovered_paths=[
            DiscoveredPath(
                url=url,
                status_code=403,
                content_length=12,
                redirect_location=None,
                source="gobuster",
                evidence_ids=["EVID-PATH-ADMIN403"],
                tags=[],
            )
        ],
    )
    candidates = generate_candidates(state)
    triage = render_human_triage_brief_markdown(build_human_triage_brief(state, candidates))
    report = render_markdown_report(state, candidates, human_triage_brief_markdown=triage)
    primary = report.split("## Scope Summary", 1)[0]
    start_here = primary.split("### Start Here", 1)[1].split(
        "### Evidence Values Worth Noting",
        1,
    )[0]

    assert primary.count("Access-controlled path context") == 1
    assert primary.count(url) == 1
    assert "access-control context" in primary
    assert url not in start_here
    assert "Admin/hidden route observed" not in primary
    assert "Admin-labelled route observed" not in primary


def test_primary_report_independent_forbidden_route_evidence_merges_operator_prompt() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    url = "https://app.example-bounty.test/management"
    state = replace(
        state,
        endpoints=[
            Endpoint(
                url=url,
                hostname="app.example-bounty.test",
                path="/management",
                query_params=[],
                evidence_ids=["EVID-SOURCE-MGMT"],
                tags=[],
            ),
        ],
        discovered_paths=[
            DiscoveredPath(
                url=url,
                status_code=403,
                content_length=12,
                redirect_location=None,
                source="gobuster",
                evidence_ids=["EVID-HTTP-MGMT403"],
                tags=[],
            )
        ],
    )
    candidates = generate_candidates(state)
    triage = render_human_triage_brief_markdown(build_human_triage_brief(state, candidates))
    report = render_markdown_report(state, candidates, human_triage_brief_markdown=triage)
    primary = report.split("## Scope Summary", 1)[0]

    assert primary.count(url) == 1
    assert "Independently referenced access-boundary route" in primary
    assert "bounded request returned HTTP 403" in primary
    assert "EVID-SOURCE-MGMT" in primary
    assert "EVID-HTTP-MGMT403" in primary
    assert "Access-controlled path context" not in primary
    lowered = primary.lower()
    assert "vulnerable" not in lowered
    assert "authentication bypass" not in lowered
    assert "exposed" not in lowered


def test_primary_report_non_forbidden_admin_route_can_still_promote() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    url = "https://app.example-bounty.test/admin"
    state = replace(
        state,
        endpoints=[
            Endpoint(
                url=url,
                hostname="app.example-bounty.test",
                path="/admin",
                query_params=[],
                evidence_ids=["EVID-ENDPOINT-ADMIN200"],
                tags=[],
            ),
        ],
    )
    candidates = generate_candidates(state)
    triage = render_human_triage_brief_markdown(build_human_triage_brief(state, candidates))
    report = render_markdown_report(state, candidates, human_triage_brief_markdown=triage)

    assert "Admin-labelled route observed" in report
    assert "Access-controlled path context" not in report


def test_encoded_artifact_classification_keeps_signal_noise_and_raw_rows() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_raw_recon_pack")
    signal = HTTPArtifact(
        url="http://10.10.10.10/hidden/",
        artifact_type="encoded_like_artifact",
        value="9fdafbd64c47471a8f54cd3fc64cd312",
        source_file="body-fetch-10.10.10.10-80-hidden.html",
        evidence_ids=["EVID-ART-SIGNAL"],
        tags=["encoded_or_hidden_artifact"],
    )
    noise = HTTPArtifact(
        url="http://10.10.10.10:65524/",
        artifact_type="encoded_like_artifact",
        value="org/TR/xhtml1/DTD/xhtml1",
        source_file="homepage-65524.html",
        evidence_ids=["EVID-ART-NOISE"],
        tags=["encoded_or_hidden_artifact"],
    )
    state = replace(state, http_artifacts=[*state.http_artifacts, signal, noise])
    candidates = generate_candidates(state)
    report = render_markdown_report(state, candidates)
    summary = report.split("## Operator Summary", 1)[1].split("## Scope Summary", 1)[0]
    classification = report.split("### Encoded Artefact Classification", 1)[1].split(
        "### Raw Evidence References",
        1,
    )[0]
    raw_artifacts = report.split("### HTTP Artefacts", 1)[1].split(
        "### Encoded Artefact Classification",
        1,
    )[0]

    assert "EVID-ART-SIGNAL" in summary
    assert "EVID-ART-NOISE" not in summary.split("### Review First", 1)[1].split(
        "### Low-Signal / Avoid Rabbit Holes",
        1,
    )[0]
    assert "Likely / Possible Signal" in classification
    assert "Likely Noise" in classification
    assert "`likely_signal`" in classification
    assert "`likely_noise`" in classification
    assert "EVID-ART-SIGNAL" in classification
    assert "EVID-ART-NOISE" in classification
    assert signal.value in raw_artifacts
    assert noise.value in raw_artifacts
    assert "vulnerable" not in classification.lower()
    assert "exploitable" not in classification.lower()


def test_raw_recon_pack_json_preserves_manifest_metadata() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_raw_recon_pack")
    candidates = generate_candidates(state)
    exported = json.loads(export_project_state_json(state, candidates))

    manifest = exported["project_state"]["recon_manifest"]
    assert manifest["schema_version"] == "1.0"
    assert manifest["target"] == "10.10.10.10"
    assert manifest["created_by"] == "manual"
    assert manifest["profile"] == "manual-import"
    assert len(manifest["artifacts"]) == 14
