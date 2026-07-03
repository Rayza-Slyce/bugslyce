"""Tests for Standard Human Triage Brief report rendering."""

from __future__ import annotations

from dataclasses import replace

from bugslyce.core.models import (
    Candidate,
    DiscoveredPath,
    Endpoint,
    HTTPArtifact,
    HTTPService,
    PortService,
    ProjectState,
)
from bugslyce.reports.human_triage import (
    build_human_triage_brief,
    render_human_triage_brief_markdown,
    render_readable_evidence_cards_markdown,
)


def test_human_triage_brief_promotes_universal_manual_review_signals() -> None:
    state = _project_state(
        http_services=[
            HTTPService(
                url="http://example.test:8080/",
                hostname="example.test",
                status_code=200,
                title="Example app",
                technologies=["Apache"],
                content_length=1234,
                evidence_ids=["EVID-HTTP-0001"],
                tags=[],
            )
        ],
        endpoints=[
            Endpoint(
                url="http://example.test/login",
                hostname="example.test",
                path="/login",
                query_params=[],
                evidence_ids=["EVID-ENDPOINT-LOGIN"],
                tags=[],
            ),
            Endpoint(
                url="http://example.test/static/jquery.js",
                hostname="example.test",
                path="/static/jquery.js",
                query_params=[],
                evidence_ids=["EVID-ENDPOINT-STATIC"],
                tags=[],
            ),
        ],
        discovered_paths=[
            DiscoveredPath(
                url="http://example.test/admin/",
                status_code=200,
                content_length=512,
                redirect_location=None,
                source="gobuster",
                evidence_ids=["EVID-PATH-ADMIN"],
                tags=["directory_listing"],
            )
        ],
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="unusual_user_agent",
                value="a18672860d0510e5ab6699730763b250",
                source_file="robots.txt",
                evidence_ids=["EVID-ART-ROBOTS"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Token-like review value: dG9rZW4tdmFsdWU=",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-COMMENT"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="encoded_like_artifact",
                value="L2FkbWluL3Jldmlldw==",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-ENCODED"],
                tags=["encoded_or_hidden_artifact"],
            ),
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="robots",
                value="/home/user/bugslyce-output/demo/robots-example.txt",
                source_file="/home/user/bugslyce-output/demo/robots-example.txt",
                evidence_ids=["EVID-ART-ROBOTS-FILE"],
                tags=[],
            ),
        ],
        port_services=[
            PortService(
                host="example.test",
                port=22,
                protocol="tcp",
                state="open",
                service="ssh",
                product="OpenSSH",
                version="9.2",
                source_file="nmap.xml",
                evidence_ids=["EVID-PORT-SSH"],
                tags=[],
            )
        ],
    )

    brief = build_human_triage_brief(state, [])
    markdown = render_human_triage_brief_markdown(brief)

    assert "## Human Triage Brief" in markdown
    assert "### Start Here" in markdown
    assert "### Evidence Values Worth Noting" in markdown
    assert "### Review Next" in markdown
    assert "### Ignore For Now" in markdown
    assert "### Raw Evidence Pointers" in markdown
    assert "Auth/account route observed" in markdown
    assert "Directory listing or browsable path observed" in markdown
    assert "robots.txt or metadata clue observed" in markdown
    assert "Source credential/context clue group observed" in markdown
    assert "source credential/context cluster" in markdown
    assert "SSH service context" in markdown
    assert "Static or library route" in markdown
    assert "EVID-ENDPOINT-LOGIN" in markdown
    assert "EVID-PATH-ADMIN" in markdown
    assert "EVID-ART-ROBOTS" in markdown
    assert "EVID-ART-COMMENT" in markdown
    assert "EVID-ART-ENCODED" in markdown
    assert "EVID-PORT-SSH" in markdown
    assert "EVID-ENDPOINT-STATIC" in markdown
    assert "/home/user/bugslyce-output" not in markdown
    assert "manual review prompts" in markdown
    assert "confirmed findings" in markdown
    assert "flag" not in markdown.lower()
    assert "exploit" not in markdown.lower()
    assert "vulnerable" not in markdown.lower()
    assert "brute force" not in markdown.lower()
    assert "password spraying" not in markdown.lower()
    assert "credential stuffing" not in markdown.lower()
    assert "form submission" not in markdown.lower()
    assert "payload injection" not in markdown.lower()


def test_readable_evidence_cards_are_bullet_blocks_not_tables() -> None:
    state = _project_state(
        discovered_paths=[
            DiscoveredPath(
                url="http://example.test/assets/",
                status_code=200,
                content_length=99,
                redirect_location=None,
                source="gobuster",
                evidence_ids=["EVID-PATH-DIR"],
                tags=["directory_listing"],
            )
        ]
    )
    brief = build_human_triage_brief(state, [])

    markdown = render_readable_evidence_cards_markdown(brief)

    assert "## Readable Evidence Cards" in markdown
    assert "### Directory listing or browsable path observed" in markdown
    assert "- URL: `http://example.test/assets/`" in markdown
    assert "- Signal: directory listing" in markdown
    assert "- Why it matters:" in markdown
    assert "- Suggested manual action:" in markdown
    assert "- Evidence: `EVID-PATH-DIR`" in markdown
    assert "| URL |" not in markdown


def test_human_triage_promotes_discovered_login_php_as_manual_auth_route() -> None:
    state = _project_state(
        discovered_paths=[
            DiscoveredPath(
                url="http://example.test/login.php",
                status_code=200,
                content_length=456,
                redirect_location=None,
                source="gobuster-standard-auth-core",
                evidence_ids=["EVID-PATH-LOGIN-PHP"],
                tags=[],
            )
        ]
    )

    brief = build_human_triage_brief(state, [])
    markdown = render_human_triage_brief_markdown(brief)
    cards = render_readable_evidence_cards_markdown(brief)

    assert "Auth/account path discovered" in markdown
    assert "http://example.test/login.php" in markdown
    assert "EVID-PATH-LOGIN-PHP" in markdown
    assert "local validation" in markdown
    assert "### Auth/account path discovered" in cards
    assert "- URL: `http://example.test/login.php`" in cards
    assert "- Signal: application route" in cards
    assert "vulnerable" not in markdown.lower()
    assert "credentials found" not in markdown.lower()
    assert "login bypass" not in markdown.lower()
    assert "brute force" not in markdown.lower()


def test_readable_evidence_cards_deduplicate_start_and_value_items() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Token-like review value: dG9rZW4tdmFsdWU=",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-COMMENT"],
                tags=[],
            )
        ]
    )

    markdown = render_readable_evidence_cards_markdown(build_human_triage_brief(state, []))

    assert markdown.count("### Source comment or keyword context observed") == 1
    assert markdown.count("EVID-ART-COMMENT") == 1


def test_readable_evidence_cards_do_not_duplicate_http_service_fallback() -> None:
    state = _project_state(
        http_services=[
            HTTPService(
                url="http://example.test/",
                hostname="example.test",
                status_code=200,
                title="Example app",
                technologies=[],
                content_length=42,
                evidence_ids=["EVID-HTTP-0001"],
                tags=[],
            )
        ]
    )

    markdown = render_readable_evidence_cards_markdown(build_human_triage_brief(state, []))

    assert markdown.count("http://example.test/") == 1
    assert markdown.count("EVID-HTTP-0001") == 1
    assert "### HTTP application surface review" in markdown
    assert "### HTTP service" not in markdown


def test_readable_evidence_cards_preserve_distinct_same_url_signals() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Token-like review value: dG9rZW4tdmFsdWU=",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-COMMENT"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="encoded_like_artifact",
                value="L2FkbWluL3Jldmlldw==",
                source_file="followup-body.html",
                evidence_ids=["EVID-ART-ENCODED"],
                tags=["encoded_or_hidden_artifact"],
            ),
        ]
    )

    markdown = render_readable_evidence_cards_markdown(build_human_triage_brief(state, []))

    assert "### Source comment or keyword context observed" in markdown
    assert "### Encoded-looking source artefact observed" in markdown
    assert "EVID-ART-COMMENT" in markdown
    assert "EVID-ART-ENCODED" in markdown


def test_human_triage_groups_same_source_comment_keyword_clues() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Note to self, remember username: demo-user",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-0006"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="keyword_hit",
                value="password",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-0007"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="keyword_hit",
                value="secret",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-0008"],
                tags=[],
            ),
        ]
    )

    brief = build_human_triage_brief(state, [])
    markdown = render_human_triage_brief_markdown(brief)

    start_here = markdown.split("### Start Here", 1)[1].split(
        "### Evidence Values Worth Noting",
        1,
    )[0]

    assert start_here.count("**Source credential/context clue group observed**") == 1
    assert "source credential/context cluster" in markdown
    assert "`EVID-ART-0006`, `EVID-ART-0007`, `EVID-ART-0008`" in markdown
    assert "Note to self, remember username: demo-user; password; secret" in markdown
    assert "Source comment or keyword context observed" not in start_here
    assert start_here.count("password") == 0
    assert start_here.count("secret") == 0
    assert "confirmed" not in start_here.lower()
    assert "flag" not in start_here.lower()
    assert "exploit" not in start_here.lower()
    assert "vulnerable" not in start_here.lower()


def test_human_triage_group_absorbs_matching_credential_like_candidate() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Note to self, remember username: demo-user",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-0006"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="keyword_hit",
                value="password",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-0007"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="keyword_hit",
                value="secret",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-0008"],
                tags=[],
            ),
        ]
    )
    candidate = Candidate(
        id="CAND-0001",
        candidate_type="credential_like_artifact_review",
        title="Credential-like artefact review in homepage HTML",
        priority="high",
        rationale="Source evidence contains credential-like context.",
        affected_assets=["example.test"],
        affected_endpoints=["http://example.test/"],
        evidence_ids=["EVID-ART-0006", "EVID-ART-0007", "EVID-ART-0008"],
        suggested_manual_validation=["Review source locally."],
        kill_switch_guidance=None,
    )

    markdown = render_human_triage_brief_markdown(build_human_triage_brief(state, [candidate]))

    start_here = markdown.split("### Start Here", 1)[1].split(
        "### Evidence Values Worth Noting",
        1,
    )[0]
    assert start_here.count("Source credential/context clue group observed") == 1
    assert "Credential-like artefact review in homepage HTML" not in start_here
    assert "`EVID-ART-0006`, `EVID-ART-0007`, `EVID-ART-0008`" in start_here


def test_readable_cards_group_same_source_clues_once() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Note to self, remember username: demo-user",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-0006"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="keyword_hit",
                value="password",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-0007"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="keyword_hit",
                value="secret",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-0008"],
                tags=[],
            ),
        ]
    )

    markdown = render_readable_evidence_cards_markdown(build_human_triage_brief(state, []))

    assert markdown.count("### Source credential/context clue group observed") == 1
    assert "### Source comment or keyword context observed" not in markdown
    assert "EVID-ART-0006" in markdown
    assert "EVID-ART-0007" in markdown
    assert "EVID-ART-0008" in markdown
    assert "Note to self, remember username: demo-user; password; secret" in markdown


def test_human_triage_promotes_robots_body_value_as_metadata_context() -> None:
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

    brief = build_human_triage_brief(state, [])
    markdown = render_human_triage_brief_markdown(brief)
    cards = render_readable_evidence_cards_markdown(brief)

    assert "robots.txt clue-like value observed" in markdown
    assert "Wubbalubbadubdub" in markdown
    assert "robots value" in markdown
    assert "Review the saved metadata body locally" in markdown
    assert "### robots.txt clue-like value observed" in cards
    assert "- URL: `http://example.test/robots.txt`" in cards
    assert "- Signal: robots value" in cards
    assert "- Value preview: `Wubbalubbadubdub`" in cards
    assert "valid credential" not in markdown.lower()
    assert "this is the password" not in markdown.lower()
    assert "probably the password" not in markdown.lower()
    assert "confirmed" not in cards.lower()
    assert "vulnerable" not in cards.lower()
    assert "exploit" not in cards.lower()


def test_human_triage_keeps_source_group_and_robots_value_separate() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Note to self, remember username: demo-user",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-SOURCE-1"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="keyword_hit",
                value="password",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-SOURCE-2"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="robots_value",
                value="Wubbalubbadubdub",
                source_file="robots-example.txt",
                evidence_ids=["EVID-ART-ROBOTS-VALUE"],
                tags=["robots_artifact"],
            ),
        ]
    )

    markdown = render_human_triage_brief_markdown(build_human_triage_brief(state, []))
    start_here = markdown.split("### Start Here", 1)[1].split(
        "### Evidence Values Worth Noting",
        1,
    )[0]

    assert "Source credential/context clue group observed" in start_here
    assert "robots.txt clue-like value observed" in start_here
    assert "username + robots" not in markdown.lower()
    assert "use this with the username" not in markdown.lower()
    assert "credentials found" not in markdown.lower()
    assert "probably the password" not in markdown.lower()


def test_human_triage_disallow_rule_is_route_context_not_credentials() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/robots.txt",
                artifact_type="disallow_rule",
                value="/admin/",
                source_file="robots-example.txt",
                evidence_ids=["EVID-ART-ROBOTS-DISALLOW"],
                tags=["robots_artifact"],
            )
        ]
    )

    markdown = render_human_triage_brief_markdown(build_human_triage_brief(state, []))

    assert "robots.txt or metadata clue observed" in markdown
    assert "/admin/" in markdown
    assert "valid credential" not in markdown.lower()
    assert "credentials found" not in markdown.lower()
    assert "password" not in markdown.lower()
    assert "confirmed credential" not in markdown.lower()


def test_human_triage_brief_separates_evidence_values_from_review_next() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Token-like review value: dG9rZW4tdmFsdWU=",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-COMMENT"],
                tags=[],
            )
        ]
    )

    markdown = render_human_triage_brief_markdown(build_human_triage_brief(state, []))
    evidence_values = markdown.split("### Evidence Values Worth Noting", 1)[1]

    assert "\n  - Evidence: `EVID-ART-COMMENT`\n\n### Review Next" in evidence_values


def test_human_triage_brief_output_is_deterministic() -> None:
    state = _project_state(
        endpoints=[
            Endpoint(
                url="http://example.test/admin",
                hostname="example.test",
                path="/admin",
                query_params=[],
                evidence_ids=["EVID-ENDPOINT-ADMIN"],
                tags=[],
            )
        ]
    )

    first = render_human_triage_brief_markdown(build_human_triage_brief(state, []))
    second = render_human_triage_brief_markdown(build_human_triage_brief(state, []))

    assert first == second


def test_human_triage_empty_state_is_safe_and_compact() -> None:
    brief = build_human_triage_brief(_project_state(), [])

    markdown = render_human_triage_brief_markdown(brief)

    assert "## Human Triage Brief" in markdown
    assert "No high-confidence manual triage leads were identified" in markdown
    assert "confirmed finding" not in markdown.lower()


def test_human_triage_candidate_input_is_not_mutated() -> None:
    state = _project_state()
    candidate = Candidate(
        id="CAND-0001",
        candidate_type="high_port_http_service",
        title="High-port HTTP service",
        priority="medium",
        rationale="Non-default HTTP port.",
        affected_assets=["example.test"],
        affected_endpoints=["http://example.test:8080/"],
        evidence_ids=["EVID-CAND-0001"],
        suggested_manual_validation=["Compare with default HTTP service."],
        kill_switch_guidance=None,
    )
    candidates = [candidate]
    before = replace(candidate)

    build_human_triage_brief(state, candidates)

    assert candidates == [before]


def _project_state(
    *,
    http_services: list[HTTPService] | None = None,
    endpoints: list[Endpoint] | None = None,
    port_services: list[PortService] | None = None,
    http_artifacts: list[HTTPArtifact] | None = None,
    discovered_paths: list[DiscoveredPath] | None = None,
) -> ProjectState:
    return ProjectState(
        project_name="human-triage-test",
        input_dir="/tmp/human-triage-test",
        processed_files=[],
        scope_summary="No scope file parsed.",
        assets=[],
        http_services=http_services or [],
        endpoints=endpoints or [],
        port_services=port_services or [],
        http_artifacts=http_artifacts or [],
        discovered_paths=discovered_paths or [],
        recon_summary=None,
        recon_manifest=None,
        evidence=[],
        warnings=[],
        generated_at="2026-07-01T00:00:00Z",
        engagement_context="unknown",
    )
