"""Tests for Standard Human Triage Brief report rendering."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from bugslyce.core.models import (
    Candidate,
    DiscoveredPath,
    Endpoint,
    Evidence,
    HTTPArtifact,
    HTTPService,
    PortService,
    ProjectState,
)
from bugslyce.recon.route_provenance import route_evidence_provenance
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
                value="Ops team: rotate the staging token before release",
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
    assert "Human-authored source comment observed" in markdown
    assert "html_comment" in markdown
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


def test_human_triage_treats_generic_login_form_as_auth_context_not_clue_group() -> None:
    state = _project_state(
        discovered_paths=[
            DiscoveredPath(
                url="http://example.test/login.php",
                status_code=200,
                content_length=456,
                redirect_location=None,
                source="gobuster-standard-bounded-core",
                evidence_ids=["EVID-PATH-LOGIN-PHP"],
                tags=[],
            )
        ],
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/login.php",
                artifact_type="form",
                value="",
                source_file="login.html",
                evidence_ids=["EVID-ART-FORM"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/login.php",
                artifact_type="input",
                value="name=username;type=text",
                source_file="login.html",
                evidence_ids=["EVID-ART-USER-INPUT"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/login.php",
                artifact_type="input",
                value="name=password;type=password",
                source_file="login.html",
                evidence_ids=["EVID-ART-PASS-INPUT"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/login.php",
                artifact_type="keyword_hit",
                value="login",
                source_file="login.html",
                evidence_ids=["EVID-ART-LOGIN"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/login.php",
                artifact_type="keyword_hit",
                value="password",
                source_file="login.html",
                evidence_ids=["EVID-ART-PASS"],
                tags=[],
            ),
        ],
    )

    markdown = render_human_triage_brief_markdown(build_human_triage_brief(state, []))
    cards = render_readable_evidence_cards_markdown(build_human_triage_brief(state, []))

    assert "Auth/account path discovered" in markdown
    assert "Source credential/context clue group observed" not in markdown
    assert "Credential-like artefact review in HTML for /login.php" not in markdown
    assert "Source credential/context clue group observed" not in cards
    assert "credentials found" not in markdown.lower()
    assert "valid credential" not in markdown.lower()
    assert "form submission" not in markdown.lower()
    assert "authentication testing" not in markdown.lower()


def test_readable_evidence_cards_deduplicate_start_and_value_items() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Ops team: rotate the staging token before release",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-COMMENT"],
                tags=[],
            )
        ]
    )

    markdown = render_readable_evidence_cards_markdown(build_human_triage_brief(state, []))

    assert markdown.count("### Human-authored source comment observed") == 1
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
                value="Ops team: rotate the staging token before release",
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

    assert "### Human-authored source comment observed" in markdown
    assert "### Encoded-looking source artefact observed" in markdown
    assert "EVID-ART-COMMENT" in markdown
    assert "EVID-ART-ENCODED" in markdown


def test_human_triage_groups_same_source_comment_keyword_clues() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Ops team: update credential configuration username: demo-user before release",
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

    assert start_here.count("**Human-authored source comment observed**") == 1
    assert "`EVID-ART-0006`" in markdown
    assert "EVID-ART-0007" not in start_here
    assert "EVID-ART-0008" not in start_here
    assert "Ops team: update credential configuration username: demo-user before release" in markdown
    assert "Source credential/context clue group observed" not in start_here
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
                value="Ops team: update credential configuration username: demo-user before release",
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
    assert start_here.count("Human-authored source comment observed") == 1
    assert "Credential-like artefact review in homepage HTML" not in start_here
    assert "`EVID-ART-0006`" in start_here


def test_readable_cards_group_same_source_clues_once() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Ops team: update credential configuration username: demo-user before release",
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

    assert markdown.count("### Human-authored source comment observed") == 1
    assert "### Source credential/context clue group observed" not in markdown
    assert "EVID-ART-0006" in markdown
    assert "EVID-ART-0007" not in markdown
    assert "EVID-ART-0008" not in markdown
    assert "Ops team: update credential configuration username: demo-user before release" in markdown


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
                value="Ops team: update credential configuration username: demo-user before release",
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

    assert "Human-authored source comment observed" in start_here
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
                value="Ops team: rotate the staging token before release",
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


def test_human_authored_operational_comment_is_rendered_with_excerpt_and_url() -> None:
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="html_comment",
                value="Jessie don't forget to udate the webiste",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-0015"],
                tags=[],
            ),
            HTTPArtifact(
                url="http://example.test/",
                artifact_type="keyword_hit",
                value="admin",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-0016"],
                tags=[],
            ),
        ]
    )

    brief = build_human_triage_brief(state, [])
    rendered = render_human_triage_brief_markdown(brief)

    assert "Jessie don't forget to udate the webiste" in rendered
    assert "http://example.test/" in rendered
    assert "EVID-ART-0015" in rendered
    assert "Credential-like artefact review" not in rendered


def test_varied_operational_source_comments_surface_without_exact_phrase_rules() -> None:
    comments = (
        "Sarah, update the staging configuration before release",
        "Dev team: remove the legacy login route before launch",
        "Mike, the backup page still points to the old server",
    )
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url=f"http://example.test/page-{index}.html",
                artifact_type="html_comment",
                value=value,
                source_file=f"page-{index}.html",
                evidence_ids=[f"EVID-COMMENT-{index}"],
                tags=[],
            )
            for index, value in enumerate(comments, start=1)
        ]
    )

    rendered = render_human_triage_brief_markdown(build_human_triage_brief(state, []))

    for index, value in enumerate(comments, start=1):
        assert value in rendered
        assert f"http://example.test/page-{index}.html" in rendered
        assert f"EVID-COMMENT-{index}" in rendered
    assert rendered.count("Human-authored source comment observed") >= 3
    assert "Credential-like artefact review" not in rendered


def test_generic_template_marketing_and_documentation_comments_stay_low_signal() -> None:
    comments = (
        "Remember to follow us on Twitter",
        "Password reset documentation",
        "User administration template",
        "Do not forget to subscribe",
        "Bootstrap template",
        "Facebook and Twitter integration",
        "Animate.css",
        "Icomoon Icon Fonts",
    )
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/template.html",
                artifact_type="html_comment",
                value=value,
                source_file="template.html",
                evidence_ids=[f"EVID-NOISE-{index}"],
                tags=[],
            )
            for index, value in enumerate(comments, start=1)
        ]
    )

    rendered = render_human_triage_brief_markdown(build_human_triage_brief(state, []))

    assert "Human-authored source comment observed" not in rendered
    assert "Source credential/context clue group observed" not in rendered
    assert "Credential-like artefact review" not in rendered


def test_structural_comment_noise_with_punctuation_stays_low_signal() -> None:
    comments = (
        "Copyright 2026 Example Company, all rights reserved.",
        "Licensed under permissive terms; see the distribution notice for details.",
        "Load component: responsive menu assets for the public landing page.",
        "Social metadata: share this article with your professional network.",
        "Deployment documentation heading: rotate token generation workflow.",
        "Subscribe today, review our new launch guide, and follow the product news.",
    )
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/page.html",
                artifact_type="html_comment",
                value=value,
                source_file="page.html",
                evidence_ids=[f"EVID-STRUCT-NOISE-{index}"],
                tags=[],
            )
            for index, value in enumerate(comments, start=1)
        ]
    )

    rendered = render_human_triage_brief_markdown(build_human_triage_brief(state, []))

    assert "Human-authored source comment observed" not in rendered
    assert "Source credential/context clue group observed" not in rendered
    assert "Credential-like artefact review" not in rendered


def test_differently_worded_operational_comment_surfaces_as_source_clue() -> None:
    comment = "Ops team: rotate the staging certificate before the next deployment"
    state = _project_state(
        http_artifacts=[
            HTTPArtifact(
                url="http://example.test/releases.html",
                artifact_type="html_comment",
                value=comment,
                source_file="releases.html",
                evidence_ids=["EVID-OPS-COMMENT"],
                tags=[],
            )
        ]
    )

    rendered = render_human_triage_brief_markdown(build_human_triage_brief(state, []))

    assert "Human-authored source comment observed" in rendered
    assert comment in rendered
    assert "http://example.test/releases.html" in rendered
    assert "EVID-OPS-COMMENT" in rendered
    assert "Credential-like artefact review" not in rendered


def test_forbidden_server_status_is_access_control_context_not_admin_prompt() -> None:
    state = _project_state(
        discovered_paths=[
            DiscoveredPath(
                url="http://example.test/server-status",
                status_code=403,
                content_length=12,
                redirect_location=None,
                source="gobuster",
                evidence_ids=["EVID-PATH-STATUS"],
                tags=[],
            )
        ]
    )

    brief = build_human_triage_brief(state, [])
    rendered = render_human_triage_brief_markdown(brief)

    assert "Access-control response context" not in rendered
    assert "HTTP 403" not in rendered
    assert "Admin/hidden path discovered" not in rendered


def test_endpoint_and_discovered_forbidden_route_have_one_access_boundary_prompt() -> None:
    url = "http://example.test/management"
    state = _project_state(
        endpoints=[
            Endpoint(
                url=url,
                hostname="example.test",
                path="/management",
                query_params=[],
                evidence_ids=["EVID-PATH-MGMT"],
                tags=[],
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url=url,
                status_code=403,
                content_length=12,
                redirect_location=None,
                source="gobuster",
                evidence_ids=["EVID-PATH-MGMT"],
                tags=[],
            )
        ],
    )

    rendered = render_human_triage_brief_markdown(build_human_triage_brief(state, []))
    before_pointers = rendered.split("### Raw Evidence Pointers", 1)[0]

    assert url not in before_pointers
    assert "Access-control response context" not in before_pointers
    assert "Admin-labelled route observed" not in before_pointers
    assert "Admin/hidden path discovered" not in before_pointers


def test_repeated_forbidden_collection_observations_are_not_independent() -> None:
    url = "https://portal.example.test/restricted-area"
    discovery = DiscoveredPath(
        url=url,
        status_code=403,
        content_length=24,
        redirect_location=None,
        source="bounded-discovery.txt",
        evidence_ids=["EVID-DISCOVERY"],
        tags=[],
    )
    followup = DiscoveredPath(
        url=url,
        status_code=403,
        content_length=24,
        redirect_location=None,
        source="bounded-header-followup.txt",
        evidence_ids=["EVID-FOLLOWUP"],
        tags=[],
    )
    endpoint = Endpoint(
        url=url,
        hostname="portal.example.test",
        path="/restricted-area",
        query_params=[],
        evidence_ids=["EVID-FOLLOWUP", "EVID-DISCOVERY"],
        tags=[],
    )

    first = build_human_triage_brief(
        _project_state(endpoints=[endpoint], discovered_paths=[discovery, followup]),
        [],
    )
    reversed_input = build_human_triage_brief(
        _project_state(
            endpoints=[replace(endpoint, evidence_ids=list(reversed(endpoint.evidence_ids)))],
            discovered_paths=[followup, discovery],
        ),
        [],
    )

    assert first.start_here == reversed_input.start_here == ()
    assert first.review_next == reversed_input.review_next
    assert all(url not in item for item in first.review_next)
    assert first.evidence_cards == reversed_input.evidence_cards == ()
    assert "Independently referenced access-boundary route" not in (
        render_human_triage_brief_markdown(first)
    )


def test_repeated_unauthorised_collection_observations_are_not_independent() -> None:
    url = "https://portal.example.test/member-area"
    state = _project_state(
        endpoints=[
            Endpoint(
                url=url,
                hostname="portal.example.test",
                path="/member-area",
                query_params=[],
                evidence_ids=["EVID-HEADERS-401", "EVID-DISCOVERY-401"],
                tags=[],
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url=url,
                status_code=401,
                content_length=20,
                redirect_location=None,
                source="bounded-discovery.txt",
                evidence_ids=["EVID-DISCOVERY-401"],
                tags=[],
            ),
            DiscoveredPath(
                url=url,
                status_code=401,
                content_length=20,
                redirect_location=None,
                source="bounded-header-followup.txt",
                evidence_ids=["EVID-HEADERS-401"],
                tags=[],
            ),
        ],
    )

    brief = build_human_triage_brief(state, [])

    assert all(item.url != url for item in brief.start_here)
    assert all(item.url != url for item in brief.evidence_cards)
    assert "Independently referenced access-boundary route" not in (
        render_human_triage_brief_markdown(brief)
    )


def test_endpoint_only_header_request_is_not_an_independent_reference() -> None:
    url = "https://portal.example.test/"
    state = _project_state(
        endpoints=[
            Endpoint(
                url=url,
                hostname="portal.example.test",
                path="/",
                query_params=[],
                evidence_ids=["EVID-DISCOVERY", "EVID-HEADERS"],
                tags=[],
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url=url,
                status_code=403,
                content_length=24,
                redirect_location=None,
                source="bounded-discovery.txt",
                evidence_ids=["EVID-DISCOVERY"],
                tags=[],
            )
        ],
        evidence=[
            Evidence(
                id="EVID-DISCOVERY",
                source_file="bounded-discovery.txt",
                evidence_type="discovered_path",
                value=url,
                context={"status_code": 403},
            ),
            Evidence(
                id="EVID-HEADERS",
                source_file="saved-headers.txt",
                evidence_type="http_headers",
                value=url,
                context={"status_code": 403},
            ),
        ],
    )

    provenance = route_evidence_provenance(state, url)
    brief = build_human_triage_brief(state, [])

    assert provenance.request_evidence_ids == (
        "EVID-DISCOVERY",
        "EVID-HEADERS",
    )
    assert provenance.independent_reference_evidence_ids == ()
    assert all(item.url != url for item in brief.start_here)
    assert all(url not in item for item in brief.review_next)
    assert all(item.url != url for item in brief.evidence_cards)


def test_html_reference_remains_independent_from_forbidden_response() -> None:
    url = "https://portal.example.test/restricted-area"
    state = _project_state(
        endpoints=[
            Endpoint(
                url=url,
                hostname="portal.example.test",
                path="/restricted-area",
                query_params=[],
                evidence_ids=["EVID-RESPONSE", "EVID-HTML-LINK"],
                tags=[],
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url=url,
                status_code=403,
                content_length=24,
                redirect_location=None,
                source="bounded-discovery.txt",
                evidence_ids=["EVID-RESPONSE"],
                tags=[],
            )
        ],
        evidence=[
            Evidence(
                id="EVID-RESPONSE",
                source_file="bounded-discovery.txt",
                evidence_type="discovered_path",
                value=url,
                context={"status_code": 403},
            ),
            Evidence(
                id="EVID-HTML-LINK",
                source_file="saved-page.html",
                evidence_type="link",
                value="/restricted-area",
                context={"url": "https://portal.example.test/"},
            ),
        ],
    )

    provenance = route_evidence_provenance(state, url)
    brief = build_human_triage_brief(state, [])
    promoted = next(item for item in brief.start_here if item.url == url)

    assert provenance.request_evidence_ids == ("EVID-RESPONSE",)
    assert provenance.independent_reference_evidence_ids == ("EVID-HTML-LINK",)
    assert promoted.title == "Independently referenced access-boundary route"
    assert promoted.evidence_ids == ("EVID-HTML-LINK", "EVID-RESPONSE")


def test_parsed_url_inventory_reference_remains_independent() -> None:
    url = "https://portal.example.test/restricted-area"
    state = _project_state(
        endpoints=[
            Endpoint(
                url=url,
                hostname="portal.example.test",
                path="/restricted-area",
                query_params=[],
                evidence_ids=["EVID-RESPONSE", "EVID-URL-INVENTORY"],
                tags=[],
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url=url,
                status_code=403,
                content_length=24,
                redirect_location=None,
                source="bounded-discovery.txt",
                evidence_ids=["EVID-RESPONSE"],
                tags=[],
            )
        ],
        evidence=[
            Evidence(
                id="EVID-RESPONSE",
                source_file="bounded-discovery.txt",
                evidence_type="discovered_path",
                value=url,
                context={"status_code": 403},
            ),
            Evidence(
                id="EVID-URL-INVENTORY",
                source_file="urls.txt",
                evidence_type="endpoint",
                value=url,
                context={"path": "/restricted-area"},
            ),
        ],
    )

    provenance = route_evidence_provenance(state, url)

    assert provenance.request_evidence_ids == ("EVID-RESPONSE",)
    assert provenance.independent_reference_evidence_ids == (
        "EVID-URL-INVENTORY",
    )


def test_unknown_endpoint_evidence_is_not_assumed_independent() -> None:
    url = "https://portal.example.test/restricted-area"
    state = _project_state(
        endpoints=[
            Endpoint(
                url=url,
                hostname="portal.example.test",
                path="/restricted-area",
                query_params=[],
                evidence_ids=["EVID-RESPONSE", "EVID-UNKNOWN"],
                tags=[],
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url=url,
                status_code=403,
                content_length=24,
                redirect_location=None,
                source="bounded-discovery.txt",
                evidence_ids=["EVID-RESPONSE"],
                tags=[],
            )
        ],
        evidence=[
            Evidence(
                id="EVID-RESPONSE",
                source_file="bounded-discovery.txt",
                evidence_type="discovered_path",
                value=url,
                context={"status_code": 403},
            )
        ],
    )

    provenance = route_evidence_provenance(state, url)

    assert provenance.request_evidence_ids == ("EVID-RESPONSE",)
    assert provenance.independent_reference_evidence_ids == ()


def test_robots_response_artefact_is_not_an_independent_route_reference() -> None:
    url = "https://portal.example.test/robots.txt"
    state = _project_state(
        endpoints=[
            Endpoint(
                url=url,
                hostname="portal.example.test",
                path="/robots.txt",
                query_params=[],
                evidence_ids=["EVID-ROBOTS-403", "EVID-ROBOTS-ARTEFACT"],
                tags=["robots_artifact"],
            )
        ],
        discovered_paths=[
            DiscoveredPath(
                url=url,
                status_code=403,
                content_length=24,
                redirect_location=None,
                source="bounded-discovery.txt",
                evidence_ids=["EVID-ROBOTS-403"],
                tags=[],
            )
        ],
        evidence=[
            Evidence(
                id="EVID-ROBOTS-403",
                source_file="bounded-discovery.txt",
                evidence_type="discovered_path",
                value=url,
                context={"status_code": 403},
            ),
            Evidence(
                id="EVID-ROBOTS-ARTEFACT",
                source_file="/tmp/saved-robots.txt",
                evidence_type="robots",
                value="/tmp/saved-robots.txt",
                context={"url": url, "tags": ["robots_artifact"]},
            ),
        ],
    )

    provenance = route_evidence_provenance(state, url)
    brief = build_human_triage_brief(state, [])

    assert provenance.request_evidence_ids == (
        "EVID-ROBOTS-403",
        "EVID-ROBOTS-ARTEFACT",
    )
    assert provenance.independent_reference_evidence_ids == ()
    assert all(item.url != url for item in brief.start_here)
    assert all(url not in item for item in brief.review_next)
    assert all(item.url != url for item in brief.evidence_cards)


def test_correlated_admin_route_without_forbidden_boundary_can_still_promote() -> None:
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

    rendered = render_human_triage_brief_markdown(build_human_triage_brief(state, []))

    assert "Admin-labelled route observed" in rendered
    assert "Access-control response context" not in rendered


def test_test_route_uses_non_admin_title_in_triage_and_readable_card() -> None:
    url = "http://example.test/test"
    state = _project_state(
        endpoints=[
            Endpoint(
                url=url,
                hostname="example.test",
                path="/test",
                query_params=[],
                evidence_ids=["EVID-ENDPOINT-TEST"],
                tags=[],
            )
        ]
    )

    brief = build_human_triage_brief(state, [])
    triage_item = next(item for item in brief.start_here if item.url == url)
    card = next(item for item in brief.evidence_cards if item.url == url)

    assert triage_item.title == "Test/development route observed"
    assert card.title == triage_item.title
    assert "Admin-labelled" not in render_human_triage_brief_markdown(brief)
    assert "Admin-labelled" not in render_readable_evidence_cards_markdown(brief)


def test_bounded_admin_path_segment_keeps_admin_title() -> None:
    for path in ("/admin", "/admin/", "/admin/index.php"):
        url = f"http://example.test{path}"
        state = _project_state(
            endpoints=[
                Endpoint(
                    url=url,
                    hostname="example.test",
                    path=path,
                    query_params=[],
                    evidence_ids=[f"EVID-{path}"],
                    tags=[],
                )
            ]
        )

        brief = build_human_triage_brief(state, [])

        assert next(item for item in brief.start_here if item.url == url).title == (
            "Admin-labelled route observed"
        )


def test_structured_configuration_suppresses_duplicate_test_route_prompt() -> None:
    url = "http://example.test/test"
    state = _project_state(
        endpoints=[
            Endpoint(
                url=url,
                hostname="example.test",
                path="/test",
                query_params=[],
                evidence_ids=["EVID-ENDPOINT-TEST"],
                tags=[],
            )
        ]
    )
    orchestration = SimpleNamespace(
        source_route_collection_review=SimpleNamespace(
            review_leads=(
                SimpleNamespace(
                    category="structured_configuration_body",
                    urls=(url,),
                    final_urls=(url,),
                    evidence_ids=("EVID-CONFIG",),
                    evidence_excerpt=("service_port 9000",),
                ),
            )
        )
    )

    brief = build_human_triage_brief(
        state,
        [],
        deep_orchestration=orchestration,
        workflow_leads=(),
    )

    assert all(item.url != url for item in brief.start_here)
    assert all(item.url != url for item in brief.evidence_cards)
    from bugslyce.project_pipeline import _deep_operator_summary_leads

    direct_lead = _deep_operator_summary_leads(orchestration)[0]
    assert direct_lead.title == "Structured operational configuration observed"
    assert direct_lead.endpoints == [url]
    assert direct_lead.evidence_ids == ["EVID-CONFIG"]


def test_successful_deep_text_response_is_available_for_primary_offline_review() -> None:
    url = "https://portal.example.test/public/notice.txt"
    orchestration = SimpleNamespace(
        source_route_collection_review=SimpleNamespace(review_leads=()),
        successful_content_reviews=(
            SimpleNamespace(
                review_id="DEEP-CONTENT-0001",
                canonical_url=url,
                requested_urls=(url,),
                status_code=200,
                content_type="text/plain",
                body_bytes=42,
                body_sha256="a" * 64,
                body_preview="Scheduled maintenance starts at 18:00.",
                evidence_ids=("EVID-DEEP-TEXT",),
                artefact_references=("deep_source_route_collection.json",),
            ),
        ),
    )

    brief = build_human_triage_brief(
        _project_state(),
        [],
        deep_orchestration=orchestration,
        workflow_leads=(),
    )
    rendered = render_human_triage_brief_markdown(brief)

    assert "Successfully collected Deep content" in rendered
    assert url in rendered
    assert "HTTP 200" in rendered
    assert "Scheduled maintenance starts at 18:00." in rendered
    assert "EVID-DEEP-TEXT" in rendered
    assert "deep_source_route_collection.json" in rendered


def test_existing_primary_route_and_deep_response_remain_complementary() -> None:
    url = "https://portal.example.test/review/item"
    candidate = Candidate(
        id="CAND-ROUTE",
        candidate_type="hidden_path_review",
        title="Application route review",
        priority="medium",
        rationale="A directly observed application route warrants manual review.",
        affected_assets=["portal.example.test"],
        affected_endpoints=[url],
        evidence_ids=["EVID-ROUTE"],
        suggested_manual_validation=["Review the retained route evidence."],
        kill_switch_guidance=None,
    )
    orchestration = SimpleNamespace(
        source_route_collection_review=SimpleNamespace(review_leads=()),
        successful_content_reviews=(
            SimpleNamespace(
                review_id="DEEP-CONTENT-0001",
                canonical_url=url,
                requested_urls=(url,),
                status_code=200,
                content_type="text/plain",
                body_bytes=19,
                body_sha256="d" * 64,
                body_preview="Retained route body.",
                evidence_ids=("EVID-DEEP-RESPONSE",),
                artefact_references=("deep_source_route_collection.json",),
            ),
        ),
    )

    rendered = render_human_triage_brief_markdown(
        build_human_triage_brief(
            _project_state(),
            [candidate],
            deep_orchestration=orchestration,
            workflow_leads=(),
        )
    )

    assert rendered.count("Application route review") == 1
    assert rendered.count("**Successfully collected Deep content**") == 1
    assert "EVID-ROUTE" in rendered
    assert "EVID-DEEP-RESPONSE" in rendered
    assert "not confirmed findings" in rendered


def _project_state(
    *,
    http_services: list[HTTPService] | None = None,
    endpoints: list[Endpoint] | None = None,
    port_services: list[PortService] | None = None,
    http_artifacts: list[HTTPArtifact] | None = None,
    discovered_paths: list[DiscoveredPath] | None = None,
    evidence: list[Evidence] | None = None,
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
        evidence=evidence or [],
        warnings=[],
        generated_at="2026-07-01T00:00:00Z",
        engagement_context="unknown",
    )
