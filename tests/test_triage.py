"""Tests for deterministic triage candidate generation."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from bugslyce.core.models import DiscoveredPath, Endpoint, Evidence, HTTPArtifact, ProjectState
from bugslyce.core.project import build_project_state
from bugslyce.recon.robots_policy import (
    represented_robots_status_codes,
    robots_policy_review_eligible,
)
from bugslyce.reports.human_triage import build_human_triage_brief
from bugslyce.triage.candidates import generate_candidates


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def _robots_response_state(
    *,
    status_code: int | None,
    artefacts: list[HTTPArtifact] | None = None,
) -> ProjectState:
    url = "https://portal.example.test/robots.txt"
    robots_artefacts = artefacts or [
        HTTPArtifact(
            url=url,
            artifact_type="robots",
            value="/tmp/robots-negative-response/robots-portal.txt",
            source_file="/tmp/robots-negative-response/robots-portal.txt",
            evidence_ids=["EVID-ROBOTS-ARTEFACT"],
            tags=["robots_artifact"],
        )
    ]
    evidence = [
        Evidence(
            id="EVID-ROBOTS-ARTEFACT",
            source_file="robots-portal.txt",
            evidence_type="robots",
            value="retained robots response",
            context={"url": url, "status_code": status_code},
        )
    ]
    discovered_paths = []
    path_evidence_ids: list[str] = []
    if status_code is not None:
        path_evidence_ids.append("EVID-ROBOTS-STATUS")
        discovered_paths.append(
            DiscoveredPath(
                url=url,
                status_code=status_code,
                content_length=128,
                redirect_location=None,
                source="robots-portal.txt",
                evidence_ids=path_evidence_ids,
                tags=["dead_path"] if status_code == 404 else [],
            )
        )
        evidence.insert(
            0,
            Evidence(
                id="EVID-ROBOTS-STATUS",
                source_file="robots-portal.txt",
                evidence_type="discovered_path",
                value=url,
                context={"status_code": status_code},
            ),
        )
    return ProjectState(
        project_name="robots-negative-response",
        input_dir="/tmp/robots-negative-response",
        processed_files=["robots-portal.txt"],
        scope_summary="Synthetic authorised scope.",
        assets=[],
        http_services=[],
        endpoints=[
            Endpoint(
                url=url,
                hostname="portal.example.test",
                path="/robots.txt",
                query_params=[],
                evidence_ids=[*path_evidence_ids, "EVID-ROBOTS-ARTEFACT"],
                tags=["robots_artifact"],
            )
        ],
        port_services=[],
        http_artifacts=robots_artefacts,
        discovered_paths=discovered_paths,
        recon_summary=None,
        recon_manifest=None,
        evidence=evidence,
        warnings=[],
        generated_at="2026-07-20T00:00:00Z",
    )


def test_missing_robots_response_does_not_create_policy_review_candidate() -> None:
    state = _robots_response_state(status_code=404)

    candidates = generate_candidates(state)
    brief = build_human_triage_brief(state, candidates)

    assert all(candidate.candidate_type != "robots_artifact" for candidate in candidates)
    assert all("robots" not in item.title.lower() for item in brief.start_here)
    assert all("robots" not in item.lower() for item in brief.review_next)
    assert all("robots" not in card.title.lower() for card in brief.evidence_cards)
    assert {item.id for item in state.evidence} == {
        "EVID-ROBOTS-STATUS",
        "EVID-ROBOTS-ARTEFACT",
    }
    assert state.discovered_paths[0].status_code == 404


def test_missing_plaintext_robots_value_does_not_create_policy_review() -> None:
    url = "https://portal.example.test/robots.txt"
    state = _robots_response_state(
        status_code=404,
        artefacts=[
            HTTPArtifact(
                url=url,
                artifact_type="robots_value",
                value="Resource unavailable",
                source_file="robots-portal.txt",
                evidence_ids=["EVID-ROBOTS-ARTEFACT"],
                tags=["robots_artifact"],
            )
        ],
    )

    candidates = generate_candidates(state)
    brief = build_human_triage_brief(state, candidates)

    assert all(candidate.candidate_type != "robots_artifact" for candidate in candidates)
    assert not brief.start_here
    assert not brief.evidence_cards


def test_successful_robots_directives_preserve_candidate_and_triage() -> None:
    url = "https://portal.example.test/robots.txt"
    state = _robots_response_state(
        status_code=200,
        artefacts=[
            HTTPArtifact(
                url=url,
                artifact_type="disallow_rule",
                value="/private-area/",
                source_file="robots-portal.txt",
                evidence_ids=["EVID-ROBOTS-ARTEFACT"],
                tags=["robots_artifact"],
            )
        ],
    )

    candidates = generate_candidates(state)
    brief = build_human_triage_brief(state, candidates)
    robots_candidate = next(
        candidate for candidate in candidates if candidate.candidate_type == "robots_artifact"
    )

    assert robots_candidate.evidence_ids == [
        "EVID-ROBOTS-STATUS",
        "EVID-ROBOTS-ARTEFACT",
    ]
    assert robots_candidate.priority == "kill_switch"
    assert any("robots.txt or metadata clue observed" in item.title for item in brief.start_here)


def test_unknown_robots_status_preserves_legacy_candidate_behaviour() -> None:
    state = _robots_response_state(status_code=None)

    candidates = generate_candidates(state)

    assert any(candidate.candidate_type == "robots_artifact" for candidate in candidates)


def test_missing_robots_classification_is_order_deterministic() -> None:
    state = _robots_response_state(status_code=404)
    reversed_state = replace(
        state,
        evidence=list(reversed(state.evidence)),
        endpoints=[
            replace(
                state.endpoints[0],
                evidence_ids=list(reversed(state.endpoints[0].evidence_ids)),
            )
        ],
        discovered_paths=list(reversed(state.discovered_paths)),
        http_artifacts=list(reversed(state.http_artifacts)),
    )

    assert generate_candidates(state) == generate_candidates(reversed_state)
    assert build_human_triage_brief(state, []) == build_human_triage_brief(
        reversed_state,
        [],
    )


def test_mixed_and_duplicate_robots_statuses_are_deterministic() -> None:
    state = _robots_response_state(status_code=404)
    mixed_paths = [
        *state.discovered_paths,
        replace(
            state.discovered_paths[0],
            status_code=200,
            evidence_ids=["EVID-ROBOTS-SECOND"],
        ),
        replace(state.discovered_paths[0]),
    ]
    mixed_state = replace(state, discovered_paths=mixed_paths)
    reversed_state = replace(mixed_state, discovered_paths=list(reversed(mixed_paths)))

    assert represented_robots_status_codes(mixed_state, state.endpoints[0].url) == (
        200,
        404,
    )
    assert represented_robots_status_codes(
        reversed_state,
        state.endpoints[0].url,
    ) == (200, 404)
    assert robots_policy_review_eligible(mixed_state, state.endpoints[0].url) is True
    assert generate_candidates(mixed_state) == generate_candidates(reversed_state)


def test_generate_candidates_basic_saas() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    assert candidates
    assert len(candidates) < 25
    assert candidates[0].id == "CAND-0001"
    assert {candidate.candidate_type for candidate in candidates} >= {
        "auth_surface",
        "admin_surface",
        "environment_surface",
        "api_surface",
        "file_or_content_surface",
        "object_reference_review",
        "redirect_parameter_review",
        "technology_review",
        "low_signal_static",
    }
    assert "manual_note_review" not in {candidate.candidate_type for candidate in candidates}


def test_auth_endpoints_create_auth_review_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    auth_candidates = [candidate for candidate in candidates if candidate.candidate_type == "auth_surface"]
    app_auth_candidates = [
        candidate for candidate in auth_candidates if candidate.affected_assets == ["app.example-bounty.test"]
    ]

    assert auth_candidates
    assert len(app_auth_candidates) == 1
    assert len(app_auth_candidates[0].affected_endpoints) > 1
    assert any("/login" in endpoint for endpoint in app_auth_candidates[0].affected_endpoints)
    assert any("/account" in endpoint for endpoint in app_auth_candidates[0].affected_endpoints)
    assert "manual review" in app_auth_candidates[0].title.lower()
    assert len(app_auth_candidates[0].evidence_ids) == len(app_auth_candidates[0].affected_endpoints)


def test_html_comment_username_creates_credential_like_review_candidate() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    state = replace(
        state,
        http_artifacts=[
            *state.http_artifacts,
            HTTPArtifact(
                url="https://app.example-bounty.test/",
                artifact_type="html_comment",
                value="Note to self, remember username! Username: R1ckRul3s",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-USER"],
                tags=[],
            ),
        ],
    )

    candidate = next(
        candidate
        for candidate in generate_candidates(state)
        if candidate.candidate_type == "credential_like_artifact_review"
    )

    assert candidate.priority == "medium"
    assert "Credential-like artefact review" in candidate.title
    assert candidate.candidate_type == "credential_like_artifact_review"
    assert candidate.affected_endpoints == ["https://app.example-bounty.test/"]
    assert candidate.evidence_ids == ["EVID-ART-USER"]
    assert "valid credential" not in candidate.rationale.lower()
    assert any("Do not brute force" in item for item in candidate.suggested_manual_validation)
    assert any(
        "Do not attempt authentication unless explicitly authorised" in item
        for item in candidate.suggested_manual_validation
    )


def test_keyword_only_sensitive_hits_do_not_create_credential_candidate() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    state = replace(
        state,
        http_artifacts=[
            *state.http_artifacts,
            HTTPArtifact(
                url="https://app.example-bounty.test/",
                artifact_type="keyword_hit",
                value="password",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-PASS"],
                tags=[],
            ),
            HTTPArtifact(
                url="https://app.example-bounty.test/",
                artifact_type="keyword_hit",
                value="secret",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-SECRET"],
                tags=[],
            ),
        ],
    )

    credential_candidates = [
        candidate
        for candidate in generate_candidates(state)
        if candidate.candidate_type == "credential_like_artifact_review"
    ]

    assert credential_candidates == []


def test_contextual_secret_comment_creates_review_candidate_with_supporting_keywords() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    state = replace(
        state,
        http_artifacts=[
            *state.http_artifacts,
            HTTPArtifact(
                url="https://app.example-bounty.test/",
                artifact_type="html_comment",
                value="Deployment note: api_key = sk_test_placeholder_12345",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-COMMENT"],
                tags=[],
            ),
            HTTPArtifact(
                url="https://app.example-bounty.test/",
                artifact_type="keyword_hit",
                value="secret",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-SECRET"],
                tags=[],
            ),
        ],
    )

    credential_candidates = [
        candidate
        for candidate in generate_candidates(state)
        if candidate.candidate_type == "credential_like_artifact_review"
    ]

    assert len(credential_candidates) == 1
    assert credential_candidates[0].priority == "high"
    assert credential_candidates[0].evidence_ids == ["EVID-ART-COMMENT", "EVID-ART-SECRET"]
    assert "confirmed credential" not in credential_candidates[0].kill_switch_guidance.lower()


def test_generic_template_keywords_do_not_create_credential_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    url = "https://app.example-bounty.test/sitemap/"
    state = replace(
        state,
        http_artifacts=[
            HTTPArtifact(
                url=url,
                artifact_type="keyword_hit",
                value=value,
                source_file="sitemap.html",
                evidence_ids=[f"EVID-ART-{index:04d}"],
                tags=[],
            )
            for index, value in enumerate(("admin", "api", "key", "token", "user"), start=1)
        ],
    )

    credential_candidates = [
        candidate
        for candidate in generate_candidates(state)
        if candidate.candidate_type == "credential_like_artifact_review"
    ]

    assert credential_candidates == []


def test_security_vocabulary_comments_without_values_do_not_create_credential_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    comments = (
        "Password reset page",
        "Pass this note to the frontend team",
        "Token generation documentation",
        "Username field styling",
        "Secret management documentation",
    )
    state = replace(
        state,
        http_artifacts=[
            HTTPArtifact(
                url="https://app.example-bounty.test/docs.html",
                artifact_type="html_comment",
                value=value,
                source_file="docs.html",
                evidence_ids=[f"EVID-COMMENT-{index}"],
                tags=[],
            )
            for index, value in enumerate(comments, start=1)
        ],
    )

    credential_candidates = [
        candidate
        for candidate in generate_candidates(state)
        if candidate.candidate_type == "credential_like_artifact_review"
    ]

    assert credential_candidates == []


def test_documentation_assignments_do_not_create_credential_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    comments = (
        "password: reset",
        "token: generation",
        "secret = management",
        "username: field",
        "api key: documentation",
    )
    state = replace(
        state,
        http_artifacts=[
            HTTPArtifact(
                url="https://app.example-bounty.test/docs.html",
                artifact_type="html_comment",
                value=value,
                source_file="docs.html",
                evidence_ids=[f"EVID-DOC-{index}"],
                tags=[],
            )
            for index, value in enumerate(comments, start=1)
        ],
    )

    credential_candidates = [
        candidate
        for candidate in generate_candidates(state)
        if candidate.candidate_type == "credential_like_artifact_review"
    ]

    assert credential_candidates == []


def test_standalone_username_assignment_creates_medium_review_candidate() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    state = replace(
        state,
        http_artifacts=[
            HTTPArtifact(
                url="https://app.example-bounty.test/config.html",
                artifact_type="html_comment",
                value="username: appuser",
                source_file="config.html",
                evidence_ids=["EVID-USER"],
                tags=[],
            ),
        ],
    )

    credential_candidates = [
        candidate
        for candidate in generate_candidates(state)
        if candidate.candidate_type == "credential_like_artifact_review"
    ]

    assert len(credential_candidates) == 1
    assert credential_candidates[0].priority == "medium"
    assert credential_candidates[0].evidence_ids == ["EVID-USER"]


def test_username_password_pair_comment_creates_review_candidate() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    state = replace(
        state,
        http_artifacts=[
            HTTPArtifact(
                url="https://app.example-bounty.test/",
                artifact_type="html_comment",
                value="DB_USER=appuser DB_PASSWORD=correct-horse-battery-staple",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-PAIR"],
                tags=[],
            ),
        ],
    )

    credential_candidates = [
        candidate
        for candidate in generate_candidates(state)
        if candidate.candidate_type == "credential_like_artifact_review"
    ]

    assert len(credential_candidates) == 1
    assert credential_candidates[0].priority == "high"
    assert credential_candidates[0].evidence_ids == ["EVID-ART-PAIR"]


def test_keyword_matching_respects_token_boundaries() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    state = replace(
        state,
        http_artifacts=[
            HTTPArtifact(
                url="https://app.example-bounty.test/",
                artifact_type="keyword_hit",
                value="admin",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-ADMIN"],
                tags=[],
            ),
            HTTPArtifact(
                url="https://app.example-bounty.test/",
                artifact_type="keyword_hit",
                value="api",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-API"],
                tags=[],
            ),
        ],
    )

    assert not [
        candidate
        for candidate in generate_candidates(state)
        if candidate.candidate_type == "credential_like_artifact_review"
    ]


def test_comment_and_keyword_hits_on_same_url_are_grouped() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    state = replace(
        state,
        http_artifacts=[
            *state.http_artifacts,
            HTTPArtifact(
                url="https://app.example-bounty.test/",
                artifact_type="html_comment",
                value="Username: R1ckRul3s",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-USER"],
                tags=[],
            ),
            HTTPArtifact(
                url="https://app.example-bounty.test/",
                artifact_type="keyword_hit",
                value="password",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-PASS"],
                tags=[],
            ),
            HTTPArtifact(
                url="https://app.example-bounty.test/",
                artifact_type="keyword_hit",
                value="secret",
                source_file="homepage.html",
                evidence_ids=["EVID-ART-SECRET"],
                tags=[],
            ),
        ],
    )

    credential_candidates = [
        candidate
        for candidate in generate_candidates(state)
        if candidate.candidate_type == "credential_like_artifact_review"
    ]

    assert len(credential_candidates) == 1
    assert credential_candidates[0].priority == "medium"
    assert credential_candidates[0].evidence_ids == [
        "EVID-ART-USER",
        "EVID-ART-PASS",
        "EVID-ART-SECRET",
    ]


def test_generic_login_form_fields_do_not_create_credential_like_candidate() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    login_url = "https://app.example-bounty.test/login.php"
    state = replace(
        state,
        http_artifacts=[
            HTTPArtifact(
                url=login_url,
                artifact_type="form",
                value="",
                source_file="login.html",
                evidence_ids=["EVID-ART-FORM"],
                tags=[],
            ),
            HTTPArtifact(
                url=login_url,
                artifact_type="input",
                value="name=username;type=text",
                source_file="login.html",
                evidence_ids=["EVID-ART-USER-INPUT"],
                tags=[],
            ),
            HTTPArtifact(
                url=login_url,
                artifact_type="input",
                value="name=password;type=password",
                source_file="login.html",
                evidence_ids=["EVID-ART-PASS-INPUT"],
                tags=[],
            ),
            HTTPArtifact(
                url=login_url,
                artifact_type="keyword_hit",
                value="login",
                source_file="login.html",
                evidence_ids=["EVID-ART-LOGIN-KEYWORD"],
                tags=[],
            ),
            HTTPArtifact(
                url=login_url,
                artifact_type="keyword_hit",
                value="password",
                source_file="login.html",
                evidence_ids=["EVID-ART-PASS-KEYWORD"],
                tags=[],
            ),
        ],
    )

    credential_candidates = [
        candidate
        for candidate in generate_candidates(state)
        if candidate.candidate_type == "credential_like_artifact_review"
    ]

    assert not any(login_url in candidate.affected_endpoints for candidate in credential_candidates)


def test_api_account_resource_path_does_not_create_auth_candidate() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)
    api_resource_url = "https://api.example-bounty.test/v1/accounts/1001/orders?order_id=5001"

    assert any(
        api_resource_url in endpoint
        for candidate in candidates
        if candidate.candidate_type == "object_reference_review"
        for endpoint in candidate.affected_endpoints
    )
    assert not any(
        api_resource_url in endpoint
        for candidate in candidates
        if candidate.candidate_type == "auth_surface"
        for endpoint in candidate.affected_endpoints
    )


def test_profile_route_requires_direct_file_evidence_for_file_candidate() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    url = "https://app.example-bounty.test/profile.php"
    endpoint = Endpoint(
        url=url,
        hostname="app.example-bounty.test",
        path="/profile.php",
        query_params=[],
        evidence_ids=["EVID-ENDPOINT-PROFILE"],
        tags=["auth_surface"],
    )
    without_file_control = replace(state, endpoints=[endpoint], http_artifacts=[])

    assert not any(
        item.candidate_type == "file_or_content_surface"
        for item in generate_candidates(without_file_control)
    )

    with_file_control = replace(
        without_file_control,
        http_artifacts=[
            HTTPArtifact(
                url=url,
                artifact_type="input",
                value="name=attachment;type=file",
                source_file="profile.html",
                evidence_ids=["EVID-FILE-CONTROL"],
                tags=[],
            )
        ],
    )
    first = generate_candidates(with_file_control)
    second = generate_candidates(with_file_control)
    candidate = next(
        item for item in first if item.candidate_type == "file_or_content_surface"
    )

    assert first == second
    assert candidate.affected_endpoints == [url]
    assert candidate.evidence_ids == ["EVID-ENDPOINT-PROFILE", "EVID-FILE-CONTROL"]
    assert any(
        item.candidate_type == "auth_surface" and url in item.affected_endpoints
        for item in first
    )


def test_api_object_like_params_create_object_reference_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    object_candidates = [
        candidate for candidate in candidates if candidate.candidate_type == "object_reference_review"
    ]

    assert object_candidates
    assert any("tenant_id" in endpoint for candidate in object_candidates for endpoint in candidate.affected_endpoints)
    assert all("object reference" in candidate.title.lower() for candidate in object_candidates)


def test_redirect_like_params_create_redirect_parameter_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    redirect_candidates = [
        candidate for candidate in candidates if candidate.candidate_type == "redirect_parameter_review"
    ]

    assert redirect_candidates
    assert any("next=" in endpoint for candidate in redirect_candidates for endpoint in candidate.affected_endpoints)
    assert all("redirect-parameter" in candidate.title.lower() for candidate in redirect_candidates)


def test_static_cdn_assets_are_low_or_kill_switch() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)

    static_candidates = [candidate for candidate in candidates if candidate.candidate_type == "low_signal_static"]

    assert static_candidates
    assert all(candidate.priority in {"low", "kill_switch"} for candidate in static_candidates)
    assert any("static" in (candidate.kill_switch_guidance or "").lower() for candidate in static_candidates)


def test_grouped_endpoint_candidates_preserve_endpoints_and_evidence() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)
    grouped = next(
        candidate
        for candidate in candidates
        if candidate.candidate_type == "object_reference_review"
        and candidate.affected_assets == ["app.example-bounty.test"]
    )

    assert len(grouped.affected_endpoints) == 3
    assert len(grouped.evidence_ids) == 3
    assert all(endpoint.startswith("https://app.example-bounty.test/") for endpoint in grouped.affected_endpoints)


def test_every_candidate_has_evidence_ids() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)
    evidence_ids = {item.id for item in state.evidence}

    assert all(candidate.evidence_ids for candidate in candidates)
    assert all(evidence_id in evidence_ids for candidate in candidates for evidence_id in candidate.evidence_ids)


def test_candidate_ids_are_stable_and_ordered() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    first = generate_candidates(state)
    second = generate_candidates(state)

    assert [candidate.id for candidate in first] == [f"CAND-{index:04d}" for index in range(1, len(first) + 1)]
    assert [candidate.id for candidate in first] == [candidate.id for candidate in second]
    assert [candidate.candidate_type for candidate in first] == [candidate.candidate_type for candidate in second]


def test_low_signal_demo_only_produces_low_or_kill_switch_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "boring_low_signal")
    candidates = generate_candidates(state)

    assert candidates
    assert all(candidate.priority in {"low", "kill_switch"} for candidate in candidates)
    assert not any(candidate.priority in {"high", "medium"} for candidate in candidates)


def test_notes_do_not_generate_manual_review_candidates(tmp_path: Path) -> None:
    (tmp_path / "notes.md").write_text(
        "\n".join(f"- Operator context item {index}" for index in range(20)),
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)
    candidates = generate_candidates(state)

    assert len([item for item in state.evidence if item.evidence_type == "note"]) == 20
    assert candidates == []


def test_scope_policy_lines_do_not_generate_kill_switch_candidates(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text(
        "\n".join(
            [
                "# Scope",
                "",
                "## In Scope",
                "",
                "* 10.82.158.153",
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

    assert candidates == []
    assert [asset.hostname for asset in state.assets] == ["10.82.158.153"]


def test_duplicate_heavy_url_file_does_not_explode_candidates(tmp_path: Path) -> None:
    (tmp_path / "urls.txt").write_text(
        "\n".join(["https://app.example-bounty.test/account?user_id=1001"] * 25),
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)
    candidates = generate_candidates(state)

    assert len(state.endpoints) == 1
    assert len(candidates) == 2
    assert {candidate.candidate_type for candidate in candidates} == {
        "auth_surface",
        "object_reference_review",
    }


def test_generic_technology_review_candidates_are_low_priority() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    candidates = generate_candidates(state)
    technology_candidates = [candidate for candidate in candidates if candidate.candidate_type == "technology_review"]

    assert technology_candidates
    assert all(candidate.priority == "low" for candidate in technology_candidates)


def test_ip_based_fixture_generates_expected_surface_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "local_lab_ip")
    candidates = generate_candidates(state)
    candidate_types = {candidate.candidate_type for candidate in candidates}

    assert "auth_surface" in candidate_types
    assert "admin_surface" in candidate_types
    assert "api_surface" in candidate_types
    assert "file_or_content_surface" in candidate_types
    assert "object_reference_review" in candidate_types
    assert any("10.10.10.10" in candidate.affected_assets for candidate in candidates)


def test_lab_recon_pack_generates_evidence_first_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_recon_pack")
    candidates = generate_candidates(state)
    candidate_types = {candidate.candidate_type for candidate in candidates}

    assert "multiple_http_services" in candidate_types
    assert "high_port_http_service" in candidate_types
    assert "robots_artifact" in candidate_types
    assert "hidden_path_review" in candidate_types
    assert "low_signal_static" in candidate_types
    assert "manual_note_review" not in candidate_types
    assert all(candidate.evidence_ids for candidate in candidates)


def test_raw_recon_pack_generates_structured_evidence_candidates() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_raw_recon_pack")
    candidates = generate_candidates(state)
    candidate_types = {candidate.candidate_type for candidate in candidates}

    assert {
        "exposed_service_context",
        "high_port_http_service",
        "multiple_http_services",
        "robots_artifact",
        "hidden_path_review",
        "encoded_artifact_review",
        "dead_low_signal_path",
        "low_signal_static",
    } <= candidate_types
    assert "manual_note_review" not in candidate_types
    assert state.recon_summary is not None
    assert state.recon_summary.candidate_count == len(candidates)


def test_api_style_raw_recon_is_behaviour_driven(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- `api.example-bounty.test`\n",
        encoding="utf-8",
    )
    (tmp_path / "subdomains.txt").write_text("api.example-bounty.test\n", encoding="utf-8")
    (tmp_path / "nmap-services.txt").write_text(
        "\n".join(
            [
                "Nmap scan report for api.example-bounty.test",
                "PORT     STATE SERVICE VERSION",
                "8088/tcp open  http    Caddy 2.7",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "gobuster-8088-root.txt").write_text(
        "\n".join(
            [
                "api/v1/users?id=1 (Status: 200) [Size: 128]",
                "login?next=/dashboard (Status: 200) [Size: 512]",
                "account?redirect_url=/home (Status: 200) [Size: 610]",
                "upload (Status: 200) [Size: 420]",
                "static/app.js (Status: 200) [Size: 1400]",
            ]
        ),
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)
    candidate_types = {candidate.candidate_type for candidate in generate_candidates(state)}

    assert {
        "api_surface",
        "auth_surface",
        "file_or_content_surface",
        "object_reference_review",
        "redirect_parameter_review",
        "low_signal_static",
        "high_port_http_service",
    } <= candidate_types
