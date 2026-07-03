"""Tests for deterministic triage candidate generation."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from bugslyce.core.models import HTTPArtifact
from bugslyce.core.project import build_project_state
from bugslyce.triage.candidates import generate_candidates


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


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

    assert candidate.priority == "high"
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


def test_keyword_only_sensitive_hits_create_medium_grouped_candidate() -> None:
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

    assert len(credential_candidates) == 1
    assert credential_candidates[0].priority == "medium"
    assert credential_candidates[0].evidence_ids == ["EVID-ART-PASS", "EVID-ART-SECRET"]
    assert "confirmed credential" not in credential_candidates[0].kill_switch_guidance.lower()


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
    assert credential_candidates[0].priority == "high"
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
