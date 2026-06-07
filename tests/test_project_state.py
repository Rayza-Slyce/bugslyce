"""Tests for deterministic project state assembly."""

from __future__ import annotations

from pathlib import Path

from bugslyce.core.project import build_project_state


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def test_build_project_state_basic_saas() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")

    assert state.project_name == "basic_saas"
    assert len(state.processed_files) == 5
    assert "5 in-scope entries" in state.scope_summary
    assert state.evidence
    assert state.assets
    assert state.http_services
    assert state.endpoints
    assert state.generated_at


def test_assets_include_expected_fake_hosts() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    assets = {asset.hostname: asset for asset in state.assets}

    assert "app.example-bounty.test" in assets
    assert "api.example-bounty.test" in assets
    assert "staging.example-bounty.test" in assets
    assert "admin.example-bounty.test" in assets
    assert "cdn.example-bounty.test" in assets
    assert assets["app.example-bounty.test"].in_scope is True
    assert assets["assets.cdn.example-bounty.test"].in_scope is True


def test_duplicate_subdomains_and_urls_do_not_duplicate_assets_or_endpoints() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    asset_hosts = [asset.hostname for asset in state.assets]
    endpoint_urls = [endpoint.url for endpoint in state.endpoints]

    assert asset_hosts.count("app.example-bounty.test") == 1
    assert endpoint_urls.count("https://app.example-bounty.test/dashboard?org_id=acme-demo") == 1


def test_evidence_ids_are_generated_and_linked() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    evidence_ids = {item.id for item in state.evidence}

    assert "EVID-SCOPE-0001" in evidence_ids
    assert "EVID-HOST-0001" in evidence_ids
    assert "EVID-HTTP-0001" in evidence_ids
    assert "EVID-URL-0001" in evidence_ids
    assert "EVID-NOTE-0001" in evidence_ids
    assert all(evidence_id in evidence_ids for asset in state.assets for evidence_id in asset.evidence_ids)
    assert all(evidence_id in evidence_ids for endpoint in state.endpoints for evidence_id in endpoint.evidence_ids)


def test_every_asset_and_endpoint_has_evidence() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")

    assert all(asset.evidence_ids for asset in state.assets)
    assert all(endpoint.evidence_ids for endpoint in state.endpoints)


def test_httpx_records_become_http_services() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    services = {service.url: service for service in state.http_services}

    service = services["https://api.example-bounty.test/"]
    assert service.hostname == "api.example-bounty.test"
    assert service.status_code == 200
    assert service.title == "API Gateway"
    assert service.technologies == ["nginx"]
    assert service.content_length == 821
    assert service.evidence_ids == ["EVID-HTTP-0002"]


def test_endpoint_query_params_are_preserved() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    endpoints = {endpoint.url: endpoint for endpoint in state.endpoints}

    assert endpoints["https://app.example-bounty.test/account/settings?user_id=1001"].query_params == ["user_id"]
    assert endpoints["https://app.example-bounty.test/auth/callback?next=/dashboard"].query_params == ["next"]


def test_deterministic_tags_are_applied() -> None:
    state = build_project_state(FIXTURES_ROOT / "basic_saas")
    assets = {asset.hostname: asset for asset in state.assets}
    endpoints = {endpoint.url: endpoint for endpoint in state.endpoints}

    assert "api" in assets["api.example-bounty.test"].tags
    assert "admin" in assets["admin.example-bounty.test"].tags
    assert "environment" in assets["staging.example-bounty.test"].tags
    assert "static_or_cdn" in assets["cdn.example-bounty.test"].tags

    account_endpoint = endpoints["https://app.example-bounty.test/account/settings?user_id=1001"]
    export_endpoint = endpoints["https://app.example-bounty.test/export?account_id=1001&format=csv"]
    callback_endpoint = endpoints["https://app.example-bounty.test/auth/callback?next=/dashboard"]
    api_endpoint = endpoints["https://api.example-bounty.test/v1/users?tenant_id=demo-tenant"]
    api_account_endpoint = endpoints[
        "https://api.example-bounty.test/v1/accounts/1001/orders?order_id=5001"
    ]
    static_endpoint = endpoints["https://cdn.example-bounty.test/static/app.js"]

    assert "auth_surface" in account_endpoint.tags
    assert "object_reference" in account_endpoint.tags
    assert "file_or_content_surface" in export_endpoint.tags
    assert "redirect_parameter" in callback_endpoint.tags
    assert "api_surface" in api_endpoint.tags
    assert "api_surface" in api_account_endpoint.tags
    assert "object_reference" in api_account_endpoint.tags
    assert "auth_surface" not in api_account_endpoint.tags
    assert "static_asset" in static_endpoint.tags


def test_missing_optional_files_do_not_crash_project_assembly(tmp_path: Path) -> None:
    (tmp_path / "subdomains.txt").write_text(
        "app.example-bounty.test\napp.example-bounty.test\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert state.project_name == tmp_path.name
    assert [asset.hostname for asset in state.assets] == ["app.example-bounty.test"]
    assert state.http_services == []
    assert state.endpoints == []
    assert state.warnings
    assert any("Optional input file missing" in warning for warning in state.warnings)


def test_project_state_builds_from_local_lab_ip_fixture() -> None:
    state = build_project_state(FIXTURES_ROOT / "local_lab_ip")
    assets = {asset.hostname: asset for asset in state.assets}
    services = {service.url: service for service in state.http_services}
    endpoints = {endpoint.url: endpoint for endpoint in state.endpoints}

    assert "10.10.10.10" in assets
    assert assets["10.10.10.10"].in_scope is True
    assert "http://10.10.10.10/" in services
    assert "http://10.10.10.10:8080/" in services
    assert "http://10.10.10.10/login" in endpoints
    assert "http://10.10.10.10:8080/api/users?user_id=1" in endpoints
    assert endpoints["http://10.10.10.10:8080/api/users?user_id=1"].query_params == ["user_id"]
    assert endpoints["http://10.10.10.10:8080/api/users?user_id=1"].tags == [
        "api_surface",
        "object_reference",
    ]


def test_project_state_builds_from_raw_recon_fixture() -> None:
    state = build_project_state(FIXTURES_ROOT / "lab_raw_recon_pack")

    assert state.recon_manifest is not None
    assert state.recon_manifest.schema_version == "1.0"
    assert state.recon_manifest.target == "10.10.10.10"
    assert len(state.recon_manifest.artifacts) == 14
    assert {(service.port, service.service) for service in state.port_services} == {
        (80, "http"),
        (2222, "ssh"),
        (65524, "http"),
    }
    assert {service.url for service in state.http_services} == {
        "http://10.10.10.10/",
        "http://10.10.10.10:65524/",
    }
    assert state.discovered_paths
    assert state.http_artifacts
    assert state.recon_summary is not None
    assert state.recon_summary.open_port_count == 3
    assert any(item.artifact_type == "encoded_like_artifact" for item in state.http_artifacts)
    assert all(item.evidence_ids for item in state.port_services)
    assert all(item.evidence_ids for item in state.discovered_paths)
    assert all(item.evidence_ids for item in state.http_artifacts)


def test_malformed_httpx_lines_do_not_crash_project_assembly(tmp_path: Path) -> None:
    (tmp_path / "httpx.jsonl").write_text(
        "\n".join(
            [
                '{"url":"https://app.example-bounty.test","host":"app.example-bounty.test"}',
                "{bad json",
                '["not", "object"]',
            ]
        ),
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert len(state.http_services) == 1
    assert any("Skipping malformed JSONL line" in warning for warning in state.warnings)
    assert any("Skipping non-object JSONL line" in warning for warning in state.warnings)


def test_invalid_urls_do_not_crash_project_assembly(tmp_path: Path) -> None:
    (tmp_path / "urls.txt").write_text(
        "\n".join(
            [
                "not-a-url",
                "http://",
                "https://",
                "javascript:alert(1)",
                "mailto:test@example.com",
                "https://app.example-bounty.test/login",
            ]
        ),
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert [endpoint.url for endpoint in state.endpoints] == ["https://app.example-bounty.test/login"]
    assert len([warning for warning in state.warnings if "Skipping malformed URL" in warning]) == 5


def test_duplicate_heavy_url_file_does_not_duplicate_endpoints(tmp_path: Path) -> None:
    (tmp_path / "urls.txt").write_text(
        "\n".join(["https://app.example-bounty.test/account?user_id=1001"] * 25),
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert len(state.endpoints) == 1
    assert len([item for item in state.evidence if item.evidence_type == "endpoint"]) == 1
