"""Tests for deterministic project state assembly."""

from __future__ import annotations

import json
from pathlib import Path

from bugslyce.core.project import build_project_state
from bugslyce.recon.http_service_identity import resolve_target_http_origins
from bugslyce.reports.markdown import render_markdown_report


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
    assert state.nmap_reported_host_peers == []


def test_project_state_deduplicates_nmap_host_peers_and_resolves_all_target_ports(
    tmp_path: Path,
) -> None:
    first = tmp_path / "nmap-allports.txt"
    second = tmp_path / "nmap-services-all.txt"
    first.write_text(
        "Nmap scan report for blog.thm (10.82.174.151)\n"
        "PORT     STATE SERVICE\n"
        "80/tcp   open  http\n"
        "443/tcp  open  https\n"
        "8080/tcp open  http\n"
        "Nmap scan report for unrelated.thm (10.82.174.152)\n"
        "PORT     STATE SERVICE\n"
        "8080/tcp open  http\n",
        encoding="utf-8",
    )
    second.write_text(first.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "blog.thm",
                "artifacts": [
                    {"type": "nmap", "file": first.name},
                    {"type": "nmap", "file": second.name},
                ],
            }
        ),
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert [
        (item.reported_host, item.peer_host, item.source_file, item.report_line)
        for item in state.nmap_reported_host_peers
    ] == [
        ("blog.thm", "10.82.174.151", str(first), 1),
        ("unrelated.thm", "10.82.174.152", str(first), 6),
    ]
    assert [
        (item.observed_origin, item.logical_origin)
        for item in resolve_target_http_origins(state, "blog.thm")
    ] == [
        ("http://10.82.174.151/", "http://blog.thm/"),
        ("http://10.82.174.151:8080/", "http://blog.thm:8080/"),
        ("https://10.82.174.151/", "https://blog.thm/"),
    ]


def test_hostname_only_nmap_service_keeps_exact_logical_origin(tmp_path: Path) -> None:
    (tmp_path / "nmap-services.txt").write_text(
        "Nmap scan report for blog.thm\n"
        "PORT   STATE SERVICE\n"
        "80/tcp open  http\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert state.nmap_reported_host_peers == []
    assert [item.logical_origin for item in resolve_target_http_origins(state, "blog.thm")] == [
        "http://blog.thm/"
    ]


def test_parenthesized_ipv6_peer_projects_to_hostname_without_malformed_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "nmap-services.txt").write_text(
        "Nmap scan report for blog.thm (2001:db8::151)\n"
        "PORT     STATE SERVICE\n"
        "443/tcp  open  https\n"
        "8080/tcp open  http\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert [item.url for item in state.http_services] == [
        "https://[2001:db8::151]/",
        "http://[2001:db8::151]:8080/",
    ]
    assert [
        (item.observed_origin, item.logical_origin)
        for item in resolve_target_http_origins(state, "blog.thm")
    ] == [
        ("http://[2001:db8::151]:8080/", "http://blog.thm:8080/"),
        ("https://[2001:db8::151]/", "https://blog.thm/"),
    ]


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


def test_file_content_tags_use_bounded_path_and_parameter_tokens(tmp_path: Path) -> None:
    (tmp_path / "urls.txt").write_text(
        "\n".join(
            (
                "https://app.example.test/profile.php",
                "https://app.example.test/uploads/",
                "https://app.example.test/files/",
                "https://app.example.test/download",
                "https://app.example.test/account?profile=compact",
                "https://app.example.test/view?file=report",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    endpoints = {item.url: item for item in build_project_state(tmp_path).endpoints}

    assert "file_or_content_surface" not in endpoints[
        "https://app.example.test/profile.php"
    ].tags
    assert "file_or_content_surface" not in endpoints[
        "https://app.example.test/account?profile=compact"
    ].tags
    for url in (
        "https://app.example.test/uploads/",
        "https://app.example.test/files/",
        "https://app.example.test/download",
        "https://app.example.test/view?file=report",
    ):
        assert "file_or_content_surface" in endpoints[url].tags


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


def test_project_state_derives_plain_http_from_nmap_fingerprint_without_changing_label(
    tmp_path: Path,
) -> None:
    (tmp_path / "nmap-services.txt").write_text(
        "\n".join(
            [
                "Nmap scan report for 10.10.10.10",
                "PORT     STATE SERVICE VERSION",
                "3000/tcp open  ppp?",
                "8080/tcp open  http TestServer",
                "==============NEXT SERVICE FINGERPRINT==============",
                "SF-Port3000-TCP:V=7.94%r(GetRequest,123,",
                'SF:"HTTP/1\\.1\\x20200\\x20OK\\r\\nContent-Type:\\x20text/html")',
                "==============NEXT SERVICE FINGERPRINT==============",
                "SF-Port8080-TCP:V=7.94%r(GetRequest,123,",
                'SF:"HTTP/1\\.1\\x20200\\x20OK\\r\\nContent-Type:\\x20text/html")',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)
    ports = {service.port: service for service in state.port_services}

    assert ports[3000].service == "ppp?"
    assert "http_protocol_evidence" in ports[3000].tags
    assert {service.url for service in state.http_services} == {
        "http://10.10.10.10:3000/",
        "http://10.10.10.10:8080/",
    }
    assert len(state.http_services) == 2
    assert "http://10.10.10.10:3000/" in render_markdown_report(state, [])


def test_root_page_title_enriches_reconciled_nmap_http_service(tmp_path: Path) -> None:
    (tmp_path / "nmap-allports.txt").write_text(
        "Nmap scan report for 10.10.10.10\n"
        "PORT   STATE SERVICE\n"
        "80/tcp open  http\n",
        encoding="utf-8",
    )
    (tmp_path / "homepage-80.html").write_text(
        "<html><head><title>Administration</title></head><body></body></html>",
        encoding="utf-8",
    )
    (tmp_path / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "artifacts": [
                    {"type": "nmap", "file": "nmap-allports.txt"},
                    {
                        "type": "html",
                        "file": "homepage-80.html",
                        "url": "http://10.10.10.10/",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert [(service.url, service.title) for service in state.http_services] == [
        ("http://10.10.10.10/", "Administration")
    ]
    titles = [
        artifact
        for artifact in state.http_artifacts
        if artifact.artifact_type == "page_title"
    ]
    assert [(artifact.url, artifact.value) for artifact in titles] == [
        ("http://10.10.10.10/", "Administration")
    ]


def test_service_version_identity_supersedes_discovery_without_stale_http_state(
    tmp_path: Path,
) -> None:
    (tmp_path / "nmap-allports.txt").write_text(
        "Nmap scan report for 10.10.10.10\n"
        "PORT     STATE SERVICE\n"
        "80/tcp   open  http\n"
        "8080/tcp open  http\n",
        encoding="utf-8",
    )
    (tmp_path / "nmap-services-all.txt").write_text(
        "Nmap scan report for 10.10.10.10\n"
        "PORT     STATE SERVICE VERSION\n"
        "80/tcp   open  ssh     OpenSSH 9.0\n"
        "8080/tcp open  http    Caddy 2.7\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)
    ports = {service.port: service for service in state.port_services}

    assert tuple(ports) == (80, 8080)
    assert (ports[80].service, ports[80].product, ports[80].version) == (
        "ssh",
        "OpenSSH",
        "9.0",
    )
    assert len(ports[80].evidence_ids) == 2
    assert "open_service" in ports[80].tags
    assert "http_service" not in ports[80].tags
    assert "non_default_http_port" not in ports[80].tags
    assert (ports[8080].service, ports[8080].product, ports[8080].version) == (
        "http",
        "Caddy",
        "2.7",
    )
    evidence = {
        item.id: item
        for item in state.evidence
        if item.id in ports[80].evidence_ids
    }
    assert [evidence[evidence_id].context["service"] for evidence_id in ports[80].evidence_ids] == [
        "http",
        "ssh",
    ]
    assert [service.url for service in state.http_services] == [
        "http://10.10.10.10:8080/"
    ]


def test_identity_less_service_version_observation_keeps_discovery_fallback(
    tmp_path: Path,
) -> None:
    (tmp_path / "nmap-allports.txt").write_text(
        "Nmap scan report for 10.10.10.10\n"
        "PORT   STATE SERVICE\n"
        "22/tcp open  ssh\n",
        encoding="utf-8",
    )
    (tmp_path / "nmap-services-all.txt").write_text(
        "Nmap scan report for 10.10.10.10\n"
        "PORT   STATE SERVICE VERSION\n"
        "22/tcp open  unknown OpenSSH 9.0\n",
        encoding="utf-8",
    )

    service = build_project_state(tmp_path).port_services[0]

    assert (service.service, service.product, service.version) == ("ssh", None, None)
    assert len(service.evidence_ids) == 2


def test_nmap_http_service_uses_only_http_supporting_observations(tmp_path: Path) -> None:
    (tmp_path / "nmap-allports.txt").write_text(
        "Nmap scan report for 10.10.10.10\n"
        "PORT     STATE SERVICE\n"
        "8080/tcp open  unknown\n",
        encoding="utf-8",
    )
    (tmp_path / "nmap-services-all.txt").write_text(
        "Nmap scan report for 10.10.10.10\n"
        "PORT     STATE SERVICE VERSION\n"
        "8080/tcp open  http    Caddy 2.7\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)
    port_service = state.port_services[0]
    evidence_by_file = {Path(item.source_file).name: item.id for item in state.evidence}

    assert len(port_service.evidence_ids) == 2
    assert state.http_services[0].evidence_ids == [
        evidence_by_file["nmap-services-all.txt"]
    ]
    assert evidence_by_file["nmap-allports.txt"] not in state.http_services[0].evidence_ids


def test_saved_robots_body_value_becomes_http_artifact(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (tmp_path / "robots-10.10.10.10-80.txt").write_text(
        "Wubbalubbadubdub\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)
    robots_values = [
        artifact
        for artifact in state.http_artifacts
        if artifact.artifact_type == "robots_value"
    ]

    assert len(robots_values) == 1
    assert robots_values[0].url == "http://10.10.10.10/robots.txt"
    assert robots_values[0].value == "Wubbalubbadubdub"
    assert robots_values[0].source_file.endswith("robots-10.10.10.10-80.txt")
    assert robots_values[0].evidence_ids == ["EVID-ART-0002"]
    assert "robots_artifact" in robots_values[0].tags


def test_generic_robots_user_agent_does_not_create_body_value(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (tmp_path / "robots-10.10.10.10-80.txt").write_text(
        "User-agent: *\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert any(artifact.artifact_type == "user_agent" for artifact in state.http_artifacts)
    assert not any(
        artifact.artifact_type == "robots_value"
        for artifact in state.http_artifacts
    )


def test_noisy_robots_body_lines_are_not_promoted(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text(
        "# Scope\n\n## In Scope\n\n- 10.10.10.10\n",
        encoding="utf-8",
    )
    (tmp_path / "robots-10.10.10.10-80.txt").write_text(
        "\n".join(
            [
                "A" * 200,
                "<html><title>Not robots</title></html>",
            ]
        ),
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert not any(
        artifact.artifact_type == "robots_value"
        for artifact in state.http_artifacts
    )


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


def test_scope_policy_lines_do_not_create_assets(tmp_path: Path) -> None:
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
                "* Any other IP or domain",
                "* Scanners",
                "* Content discovery",
                "* Brute force",
                "* Exploitation",
            ]
        ),
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert [asset.hostname for asset in state.assets] == ["10.82.158.153"]
    assert state.assets[0].in_scope is True
    assert len([item for item in state.evidence if item.evidence_type == "scope_in_target"]) == 1
    assert len([item for item in state.evidence if item.evidence_type == "scope_policy"]) == 5


def test_scope_url_and_wildcard_entries_create_normalised_assets(tmp_path: Path) -> None:
    (tmp_path / "scope.md").write_text(
        "\n".join(
            [
                "# Scope",
                "",
                "## In Scope",
                "",
                "* https://app.example.com/login",
                "",
                "## Out of Scope",
                "",
                "* *.third-party.example",
            ]
        ),
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)
    assets = {asset.hostname: asset for asset in state.assets}

    assert assets["app.example.com"].in_scope is True
    assert assets["third-party.example"].in_scope is False
