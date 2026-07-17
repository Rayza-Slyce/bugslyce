"""Tests for non-executing content discovery planning."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugslyce.cli import main
from bugslyce.core.project import build_project_state
from bugslyce.recon.content_plan import (
    CONTENT_DISCOVERY_PROFILE,
    CONTENT_DISCOVERY_TINY_PROFILE,
    DEEP_BOUNDED_CORE_PROFILE,
    DEEP_BOUNDED_CORE_WORDLIST,
    DEFAULT_WORDLIST,
    MAX_CONTENT_PLAN_ORIGINS,
    STANDARD_AUTH_CORE_PROFILE,
    STANDARD_AUTH_CORE_WORDLIST,
    STANDARD_AUTH_SURFACE_ROUTES,
    STANDARD_BOUNDED_CORE_PROFILE,
    STANDARD_BOUNDED_CORE_WORDLIST,
    TINY_WORDLIST,
    build_content_discovery_plan,
    discover_content_plan_origins,
    render_content_discovery_plan,
    write_content_discovery_plan,
)


def test_content_plan_writes_json_and_markdown(tmp_path: Path) -> None:
    input_dir, scope = _content_plan_input(tmp_path)
    output_dir = tmp_path / "bugslyce-output" / "content-plan"

    plan = build_content_discovery_plan(
        input_dir, scope, CONTENT_DISCOVERY_PROFILE, output_dir
    )
    json_path, markdown_path = write_content_discovery_plan(plan)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")

    assert plan.origins == [
        "http://10.10.10.10/",
        "http://10.10.10.10:65524/",
    ]
    assert json_path.name == "content_discovery_plan.json"
    assert markdown_path.name == "content_discovery_plan.md"
    assert payload["no_commands_executed"] is True
    assert all(step["no_commands_executed"] is True for step in payload["steps"])
    assert all(step["requires_confirmation"] is True for step in payload["steps"])
    assert "No commands were executed." in markdown


def test_cli_content_plan_writes_outputs(tmp_path: Path, capsys) -> None:
    input_dir, scope = _content_plan_input(tmp_path)
    output_dir = tmp_path / "bugslyce-output" / "cli-content-plan"

    exit_code = main(
        [
            "recon",
            "content-plan",
            "--input-dir",
            str(input_dir),
            "--scope",
            str(scope),
            "--profile",
            CONTENT_DISCOVERY_PROFILE,
            "--output",
            str(output_dir),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert (output_dir / "content_discovery_plan.json").exists()
    assert (output_dir / "content_discovery_plan.md").exists()
    assert "BugSlyce content discovery plan created" in captured.out
    assert "No commands were executed." in captured.out


def test_content_plan_uses_only_discovered_service_roots(tmp_path: Path) -> None:
    input_dir, _scope = _content_plan_input(tmp_path)
    state = build_project_state(input_dir)

    origins = discover_content_plan_origins(state, "10.10.10.10")

    assert origins == [
        "http://10.10.10.10/",
        "http://10.10.10.10:65524/",
    ]
    rendered = "\n".join(origins)
    assert "/manual" not in rendered
    assert "/robots.txt" not in rendered
    assert "openlogo" not in rendered
    assert "example.org" not in rendered


def test_content_plan_previews_fixed_gobuster_root_shape(tmp_path: Path) -> None:
    input_dir, scope = _content_plan_input(tmp_path)
    output_dir = tmp_path / "bugslyce-output" / "content-plan"

    plan = build_content_discovery_plan(
        input_dir, scope, CONTENT_DISCOVERY_PROFILE, output_dir
    )

    first = plan.steps[0]
    assert first.command_preview == [
        "gobuster",
        "dir",
        "-u",
        "http://10.10.10.10/",
        "-w",
        str(DEFAULT_WORDLIST),
        "-t",
        "10",
        "-o",
        str(output_dir.resolve() / "gobuster-10.10.10.10-80-root.txt"),
    ]
    assert first.allowed_tool == "gobuster"
    assert first.risk_level == "moderate"
    assert first.requires_confirmation is True
    assert first.scope_sensitive is True
    assert "--recursive" not in first.command_preview
    assert "-x" not in first.command_preview


def test_content_plan_tiny_profile_uses_bundled_wordlist(tmp_path: Path) -> None:
    input_dir, scope = _content_plan_input(tmp_path)
    output_dir = tmp_path / "bugslyce-output" / "tiny-content-plan"

    plan = build_content_discovery_plan(
        input_dir,
        scope,
        CONTENT_DISCOVERY_TINY_PROFILE,
        output_dir,
    )
    first = plan.steps[0]

    assert TINY_WORDLIST.is_file()
    assert TINY_WORDLIST.read_text(encoding="utf-8").count("\n") >= 20
    assert first.command_preview[5] == str(TINY_WORDLIST)
    assert first.command_preview[7] == "5"
    assert first.expected_artifact.file == "gobuster-tiny-10.10.10.10-80-root.txt"
    assert any("first-live proving profile" in note for note in plan.safety_notes)
    assert not any("wordlist was not found" in warning for warning in plan.warnings)


def test_standard_auth_core_profile_uses_small_fixed_route_set(tmp_path: Path) -> None:
    input_dir, scope = _content_plan_input(tmp_path)
    output_dir = tmp_path / "bugslyce-output" / "standard-auth-content-plan"

    plan = build_content_discovery_plan(
        input_dir,
        scope,
        STANDARD_AUTH_CORE_PROFILE,
        output_dir,
    )
    first = plan.steps[0]
    routes = [
        f"/{line.strip()}"
        for line in STANDARD_AUTH_CORE_WORDLIST.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    assert plan.profile == STANDARD_AUTH_CORE_PROFILE
    assert tuple(routes) == STANDARD_AUTH_SURFACE_ROUTES
    assert len(STANDARD_AUTH_SURFACE_ROUTES) == 15
    assert "/login.php" in STANDARD_AUTH_SURFACE_ROUTES
    assert first.command_preview[5] == str(STANDARD_AUTH_CORE_WORDLIST)
    assert first.command_preview[7] == "5"
    assert first.expected_artifact.file == (
        "gobuster-standard-auth-core-10.10.10.10-80-root.txt"
    )
    assert "--recursive" not in first.command_preview
    assert "-x" not in first.command_preview
    assert all("?" not in route for route in STANDARD_AUTH_SURFACE_ROUTES)
    assert any("fixed route set" in note for note in plan.safety_notes)
    assert any("No form submission" in note for note in plan.safety_notes)


def test_standard_bounded_core_profile_preserves_tiny_auth_and_sitemap_routes(
    tmp_path: Path,
) -> None:
    input_dir, scope = _content_plan_input(tmp_path)
    output_dir = tmp_path / "bugslyce-output" / "standard-bounded-content-plan"
    tiny_routes = _wordlist_routes(TINY_WORDLIST)
    bounded_routes = _wordlist_routes(STANDARD_BOUNDED_CORE_WORDLIST)
    expected_auth_additions = [
        route
        for route in STANDARD_AUTH_SURFACE_ROUTES
        if route.lstrip("/") not in tiny_routes
    ]

    plan = build_content_discovery_plan(
        input_dir,
        scope,
        STANDARD_BOUNDED_CORE_PROFILE,
        output_dir,
    )
    first = plan.steps[0]

    assert plan.profile == STANDARD_BOUNDED_CORE_PROFILE
    assert bounded_routes[: len(tiny_routes)] == tiny_routes
    assert bounded_routes[len(tiny_routes) : len(tiny_routes) + len(expected_auth_additions)] == [
        route.lstrip("/") for route in expected_auth_additions
    ]
    assert len(bounded_routes) == len(set(bounded_routes))
    assert 150 <= len(bounded_routes) <= 300
    assert "manual" in bounded_routes
    assert "server-status" in bounded_routes
    assert "sitemap" in bounded_routes
    assert "login.php" in bounded_routes
    assert "swagger.json" in bounded_routes
    assert ".well-known/security.txt" in bounded_routes
    assert all(route.lstrip("/") in bounded_routes for route in STANDARD_AUTH_SURFACE_ROUTES)
    assert first.command_preview[5] == str(STANDARD_BOUNDED_CORE_WORDLIST)
    assert first.command_preview[7] == "5"
    assert first.expected_artifact.file == (
        "gobuster-standard-bounded-core-10.10.10.10-80-root.txt"
    )
    assert "--recursive" not in first.command_preview
    assert "-x" not in first.command_preview
    assert all("?" not in route for route in bounded_routes)
    assert any("lab-root-tiny general root coverage" in note for note in plan.safety_notes)


def test_deep_bounded_core_profile_is_broader_than_standard_and_bounded(
    tmp_path: Path,
) -> None:
    input_dir, scope = _content_plan_input(tmp_path)
    output_dir = tmp_path / "bugslyce-output" / "deep-bounded-content-plan"
    standard_routes = _wordlist_routes(STANDARD_BOUNDED_CORE_WORDLIST)
    deep_routes = _wordlist_routes(DEEP_BOUNDED_CORE_WORDLIST)

    plan = build_content_discovery_plan(
        input_dir,
        scope,
        DEEP_BOUNDED_CORE_PROFILE,
        output_dir,
    )
    first = plan.steps[0]

    assert plan.profile == DEEP_BOUNDED_CORE_PROFILE
    assert deep_routes[: len(standard_routes)] == standard_routes
    assert len(deep_routes) == len(set(deep_routes))
    assert 1000 <= len(deep_routes) <= 3000
    assert len(deep_routes) > len(standard_routes)
    assert "sitemap" in deep_routes
    for general_route in (
        "api/v1",
        "graphql",
        "swagger-ui.html",
        ".well-known/openid-configuration",
        "wp-admin",
        "cgi-bin",
        "database.zip",
        "config.json",
        "admin/login",
    ):
        assert general_route in deep_routes
    for target_shaped_route in (
        "work-grid",
        "work-grid.html",
        "work-grid-without-text",
        "work-grid-without-text.html",
    ):
        assert target_shaped_route not in deep_routes
    assert first.command_preview[5] == str(DEEP_BOUNDED_CORE_WORDLIST)
    assert first.command_preview[7] == "5"
    assert first.expected_artifact.file == "gobuster-deep-bounded-core-10.10.10.10-80-root.txt"
    assert "--recursive" not in first.command_preview
    assert "-x" not in first.command_preview
    assert all("?" not in route for route in deep_routes)


def test_quick_tiny_profile_does_not_use_standard_auth_core_wordlist(
    tmp_path: Path,
) -> None:
    input_dir, scope = _content_plan_input(tmp_path)
    output_dir = tmp_path / "bugslyce-output" / "tiny-content-plan"

    plan = build_content_discovery_plan(
        input_dir,
        scope,
        CONTENT_DISCOVERY_TINY_PROFILE,
        output_dir,
    )

    assert plan.profile == CONTENT_DISCOVERY_TINY_PROFILE
    assert all(step.command_preview[5] == str(TINY_WORDLIST) for step in plan.steps)
    assert STANDARD_AUTH_CORE_PROFILE != CONTENT_DISCOVERY_TINY_PROFILE
    assert STANDARD_BOUNDED_CORE_PROFILE != CONTENT_DISCOVERY_TINY_PROFILE
    assert DEEP_BOUNDED_CORE_PROFILE != CONTENT_DISCOVERY_TINY_PROFILE
    assert str(STANDARD_AUTH_CORE_WORDLIST) not in json.dumps(
        [step.command_preview for step in plan.steps]
    )
    assert str(STANDARD_BOUNDED_CORE_WORDLIST) not in json.dumps(
        [step.command_preview for step in plan.steps]
    )
    assert str(DEEP_BOUNDED_CORE_WORDLIST) not in json.dumps(
        [step.command_preview for step in plan.steps]
    )


def test_content_plan_refuses_missing_input_scope_and_unsupported_profile(
    tmp_path: Path,
) -> None:
    input_dir, scope = _content_plan_input(tmp_path)
    output_dir = tmp_path / "bugslyce-output" / "content-plan"

    with pytest.raises(ValueError, match="Input directory does not exist"):
        build_content_discovery_plan(
            tmp_path / "missing", scope, CONTENT_DISCOVERY_PROFILE, output_dir
        )
    with pytest.raises(ValueError, match="Scope file does not exist"):
        build_content_discovery_plan(
            input_dir,
            tmp_path / "missing-scope.md",
            CONTENT_DISCOVERY_PROFILE,
            output_dir,
        )
    with pytest.raises(ValueError, match="Unsupported content discovery profile"):
        build_content_discovery_plan(input_dir, scope, "recursive-full", output_dir)


def test_content_plan_refuses_target_not_in_scope(tmp_path: Path) -> None:
    input_dir, _scope = _content_plan_input(tmp_path)
    scope = tmp_path / "other-scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 192.0.2.10\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not explicitly listed"):
        build_content_discovery_plan(
            input_dir,
            scope,
            CONTENT_DISCOVERY_PROFILE,
            tmp_path / "bugslyce-output" / "content-plan",
        )


def test_content_plan_refuses_no_http_origins(tmp_path: Path) -> None:
    input_dir, scope = _content_plan_input(tmp_path, include_http=False)

    with pytest.raises(ValueError, match="No discovered HTTP service origins"):
        build_content_discovery_plan(
            input_dir,
            scope,
            CONTENT_DISCOVERY_PROFILE,
            tmp_path / "bugslyce-output" / "content-plan",
        )


def test_content_plan_deduplicates_sorts_and_caps_origins(tmp_path: Path) -> None:
    input_dir, scope = _content_plan_input(
        tmp_path,
        ports=[9005, 9001, 9004, 9002, 9003, 9000, 9006],
    )

    plan = build_content_discovery_plan(
        input_dir,
        scope,
        CONTENT_DISCOVERY_PROFILE,
        tmp_path / "bugslyce-output" / "content-plan",
    )

    assert len(plan.origins) == MAX_CONTENT_PLAN_ORIGINS
    assert plan.origins == [
        "http://10.10.10.10:9000/",
        "http://10.10.10.10:9001/",
        "http://10.10.10.10:9002/",
        "http://10.10.10.10:9003/",
        "http://10.10.10.10:9004/",
    ]
    assert any("capped at 5 origins" in warning for warning in plan.warnings)


def test_content_plan_refuses_unsafe_output_directory(tmp_path: Path) -> None:
    input_dir, scope = _content_plan_input(tmp_path)

    with pytest.raises(ValueError, match="output must be under"):
        build_content_discovery_plan(
            input_dir, scope, CONTENT_DISCOVERY_PROFILE, Path.home()
        )


def test_content_plan_module_has_no_execution_api() -> None:
    source = Path("bugslyce/recon/content_plan.py").read_text(encoding="utf-8").lower()

    for forbidden in ("subprocess", "os.system", "popen", "pexpect", "shell=true"):
        assert forbidden not in source


def test_content_plan_markdown_is_explicitly_non_executing(tmp_path: Path) -> None:
    input_dir, scope = _content_plan_input(tmp_path)
    plan = build_content_discovery_plan(
        input_dir,
        scope,
        CONTENT_DISCOVERY_PROFILE,
        tmp_path / "bugslyce-output" / "content-plan",
    )

    markdown = render_content_discovery_plan(plan)

    assert "No commands were executed." in markdown
    assert "Ready for execution: `false`" in markdown
    assert "Recursive discovery: `false`" in markdown


def _content_plan_input(
    tmp_path: Path,
    include_http: bool = True,
    ports: list[int] | None = None,
) -> tuple[Path, Path]:
    input_dir = tmp_path / "input"
    input_dir.mkdir(parents=True)
    scope = input_dir / "scope.md"
    scope.write_text("# Scope\n\n## In Scope\n\n- 10.10.10.10\n", encoding="utf-8")

    selected_ports = ports if ports is not None else [80, 65524]
    service_lines = (
        [
            f"{port}/tcp open  http    Test HTTP service"
            for port in selected_ports
        ]
        if include_http
        else ["6498/tcp open  ssh     OpenSSH"]
    )
    (input_dir / "nmap-services-all.txt").write_text(
        "\n".join(
            [
                "Nmap scan report for 10.10.10.10",
                "PORT      STATE SERVICE VERSION",
                *service_lines,
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (input_dir / "homepage-80.html").write_text(
        '<a href="/manual">manual</a>'
        '<img src="/icons/openlogo-75.png">'
        '<a href="https://example.org/external">external</a>',
        encoding="utf-8",
    )
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "scope_file": "scope.md",
                "created_by": "test",
                "profile": "lab-tcp-full-plus-services-plus-http-metadata",
                "artifacts": [
                    {"type": "nmap", "file": "nmap-services-all.txt"},
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
    return input_dir, scope


def _wordlist_routes(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
