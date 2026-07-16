"""Release-candidate safety invariants for executable recon boundaries."""

from __future__ import annotations

import ast
from dataclasses import replace
import json
from pathlib import Path
import zipfile

import pytest

from bugslyce.core.models import ReconCommand
from bugslyce.core.scope import scope_entry_target
from bugslyce.recon.body_fetch_commands import validate_live_body_fetch_command
from bugslyce.recon.commands import (
    build_live_curl_header_command,
    validate_live_curl_header_command,
)
from bugslyce.recon.content_commands import validate_live_content_discovery_command
from bugslyce.recon.content_followup_commands import (
    validate_live_content_followup_command,
)
from bugslyce.recon.content_plan import (
    STANDARD_BOUNDED_CORE_PROFILE,
    get_content_discovery_profile,
)
from bugslyce.recon.deep_collection_policy import (
    DeepCollectionRequest,
    evaluate_deep_collection_request,
)
from bugslyce.recon.export import export_recon_evidence_pack
from bugslyce.recon.http_metadata_commands import validate_live_http_metadata_command
from bugslyce.recon.http_origin import http_origin_from_url, same_http_origin
from bugslyce.recon.nmap_profiles import (
    build_live_nmap_service_scan_command,
    build_live_nmap_top_ports_command,
    validate_explicit_nmap_target_scope,
    validate_live_nmap_discovery_command,
    validate_live_nmap_service_scan_command,
)
from bugslyce.recon.path_followup_commands import validate_live_path_followup_command


def test_live_command_validators_reject_control_characters_before_execution(
    tmp_path: Path,
) -> None:
    curl = build_live_curl_header_command("http://example.test/", tmp_path)
    curl.argv[-1] = "http://example.test/\n-H"
    assert _has_control_error(validate_live_curl_header_command(curl, tmp_path).errors)

    nmap_discovery = build_live_nmap_top_ports_command("example.test", tmp_path)
    nmap_discovery.argv[-1] = "example.test\n--script"
    assert _has_control_error(
        validate_live_nmap_discovery_command(nmap_discovery, tmp_path).errors
    )

    nmap_service = build_live_nmap_service_scan_command("example.test", "80", tmp_path)
    nmap_service.argv[-1] = "example.test\n-oN"
    assert _has_control_error(
        validate_live_nmap_service_scan_command(nmap_service, tmp_path).errors
    )

    gobuster = _gobuster_command(tmp_path, "http://example.test/")
    gobuster.argv[3] = "http://example.test/\n--help"
    assert _has_control_error(
        validate_live_content_discovery_command(
            gobuster,
            tmp_path,
            "example.test",
            {"http://example.test/"},
            STANDARD_BOUNDED_CORE_PROFILE,
        ).errors
    )


@pytest.mark.parametrize(
    ("validator_name", "command"),
    [
        ("metadata", "metadata"),
        ("path", "path"),
        ("content", "content"),
        ("body", "body"),
    ],
)
def test_curl_followup_validators_reject_control_character_urls(
    tmp_path: Path,
    validator_name: str,
    command: str,
) -> None:
    del validator_name
    url = "http://example.test/\n-H"
    clean = "http://example.test/"
    output_file = tmp_path / "out.txt"
    base = ReconCommand(
        id="CMD-TEST",
        tool="curl",
        argv=[],
        output_file=str(output_file),
        timeout_seconds=10,
        phase="test",
        risk_level="low",
        requires_confirmation=True,
        scope_sensitive=True,
        description="test",
        ready_for_execution=True,
        placeholders=[],
    )

    if command == "metadata":
        base = replace(base, argv=_head_argv(output_file, url))
        errors = validate_live_http_metadata_command(
            base, tmp_path, "example.test", {clean}
        ).errors
    elif command == "path":
        base = replace(base, argv=_head_argv(output_file, url))
        errors = validate_live_path_followup_command(
            base, tmp_path, "example.test", {clean}, {url}
        ).errors
    elif command == "content":
        base = replace(base, argv=_head_argv(output_file, url))
        errors = validate_live_content_followup_command(
            base, tmp_path, "example.test", {clean}, {url}
        ).errors
    else:
        base = replace(base, argv=_get_argv(output_file, url))
        errors = validate_live_body_fetch_command(
            base, tmp_path, "example.test", {clean}, {url}
        ).errors

    assert _has_control_error(errors)


def test_subprocess_usage_never_invokes_shell_or_popen() -> None:
    for source_path in sorted(Path("bugslyce").rglob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute):
                full_name = _attribute_name(node.func)
                assert full_name != "os.system", source_path
                assert full_name != "subprocess.Popen", source_path
                if full_name == "subprocess.run":
                    assert not any(
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                        for keyword in node.keywords
                    ), source_path


def test_scope_and_origin_checks_reject_deceptive_hosts(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.md"
    scope_file.write_text("## In Scope\n\n- example.test\n", encoding="utf-8")

    assert scope_entry_target("http://example.test@evil.test") == "evil.test"
    with pytest.raises(ValueError, match="not explicitly listed"):
        validate_explicit_nmap_target_scope("example.test.evil.test", scope_file)
    with pytest.raises(ValueError, match="not explicitly listed"):
        validate_explicit_nmap_target_scope("notexample.test", scope_file)

    assert same_http_origin("http://example.test", "http://example.test:80")
    assert same_http_origin("https://example.test", "https://example.test:443")
    assert not same_http_origin("http://example.test", "https://example.test")
    assert not same_http_origin("http://example.test", "http://example.test:8080")
    assert not same_http_origin("http://example.test", "http://example.test.evil.test")
    assert http_origin_from_url("http://example.test@evil.test") is None
    assert http_origin_from_url("http://example.test/\n-H") is None


def test_deep_policy_rejects_unsafe_methods_and_malformed_executable_urls() -> None:
    allowed = ("http://example.test",)

    post = evaluate_deep_collection_request(
        DeepCollectionRequest(
            url="http://example.test/admin",
            method="POST",
            source="source_route_coverage",
            reason="route",
            origin="http://example.test",
            path="/admin",
            evidence_ids=(),
            tags=(),
        ),
        allowed_origins=allowed,
    )
    control = evaluate_deep_collection_request(
        DeepCollectionRequest(
            url="http://example.test/\n-H",
            method="GET",
            source="source_route_coverage",
            reason="route",
            origin="http://example.test",
            path="/",
            evidence_ids=(),
            tags=(),
        ),
        allowed_origins=allowed,
    )
    cross_origin = evaluate_deep_collection_request(
        DeepCollectionRequest(
            url="https://evil.test/path",
            method="GET",
            source="source_route_coverage",
            reason="route",
            origin="https://evil.test",
            path="/path",
            evidence_ids=(),
            tags=(),
        ),
        allowed_origins=allowed,
    )

    assert not post.allowed
    assert post.reason == "method_not_allowed"
    assert not control.allowed
    assert control.reason == "invalid_url"
    assert not cross_origin.allowed
    assert cross_origin.reason == "cross_origin_not_allowed"


def test_evidence_export_excludes_unreferenced_sensitive_decoys(
    tmp_path: Path,
) -> None:
    input_dir = _minimal_export_input(tmp_path)
    (input_dir / ".env").write_text("BUGSLYCE_SYNTHETIC_SECRET=inside\n", encoding="utf-8")
    (input_dir / "id_rsa").write_text("SYNTHETIC PRIVATE KEY\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ".env").write_text("BUGSLYCE_SYNTHETIC_SECRET=outside\n", encoding="utf-8")
    output_path = tmp_path / "pack.zip"

    export_recon_evidence_pack(input_dir, output_path)

    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
        payload = b"\n".join(archive.read(name) for name in names)

    assert ".env" not in names
    assert "id_rsa" not in names
    assert all(not name.startswith("/") for name in names)
    assert all(".." not in Path(name).parts for name in names)
    assert b"BUGSLYCE_SYNTHETIC_SECRET" not in payload
    assert b"SYNTHETIC PRIVATE KEY" not in payload


def test_manifest_symlink_escape_is_rejected(tmp_path: Path) -> None:
    input_dir = _minimal_export_input(tmp_path)
    outside = tmp_path / "outside-evidence.txt"
    outside.write_text("outside\n", encoding="utf-8")
    link = input_dir / "linked-evidence.txt"
    link.symlink_to(outside)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"].append({"type": "text", "file": "linked-evidence.txt"})
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="outside input directory"):
        export_recon_evidence_pack(input_dir, tmp_path / "pack.zip")


def _gobuster_command(tmp_path: Path, origin: str) -> ReconCommand:
    profile = get_content_discovery_profile(STANDARD_BOUNDED_CORE_PROFILE)
    output_file = tmp_path / "gobuster-standard-bounded-core-example.test-80-root.txt"
    return ReconCommand(
        id="CMD-GOBUSTER-TEST",
        tool="gobuster",
        argv=[
            "gobuster",
            "dir",
            "-u",
            origin,
            "-w",
            str(profile.wordlist),
            "-t",
            str(profile.threads),
            "-o",
            str(output_file),
        ],
        output_file=str(output_file),
        timeout_seconds=profile.timeout_seconds,
        phase="content-discovery-root",
        risk_level="low",
        requires_confirmation=True,
        scope_sensitive=True,
        description="test",
        ready_for_execution=True,
        placeholders=[],
    )


def _head_argv(output_file: Path, url: str) -> list[str]:
    return [
        "curl",
        "-I",
        "--max-time",
        "10",
        "--silent",
        "--show-error",
        "--output",
        str(output_file),
        url,
    ]


def _get_argv(output_file: Path, url: str) -> list[str]:
    return [
        "curl",
        "--max-time",
        "10",
        "--silent",
        "--show-error",
        "--output",
        str(output_file),
        url,
    ]


def _minimal_export_input(tmp_path: Path) -> Path:
    input_dir = tmp_path / "recon"
    input_dir.mkdir()
    files = {
        "report.md": "# Report\n",
        "project_state.json": '{"project_state": {}, "candidates": []}\n',
        "recon_status.md": "# Status\n",
        "recon_status.json": '{"target": "example.test"}\n',
        "scope.md": "## In Scope\n\n- example.test\n",
        "nmap-allports.txt": "80/tcp open http\n",
    }
    for name, content in files.items():
        (input_dir / name).write_text(content, encoding="utf-8")
    manifest = {
        "schema_version": "1.0",
        "target": "example.test",
        "scope_file": "scope.md",
        "profile": "lab-safe-tiny",
        "artifacts": [{"type": "nmap", "file": "nmap-allports.txt"}],
    }
    (input_dir / "recon_manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    return input_dir


def _has_control_error(errors: list[str]) -> bool:
    return any("control character" in error for error in errors)


def _attribute_name(node: ast.Attribute) -> str:
    parts = [node.attr]
    value = node.value
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    return ".".join(reversed(parts))
