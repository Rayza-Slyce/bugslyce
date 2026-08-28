"""Regression coverage for strict runtime diagnostic-sidecar ownership."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from bugslyce.core.engagement_policy import (
    AUTOMATION_PERMITTED,
    CONFIRMED,
    IDENTIFICATION_NONE,
    SERVICE_VERSION_NOT_PERMITTED,
    build_bug_bounty_policy,
)
from bugslyce.core.models import ReconCommand
from bugslyce.core.programme_scope import (
    build_programme_scope_policy,
    build_programme_scope_rule,
)
from bugslyce.project_session import (
    initialize_project,
    load_project,
    save_project_engagement_policy,
    save_project_programme_scope_policy,
)
from bugslyce.recon.external_enforcement import assess_tool_capabilities
from bugslyce.recon.modes import STANDARD_RECON_PROFILE
from bugslyce.recon.project_runtime import build_bug_bounty_project_runtime


PREEXISTING_DIAGNOSTIC = b"PREEXISTING-RETAINED-DIAGNOSTIC-DO-NOT-OVERWRITE\n"
NEW_DIAGNOSTIC = "TLS handshake failed: synthetic new failure\n"


def _capabilities():
    return {
        "curl": assess_tool_capabilities(
            "curl",
            "--disable --connect-timeout --dump-header --globoff --header --head "
            "--max-redirs --max-time --noproxy --output --proto --resolve --silent "
            "--show-error --user-agent --write-out",
        ),
        "gobuster": assess_tool_capabilities(
            "gobuster",
            "dir --url --wordlist --threads --delay --useragent --headers value "
            "-H value --timeout --output --follow-redirect (default false) "
            "--no-tls-validation",
        ),
        "nmap": assess_tool_capabilities(
            "nmap", "-sT -sV -Pn -n -p --max-rate --max-retries -oN"
        ),
    }


def _project(tmp_path: Path):
    scope = tmp_path / "scope.md"
    scope.write_text("# Authorised scope\n", encoding="utf-8")
    _project, project_file = initialize_project(
        "strict-runtime-diagnostic-collision",
        "app.example.test",
        scope,
        tmp_path / "project",
        engagement_context="bug_bounty",
    )
    save_project_engagement_policy(
        project_file,
        build_bug_bounty_policy(
            programme_rules_reviewed=CONFIRMED,
            automated_reconnaissance=AUTOMATION_PERMITTED,
            identification_requirement=IDENTIFICATION_NONE,
            service_version_detection=SERVICE_VERSION_NOT_PERMITTED,
            updated_at="2026-08-28T12:00:00Z",
        ),
    )
    save_project_programme_scope_policy(
        project_file,
        build_programme_scope_policy(
            (
                build_programme_scope_rule(
                    rule_id="include-target",
                    action="include",
                    kind="exact_hostname",
                    value="app.example.test",
                ),
                build_programme_scope_rule(
                    rule_id="fixture-peer-network",
                    action="include",
                    kind="ipv4_cidr",
                    value="192.0.2.0/24",
                ),
            ),
            updated_at="2026-08-28T12:00:00Z",
        ),
    )
    return load_project(project_file)


def _curl_command(output_file: Path) -> ReconCommand:
    return ReconCommand(
        id="HTTP_METADATA_DIAGNOSTIC_COLLISION",
        tool="curl",
        argv=["curl", "-I", "https://app.example.test/"],
        output_file=str(output_file),
        timeout_seconds=120,
        phase="http_metadata",
        risk_level="bounded",
        requires_confirmation=True,
        scope_sensitive=True,
        description="Synthetic strict runtime collision command",
        ready_for_execution=True,
        placeholders=[],
    )


class _FailedCurlProcess:
    def run(self, _argv, _timeout_seconds, _environment):
        return SimpleNamespace(returncode=35, stdout="", stderr=NEW_DIAGNOSTIC)


def test_failed_strict_curl_diagnostic_does_not_overwrite_existing_sidecar(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    runtime = build_bug_bounty_project_runtime(
        project,
        STANDARD_RECON_PROFILE,
        capabilities=_capabilities(),
        ipv4_resolver=lambda _hostname, _port: ("192.0.2.10",),
        process_runner=_FailedCurlProcess(),
    )
    runtime.bind_http_origins(("https://app.example.test/",))
    output_path = Path(project.output_dir) / "curl-headers.txt"
    existing_sidecar = output_path.with_suffix(output_path.suffix + ".stderr.log")
    existing_sidecar.write_bytes(PREEXISTING_DIAGNOSTIC)

    result = runtime.curl_runner().run(_curl_command(output_path))

    observed = existing_sidecar.read_bytes()
    assert observed == PREEXISTING_DIAGNOSTIC, (
        f"stderr_path={result.stderr_path!r}; observed={observed!r}"
    )
    if result.stderr_path is not None:
        retained_path = Path(result.stderr_path)
        assert retained_path != existing_sidecar
        retained_path.resolve().relative_to(Path(project.output_dir).resolve())
        assert retained_path.read_text(encoding="utf-8") == NEW_DIAGNOSTIC
