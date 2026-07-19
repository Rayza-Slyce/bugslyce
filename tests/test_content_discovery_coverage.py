"""Regression coverage for bounded content discovery cascade inputs."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

from bugslyce import __version__
from bugslyce.doctor import DoctorReport, ResourceReadiness, ToolReadiness
from bugslyce.core.project import build_project_state
from bugslyce.core.models import DiscoveredPath, ProjectState
from bugslyce.core.sensitive_evidence import (
    DEEP_SENSITIVE_EVIDENCE_NOTICE,
    PACK_SENSITIVE_EVIDENCE_NOTICE,
    REPORT_SENSITIVE_EVIDENCE_NOTICE,
)
from bugslyce.project_pipeline import DEEP_PIPELINE_PROFILE, run_project_pipeline
from bugslyce.project_session import scaffold_project
from bugslyce.recon.content_followup import select_content_followup_urls
from bugslyce.recon.content_plan import DEEP_BOUNDED_CORE_PROFILE
from bugslyce.recon.deep_metadata_collector import DeepHTTPResponse
from bugslyce.recon.deep_shallow_route_followup import DEFAULT_MAX_REQUESTS


SITEMAP_HTML = b"""<!doctype html>
<html>
  <head>
    <title>Sitemap</title>
    <link rel="stylesheet" href="/assets/site.css">
    <script src="/js/app.js"></script>
  </head>
  <body>
    <a href="/application-overview.html">Overview</a>
    <a href="/feature-tour.html">Feature Tour</a>
    <a href="/customer-stories.html">Stories</a>
    <a href="/pricing-details.html">Pricing Details</a>
    <a href="/operator-notes.html">Notes</a>
    <a href="https://external.example.test/offsite.html">External</a>
    <form action="/subscribe" method="post">
      <input type="email" name="email" required>
      <button type="submit">Subscribe</button>
    </form>
  </body>
</html>
"""


def test_sitemap_redirect_is_retained_and_canonical_route_enters_followup(
    tmp_path: Path,
) -> None:
    state = _project_state(
        tmp_path,
        DiscoveredPath(
            url="http://example.test/sitemap",
            status_code=301,
            content_length=0,
            redirect_location="http://example.test/sitemap/",
            source=str(tmp_path / "gobuster-deep-bounded-core-example.test-80-root.txt"),
            evidence_ids=["EVID-SITEMAP"],
            tags=[],
        ),
    )

    considered, selected = select_content_followup_urls(state, "example.test", {"artifacts": []})

    assert considered == 1
    assert selected == ["http://example.test/sitemap/"]


def test_deep_pipeline_carries_sitemap_redirect_body_into_offline_reviews(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scaffold = scaffold_project("coverage-pipeline", "10.10.10.10", tmp_path / "projects")
    project_file = Path(scaffold.project_file)
    output_dir = Path(scaffold.project.output_dir)
    fetch_urls: list[str] = []

    _patch_local_base_pipeline(monkeypatch, output_dir)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_content_discovery_workflow",
        lambda plan_path, scope_file: _write_sitemap_content_discovery(output_dir, plan_path),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_content_discovery_execution_result",
        lambda result, output_dir: (output_dir / "content-run.json", output_dir / "content-run.md"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_content_followup_workflow",
        lambda input_dir, scope_file: _write_sitemap_content_followup(input_dir),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_content_followup_execution_result",
        lambda result, output_dir: (output_dir / "content-followup.json", output_dir / "content-followup.md"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.urllib_deep_http_fetcher",
        lambda request, bounds: _deep_fetcher(request, fetch_urls),
    )

    result = run_project_pipeline(project_file, DEEP_PIPELINE_PROFILE)

    assert result.final_status == "completed"
    assert "http://10.10.10.10/sitemap/" in fetch_urls
    assert fetch_urls.count("http://10.10.10.10/sitemap/") == 1
    assert "http://10.10.10.10/application-overview.html" in fetch_urls
    assert "https://external.example.test/offsite.html" not in fetch_urls
    assert "http://10.10.10.10/subscribe" not in fetch_urls
    shallow_urls = [url for url in fetch_urls if url != "http://10.10.10.10/sitemap/"]
    assert 1 <= len(shallow_urls) <= DEFAULT_MAX_REQUESTS

    source_json = json.loads(
        (output_dir / "deep_source_route_collection.json").read_text(encoding="utf-8")
    )
    orchestration_json = json.loads(
        (output_dir / "deep_recon_orchestration.json").read_text(encoding="utf-8")
    )
    status_json = json.loads((output_dir / "recon_status.json").read_text(encoding="utf-8"))
    pipeline_json = json.loads(
        (output_dir / "project_pipeline.json").read_text(encoding="utf-8")
    )
    sitemap_items = [
        item
        for item in source_json["collected"]
        if item["url"] == "http://10.10.10.10/sitemap/"
    ]
    assert sitemap_items
    assert "application-overview.html" in sitemap_items[0]["body_preview"]
    assert orchestration_json["deep_mode_enabled"] is True
    assert orchestration_json["deep_profile_selected"] is True
    assert orchestration_json["deep_collection_completed"] is True
    assert orchestration_json["deep_offline_review_completed"] is True
    assert pipeline_json["final_status"] == "completed"
    pipeline_statuses = {
        step["step_id"]: step["status"] for step in pipeline_json["steps"]
    }
    assert pipeline_statuses["PIPELINE-STEP-010D"] == "completed"
    assert pipeline_statuses["PIPELINE-STEP-011D"] == "completed"
    assert status_json["latest_execution"]["pipeline_final_status"] == "completed"
    local_status = (output_dir / "recon_status.md").read_text(encoding="utf-8")
    assert "- Pipeline Final Status: completed" in local_status
    assert "review the Operator Summary in `report.md`" in local_status
    assert "Optional additional bounded collection:" in local_status
    local_runbook = (output_dir / "runbook.md").read_text(encoding="utf-8")
    assert "Pipeline steps satisfied: 14/14" in local_runbook
    assert "Deep pipeline phases: 2/2" in local_runbook
    assert "Review the Operator Summary and raw evidence manually." in local_runbook
    assert "Optional bounded" in local_runbook

    deep_report = (output_dir / "deep_recon_review.md").read_text(encoding="utf-8")
    deep_runbook = (output_dir / "deep_recon_runbook.md").read_text(
        encoding="utf-8"
    )
    primary_report = (output_dir / "report.md").read_text(encoding="utf-8")
    assert "http://10.10.10.10/application-overview.html" in deep_report
    assert "http://10.10.10.10/feature-tour.html" in deep_report
    assert "https://external.example.test/offsite.html" in deep_report
    assert "http://10.10.10.10/subscribe" in deep_report
    assert "Form occurrences observed: 1" in deep_report
    assert "https://external.example.test/offsite.html` | `GET`" not in deep_report
    assert "Detailed Deep review output is retained in `deep_recon_review.md`" in primary_report
    assert "## Deep Collection Review Bundle" not in primary_report
    assert "## Deep Form Inventory" not in primary_report
    assert "deep_recon_review.md" in primary_report
    assert "Deep profile selected: yes (`deep-bounded`)." in deep_report
    assert "Bounded Deep collection completed" in deep_report
    assert primary_report.count(REPORT_SENSITIVE_EVIDENCE_NOTICE[0]) == 1
    assert REPORT_SENSITIVE_EVIDENCE_NOTICE[0] not in local_runbook
    assert REPORT_SENSITIVE_EVIDENCE_NOTICE[0] not in local_status
    assert deep_report.count(DEEP_SENSITIVE_EVIDENCE_NOTICE) == 1
    assert deep_runbook.count(DEEP_SENSITIVE_EVIDENCE_NOTICE) == 1
    assert "see the `report.md` Sensitive Evidence Notice" not in deep_report
    assert "see the `report.md` Sensitive Evidence Notice" not in deep_runbook
    assert deep_report.lower().count("may retain complete set-cookie") == 0
    assert deep_runbook.lower().count("may retain complete set-cookie") == 0
    assert "Set-Cookie present: yes" in deep_report
    assert "session_id (Path=/; HttpOnly)" in deep_report
    assert "retained-cookie-value" not in deep_report
    retained_headers = [
        header
        for item in source_json["collected"]
        for header in item["headers"]
        if header[0].casefold() == "set-cookie"
    ]
    assert retained_headers == [
        ["Set-Cookie", "session_id=retained-cookie-value; Path=/; HttpOnly"]
    ]
    with zipfile.ZipFile(f"{output_dir}-evidence-pack.zip") as archive:
        packed_report = archive.read("report.md").decode("utf-8")
        packed_readme = archive.read("BUGSLYCE_EXPORT_README.md").decode("utf-8")
        packed_status = json.loads(archive.read("recon_status.json").decode("utf-8"))
        packed_status_markdown = archive.read("recon_status.md").decode("utf-8")
        packed_runbook = archive.read("runbook.md").decode("utf-8")
        packed_orchestration = json.loads(
            archive.read("raw/deep_recon_orchestration.json").decode("utf-8")
        )
        packed_deep_review = archive.read("raw/deep_recon_review.md").decode(
            "utf-8"
        )
        packed_deep_runbook = archive.read("raw/deep_recon_runbook.md").decode(
            "utf-8"
        )
        packed_source = json.loads(
            archive.read("raw/deep_source_route_collection.json").decode("utf-8")
        )
    assert packed_report.count(REPORT_SENSITIVE_EVIDENCE_NOTICE[0]) == 1
    assert sum(
        packed_readme.count(paragraph) for paragraph in PACK_SENSITIVE_EVIDENCE_NOTICE
    ) == len(PACK_SENSITIVE_EVIDENCE_NOTICE)
    assert packed_readme.count("This archive may contain sensitive recon evidence") == 1
    assert packed_status["latest_execution"]["pipeline_final_status"] == "completed"
    assert packed_status_markdown == local_status
    assert packed_runbook == local_runbook
    assert "review the Operator Summary in `report.md`" in packed_status_markdown
    assert "Optional additional bounded collection:" in packed_status_markdown
    assert "Pipeline steps satisfied: 14/14" in packed_runbook
    assert "Deep pipeline phases: 2/2" in packed_runbook
    assert packed_orchestration["deep_mode_enabled"] is True
    assert packed_orchestration["deep_profile_selected"] is True
    assert packed_orchestration["deep_collection_completed"] is True
    assert "Deep profile selected: yes (`deep-bounded`)." in packed_deep_review
    assert "Bounded Deep collection completed" in packed_deep_review
    assert packed_deep_review.count(DEEP_SENSITIVE_EVIDENCE_NOTICE) == 1
    assert packed_deep_runbook.count(DEEP_SENSITIVE_EVIDENCE_NOTICE) == 1
    assert any(
        header[1] == "session_id=retained-cookie-value; Path=/; HttpOnly"
        for item in packed_source["collected"]
        for header in item["headers"]
        if header[0].casefold() == "set-cookie"
    )

    discovered = build_project_state(output_dir).discovered_paths
    assert any(
        path.url == "http://10.10.10.10/sitemap"
        and path.status_code == 301
        and path.redirect_location == "/sitemap/"
        for path in discovered
    )
    assert any(path.url == "http://10.10.10.10/sitemap/" for path in discovered)


def _project_state(tmp_path: Path, *paths: DiscoveredPath) -> ProjectState:
    return ProjectState(
        project_name="content-coverage",
        input_dir=str(tmp_path),
        processed_files=[],
        scope_summary="example.test",
        assets=[],
        http_services=[],
        endpoints=[],
        port_services=[],
        http_artifacts=[],
        discovered_paths=list(paths),
        recon_summary=None,
        recon_manifest=None,
        evidence=[],
        warnings=[],
        generated_at="2026-07-17T00:00:00+00:00",
    )


def _patch_local_base_pipeline(monkeypatch, output_dir: Path) -> None:
    monkeypatch.setattr("bugslyce.project_pipeline.build_doctor_report", _ready_doctor)
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_nmap_discovery_workflow",
        lambda *args, **kwargs: SimpleNamespace(
            nmap_output_path=str(output_dir / "nmap-allports.txt"),
            report_path=str(output_dir / "report.md"),
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_nmap_discovery_execution_result",
        lambda result, output_dir: (output_dir / "nmap-discover.json", output_dir / "nmap-discover.md"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_nmap_service_workflow",
        lambda *args, **kwargs: SimpleNamespace(
            nmap_output_path=str(output_dir / "nmap-services-all.txt"),
            report_path=str(output_dir / "report.md"),
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_nmap_service_execution_result",
        lambda result, output_dir: (output_dir / "nmap-services.json", output_dir / "nmap-services.md"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_http_metadata_workflow",
        lambda *args, **kwargs: _write_root_http_metadata(output_dir),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_http_metadata_execution_result",
        lambda result, output_dir: (output_dir / "http-metadata.json", output_dir / "http-metadata.md"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_path_followup_workflow",
        lambda *args, **kwargs: SimpleNamespace(
            artifact_paths=(),
            report_path=str(output_dir / "report.md"),
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_path_followup_execution_result",
        lambda result, output_dir: (output_dir / "path-followup.json", output_dir / "path-followup.md"),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.run_body_fetch_workflow",
        lambda *args, **kwargs: SimpleNamespace(
            artifact_paths=(),
            report_path=str(output_dir / "report.md"),
        ),
    )
    monkeypatch.setattr(
        "bugslyce.project_pipeline.write_body_fetch_execution_result",
        lambda result, output_dir: (output_dir / "body-fetch.json", output_dir / "body-fetch.md"),
    )


def _ready_doctor():
    tools = tuple(
        ToolReadiness(
            name=name,
            found=True,
            path=f"/usr/bin/{name}",
            executable=True,
            ready=True,
            purpose=f"{name} purpose",
            blocked_workflows=("quick", "standard", "deep"),
            problem=None,
        )
        for name in ("nmap", "curl", "gobuster")
    )
    resources = tuple(
        ResourceReadiness(
            name=name,
            path=f"/package/{name}.txt",
            exists=True,
            regular_file=True,
            readable=True,
            non_empty=True,
            inside_package=True,
            ready=True,
            blocked_workflows=workflows,
            problem=None,
        )
        for name, workflows in (
            ("lab-root-tiny", ("quick",)),
            ("standard-bounded-core", ("standard",)),
            ("deep-bounded-core", ("deep",)),
        )
    )
    return DoctorReport(
        bugslyce_version=__version__,
        python_version="3.12.3",
        python_supported=True,
        virtual_environment=True,
        platform_summary="Linux",
        current_working_directory="/tmp",
        tool_paths={tool.name: tool.path for tool in tools},
        bundled_wordlist_available=True,
        bundled_wordlist_path="/package/lab-root-tiny.txt",
        dirbuster_wordlist_available=False,
        dirbuster_wordlist_path="/usr/share/wordlists/dirbuster/small.txt",
        project_commands_available=True,
        readiness="ready",
        warnings=(),
        tools=tools,
        resources=resources,
        core_ready=True,
        recon_ready=True,
        overall_ready=True,
    )


def _write_root_http_metadata(output_dir: Path):
    header = output_dir / "homepage-10.10.10.10-80.txt"
    header.write_text(
        "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 12\n\n",
        encoding="utf-8",
    )
    (output_dir / "recon_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "target": "10.10.10.10",
                "profile": "lab-tcp-full-plus-services-plus-http-metadata",
                "artifacts": [
                    {
                        "type": "http_headers",
                        "file": header.name,
                        "url": "http://10.10.10.10/",
                        "description": "Root HTTP metadata",
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return SimpleNamespace(artifact_paths=[str(header)], report_path=str(output_dir / "report.md"))


def _write_sitemap_content_discovery(output_dir: Path, plan_path: Path):
    from bugslyce.recon.content_run import load_content_discovery_plan

    plan = load_content_discovery_plan(plan_path)
    assert plan.profile == DEEP_BOUNDED_CORE_PROFILE
    step = plan.steps[0]
    gobuster = output_dir / step.expected_artifact.file
    gobuster.write_text("sitemap (Status: 301) [Size: 0] [--> /sitemap/]\n", encoding="utf-8")
    manifest_path = output_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"].append(
        {
            "type": "gobuster",
            "file": gobuster.name,
            "base_url": step.origin,
            "description": "Bounded Deep content discovery",
        }
    )
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return SimpleNamespace(
        profile=plan.profile,
        artifact_paths=[str(gobuster)],
        report_path=str(output_dir / "report.md"),
    )


def _write_sitemap_content_followup(input_dir: Path):
    state = build_project_state(input_dir)
    manifest_path = input_dir / "recon_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    considered, selected = select_content_followup_urls(state, "10.10.10.10", manifest)
    assert considered == 1
    assert selected == ["http://10.10.10.10/sitemap/"]
    header = input_dir / "curl-headers-content-followup-10.10.10.10-80-sitemap.txt"
    header.write_text(
        "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 512\n\n",
        encoding="utf-8",
    )
    manifest["artifacts"].append(
        {
            "type": "http_headers",
            "file": header.name,
            "url": selected[0],
            "description": "Bounded header request for content-discovery result follow-up",
        }
    )
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return SimpleNamespace(
        followup_urls_selected=selected,
        artifact_paths=[str(header)],
        report_path=str(input_dir / "report.md"),
    )


def _deep_fetcher(request, fetch_urls: list[str]) -> DeepHTTPResponse:
    fetch_urls.append(request.url)
    if request.url == "http://10.10.10.10/sitemap/":
        body = SITEMAP_HTML
        headers = (
            ("Content-Type", "text/html"),
            ("Set-Cookie", "session_id=retained-cookie-value; Path=/; HttpOnly"),
        )
    else:
        body = b"<!doctype html><html><body>child</body></html>"
        headers = (("Content-Type", "text/html"),)
    return DeepHTTPResponse(
        url=request.url,
        final_url=request.url,
        status_code=200,
        headers=headers,
        body=body,
        elapsed_seconds=0.01,
    )
