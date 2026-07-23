"""Tests for the self-contained offline HTML evidence report."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re

import pytest

from bugslyce.cli import main
from bugslyce.core.project import build_project_state
from bugslyce.reports.html import (
    build_html_report_model,
    render_html_report,
    write_html_report,
)
from bugslyce.reports.markdown import export_project_state_json
from bugslyce.recon.deep_source_route_collection_export import (
    deep_source_route_collection_result_to_dict,
)
from bugslyce.recon.deep_source_route_collector import (
    DeepSourceRouteCollectedItem,
    DeepSourceRouteCollectionResult,
    DeepSourceRouteSkippedItem,
)
from bugslyce.triage.candidates import generate_candidates


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def test_html_report_renders_existing_structured_review_data(tmp_path: Path) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    output = tmp_path / "report.html"

    written = write_html_report(pack, output)

    html = written.read_text(encoding="utf-8")
    assert written == output
    assert "BugSlyce Evidence Report" in html
    assert "Reconnaissance review leads are observations, not confirmed vulnerabilities." in html
    assert "Operator summary" in html
    assert "Manual review leads" in html
    assert "Routes and provenance" in html
    assert "HTTP evidence" in html
    assert "Evidence records" in html
    assert "project_state.json" in html
    assert "High-port HTTP service review" in html
    assert 'id="report-search"' in html
    assert 'data-status="200"' in html
    assert "<details" in html


def test_html_report_missing_input_or_required_state_fails_clearly(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="input directory does not exist"):
        build_html_report_model(tmp_path / "missing")

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="required artefact is missing: project_state.json"):
        build_html_report_model(empty)


def test_html_report_rejects_malformed_required_and_present_deep_artefacts(
    tmp_path: Path,
) -> None:
    malformed_state = tmp_path / "malformed-state"
    malformed_state.mkdir()
    (malformed_state / "project_state.json").write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="could not parse project_state.json"):
        build_html_report_model(malformed_state)

    malformed_deep = _write_current_pack(tmp_path / "malformed-deep")
    (malformed_deep / "deep_source_route_collection.json").write_text(
        "[]\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="deep source/route collection payload"):
        build_html_report_model(malformed_deep)


def test_html_report_escapes_hostile_target_controlled_values(tmp_path: Path) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    state_path = pack / "project_state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    state = payload["project_state"]
    state["project_name"] = '<script>alert("project")</script>'
    state["http_services"][0]["title"] = '</title><img src=x onerror="alert(1)">'
    state["endpoints"][0]["path"] = '"><svg onload=alert(2)>'
    state["endpoints"][0]["url"] = "javascript:alert(3)"
    state["evidence"][0]["value"] = "<script>alert(4)</script> &lt;img onerror=alert(5)&gt;"
    state["http_artifacts"].append(
        {
            "url": "https://example.test/<img src=x onerror=alert(6)>",
            "artifact_type": "html_comment",
            "value": '<iframe srcdoc="<script>alert(7)</script>"></iframe>',
            "source_file": 'raw/\" onmouseover=\"alert(8).html',
            "evidence_ids": ["EVID-HOSTILE-0001"],
            "tags": ["source_evidence"],
        }
    )
    state_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    hostile_collection = DeepSourceRouteCollectionResult(
        collected=(
            _deep_item(
                "https://example.test/hostile",
                200,
                "c" * 64,
                headers=(("Server", '<img src=x onerror="alert(9)">'),),
                preview="%3Cscript%3Ealert(10)%3C/script%3E",
                evidence_ids=("EVID-HOSTILE-HEADER-0001",),
            ),
        ),
        skipped=(),
        total_considered=1,
        total_collected=1,
        total_skipped=0,
    )
    (pack / "deep_source_route_collection.json").write_text(
        json.dumps(
            deep_source_route_collection_result_to_dict(hostile_collection),
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    html = render_html_report(build_html_report_model(pack))

    for unsafe in (
        '<script>alert("project")</script>',
        '</title><img src=x onerror="alert(1)">',
        '"><svg onload=alert(2)>',
        '<script>alert(4)</script>',
        '<iframe srcdoc="<script>alert(7)</script>"></iframe>',
        '<img src=x onerror="alert(9)">',
    ):
        assert unsafe not in html
    assert '&lt;script&gt;alert(&quot;' in html
    assert "&lt;svg onload=alert(2)&gt;" in html
    assert 'href="javascript:' not in html.lower()
    assert 'src="javascript:' not in html.lower()
    assert "javascript:alert(3)" in html
    assert "%3Cscript%3Ealert(10)%3C/script%3E" in html


def test_html_report_has_no_external_assets_or_network_code(tmp_path: Path) -> None:
    html = render_html_report(build_html_report_model(_write_current_pack(tmp_path / "pack")))

    lowered = html.lower()
    assert "<link" not in lowered
    assert "<img" not in lowered
    assert "fetch(" not in lowered
    assert "xmlhttprequest" not in lowered
    assert "websocket" not in lowered
    assert 'src="http' not in lowered
    assert 'href="http' not in lowered
    assert "default-src 'none'" in lowered
    assert "unsafe-inline" not in lowered
    assert "style-src 'sha256-" in lowered
    assert "script-src 'sha256-" in lowered


def test_html_report_rebuilds_existing_deep_review_models(tmp_path: Path) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    repeated_hash = "a" * 64
    collection = DeepSourceRouteCollectionResult(
        collected=(
            _deep_item(
                "https://portal.example.test/login",
                302,
                repeated_hash,
                headers=(("Location", "/dashboard"),),
                evidence_ids=("EVID-REDIRECT-0001",),
            ),
            _deep_item(
                "https://portal.example.test/dashboard",
                200,
                "b" * 64,
                preview="<title>Existing dashboard title</title>",
                evidence_ids=("EVID-DASHBOARD-0001",),
            ),
            _deep_item(
                "https://portal.example.test/missing-a",
                404,
                repeated_hash,
                evidence_ids=("EVID-MISSING-0001",),
            ),
            _deep_item(
                "https://portal.example.test/missing-b",
                404,
                repeated_hash,
                evidence_ids=("EVID-MISSING-0002",),
            ),
        ),
        skipped=(
            DeepSourceRouteSkippedItem(
                url="https://portal.example.test/capped",
                method="GET",
                reason="policy_blocked",
                source="source_route_coverage",
                evidence_ids=("EVID-SKIPPED-0001",),
            ),
        ),
        total_considered=5,
        total_collected=4,
        total_skipped=1,
    )
    (pack / "deep_source_route_collection.json").write_text(
        json.dumps(deep_source_route_collection_result_to_dict(collection), sort_keys=True),
        encoding="utf-8",
    )

    html = render_html_report(build_html_report_model(pack))

    assert "Existing dashboard title" in html
    assert "Successful retained Deep content" in html
    assert "Redirect and authentication-flow review" in html
    assert "Route relationships" in html
    assert "Response similarity" in html
    assert "Exact repeated non-empty body hash" in html
    assert "EVID-REDIRECT-0001" in html
    assert "Warnings and skipped collection" in html
    assert "policy_blocked" in html
    assert "EVID-SKIPPED-0001" in html
    _assert_category_filter_complete(html)


def test_html_report_is_deterministic_and_preserves_existing_reasoning(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    model = build_html_report_model(pack)

    first = render_html_report(model)
    second = render_html_report(build_html_report_model(pack))

    assert first == second
    assert model.candidates
    assert model.candidates[0].rationale in first
    assert model.operator_summary.review_first[0].why in first


def test_html_report_writes_only_requested_output_and_preserves_input(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    output = output_dir / "review.html"
    before = _tree_hashes(pack)

    write_html_report(pack, output)

    assert _tree_hashes(pack) == before
    assert [path.relative_to(output_dir).as_posix() for path in output_dir.rglob("*")] == [
        "review.html"
    ]

    state_path = pack / "project_state.json"
    state_bytes = state_path.read_bytes()
    with pytest.raises(ValueError, match="output path must be outside the input directory"):
        write_html_report(pack, state_path)
    assert state_path.read_bytes() == state_bytes


def test_html_report_rejects_new_output_beneath_input_before_any_write(
    tmp_path: Path,
    capsys,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    before = _tree_hashes(pack)
    output = pack / "report.html"

    exit_code = main(
        ["report", "html", "--input-dir", str(pack), "--output", str(output)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "output path must be outside the input directory" in captured.err
    assert not output.exists()
    assert _tree_hashes(pack) == before


def test_html_report_rejects_normalised_and_symlinked_paths_beneath_input(
    tmp_path: Path,
    monkeypatch,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    child = pack / "child"
    child.mkdir()
    before = _tree_hashes(pack)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="output path must be outside the input directory"):
        write_html_report(Path("pack"), Path("pack/child/../normalised.html"))
    assert not (pack / "normalised.html").exists()
    with pytest.raises(ValueError, match="output path must be outside the input directory"):
        write_html_report(Path("pack"), Path("pack"))

    alias = tmp_path / "pack-alias"
    try:
        alias.symlink_to(pack, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")
    with pytest.raises(ValueError, match="output path must be outside the input directory"):
        write_html_report(Path("pack"), Path("pack-alias/symlinked.html"))
    assert not (pack / "symlinked.html").exists()
    assert _tree_hashes(pack) == before


def test_html_report_allows_and_overwrites_requested_output_outside_input(
    tmp_path: Path,
) -> None:
    pack = _write_current_pack(tmp_path / "pack")
    output = tmp_path / "review.html"

    write_html_report(pack, output)
    first = output.read_bytes()
    output.write_text("replace this existing output", encoding="utf-8")
    write_html_report(pack, output)

    assert output.read_bytes() == first
    assert b"replace this existing output" not in output.read_bytes()


def test_html_report_overview_counts_unique_exact_route_urls(tmp_path: Path) -> None:
    model = build_html_report_model(_write_current_pack(tmp_path / "pack"))
    expected = len(
        {item.url for item in model.project_state.endpoints}
        | {item.url for item in model.project_state.discovered_paths}
    )
    record_sum = len(model.project_state.endpoints) + len(model.project_state.discovered_paths)

    html = render_html_report(model)

    assert expected < record_sum
    assert f"<span>Unique route URLs</span><strong>{expected}</strong>" in html
    assert f"<span>Routes</span><strong>{record_sum}</strong>" not in html


def test_html_report_category_filter_covers_every_rendered_record(tmp_path: Path) -> None:
    html = render_html_report(build_html_report_model(_write_current_pack(tmp_path / "pack")))
    option_categories = _assert_category_filter_complete(html)

    assert {
        "form_or_parameter",
        "gobuster",
        "html",
        "nmap",
        "operator_summary",
    } <= option_categories


def _assert_category_filter_complete(html: str) -> set[str]:
    rendered_categories = {
        value for value in re.findall(r'data-category="([^"]*)"', html) if value
    }
    option_categories = {
        value for value in re.findall(r'<option value="([^"]*)">', html) if value
    }

    assert rendered_categories <= option_categories
    return option_categories


def test_cli_report_html_help_and_generation(tmp_path: Path, capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["report", "html", "--help"])
    help_output = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "usage: bugslyce report html" in help_output.out
    assert "--input-dir" in help_output.out
    assert "--output" in help_output.out

    pack = _write_current_pack(tmp_path / "pack")
    output = tmp_path / "review.html"
    exit_code = main(
        ["report", "html", "--input-dir", str(pack), "--output", str(output)]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert output.is_file()
    assert str(output) in captured.out
    assert "No network requests were made." in captured.out


def test_cli_report_html_reports_safe_errors_without_writing(tmp_path: Path, capsys) -> None:
    output = tmp_path / "review.html"

    exit_code = main(
        [
            "report",
            "html",
            "--input-dir",
            str(tmp_path / "missing"),
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Error: input directory does not exist" in captured.err
    assert "No network requests were made." in captured.err
    assert not output.exists()


def _write_current_pack(root: Path) -> Path:
    root.mkdir()
    state = build_project_state(FIXTURES_ROOT / "lab_raw_recon_pack")
    candidates = generate_candidates(state)
    (root / "project_state.json").write_text(
        export_project_state_json(state, candidates), encoding="utf-8"
    )
    return root


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _deep_item(
    url: str,
    status: int,
    body_hash: str,
    *,
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html"),),
    preview: str = "retained response preview",
    evidence_ids: tuple[str, ...],
) -> DeepSourceRouteCollectedItem:
    return DeepSourceRouteCollectedItem(
        url=url,
        method="GET",
        status_code=status,
        final_url=url,
        headers=headers,
        body_preview=preview,
        body_sha256=body_hash,
        body_bytes=len(preview.encode("utf-8")),
        elapsed_seconds=0.01,
        source="source_route_coverage",
        reason="existing structured review input",
        evidence_ids=evidence_ids,
    )
