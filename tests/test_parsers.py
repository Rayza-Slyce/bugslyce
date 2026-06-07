"""Tests for safe passive recon parsers."""

from __future__ import annotations

from pathlib import Path

import pytest

from bugslyce.core.normalise import normalise_hostname
from bugslyce.core.scope import parse_scope
from bugslyce.parsers.httpx import parse_httpx_jsonl
from bugslyce.parsers.notes import parse_notes
from bugslyce.parsers.subdomains import parse_subdomains
from bugslyce.parsers.urls import parse_urls


FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "examples" / "demo_recon"


def test_parse_scope_extracts_demo_in_scope_and_out_of_scope() -> None:
    parsed = parse_scope(FIXTURES_ROOT / "basic_saas" / "scope.md")

    assert "app.example-bounty.test" in parsed.in_scope
    assert "api.example-bounty.test" in parsed.in_scope
    assert "Any domain not ending in `.example-bounty.test`" in parsed.out_of_scope
    assert "Fictional authorised demo scope" in parsed.raw_text
    assert parsed.source_path.endswith("scope.md")


def test_parse_subdomains_dedupes_and_normalises_hosts() -> None:
    parsed = parse_subdomains(FIXTURES_ROOT / "basic_saas" / "subdomains.txt")
    hostnames = [record.hostname for record in parsed]

    assert hostnames.count("app.example-bounty.test") == 1
    assert hostnames[0] == "app.example-bounty.test"
    assert all(hostname == hostname.lower() for hostname in hostnames)


def test_parse_httpx_jsonl_reads_valid_demo_records() -> None:
    parsed = parse_httpx_jsonl(FIXTURES_ROOT / "api_heavy" / "httpx.jsonl")

    assert len(parsed) == 6
    assert parsed[0].url == "https://api.example-bounty.test"
    assert parsed[0].host == "api.example-bounty.test"
    assert parsed[0].status_code == 200
    assert parsed[0].title == "Example API"
    assert parsed[0].tech == ["nginx", "Go"]
    assert parsed[0].content_length == 640


def test_parse_httpx_jsonl_tolerates_malformed_lines(tmp_path: Path) -> None:
    source = tmp_path / "httpx.jsonl"
    source.write_text(
        "\n".join(
            [
                '{"url":"https://app.example-bounty.test","host":"APP.EXAMPLE-BOUNTY.TEST"}',
                "{bad json",
                '["not", "an", "object"]',
                '{"url":"https://api.example-bounty.test","status_code":"404"}',
            ]
        ),
        encoding="utf-8",
    )

    with pytest.warns(RuntimeWarning, match="Skipping"):
        parsed = parse_httpx_jsonl(source)

    assert len(parsed) == 2
    assert parsed[0].host == "app.example-bounty.test"
    assert parsed[1].status_code == 404


def test_parse_urls_dedupes_and_extracts_query_param_names() -> None:
    parsed = parse_urls(FIXTURES_ROOT / "basic_saas" / "urls.txt")
    original_urls = [record.original_url for record in parsed]

    assert original_urls.count("https://app.example-bounty.test/dashboard?org_id=acme-demo") == 1

    account_settings = next(record for record in parsed if record.path == "/account/settings")
    assert account_settings.scheme == "https"
    assert account_settings.hostname == "app.example-bounty.test"
    assert account_settings.query_param_names == ["user_id"]

    callback = next(record for record in parsed if record.path == "/auth/callback")
    assert callback.query_param_names == ["next"]


def test_parse_urls_skips_malformed_urls_safely(tmp_path: Path) -> None:
    source = tmp_path / "urls.txt"
    source.write_text(
        "\n".join(
            [
                "# comment",
                "not-a-url",
                "https://APP.EXAMPLE-BOUNTY.TEST/account?user_id=1001&next=/home",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.warns(RuntimeWarning, match="Skipping malformed URL"):
        parsed = parse_urls(source)

    assert len(parsed) == 1
    assert parsed[0].hostname == "app.example-bounty.test"
    assert parsed[0].query_param_names == ["user_id", "next"]


def test_ip_hostname_normalisation_and_url_parsing() -> None:
    assert normalise_hostname(" 10.10.10.10. ") == "10.10.10.10"

    parsed = parse_urls(FIXTURES_ROOT / "local_lab_ip" / "urls.txt")
    api_endpoint = next(record for record in parsed if record.hostname == "10.10.10.10" and record.path == "/api/users")

    assert api_endpoint.scheme == "http"
    assert api_endpoint.hostname == "10.10.10.10"
    assert api_endpoint.query_param_names == ["user_id"]


def test_missing_optional_files_are_handled_safely(tmp_path: Path) -> None:
    missing = tmp_path / "missing.txt"

    with pytest.warns(RuntimeWarning):
        assert parse_subdomains(missing) == []
    with pytest.warns(RuntimeWarning):
        assert parse_httpx_jsonl(missing) == []
    with pytest.warns(RuntimeWarning):
        assert parse_urls(missing) == []
    with pytest.warns(RuntimeWarning):
        assert parse_notes(missing).note_items == []
    with pytest.warns(RuntimeWarning):
        assert parse_scope(missing).in_scope == []


def test_parse_notes_preserves_cautious_language() -> None:
    parsed = parse_notes(FIXTURES_ROOT / "noisy_false_positive" / "notes.md")

    assert "does not demonstrate access to a backup file" in parsed.raw_text
    assert any("should temper any later language" in item for item in parsed.note_items)
    assert all("confirmed vulnerability" not in item.lower() for item in parsed.note_items)


def test_all_demo_fixture_types_parse() -> None:
    for fixture_dir in FIXTURES_ROOT.iterdir():
        if not fixture_dir.is_dir():
            continue

        assert parse_scope(fixture_dir / "scope.md").raw_text
        assert parse_subdomains(fixture_dir / "subdomains.txt")
        if (fixture_dir / "httpx.jsonl").exists():
            assert parse_httpx_jsonl(fixture_dir / "httpx.jsonl")
        if (fixture_dir / "urls.txt").exists():
            assert parse_urls(fixture_dir / "urls.txt")
        if (fixture_dir / "notes.md").exists():
            assert parse_notes(fixture_dir / "notes.md").raw_text


def test_parsers_do_not_invent_vulnerability_claims(tmp_path: Path) -> None:
    claim_words = ("vulnerable", "exploitable", "confirmed vulnerability", "bypass")

    scope_file = tmp_path / "scope.md"
    scope_file.write_text(
        "# Demo\n\n## In Scope\n\n- `app.example-bounty.test`\n",
        encoding="utf-8",
    )
    subdomains_file = tmp_path / "subdomains.txt"
    subdomains_file.write_text("app.example-bounty.test\n", encoding="utf-8")
    httpx_file = tmp_path / "httpx.jsonl"
    httpx_file.write_text(
        '{"url":"https://app.example-bounty.test","host":"app.example-bounty.test","title":"Demo App"}\n',
        encoding="utf-8",
    )
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("https://app.example-bounty.test/account?user_id=1001\n", encoding="utf-8")
    notes_file = tmp_path / "notes.md"
    notes_file.write_text("- Account path observed in passive data.\n", encoding="utf-8")

    scope = parse_scope(scope_file)
    notes = parse_notes(notes_file)
    parsed_values: list[str] = [
        *scope.in_scope,
        *scope.out_of_scope,
        *(record.hostname for record in parse_subdomains(subdomains_file)),
        *(record.original_url for record in parse_urls(urls_file)),
        notes.raw_text,
        *(
            value
            for record in parse_httpx_jsonl(httpx_file)
            for value in [record.url or "", record.host or "", record.title or ""]
        ),
    ]

    lowered = "\n".join(parsed_values).lower()
    assert not any(claim in lowered for claim in claim_words)
