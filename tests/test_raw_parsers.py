"""Tests for structured raw recon artifact parsers."""

from __future__ import annotations

from pathlib import Path

from bugslyce.parsers.gobuster import parse_gobuster
from bugslyce.parsers.html import parse_html
from bugslyce.parsers.http_headers import parse_http_headers
from bugslyce.parsers.nmap import parse_nmap_normal
from bugslyce.parsers.robots import parse_robots


def test_nmap_parser_extracts_varied_http_ssh_and_database_services(tmp_path: Path) -> None:
    source = tmp_path / "nmap-services.txt"
    source.write_text(
        "\n".join(
            [
                "Nmap scan report for api.example-bounty.test (192.0.2.25)",
                "PORT     STATE SERVICE VERSION",
                "8088/tcp open  http    Caddy 2.7",
                "2222/tcp open  ssh     OpenSSH 9.0",
                "5432/tcp open  postgresql PostgreSQL 15",
            ]
        ),
        encoding="utf-8",
    )

    records = parse_nmap_normal(source)

    assert [(record.port, record.service) for record in records] == [
        (8088, "http"),
        (2222, "ssh"),
        (5432, "postgresql"),
    ]
    assert all(record.host == "192.0.2.25" for record in records)
    assert records[0].product == "Caddy"
    assert records[0].version == "2.7"


def test_gobuster_parser_extracts_varied_paths_status_size_and_redirect(tmp_path: Path) -> None:
    source = tmp_path / "gobuster.txt"
    source.write_text(
        "\n".join(
            [
                "admin-panel (Status: 200) [Size: 415]",
                "archive (Status: 302) [Size: 0] [--> https://app.example-bounty.test/archive/]",
                "missing (Status: 404) [Size: 91]",
            ]
        ),
        encoding="utf-8",
    )

    records = parse_gobuster(source, "https://app.example-bounty.test/")

    assert records[0].url == "https://app.example-bounty.test/admin-panel"
    assert records[0].status_code == 200
    assert records[0].content_length == 415
    assert records[1].redirect_location == "https://app.example-bounty.test/archive/"
    assert records[2].status_code == 404


def test_http_header_parser_extracts_final_response_block(tmp_path: Path) -> None:
    source = tmp_path / "curl-headers-api.txt"
    source.write_text(
        "\n".join(
            [
                "HTTP/1.1 301 Moved Permanently",
                "Location: /api/",
                "",
                "HTTP/1.1 200 OK",
                "Server: ExampleServer",
                "Content-Type: application/json",
                "Content-Length: 128",
            ]
        ),
        encoding="utf-8",
    )

    parsed = parse_http_headers(source)

    assert parsed.status_code == 200
    assert parsed.server == "ExampleServer"
    assert parsed.content_type == "application/json"
    assert parsed.content_length == 128
    assert parsed.location is None


def test_robots_parser_extracts_generic_directives(tmp_path: Path) -> None:
    source = tmp_path / "robots-api.txt"
    source.write_text(
        "\n".join(
            [
                "User-Agent: CUSTOM_CRAWLER_PLACEHOLDER",
                "Allow: /public-api/",
                "Disallow: /internal-docs/",
            ]
        ),
        encoding="utf-8",
    )

    artifacts = parse_robots(source, "https://api.example-bounty.test/robots.txt")
    artifact_types = {artifact.artifact_type for artifact in artifacts}

    assert {"robots", "unusual_user_agent", "allow_rule", "disallow_rule"} <= artifact_types
    assert any(artifact.value == "CUSTOM_CRAWLER_PLACEHOLDER" for artifact in artifacts)


def test_html_parser_extracts_metadata_and_conservative_artifacts(tmp_path: Path) -> None:
    source = tmp_path / "saved-page.html"
    source.write_text(
        """
        <html>
          <head>
            <title>Example Account Portal</title>
            <link href="/static/site.css" rel="stylesheet">
            <script src="/static/app.js"></script>
          </head>
          <body>
            <!-- backup token context placeholder -->
            <div hidden id="context-marker">ENCODEDLOOKINGPLACEHOLDER1234567890ABCD</div>
            <a href="/api/v1/users?id=1">API users</a>
            <form action="/account/login"><input type="password" name="password"></form>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    artifacts = parse_html(source, "https://app.example-bounty.test/")
    artifact_types = {artifact.artifact_type for artifact in artifacts}

    assert {
        "page_title",
        "link",
        "script_or_asset",
        "html_comment",
        "hidden_element",
        "form",
        "input",
        "encoded_like_artifact",
        "keyword_hit",
    } <= artifact_types
    assert any(artifact.value == "Example Account Portal" for artifact in artifacts)


def test_html_parser_does_not_classify_url_path_fragments_as_encoded(tmp_path: Path) -> None:
    source = tmp_path / "template.html"
    source.write_text(
        """
        <html>
          <body>
            <a href="https://vimeo.example/channels/staffpicks/93951774">video</a>
            <script>const mediaPath = "com/channels/staffpicks/93951774";</script>
            <script>const token = "ObsJmP173N2X6dOrAgEAL0Vu";</script>
          </body>
        </html>
        """,
        encoding="utf-8",
    )

    artifacts = parse_html(source, "https://app.example-bounty.test/sitemap/")

    encoded_values = [
        artifact.value
        for artifact in artifacts
        if artifact.artifact_type == "encoded_like_artifact"
    ]
    assert "com/channels/staffpicks/93951774" not in encoded_values
    assert "ObsJmP173N2X6dOrAgEAL0Vu" in encoded_values


def test_html_parser_does_not_extract_encoded_fragment_from_absolute_documentation_url(
    tmp_path: Path,
) -> None:
    source = tmp_path / "documentation-link.html"
    source.write_text(
        """
        <html><body>
          <a href="https://docs.example/reference/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789">
            Reference
          </a>
          <script>const standalone = "QWxwaGEvQmV0YStHYW1tYTEyMzQ1Njc4OTA=";</script>
          <script>const slashToken = "AbCdEfGhIjKlMnOp/QrStUvWxYz0123456789ABC";</script>
        </body></html>
        """,
        encoding="utf-8",
    )

    artifacts = parse_html(source, "https://app.example.test/")
    encoded_values = {
        artifact.value
        for artifact in artifacts
        if artifact.artifact_type == "encoded_like_artifact"
    }

    assert "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" not in encoded_values
    assert "QWxwaGEvQmV0YStHYW1tYTEyMzQ1Njc4OTA=" in encoded_values
    assert "AbCdEfGhIjKlMnOp/QrStUvWxYz0123456789ABC" in encoded_values


def test_html_parser_suppresses_encoded_matches_inside_href_and_src_values(
    tmp_path: Path,
) -> None:
    source = tmp_path / "reference-paths.html"
    source.write_text(
        """
        <html><body>
          <a href="/assets/bootstrapbundleminified">asset</a>
          <script src="//static.example.test/librarybundleminified"></script>
          <a href="https://docs.example.test/reference/DocumentationBundleMinified">docs</a>
          <p>AbCdEfGhIjKlMnOp/QrStUvWxYz012345</p>
        </body></html>
        """,
        encoding="utf-8",
    )

    artifacts = parse_html(source, "https://app.example.test/")
    encoded_values = [
        artifact.value
        for artifact in artifacts
        if artifact.artifact_type == "encoded_like_artifact"
    ]

    assert "bootstrapbundleminified" not in encoded_values
    assert "librarybundleminified" not in encoded_values
    assert "DocumentationBundleMinified" not in encoded_values
    assert "AbCdEfGhIjKlMnOp/QrStUvWxYz012345" in encoded_values


def test_html_keyword_matching_respects_token_boundaries(tmp_path: Path) -> None:
    source = tmp_path / "substrings.html"
    source.write_text(
        "<html><body>administrator apical keypad tokenization username-field password_reset</body></html>",
        encoding="utf-8",
    )

    artifacts = parse_html(source, "https://app.example-bounty.test/")

    assert not [
        artifact
        for artifact in artifacts
        if artifact.artifact_type == "keyword_hit"
    ]
