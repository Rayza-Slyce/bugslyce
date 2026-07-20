"""Offline interpretation collection tests."""

from __future__ import annotations

from bugslyce.recon.artefact_analysis import (
    POSSIBLE_BASE64,
    POSSIBLE_MD5_SHAPE,
    ArtefactSource,
)
from bugslyce.recon.interpretation_collection import (
    collect_interpretation_from_sources,
)
from bugslyce.recon.modes import get_recon_mode


UNSAFE_WORDING = (
    "confirmed vulnerability",
    "confirmed exploitability",
    "confirmed credential",
    "confirmed secret",
    "this is a flag",
    "this is a password",
    "exploit this",
    "crack this",
    "attack this path",
    "no vulnerabilities found",
)


def test_collecting_from_empty_sources_returns_safe_empty_markdown() -> None:
    collection = collect_interpretation_from_sources(())

    assert collection.sources_analyzed == 0
    assert collection.hash_candidates == ()
    assert collection.transform_candidates == ()
    assert collection.robots_analyses == ()
    assert collection.html_source_analyses == ()
    assert collection.review_leads == ()
    assert collection.manual_review_leads_markdown is not None
    assert "## Manual Review Leads" in collection.manual_review_leads_markdown
    assert "No interpretation review leads were generated" in collection.manual_review_leads_markdown
    assert "No vulnerabilities found" not in collection.manual_review_leads_markdown


def test_collecting_generic_text_with_hash_candidate() -> None:
    source = ArtefactSource(
        source_id="generic-hash",
        source_kind="text",
        source_label="note",
        path="/notes.txt",
        text="flag clue abcdefabcdefabcdefabcdefabcdefab",
    )

    collection = collect_interpretation_from_sources((source,))

    assert collection.sources_analyzed == 1
    assert len(collection.hash_candidates) == 1
    assert collection.hash_candidates[0].candidate_type == POSSIBLE_MD5_SHAPE
    assert collection.robots_analyses == ()
    assert collection.html_source_analyses == ()
    assert [lead.lead_id for lead in collection.review_leads] == ["LEAD-0001"]
    assert collection.review_leads[0].lead_type == "possible_hash"
    assert collection.review_leads[0].category == "artefact"
    assert collection.review_leads[0].source_id == "generic-hash"
    assert "LEAD-0001" in (collection.manual_review_leads_markdown or "")


def test_review_lead_retains_all_exact_source_evidence_ids() -> None:
    source = ArtefactSource(
        source_id="SRC-CONFIG",
        source_kind="text",
        source_label="saved response",
        url="https://portal.example.test/documents/",
        evidence_ids=("EVID-SOURCE-A", "EVID-SOURCE-B"),
        text="flag clue abcdefabcdefabcdefabcdefabcdefab",
    )

    collection = collect_interpretation_from_sources((source,))

    assert collection.review_leads[0].evidence_ids == (
        "EVID-SOURCE-A",
        "EVID-SOURCE-B",
    )


def test_collecting_generic_text_with_encoded_candidate() -> None:
    source = ArtefactSource(
        source_id="generic-transform",
        source_kind="note",
        text="secret encoded value L2hpZGRlbi9mbGFn",
    )

    collection = collect_interpretation_from_sources((source,))

    assert len(collection.transform_candidates) == 1
    assert collection.transform_candidates[0].candidate_type == POSSIBLE_BASE64
    assert collection.transform_candidates[0].decoded_preview == "/hidden/flag"
    lead = collection.review_leads[0]
    assert lead.lead_type == "possible_transform"
    assert lead.decoded_preview == "/hidden/flag"
    assert "Derived previews are advisory" in (collection.manual_review_leads_markdown or "")


def test_collecting_robots_source_by_kind_uses_robots_analysis() -> None:
    source = ArtefactSource(
        source_id="robots-kind",
        source_kind="robots_txt",
        source_label="robots",
        url="http://example.test/robots.txt",
        path="/robots.txt",
        text="Disallow: /admin",
    )

    collection = collect_interpretation_from_sources((source,))

    assert len(collection.robots_analyses) == 1
    assert collection.html_source_analyses == ()
    assert collection.review_leads[0].category == "robots"
    assert collection.review_leads[0].field_name == "disallow"
    assert collection.review_leads[0].raw_value == "/admin"


def test_collecting_robots_source_by_url_or_path_uses_robots_analysis() -> None:
    by_url = ArtefactSource(
        source_id="robots-url",
        source_kind="text",
        url="http://example.test/robots.txt",
        text="User-agent: WeirdCrawler",
    )
    by_path = ArtefactSource(
        source_id="robots-path",
        source_kind="text",
        path="/robots.txt",
        text="Disallow: /backup",
    )

    collection = collect_interpretation_from_sources((by_url, by_path))

    assert len(collection.robots_analyses) == 2
    assert {lead.source_id for lead in collection.review_leads} == {
        "robots-url",
        "robots-path",
    }
    assert all(lead.category == "robots" for lead in collection.review_leads)


def test_collecting_html_source_by_kind_uses_html_analysis() -> None:
    source = ArtefactSource(
        source_id="html-kind",
        source_kind="html",
        source_label="homepage",
        url="http://example.test/",
        text="<html>\n<!-- flag clue -->\n</html>",
    )

    collection = collect_interpretation_from_sources((source,))

    assert len(collection.html_source_analyses) == 1
    assert collection.robots_analyses == ()
    assert collection.review_leads[0].category == "html_source"
    assert collection.review_leads[0].item_type == "html_comment"
    assert "html_source" in (collection.manual_review_leads_markdown or "")


def test_collecting_response_body_that_looks_like_html_uses_html_analysis() -> None:
    source = ArtefactSource(
        source_id="html-looking",
        source_kind="response_body",
        text="<body><a href='/admin'>admin</a></body>",
    )

    collection = collect_interpretation_from_sources((source,))

    assert len(collection.html_source_analyses) == 1
    assert all(lead.category == "html_source" for lead in collection.review_leads)
    assert "/admin" in {lead.raw_value for lead in collection.review_leads}


def test_generic_text_does_not_get_misclassified_as_html() -> None:
    source = ArtefactSource(
        source_id="plain-text",
        source_kind="response_body",
        text="flag clue abcdefabcdefabcdefabcdefabcdefab",
    )

    collection = collect_interpretation_from_sources((source,))

    assert collection.html_source_analyses == ()
    assert collection.robots_analyses == ()
    assert collection.review_leads[0].category == "artefact"
    assert collection.review_leads[0].lead_type == "possible_hash"


def test_source_metadata_is_preserved_in_review_leads_and_markdown() -> None:
    source = ArtefactSource(
        source_id="meta",
        source_kind="html",
        source_label="homepage",
        url="http://example.test/",
        path="/",
        port=80,
        service="http",
        text="<html>\n<!-- password abcdefabcdefabcdefabcdefabcdefab -->\n</html>",
    )

    collection = collect_interpretation_from_sources((source,))
    lead = collection.review_leads[0]

    assert lead.source_id == "meta"
    assert lead.source_kind == "html"
    assert lead.source_label == "homepage"
    assert lead.url == "http://example.test/"
    assert lead.path == "/"
    assert lead.port == 80
    assert lead.service == "http"
    assert lead.line_number == 2
    assert "homepage; kind=html; url=http://example.test/; service=http:80" in (
        collection.manual_review_leads_markdown or ""
    )


def test_specialised_sources_avoid_duplicate_generic_lead_explosions() -> None:
    robots = ArtefactSource(
        source_id="robots-transform",
        source_kind="robots_txt",
        text="Disallow: /decode/L2hpZGRlbi9mbGFn # secret",
    )
    html = ArtefactSource(
        source_id="html-hash",
        source_kind="html",
        text="<!-- password abcdefabcdefabcdefabcdefabcdefab -->",
    )

    collection = collect_interpretation_from_sources((robots, html))

    assert len(collection.transform_candidates) == 1
    assert len(collection.hash_candidates) == 1
    assert collection.robots_analyses[0].transform_artefacts
    assert collection.html_source_analyses[0].hash_artefacts
    assert {lead.category for lead in collection.review_leads} == {
        "robots",
        "html_source",
    }
    assert "possible_transform" not in {lead.lead_type for lead in collection.review_leads}
    assert "possible_hash" not in {lead.lead_type for lead in collection.review_leads}


def test_collection_markdown_preserves_cautious_wording() -> None:
    source = ArtefactSource(
        source_id="cautious",
        source_kind="text",
        text="secret L2hpZGRlbi9mbGFn",
    )

    collection = collect_interpretation_from_sources((source,))
    rendered = (collection.manual_review_leads_markdown or "").lower()

    assert "## manual review leads" in rendered
    assert "manual review recommended" in rendered
    assert "proof of vulnerability" in rendered
    assert all(phrase not in rendered for phrase in UNSAFE_WORDING)


def test_collection_can_skip_markdown_rendering() -> None:
    source = ArtefactSource(
        source_id="no-markdown",
        source_kind="text",
        text="abcdefabcdefabcdefabcdefabcdefab",
    )

    collection = collect_interpretation_from_sources((source,), render_markdown=False)

    assert len(collection.review_leads) == 1
    assert collection.manual_review_leads_markdown is None


def test_standard_available_and_deep_available() -> None:
    assert get_recon_mode("standard").is_available
    assert get_recon_mode("deep").is_available
