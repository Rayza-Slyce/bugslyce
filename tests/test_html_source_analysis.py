"""Offline HTML/source analysis tests."""

from __future__ import annotations

from bugslyce.recon.artefact_analysis import (
    POSSIBLE_BASE64,
    POSSIBLE_MD5_SHAPE,
    ArtefactSource,
)
from bugslyce.recon.html_source_analysis import analyse_html_source


def test_html_comment_detection_and_clue_lead() -> None:
    source = ArtefactSource(
        source_id="home",
        source_kind="html",
        text="<html>\n<!-- flag clue is elsewhere -->\n</html>",
    )

    analysis = analyse_html_source(source)

    comment = next(item for item in analysis.items if item.item_type == "html_comment")
    assert comment.raw_value == "flag clue is elsewhere"
    assert comment.line_number == 2
    lead = analysis.review_leads[0]
    assert lead.lead_type == "html_comment_clue_review"
    assert lead.priority == "high"
    assert "flag" in lead.nearby_keywords
    assert "HTML comment contains clue-like wording." == lead.title


def test_hidden_attribute_and_inline_hidden_style_detection() -> None:
    source = ArtefactSource(
        source_id="hidden",
        text=(
            "<div hidden>secret</div>\n"
            "<p style=\"display:none\">flag</p>\n"
            "<span style='visibility:hidden'>token</span>\n"
            "<em style=\"opacity:0\">key</em>"
        ),
    )

    analysis = analyse_html_source(source)
    item_types = [item.item_type for item in analysis.items]

    assert "hidden_attribute" in item_types
    assert item_types.count("inline_style_hidden") == 3
    assert any(lead.lead_type == "html_hidden_source_review" for lead in analysis.review_leads)


def test_suspicious_id_class_name_detection() -> None:
    source = ArtefactSource(
        source_id="attrs",
        text=(
            "<div id=\"hidden-flag\"></div>"
            "<input name='secret-token' value='x'>"
            "<span class=\"ordinary\"></span>"
        ),
    )

    analysis = analyse_html_source(source)
    suspicious = [
        item
        for item in analysis.items
        if item.item_type == "suspicious_id_or_class"
    ]

    assert [item.raw_value for item in suspicious] == ["hidden-flag", "secret-token"]
    assert all(item.attribute_name in {"id", "name"} for item in suspicious)


def test_local_href_src_and_form_action_reference_detection_without_submission() -> None:
    source = ArtefactSource(
        source_id="refs",
        text=(
            "<a href=\"/admin\">admin</a>"
            "<script src=\"/assets/app.js\"></script>"
            "<img src='/backup.zip'>"
            "<form action=\"/debug-submit\"></form>"
        ),
    )

    analysis = analyse_html_source(source)
    references = [
        item for item in analysis.items if item.item_type.endswith("_reference")
    ]

    assert [item.raw_value for item in references] == [
        "/admin",
        "/assets/app.js",
        "/backup.zip",
        "/debug-submit",
    ]
    lead_values = [lead.item.raw_value for lead in analysis.review_leads]
    assert "/admin" in lead_values
    assert "/backup.zip" in lead_values
    assert "/debug-submit" in lead_values
    assert "/assets/app.js" not in lead_values


def test_unusual_local_file_extensions_create_reference_leads() -> None:
    source = ArtefactSource(
        source_id="files",
        text=(
            "<a href='/db.sql'>db</a>"
            "<a href='/old.bak'>old</a>"
            "<a href='/notes.txt'>notes</a>"
            "<a href='/events.log'>log</a>"
        ),
    )

    analysis = analyse_html_source(source)

    assert [lead.item.raw_value for lead in analysis.review_leads] == [
        "/db.sql",
        "/old.bak",
        "/notes.txt",
        "/events.log",
    ]
    assert all(lead.priority == "medium" for lead in analysis.review_leads)


def test_ordinary_css_js_image_references_do_not_create_noisy_high_priority_leads() -> None:
    source = ArtefactSource(
        source_id="ordinary",
        text=(
            "<link href='/assets/site.css'>"
            "<script src='/assets/app.js'></script>"
            "<img src='/assets/logo.png'>"
        ),
    )

    analysis = analyse_html_source(source)

    assert all(lead.priority != "high" for lead in analysis.review_leads)
    assert analysis.review_leads == ()


def test_hash_shaped_value_reuses_hash_artefact_analysis() -> None:
    source = ArtefactSource(
        source_id="hash",
        text="<!-- password abcdefabcdefabcdefabcdefabcdefab -->",
    )

    analysis = analyse_html_source(source)

    assert len(analysis.hash_artefacts) == 1
    assert analysis.hash_artefacts[0].candidate_type == POSSIBLE_MD5_SHAPE
    lead = next(
        lead
        for lead in analysis.review_leads
        if lead.lead_type == "html_source_artefact_review"
    )
    assert lead.priority == "high"
    assert lead.hash_artefacts[0].value == "abcdefabcdefabcdefabcdefabcdefab"


def test_encoded_value_reuses_transform_artefact_analysis() -> None:
    source = ArtefactSource(
        source_id="encoded",
        text="<a href=\"/decode/L2hpZGRlbi9mbGFn\">secret clue</a>",
    )

    analysis = analyse_html_source(source)

    assert len(analysis.transform_artefacts) == 1
    assert analysis.transform_artefacts[0].candidate_type == POSSIBLE_BASE64
    assert analysis.transform_artefacts[0].decoded_preview == "/hidden/flag"
    lead = next(
        lead
        for lead in analysis.review_leads
        if lead.lead_type == "html_source_artefact_review"
    )
    assert lead.priority == "high"


def test_source_metadata_and_line_numbers_are_preserved() -> None:
    source = ArtefactSource(
        source_id="meta",
        source_kind="html",
        source_label="homepage",
        url="http://example.test/",
        path="/",
        port=80,
        service="http",
        text="<html>\n<a href='/backup.zip'>backup</a>\n</html>",
    )

    analysis = analyse_html_source(source)
    item = next(item for item in analysis.items if item.raw_value == "/backup.zip")

    assert item.source_id == "meta"
    assert item.source_label == "homepage"
    assert item.url == "http://example.test/"
    assert item.path == "/"
    assert item.port == 80
    assert item.service == "http"
    assert item.line_number == 2
    assert "<a href='/backup.zip'>" in item.context


def test_inline_text_clue_detection() -> None:
    source = ArtefactSource(
        source_id="text",
        text="<body><p>The secret clue is in the source.</p></body>",
    )

    analysis = analyse_html_source(source)

    lead = next(
        lead for lead in analysis.review_leads if lead.lead_type == "html_inline_text_clue_review"
    )
    assert lead.priority == "high"
    assert "secret" in lead.nearby_keywords
    assert "clue" in lead.nearby_keywords


def test_cautious_wording_and_manual_validation() -> None:
    source = ArtefactSource(
        source_id="cautious",
        text="<!-- password clue --><form action='/admin'></form>",
    )

    analysis = analyse_html_source(source)
    rendered = " ".join(
        " ".join(
            (
                lead.title,
                lead.explanation,
                " ".join(lead.suggested_manual_validation),
            )
        )
        for lead in analysis.review_leads
    ).lower()

    assert "treat hidden source content as a clue source, not proof of vulnerability" in rendered
    assert "do not brute force, submit forms, or attempt authentication" in rendered
    assert "do not submit artefacts to online decoders or hash databases automatically" in rendered
    assert "this is a flag" not in rendered
    assert "this is a password" not in rendered
    assert "confirmed secret" not in rendered
    assert "confirmed credential" not in rendered
    assert "this path is vulnerable" not in rendered
    assert "exploit this path" not in rendered


def test_malformed_html_does_not_crash_and_duplicate_leads_are_suppressed() -> None:
    source = ArtefactSource(
        source_id="weird",
        text="<div id='hidden-flag'><broken <div id='hidden-flag'>",
    )

    analysis = analyse_html_source(source)
    leads = [
        lead
        for lead in analysis.review_leads
        if lead.lead_type == "html_suspicious_attribute_review"
    ]

    assert len(leads) == 1


def test_public_names_use_uk_artefact_spelling() -> None:
    source = ArtefactSource(source_id="uk", text="<!-- secret -->")
    analysis = analyse_html_source(source)

    assert analysis.__class__.__name__ == "HtmlSourceAnalysis"
    assert analysis.review_leads[0].hash_artefacts == ()
