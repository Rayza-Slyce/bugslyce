"""Offline robots.txt analysis tests."""

from __future__ import annotations

from bugslyce.recon.artefact_analysis import (
    POSSIBLE_BASE64,
    POSSIBLE_MD5_SHAPE,
    ArtefactSource,
)
from bugslyce.recon.robots_analysis import analyse_robots_txt


def test_parses_common_robots_fields_and_comments() -> None:
    source = ArtefactSource(
        source_id="robots",
        source_kind="robots_txt",
        source_label="robots.txt",
        url="http://example.test/robots.txt",
        path="/robots.txt",
        port=80,
        service="http",
        text=(
            "# welcome\n"
            "User-Agent: *\n"
            "Disallow: /admin\n"
            "Allow: /public\n"
            "Sitemap: https://example.test/sitemap.xml\n"
            "Crawl-delay: 5\n"
        ),
    )

    analysis = analyse_robots_txt(source)

    assert [entry.field_name for entry in analysis.entries] == [
        "comment",
        "user-agent",
        "disallow",
        "allow",
        "sitemap",
        "crawl-delay",
    ]
    assert analysis.entries[1].raw_name == "User-Agent"
    assert analysis.entries[1].raw_value == "*"
    assert analysis.entries[2].line_number == 3
    assert analysis.entries[2].source_id == "robots"
    assert analysis.entries[2].url == "http://example.test/robots.txt"
    assert analysis.entries[2].port == 80


def test_case_insensitive_directive_parsing_and_unknown_preservation() -> None:
    source = ArtefactSource(
        source_id="robots",
        text="uSeR-aGeNt: crawler\nX-Clue: only this can enter\nbad line",
    )

    analysis = analyse_robots_txt(source)

    assert [entry.field_name for entry in analysis.entries] == [
        "user-agent",
        "unknown",
        "unknown",
    ]
    assert analysis.entries[1].raw_name == "X-Clue"
    assert analysis.entries[1].raw_value == "only this can enter"
    assert analysis.entries[2].raw_value == "bad line"


def test_ordinary_robots_content_does_not_create_high_priority_noise() -> None:
    source = ArtefactSource(
        source_id="ordinary",
        text="User-agent: *\nDisallow:\nAllow: /\nSitemap: https://example.test/sitemap.xml",
    )

    analysis = analyse_robots_txt(source)

    assert all(lead.priority != "high" for lead in analysis.review_leads)
    assert [lead.lead_type for lead in analysis.review_leads] == [
        "robots_empty_disallow"
    ]


def test_unusual_user_agent_detection() -> None:
    source = ArtefactSource(source_id="ua", text="User-agent: WeirdCrawler\n")

    analysis = analyse_robots_txt(source)

    lead = analysis.review_leads[0]
    assert lead.lead_type == "robots_unusual_user_agent"
    assert lead.priority == "medium"
    assert "Unusual robots User-Agent value detected." == lead.title
    assert lead.entry.raw_value == "WeirdCrawler"


def test_disallowed_high_signal_paths_create_review_leads() -> None:
    source = ArtefactSource(
        source_id="paths",
        text=(
            "User-agent: *\n"
            "Disallow: /admin\n"
            "Disallow: /backup\n"
            "Disallow: /static/css\n"
        ),
    )

    analysis = analyse_robots_txt(source)

    values = [lead.entry.raw_value for lead in analysis.review_leads]
    assert "/admin" in values
    assert "/backup" in values
    assert "/static/css" not in values
    assert all(
        lead.priority == "medium"
        for lead in analysis.review_leads
        if lead.entry.raw_value in {"/admin", "/backup"}
    )


def test_comments_with_clue_like_wording_are_high_priority() -> None:
    source = ArtefactSource(
        source_id="comments",
        text="# nothing to see here, secret clue\nUser-agent: *",
    )

    analysis = analyse_robots_txt(source)

    lead = analysis.review_leads[0]
    assert lead.lead_type == "robots_comment_clue_review"
    assert lead.priority == "high"
    assert "secret" in lead.nearby_keywords
    assert "clue" in lead.nearby_keywords
    assert "Robots comment contains clue-like wording." == lead.title


def test_hash_shaped_value_reuses_hash_artefact_analysis() -> None:
    source = ArtefactSource(
        source_id="hash",
        text="# flag: only this user-agent can enter\nUser-agent: abcdefabcdefabcdefabcdefabcdefab",
    )

    analysis = analyse_robots_txt(source)

    assert len(analysis.hash_artefacts) == 1
    assert analysis.hash_artefacts[0].candidate_type == POSSIBLE_MD5_SHAPE
    lead = next(
        item
        for item in analysis.review_leads
        if item.lead_type == "robots_unusual_user_agent_artefact_review"
    )
    assert lead.lead_type == "robots_unusual_user_agent_artefact_review"
    assert lead.priority == "high"
    assert lead.hash_artefacts[0].value == "abcdefabcdefabcdefabcdefabcdefab"
    assert "flag" in lead.nearby_keywords
    assert "unusual hash-shaped User-Agent" in lead.title
    assert "Correlate the value with other collected evidence before escalating." in (
        lead.suggested_manual_validation
    )


def test_encoded_unusual_user_agent_uses_encoded_looking_wording() -> None:
    source = ArtefactSource(
        source_id="encoded-ua",
        text="User-agent: L2hpZGRlbi9mbGFn",
    )

    analysis = analyse_robots_txt(source)

    assert analysis.hash_artefacts == ()
    assert len(analysis.transform_artefacts) == 1
    assert analysis.transform_artefacts[0].candidate_type == POSSIBLE_BASE64
    lead = analysis.review_leads[0]
    assert lead.lead_type == "robots_unusual_user_agent_artefact_review"
    assert lead.title == "Robots.txt contains an unusual encoded-looking User-Agent value."
    assert "encoded-looking pattern" in lead.explanation
    assert "hash-shaped pattern" not in lead.explanation
    assert "hash-shaped User-Agent" not in lead.title
    assert "Validate hash-shaped or encoded-looking artefacts locally." in (
        lead.suggested_manual_validation
    )


def test_encoded_value_reuses_transform_analysis() -> None:
    source = ArtefactSource(
        source_id="transform",
        text="Disallow: /decode/L2hpZGRlbi9mbGFn # secret",
    )

    analysis = analyse_robots_txt(source)

    assert len(analysis.transform_artefacts) == 1
    assert analysis.transform_artefacts[0].candidate_type == POSSIBLE_BASE64
    assert analysis.transform_artefacts[0].decoded_preview == "/hidden/flag"
    lead = next(
        item
        for item in analysis.review_leads
        if item.lead_type == "robots_artefact_review"
    )
    assert lead.priority == "high"
    assert lead.transform_artefacts[0].decoded_preview == "/hidden/flag"
    assert "secret" in lead.nearby_keywords


def test_source_metadata_and_line_numbers_are_preserved_on_leads() -> None:
    source = ArtefactSource(
        source_id="robots-meta",
        source_kind="robots_txt",
        source_label="target robots",
        url="http://example.test/robots.txt",
        path="/robots.txt",
        port=8080,
        service="http",
        text="User-agent: *\nDisallow: /hidden-dev\n",
    )

    analysis = analyse_robots_txt(source)
    lead = analysis.review_leads[0]

    assert lead.entry.source_id == "robots-meta"
    assert lead.entry.source_label == "target robots"
    assert lead.entry.url == "http://example.test/robots.txt"
    assert lead.entry.path == "/robots.txt"
    assert lead.entry.port == 8080
    assert lead.entry.service == "http"
    assert lead.entry.line_number == 2
    assert "User-agent: *" in lead.entry.context


def test_cautious_wording_and_manual_validation() -> None:
    source = ArtefactSource(
        source_id="cautious",
        text="# password clue\nDisallow: /secret",
    )

    analysis = analyse_robots_txt(source)
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

    assert "treat robots.txt as a clue source, not proof of vulnerability" in rendered
    assert "do not submit artefacts to online decoders or hash databases automatically" in rendered
    assert "do not brute force or attempt authentication based on robots.txt alone" in rendered
    assert "this is a flag" not in rendered
    assert "this path is vulnerable" not in rendered
    assert "confirmed secret" not in rendered
    assert "confirmed credential" not in rendered
    assert "exploit this path" not in rendered


def test_malformed_and_duplicate_lines_do_not_crash_or_duplicate_leads() -> None:
    source = ArtefactSource(
        source_id="weird",
        text="garbage\nX-Test: hidden\nX-Test: hidden\n::::\n",
    )

    analysis = analyse_robots_txt(source)

    assert len(analysis.entries) == 4
    hidden_unknown = [
        lead
        for lead in analysis.review_leads
        if lead.lead_type == "robots_unknown_directive"
        and lead.entry.raw_value == "hidden"
    ]
    assert len(hidden_unknown) == 1


def test_public_names_use_uk_artefact_spelling() -> None:
    source = ArtefactSource(source_id="uk", text="Disallow: /hidden")
    analysis = analyse_robots_txt(source)

    assert analysis.__class__.__name__ == "RobotsAnalysis"
    assert analysis.review_leads[0].hash_artefacts == ()
