"""Offline interpretation aggregation tests."""

from __future__ import annotations

from bugslyce.recon.artefact_analysis import (
    POSSIBLE_BASE64,
    POSSIBLE_MD5_SHAPE,
    ArtefactSource,
    find_hash_artefacts,
    find_transform_artefacts,
)
from bugslyce.recon.html_source_analysis import analyse_html_source
from bugslyce.recon.interpretation import (
    aggregate_interpretation_leads,
    normalise_hash_artefacts,
    normalise_html_source_review_leads,
    normalise_robots_review_leads,
    normalise_transform_artefacts,
)
from bugslyce.recon.robots_analysis import analyse_robots_txt


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
)


def test_hash_artefact_normalisation_preserves_context_and_caution() -> None:
    source = ArtefactSource(
        source_id="hash-src",
        source_kind="robots_txt",
        source_label="robots",
        url="http://example.test/robots.txt",
        path="/robots.txt",
        port=80,
        service="http",
        field_name="user-agent",
        text="flag user-agent abcdefabcdefabcdefabcdefabcdefab",
    )
    candidate = find_hash_artefacts(source)[0]

    lead = normalise_hash_artefacts((candidate,))[0]

    assert lead.lead_id == "LEAD-0001"
    assert lead.category == "artefact"
    assert lead.lead_type == "possible_hash"
    assert lead.priority == "high"
    assert lead.title == "Possible hash candidate detected."
    assert "Shape alone does not confirm the hash type." in lead.explanation
    assert lead.source_id == "hash-src"
    assert lead.source_kind == "robots_txt"
    assert lead.source_label == "robots"
    assert lead.url == "http://example.test/robots.txt"
    assert lead.path == "/robots.txt"
    assert lead.port == 80
    assert lead.service == "http"
    assert lead.field_name == "user-agent"
    assert lead.raw_value == "abcdefabcdefabcdefabcdefabcdefab"
    assert lead.related_artefact_types == (POSSIBLE_MD5_SHAPE,)
    assert "flag" in lead.nearby_keywords
    assert lead.suggested_manual_validation == candidate.suggested_manual_validation


def test_transform_normalisation_preserves_decoded_preview_and_guidance() -> None:
    source = ArtefactSource(
        source_id="transform-src",
        source_kind="html",
        source_label="homepage",
        url="http://example.test/",
        text="secret encoded value L2hpZGRlbi9mbGFn",
    )
    candidate = find_transform_artefacts(source)[0]

    lead = normalise_transform_artefacts((candidate,))[0]

    assert lead.lead_type == "possible_transform"
    assert lead.category == "artefact"
    assert lead.title == "Possible encoded or transformed artefact detected."
    assert "Derived previews are advisory and may be incorrect." in lead.explanation
    assert lead.raw_value == "L2hpZGRlbi9mbGFn"
    assert lead.decoded_preview == "/hidden/flag"
    assert lead.related_artefact_types == (POSSIBLE_BASE64,)
    assert "secret" in lead.nearby_keywords
    assert lead.suggested_manual_validation == candidate.suggested_manual_validation
    assert "artefact" in lead.title.lower()


def test_robots_review_lead_normalisation_preserves_entry_metadata_and_related_artefacts() -> None:
    source = ArtefactSource(
        source_id="robots-src",
        source_kind="robots_txt",
        source_label="robots",
        url="http://example.test/robots.txt",
        path="/robots.txt",
        port=8080,
        service="http",
        text="# secret clue\nDisallow: /decode/L2hpZGRlbi9mbGFn",
    )
    analysis = analyse_robots_txt(source)
    robots_lead = next(
        lead
        for lead in analysis.review_leads
        if lead.lead_type == "robots_artefact_review"
    )

    lead = normalise_robots_review_leads((robots_lead,))[0]

    assert lead.category == "robots"
    assert lead.lead_type == "robots_artefact_review"
    assert lead.priority == "high"
    assert lead.source_id == "robots-src"
    assert lead.source_kind == "robots_txt"
    assert lead.source_label == "robots"
    assert lead.url == "http://example.test/robots.txt"
    assert lead.path == "/robots.txt"
    assert lead.port == 8080
    assert lead.service == "http"
    assert lead.line_number == 2
    assert lead.field_name == "disallow"
    assert lead.raw_value == "/decode/L2hpZGRlbi9mbGFn"
    assert lead.decoded_preview == "/hidden/flag"
    assert POSSIBLE_BASE64 in lead.related_artefact_types
    assert lead.suggested_manual_validation == robots_lead.suggested_manual_validation


def test_html_source_review_lead_normalisation_preserves_item_metadata_and_related_artefacts() -> None:
    source = ArtefactSource(
        source_id="html-src",
        source_kind="html",
        source_label="homepage",
        url="http://example.test/",
        path="/",
        port=80,
        service="http",
        text="<html>\n<!-- password abcdefabcdefabcdefabcdefabcdefab -->\n</html>",
    )
    analysis = analyse_html_source(source)
    html_lead = next(
        lead
        for lead in analysis.review_leads
        if lead.lead_type == "html_source_artefact_review"
    )

    lead = normalise_html_source_review_leads((html_lead,))[0]

    assert lead.category == "html_source"
    assert lead.lead_type == "html_source_artefact_review"
    assert lead.priority == "high"
    assert lead.source_id == "html-src"
    assert lead.source_kind == "html"
    assert lead.source_label == "homepage"
    assert lead.url == "http://example.test/"
    assert lead.path == "/"
    assert lead.port == 80
    assert lead.service == "http"
    assert lead.line_number == 2
    assert lead.item_type == "html_comment"
    assert lead.raw_value == "password abcdefabcdefabcdefabcdefabcdefab"
    assert lead.related_artefact_types == (POSSIBLE_MD5_SHAPE,)
    assert lead.suggested_manual_validation == html_lead.suggested_manual_validation


def test_aggregation_accepts_one_input_collection() -> None:
    source = ArtefactSource(
        source_id="single",
        text="abcdefabcdefabcdefabcdefabcdefab",
    )

    leads = aggregate_interpretation_leads(
        hash_candidates=find_hash_artefacts(source),
    )

    assert len(leads) == 1
    assert leads[0].lead_id == "LEAD-0001"
    assert leads[0].lead_type == "possible_hash"


def test_aggregation_is_deterministic_and_orders_by_priority_then_source() -> None:
    medium_hash = find_hash_artefacts(
        ArtefactSource(source_id="z-src", text="abcdefabcdefabcdefabcdefabcdefab")
    )[0]
    high_transform = find_transform_artefacts(
        ArtefactSource(source_id="a-src", text="secret L2hpZGRlbi9mbGFn")
    )[0]
    robots = analyse_robots_txt(
        ArtefactSource(source_id="m-src", text="Disallow: /admin")
    ).review_leads

    first = aggregate_interpretation_leads(
        hash_candidates=(medium_hash,),
        transform_candidates=(high_transform,),
        robots_review_leads=robots,
    )
    second = aggregate_interpretation_leads(
        hash_candidates=(medium_hash,),
        transform_candidates=(high_transform,),
        robots_review_leads=robots,
    )

    assert [lead.lead_id for lead in first] == [
        "LEAD-0001",
        "LEAD-0002",
        "LEAD-0003",
    ]
    assert first == second
    assert [lead.priority for lead in first] == ["high", "medium", "medium"]
    assert first[0].source_id == "a-src"


def test_aggregation_preserves_distinct_contexts_for_same_raw_value() -> None:
    first = find_hash_artefacts(
        ArtefactSource(source_id="first", text="abcdefabcdefabcdefabcdefabcdefab")
    )[0]
    second = find_hash_artefacts(
        ArtefactSource(source_id="second", text="abcdefabcdefabcdefabcdefabcdefab")
    )[0]

    leads = aggregate_interpretation_leads(hash_candidates=(first, second))

    assert len(leads) == 2
    assert {lead.source_id for lead in leads} == {"first", "second"}
    assert [lead.lead_id for lead in leads] == ["LEAD-0001", "LEAD-0002"]


def test_aggregation_deduplicates_exact_same_context_only() -> None:
    candidate = find_hash_artefacts(
        ArtefactSource(source_id="same", text="abcdefabcdefabcdefabcdefabcdefab")
    )[0]

    leads = aggregate_interpretation_leads(hash_candidates=(candidate, candidate))

    assert len(leads) == 1
    assert leads[0].lead_id == "LEAD-0001"


def test_aggregation_preserves_combined_robots_user_agent_artefact_lead() -> None:
    robots_leads = analyse_robots_txt(
        ArtefactSource(
            source_id="robots",
            source_kind="robots_txt",
            source_label="robots.txt",
            text="User-agent: a18672860d0510e5ab6699730763b250",
        )
    ).review_leads

    leads = aggregate_interpretation_leads(robots_review_leads=robots_leads)

    assert len(leads) == 1
    assert leads[0].lead_id == "LEAD-0001"
    assert leads[0].lead_type == "robots_unusual_user_agent_artefact_review"
    assert leads[0].title == "Robots.txt contains an unusual hash-shaped User-Agent value."
    assert leads[0].raw_value == "a18672860d0510e5ab6699730763b250"
    assert leads[0].related_artefact_types == (POSSIBLE_MD5_SHAPE,)
    assert "Correlate the value with other collected evidence before escalating." in (
        leads[0].suggested_manual_validation
    )


def test_aggregation_combines_multiple_analyser_outputs() -> None:
    hash_candidate = find_hash_artefacts(
        ArtefactSource(source_id="hash", text="abcdefabcdefabcdefabcdefabcdefab")
    )[0]
    transform_candidate = find_transform_artefacts(
        ArtefactSource(source_id="transform", text="secret L2hpZGRlbi9mbGFn")
    )[0]
    robots_leads = analyse_robots_txt(
        ArtefactSource(source_id="robots", text="Disallow: /secret")
    ).review_leads
    html_leads = analyse_html_source(
        ArtefactSource(source_id="html", text="<!-- flag clue -->")
    ).review_leads

    leads = aggregate_interpretation_leads(
        hash_candidates=(hash_candidate,),
        transform_candidates=(transform_candidate,),
        robots_review_leads=robots_leads,
        html_source_review_leads=html_leads,
    )

    assert {lead.category for lead in leads} == {
        "artefact",
        "robots",
        "html_source",
    }
    assert {lead.lead_type for lead in leads} >= {
        "possible_hash",
        "possible_transform",
        "robots_disallowed_path_review",
        "html_comment_clue_review",
    }


def test_interpretation_leads_avoid_unsafe_confirmed_wording() -> None:
    leads = aggregate_interpretation_leads(
        transform_candidates=find_transform_artefacts(
            ArtefactSource(source_id="unsafe", text="secret L2hpZGRlbi9mbGFn")
        )
    )

    rendered = " ".join(
        " ".join(
            (
                lead.title,
                lead.explanation,
                " ".join(lead.suggested_manual_validation),
            )
        )
        for lead in leads
    ).lower()

    assert "manual review recommended" in rendered
    assert "proof of vulnerability" in rendered
    assert all(phrase not in rendered for phrase in UNSAFE_WORDING)
