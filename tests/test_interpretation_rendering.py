"""Markdown rendering tests for offline interpretation review leads."""

from __future__ import annotations

from bugslyce.recon.artefact_analysis import (
    ArtefactSource,
    find_hash_artefacts,
    find_transform_artefacts,
)
from bugslyce.recon.html_source_analysis import analyse_html_source
from bugslyce.recon.interpretation import (
    ReviewLead,
    aggregate_interpretation_leads,
)
from bugslyce.recon.interpretation_rendering import render_review_leads_markdown
from bugslyce.recon.robots_analysis import analyse_robots_txt


UNSAFE_WORDING = (
    "vulnerabilities",
    "findings",
    "confirmed issues",
    "exploits",
    "credentials",
    "secrets found",
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


def test_empty_lead_list_renders_safe_empty_state() -> None:
    markdown = render_review_leads_markdown(())

    assert markdown.startswith("## Manual Review Leads")
    assert "manual review prompts, not proof of vulnerability" in markdown
    assert "No interpretation review leads were generated" in markdown
    assert "No vulnerabilities found" not in markdown
    assert "target is clean" not in markdown.lower()


def test_render_single_hash_derived_lead() -> None:
    leads = aggregate_interpretation_leads(
        hash_candidates=find_hash_artefacts(
            ArtefactSource(
                source_id="hash",
                source_kind="robots_txt",
                source_label="robots",
                url="http://example.test/robots.txt",
                path="/robots.txt",
                port=80,
                service="http",
                field_name="user-agent",
                text="flag abcdefabcdefabcdefabcdefabcdefab",
            )
        )
    )

    markdown = render_review_leads_markdown(leads)

    assert "### LEAD-0001: Possible hash candidate detected." in markdown
    assert "- Priority: high" in markdown
    assert "- Category: artefact" in markdown
    assert "kind=robots_txt" in markdown
    assert "url=http://example.test/robots.txt" in markdown
    assert "service=http:80" in markdown
    assert "- Line: 1" in markdown
    assert "- Field: user-agent" in markdown
    assert "- Raw value: `abcdefabcdefabcdefabcdefabcdefab`" in markdown
    assert "- Nearby keywords: flag" in markdown
    assert "- Related artefact types: possible_md5_shape" in markdown
    assert "Shape alone does not confirm the hash type." in markdown
    assert "Identify the hash type locally" in markdown


def test_render_transform_derived_lead_with_decoded_preview() -> None:
    leads = aggregate_interpretation_leads(
        transform_candidates=find_transform_artefacts(
            ArtefactSource(
                source_id="transform",
                source_kind="html",
                source_label="homepage",
                url="http://example.test/",
                text="secret L2hpZGRlbi9mbGFn",
            )
        )
    )

    markdown = render_review_leads_markdown(leads)

    assert "Possible encoded or transformed artefact detected." in markdown
    assert "- Decoded/derived preview: `/hidden/flag`" in markdown
    assert "- Related artefact types: possible_base64" in markdown
    assert "Derived previews are advisory and may be incorrect." in markdown
    assert "Do not submit artefacts to online decoders automatically." in markdown


def test_render_robots_and_html_source_metadata() -> None:
    robots_leads = analyse_robots_txt(
        ArtefactSource(
            source_id="robots",
            source_kind="robots_txt",
            source_label="robots.txt",
            url="http://example.test/robots.txt",
            path="/robots.txt",
            port=8080,
            service="http",
            text="Disallow: /admin",
        )
    ).review_leads
    html_leads = analyse_html_source(
        ArtefactSource(
            source_id="html",
            source_kind="html",
            source_label="homepage",
            url="http://example.test/",
            path="/",
            port=80,
            service="http",
            text="<html>\n<!-- flag clue -->\n</html>",
        )
    ).review_leads
    leads = aggregate_interpretation_leads(
        robots_review_leads=robots_leads,
        html_source_review_leads=html_leads,
    )

    markdown = render_review_leads_markdown(leads)

    assert "- Category: robots" in markdown
    assert "- Category: html_source" in markdown
    assert "- Field: disallow" in markdown
    assert "- Item type: html_comment" in markdown
    assert "- Line: 1" in markdown
    assert "- Line: 2" in markdown
    assert "robots.txt" in markdown
    assert "homepage" in markdown


def test_renderer_preserves_existing_ids_and_input_order() -> None:
    leads = (
        _lead("LEAD-0002", "Second rendered lead"),
        _lead("LEAD-0001", "First rendered lead"),
    )

    markdown = render_review_leads_markdown(leads)

    assert markdown.index("### LEAD-0002: Second rendered lead") < markdown.index(
        "### LEAD-0001: First rendered lead"
    )


def test_renderer_truncates_long_raw_values_and_previews() -> None:
    lead = _lead(
        "LEAD-0001",
        "Long artefact review",
        raw_value="A" * 220,
        decoded_preview="/hidden/" + "B" * 220,
    )

    markdown = render_review_leads_markdown((lead,), max_value_chars=32)

    assert "- Raw value: `AAAAAAAAAAAAAAAAAAAAAAAAAAAAA...`" in markdown
    assert "- Decoded/derived preview: `/hidden/BBBBBBBBBBBBBBBBBBBBB...`" in markdown
    assert "A" * 80 not in markdown
    assert "B" * 80 not in markdown


def test_renderer_includes_suggested_manual_validation_guidance() -> None:
    lead = _lead(
        "LEAD-0001",
        "Manual validation check",
        suggested_manual_validation=(
            "Validate locally before treating this as evidence.",
            "Review same-origin paths manually only when they are in scope.",
        ),
    )

    markdown = render_review_leads_markdown((lead,))

    assert "- Suggested manual validation:" in markdown
    assert "Validate locally before treating this as evidence." in markdown
    assert "Review same-origin paths manually only when they are in scope." in markdown


def test_renderer_avoids_unsafe_confirmed_wording() -> None:
    leads = aggregate_interpretation_leads(
        transform_candidates=find_transform_artefacts(
            ArtefactSource(source_id="unsafe", text="secret L2hpZGRlbi9mbGFn")
        )
    )

    markdown = render_review_leads_markdown(leads).lower()

    assert "manual review recommended" in markdown
    assert "proof of vulnerability" in markdown
    assert all(phrase not in markdown for phrase in UNSAFE_WORDING)


def _lead(
    lead_id: str,
    title: str,
    *,
    raw_value: str = "value",
    decoded_preview: str | None = None,
    suggested_manual_validation: tuple[str, ...] = (
        "Treat this as a review lead, not proof of vulnerability.",
    ),
) -> ReviewLead:
    return ReviewLead(
        lead_id=lead_id,
        lead_type="manual_review",
        category="artefact",
        priority="medium",
        title=title,
        explanation="Manual review recommended. Treat this as a review lead, not proof of vulnerability.",
        source_id="source",
        source_kind="html",
        source_label="homepage",
        url="http://example.test/",
        path="/",
        port=80,
        service="http",
        line_number=3,
        field_name=None,
        item_type="html_comment",
        raw_value=raw_value,
        decoded_preview=decoded_preview,
        nearby_keywords=("clue",),
        related_artefact_types=("possible_base64",),
        suggested_manual_validation=suggested_manual_validation,
    )
