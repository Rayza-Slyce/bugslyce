"""Static guidance for the safe BugSlyce wizard entrypoint."""

from __future__ import annotations

from bugslyce.branding import get_banner


def render_wizard() -> str:
    """Render preview-only guidance without inspecting or changing local state."""

    return "\n".join(
        [
            get_banner(),
            "",
            "BugSlyce guided mode",
            "Local-first recon triage for authorised testing.",
            "",
            "This guided mode currently prints safe workflow guidance only.",
            "",
            "Typical workflow:",
            "",
            "1. Create a project:",
            "   bugslyce project init --name NAME --target TARGET --scope scope.md "
            "--output-dir bugslyce-output/NAME",
            "",
            "2. Check project status:",
            "   bugslyce project status "
            "--project bugslyce-output/NAME/bugslyce_project.json",
            "",
            "3. Preview the next safe action:",
            "   bugslyce project next "
            "--project bugslyce-output/NAME/bugslyce_project.json",
            "",
            "4. Review scope, then run approved recon commands manually.",
            "",
            "5. Review the generated report:",
            "   less bugslyce-output/NAME/report.md",
            "",
            "6. Export an evidence pack after review:",
            "   bugslyce recon export --input-dir bugslyce-output/NAME "
            "--output bugslyce-output/NAME-evidence-pack.zip",
            "",
            "Suggested commands are previews only.",
            "No commands were executed.",
            "No network requests were made.",
            "Review programme scope before running recon.",
        ]
    )
