"""Interactive, dependency-free BugSlyce launcher."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from bugslyce.branding import get_banner
from bugslyce.doctor import build_doctor_report, render_doctor_text
from bugslyce.project_pipeline import (
    PIPELINE_PROFILE,
    ProjectPipelineFailed,
    render_project_pipeline_summary,
    run_project_pipeline,
)
from bugslyce.project_session import (
    build_project_next,
    inspect_project_status,
    list_projects,
    load_project,
    render_project_inventory,
    render_project_next,
    render_project_show,
    render_project_status,
    render_project_scaffold_summary,
    scaffold_project,
)

InputFunc = Callable[[str], str]
PrintFunc = Callable[[str], None]

QUICK_SAFE_RECON_LABEL = "Quick Safe Recon"
MANUAL_SETUP_LABEL = "Manual Setup Only"
STANDARD_SAFE_RECON_LABEL = "Standard Safe Recon"


def run_interactive_launcher(
    input_func: InputFunc = input,
    print_func: PrintFunc = print,
    cwd: Path | None = None,
) -> int:
    """Run the simple interactive launcher using existing safe project flows."""

    base_dir = (cwd or Path.cwd()).expanduser().resolve()
    print_func(get_banner())
    print_func("")
    print_func("BugSlyce Interactive Launcher")
    print_func("Local-first recon triage for authorised testing.")
    print_func("")
    _render_main_menu(print_func)
    choice = _prompt_choice(input_func, "Choose an option", {"1", "2", "3", "4", "5"})

    if choice == "1":
        return _start_new_project(input_func, print_func, base_dir)
    if choice == "2":
        return _resume_existing_project(input_func, print_func, base_dir)
    if choice == "3":
        return _list_existing_projects(input_func, print_func, base_dir)
    if choice == "4":
        report = build_doctor_report()
        print_func(render_doctor_text(report))
        return 0

    print_func("Exiting BugSlyce launcher.")
    print_func("No commands were executed.")
    print_func("No network requests were made.")
    return 0


def render_recon_mode_menu() -> str:
    """Render user-facing recon mode names."""

    return "\n".join(
        [
            "Recon mode:",
            "1. Quick Safe Recon",
            "   Fast, bounded first-pass recon using the tiny bundled wordlist.",
            "   Best for first look, lab smoke tests, and cautious initial triage.",
            "2. Manual Setup Only",
            "   Create the project and scope template, then show the next safe "
            "command without running recon.",
            "3. Standard Safe Recon",
            "   Coming later; not available yet.",
        ]
    )


def map_user_recon_mode_to_internal_profile(choice: str) -> str | None:
    """Map launcher recon mode choices to internal profile IDs."""

    if choice == "1":
        return PIPELINE_PROFILE
    if choice == "2":
        return None
    if choice == "3":
        raise ValueError("Standard Safe Recon is not available yet.")
    raise ValueError("Unknown recon mode.")


def _render_main_menu(print_func: PrintFunc) -> None:
    print_func("1. Start a new project")
    print_func("2. Resume an existing project")
    print_func("3. List projects")
    print_func("4. Run doctor/readiness check")
    print_func("5. Exit")
    print_func("")


def _start_new_project(
    input_func: InputFunc,
    print_func: PrintFunc,
    cwd: Path,
) -> int:
    name = _prompt_text(input_func, "Project name")
    target = _prompt_text(input_func, "Target IP or domain")
    projects_dir = _resolve_prompt_path(
        _prompt_text(
            input_func,
            "Projects directory [bugslyce-output]",
            default="bugslyce-output",
        ),
        cwd,
    )
    print_func("")
    print_func(render_recon_mode_menu())
    mode_choice = _prompt_choice(input_func, "Choose recon mode", {"1", "2", "3"})
    try:
        profile = map_user_recon_mode_to_internal_profile(mode_choice)
    except ValueError as exc:
        print_func(str(exc))
        print_func("No project was created.")
        print_func("No commands were executed.")
        print_func("No network requests were made.")
        return 2

    if not _prompt_yes_exact(
        input_func,
        "Do you confirm this is an authorised lab or in-scope target? Type YES to continue:",
    ):
        print_func("No project was created.")
        print_func("No commands were executed.")
        print_func("No network requests were made.")
        return 2

    try:
        scaffold = scaffold_project(name=name, target=target, projects_dir=projects_dir)
        print_func(render_project_scaffold_summary(scaffold))
    except ValueError as exc:
        print_func(f"Error: {exc}")
        print_func("No recon was executed.")
        return 2

    project_file = Path(scaffold.project_file)
    if profile is None:
        _print_project_next(project_file, print_func)
        return 0

    if not _prompt_yes_exact(
        input_func,
        "Run Quick Safe Recon now? Type YES to run, or anything else to only scaffold:",
    ):
        print_func("Quick Safe Recon was not started.")
        print_func("Run it later with:")
        print_func(
            "bugslyce project run "
            f"--project {project_file} --profile {PIPELINE_PROFILE} --confirm"
        )
        _print_project_next(project_file, print_func)
        return 0

    return _run_pipeline(project_file, print_func, resume=False)


def _resume_existing_project(
    input_func: InputFunc,
    print_func: PrintFunc,
    cwd: Path,
) -> int:
    project_file = _resolve_prompt_path(_prompt_text(input_func, "Project file path"), cwd)
    try:
        project = load_project(project_file)
        print_func(render_project_show(project, project_file))
        print_func("")
        print_func(render_project_status(inspect_project_status(project_file)))
    except ValueError as exc:
        print_func(f"Error: {exc}")
        print_func("No commands were executed.")
        print_func("No network requests were made.")
        return 2

    if not _prompt_yes_exact(input_func, "Run resume now? Type YES to continue:"):
        print_func("Resume was not started.")
        print_func("Run it later with:")
        print_func(
            "bugslyce project run "
            f"--project {project_file} --profile {PIPELINE_PROFILE} --confirm --resume"
        )
        print_func("No commands were executed.")
        print_func("No network requests were made.")
        return 0

    return _run_pipeline(project_file, print_func, resume=True)


def _list_existing_projects(
    input_func: InputFunc,
    print_func: PrintFunc,
    cwd: Path,
) -> int:
    projects_dir = _resolve_prompt_path(
        _prompt_text(
            input_func,
            "Projects directory [bugslyce-output]",
            default="bugslyce-output",
        ),
        cwd,
    )
    try:
        print_func(render_project_inventory(list_projects(projects_dir)))
    except ValueError as exc:
        print_func(f"Error: {exc}")
        print_func("No commands were executed.")
        print_func("No network requests were made.")
        return 2
    return 0


def _run_pipeline(project_file: Path, print_func: PrintFunc, *, resume: bool) -> int:
    try:
        result = run_project_pipeline(
            project_file=project_file,
            profile=PIPELINE_PROFILE,
            resume=resume,
            progress_callback=print_func,
        )
    except ProjectPipelineFailed as exc:
        result = exc.result
        failed = next(step for step in result.steps if step.status == "failed")
        print_func(f"Error: {exc}")
        print_func(f"Pipeline stopped at step {failed.step_id}.")
        print_func("No later steps were executed.")
        print_func("Review the error and local evidence.")
        return 2
    except ValueError as exc:
        print_func(f"Error: {exc}")
        print_func("No pipeline phase was executed.")
        return 2
    print_func(render_project_pipeline_summary(result))
    return 0


def _print_project_next(project_file: Path, print_func: PrintFunc) -> None:
    try:
        print_func("")
        print_func(render_project_next(build_project_next(project_file)))
    except ValueError as exc:
        print_func(f"Could not build project next preview: {exc}")


def _prompt_choice(input_func: InputFunc, prompt: str, valid_choices: set[str]) -> str:
    choice = input_func(f"{prompt}: ").strip()
    if choice not in valid_choices:
        raise ValueError(f"Invalid choice: {choice}")
    return choice


def _prompt_text(input_func: InputFunc, prompt: str, *, default: str | None = None) -> str:
    value = input_func(f"{prompt}: ").strip()
    if not value and default is not None:
        return default
    if not value:
        raise ValueError(f"{prompt} is required.")
    return value


def _prompt_yes_exact(input_func: InputFunc, prompt: str) -> bool:
    return input_func(f"{prompt} ").strip() == "YES"


def _resolve_prompt_path(value: str, cwd: Path) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else (cwd / path).resolve()
