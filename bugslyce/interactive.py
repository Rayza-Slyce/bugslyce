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
from bugslyce.recon.modes import (
    DEEP_MODE_ID,
    QUICK_MODE_ID,
    STANDARD_MODE_ID,
    get_recon_mode,
    resolve_executable_profile,
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
    _validate_target,
)

InputFunc = Callable[[str], str]
PrintFunc = Callable[[str], None]

QUICK_RECON_LABEL = get_recon_mode(QUICK_MODE_ID).display_name
MANUAL_SETUP_LABEL = "Manual Setup Only"
STANDARD_RECON_LABEL = get_recon_mode(STANDARD_MODE_ID).display_name
DEEP_RECON_LABEL = get_recon_mode(DEEP_MODE_ID).display_name
DEFAULT_PROJECTS_DIR_NAME = "bugslyce-output"


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

    quick = get_recon_mode(QUICK_MODE_ID)
    standard = get_recon_mode(STANDARD_MODE_ID)
    deep = get_recon_mode(DEEP_MODE_ID)
    return "\n".join(
        [
            "Recon mode:",
            f"1. {quick.display_name}",
            "   Fast first-pass recon using the bounded MVP pipeline.",
            "   Good for initial lab/CTF triage and quickly finding review leads.",
            f"2. {MANUAL_SETUP_LABEL}",
            "   Create the project and scope template, then show the next safe "
            "command without running recon.",
            f"3. {standard.display_name}",
            f"   {standard.purpose.capitalize()}.",
            "   Coming later; not available yet.",
            f"4. {deep.display_name}",
            f"   {deep.purpose.capitalize()}.",
            "   Coming later; not available yet.",
        ]
    )


def map_user_recon_mode_to_internal_profile(choice: str) -> str | None:
    """Map launcher recon mode choices to internal profile IDs."""

    if choice == "1":
        return resolve_executable_profile(QUICK_MODE_ID)
    if choice == "2":
        return None
    if choice == "3":
        return resolve_executable_profile(STANDARD_MODE_ID)
    if choice == "4":
        return resolve_executable_profile(DEEP_MODE_ID)
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
    target_input, target = _prompt_target_with_retries(input_func, print_func)
    if not target:
        print_func("No project was created.")
        print_func("No commands were executed.")
        print_func("No network requests were made.")
        return 2
    projects_dir = _prompt_projects_dir(input_func, cwd)
    print_func("")
    print_func(render_recon_mode_menu())
    profile = _prompt_available_recon_mode(input_func, print_func)

    print_func("")
    print_func(_render_project_summary(name, target, projects_dir, profile, target_input))
    print_func("")
    print_func(f"BugSlyce will prepare recon for: {target}")
    print_func(
        "Only continue if this is your own lab, a CTF/THM box, or an "
        "explicitly in-scope target."
    )
    if not _prompt_yes_exact_with_retries(
        input_func,
        print_func,
        "Type YES to confirm you are authorised to test this target:",
        "Type YES to continue, or press Enter to cancel:",
    ):
        print_func("Confirmation was not provided.")
        print_func("No project was created.")
        print_func("No commands were executed.")
        print_func("No network requests were made.")
        return 2

    try:
        scaffold = scaffold_project(name=name, target=target, projects_dir=projects_dir)
        print_func(
            render_project_scaffold_summary(
                scaffold,
                include_next_preview=False,
                include_safety_footer=False,
            )
        )
    except ValueError as exc:
        print_func(f"Error: {exc}")
        print_func("No recon was executed.")
        return 2

    project_file = Path(scaffold.project_file)
    if profile is None:
        _print_interactive_next_steps(scaffold, print_func)
        return 0

    if not _prompt_yes_exact_with_retries(
        input_func,
        print_func,
        "Run Quick Recon now? Type YES to run, or press Enter to only create the project:",
        "Type YES to run Quick Recon, or press Enter to only create the project:",
    ):
        print_func("Quick Recon was not started.")
        _print_interactive_next_steps(scaffold, print_func)
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

    if not _prompt_yes_exact_with_retries(
        input_func,
        print_func,
        "Run resume now? Type YES to continue, or press Enter to show the resume command only:",
        "Type YES to resume, or press Enter to show the resume command only:",
    ):
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
    projects_dir = _prompt_projects_dir(input_func, cwd)
    try:
        print_func(render_project_inventory(list_projects(projects_dir)))
    except ValueError as exc:
        print_func(f"Error: {exc}")
        print_func("No commands were executed.")
        print_func("No network requests were made.")
        return 2
    return 0


def _prompt_available_recon_mode(
    input_func: InputFunc,
    print_func: PrintFunc,
) -> str | None:
    while True:
        mode_choice = _prompt_choice(input_func, "Choose recon mode", {"1", "2", "3", "4"})
        try:
            return map_user_recon_mode_to_internal_profile(mode_choice)
        except ValueError:
            print_func("This recon mode is not available yet.")
            print_func("Choose Quick Recon or Manual Setup Only.")


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


def _print_interactive_next_steps(scaffold, print_func: PrintFunc) -> None:
    print_func("")
    print_func("Project created.")
    print_func("")
    print_func("Next steps:")
    print_func("1. Review the generated scope file:")
    print_func(f"   {scaffold.scope_file}")
    print_func("")
    print_func("2. To run Quick Recon later:")
    print_func(
        "   bugslyce project run "
        f"--project {scaffold.project_file} --profile {PIPELINE_PROFILE} --confirm"
    )
    print_func("")
    print_func("3. To preview next safe action:")
    print_func(f"   bugslyce project next --project {scaffold.project_file}")
    print_func("")
    print_func("No recon was run.")
    print_func("No commands were executed.")
    print_func("No network requests were made.")


def _default_projects_dir() -> Path:
    return (Path.home() / DEFAULT_PROJECTS_DIR_NAME).expanduser().resolve()


def _prompt_projects_dir(input_func: InputFunc, cwd: Path) -> Path:
    default_dir = _default_projects_dir()
    value = input_func(
        "\n".join(
            [
                "Projects directory",
                f"Press Enter to use default: {default_dir}",
                "Or type a different path: ",
            ]
        )
    )
    if not value.strip():
        value = str(default_dir)
    return _resolve_prompt_path(value, cwd)


def _render_project_summary(
    name: str,
    target: str,
    projects_dir: Path,
    profile: str | None,
    target_input: str | None = None,
) -> str:
    mode = QUICK_RECON_LABEL if profile == PIPELINE_PROFILE else MANUAL_SETUP_LABEL
    lines = [
        "Project summary:",
        f"* Name: {name}",
    ]
    if target_input and target_input.strip().lower() != target:
        lines.append(f"* Input: {target_input}")
    lines.extend(
        [
            f"* Target: {target}",
            f"* Projects directory: {projects_dir}",
            f"* Project directory: {projects_dir / name}",
            f"* Recon mode: {mode}",
        ]
    )
    return "\n".join(lines)


def _prompt_target_with_retries(
    input_func: InputFunc,
    print_func: PrintFunc,
    *,
    attempts: int = 3,
) -> tuple[str, str | None]:
    prompt = "Target IP, hostname, or simple URL"
    for attempt in range(attempts):
        value = input_func(f"{prompt}: ").strip()
        if not value and attempt > 0:
            print_func("Target entry was cancelled.")
            return "", None
        try:
            return value, _validate_target(value)
        except ValueError as exc:
            print_func(str(exc))
            print_func("Examples:")
            print_func("* 10.10.10.10")
            print_func("* example.com")
            print_func("* https://example.com")
            if attempt < attempts - 1:
                prompt = "Type a valid target, or press Enter to cancel"
    print_func("Target entry was cancelled.")
    return "", None


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


def _prompt_yes_exact_with_retries(
    input_func: InputFunc,
    print_func: PrintFunc,
    first_prompt: str,
    retry_prompt: str,
    *,
    attempts: int = 3,
) -> bool:
    prompt = first_prompt
    for attempt in range(attempts):
        value = input_func(f"{prompt} ").strip()
        if value == "YES":
            return True
        if value == "":
            return False
        if attempt < attempts - 1:
            print_func("Confirmation must be exactly YES.")
            prompt = retry_prompt
    return False


def _resolve_prompt_path(value: str, cwd: Path) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else (cwd / path).resolve()
