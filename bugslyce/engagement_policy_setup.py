"""Dependency-free, platform-neutral engagement-policy setup."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from bugslyce.core.engagement_context import BUG_BOUNTY_CONTEXT
from bugslyce.core.engagement_policy import (
    AUTOMATION_NOT_PERMITTED,
    AUTOMATION_PERMITTED,
    CONFIRMED,
    ENGAGEMENT_POLICY_FILENAME,
    IDENTIFICATION_HEADERS,
    IDENTIFICATION_HEADERS_AND_USER_AGENT,
    IDENTIFICATION_NONE,
    IDENTIFICATION_UNKNOWN,
    IDENTIFICATION_USER_AGENT,
    NOT_CONFIRMED,
    NOT_YET_CONFIRMED,
    RATE_SOURCE_CONSERVATIVE,
    RATE_SOURCE_PROGRAMME,
    TCP_CONSERVATIVE,
    TCP_CUSTOM,
    TCP_FULL,
    TCP_SKIP,
    EngagementPolicy,
    IdentificationHeader,
    build_bug_bounty_policy,
    load_engagement_policy,
    render_redacted_policy,
    validate_http_concurrency,
    validate_http_rate,
    validate_identification_header_name,
    validate_identification_value,
    normalise_tcp_port_specification,
)
from bugslyce.project_session import (
    load_project,
    save_project_engagement_policy,
)


InputFunc = Callable[[str], str]
PrintFunc = Callable[[str], None]


@dataclass(frozen=True)
class PolicySetupResult:
    """Outcome of one save-only policy setup flow."""

    saved: bool
    cancelled: bool
    policy: EngagementPolicy | None = None
    policy_path: str | None = None


def configure_project_policy_interactively(
    project_file: Path,
    *,
    input_func: InputFunc = input,
    print_func: PrintFunc = print,
) -> PolicySetupResult:
    """Create or deliberately replace one project policy without running recon."""

    project_file = project_file.expanduser().resolve()
    project = load_project(project_file)
    if project.engagement_context != BUG_BOUNTY_CONTEXT:
        raise ValueError("Engagement-policy setup requires a bug bounty project.")
    existing: EngagementPolicy | None = None
    policy_path = Path(project.output_dir) / ENGAGEMENT_POLICY_FILENAME
    if policy_path.exists() or policy_path.is_symlink():
        existing = load_engagement_policy(Path(project.output_dir))
        print_func(render_redacted_policy(existing))
        print_func("")
        if input_func(
            "Type YES to deliberately revise this policy, or press Enter to cancel: "
        ).strip() != "YES":
            print_func("Engagement-policy update cancelled; stored values are unchanged.")
            return PolicySetupResult(saved=False, cancelled=True, policy=existing)

    print_func("Bug bounty engagement policy setup (save only)")
    print_func(
        "Copy exact traffic and identification requirements from the current "
        "programme brief. No platform preset supersedes those rules."
    )
    print_func(
        "R0B1 enforces policy values for internal Python HTTP requests, but not yet "
        "for curl, Gobuster or Nmap. Live bug bounty project reconnaissance remains blocked."
    )
    print_func("")

    reviewed_answer = _choice(
        input_func,
        "Have you reviewed the current programme rules? [1 yes, 2 no, 3 cancel]: ",
        {"1", "2", "3"},
    )
    if reviewed_answer == "3":
        print_func("Engagement-policy setup cancelled. No policy was written.")
        return PolicySetupResult(saved=False, cancelled=True)
    rules_state = CONFIRMED if reviewed_answer == "1" else NOT_CONFIRMED
    if rules_state != CONFIRMED:
        print_func("Current programme rules are not reviewed; live recon cannot begin.")
        return _review_and_save(
            project_file,
            build_bug_bounty_policy(programme_rules_reviewed=rules_state),
            input_func,
            print_func,
        )

    automation_choice = _choice(
        input_func,
        (
            "Automated reconnaissance permission "
            "[1 explicitly permitted, 2 not permitted, 3 not yet confirmed, 4 cancel]: "
        ),
        {"1", "2", "3", "4"},
    )
    if automation_choice == "4":
        print_func("Engagement-policy setup cancelled. No policy was written.")
        return PolicySetupResult(saved=False, cancelled=True)
    automation_state = {
        "1": AUTOMATION_PERMITTED,
        "2": AUTOMATION_NOT_PERMITTED,
        "3": NOT_YET_CONFIRMED,
    }[automation_choice]
    if automation_state != AUTOMATION_PERMITTED:
        print_func("Automated reconnaissance is unavailable under the recorded rules.")
        return _review_and_save(
            project_file,
            build_bug_bounty_policy(
                programme_rules_reviewed=CONFIRMED,
                automated_reconnaissance=automation_state,
            ),
            input_func,
            print_func,
        )

    rate_choice = _choice(
        input_func,
        (
            "HTTP rate [1 BugSlyce conservative default: 2 requests/second, "
            "2 exact programme-published maximum]: "
        ),
        {"1", "2"},
    )
    rate: object = "2"
    rate_source = RATE_SOURCE_CONSERVATIVE
    rate_confirmed = NOT_YET_CONFIRMED
    if rate_choice == "2":
        rate = _validated_prompt(
            input_func,
            print_func,
            "Exact programme-published maximum requests per second: ",
            validate_http_rate,
        )
        rate_source = RATE_SOURCE_PROGRAMME
        rate_confirmed = _yes_confirmation(
            input_func,
            "Type YES to confirm this exact rate came from the current programme rules: ",
        )

    concurrency = _validated_prompt(
        input_func,
        print_func,
        "Maximum HTTP concurrency [press Enter for 1]: ",
        validate_http_concurrency,
        empty_default="1",
    )
    concurrency_confirmed = NOT_YET_CONFIRMED
    if concurrency > 1:
        concurrency_confirmed = _yes_confirmation(
            input_func,
            "Type YES to confirm the programme permits this concurrency: ",
        )

    tcp_choice = _choice(
        input_func,
        (
            "TCP discovery [1 skip, 2 conservative common web ports, "
            "3 programme-approved custom ports, 4 full TCP explicitly permitted]: "
        ),
        {"1", "2", "3", "4"},
    )
    tcp_policy = {
        "1": TCP_SKIP,
        "2": TCP_CONSERVATIVE,
        "3": TCP_CUSTOM,
        "4": TCP_FULL,
    }[tcp_choice]
    custom_ports: str | None = None
    tcp_confirmed = NOT_YET_CONFIRMED
    if tcp_policy == TCP_CUSTOM:
        custom_ports = _validated_prompt(
            input_func,
            print_func,
            "Programme-approved TCP ports or ranges: ",
            normalise_tcp_port_specification,
        )
        tcp_confirmed = _yes_confirmation(
            input_func,
            "Type YES to confirm these ports came from the current programme rules: ",
        )
    elif tcp_policy == TCP_FULL:
        tcp_confirmed = _yes_confirmation(
            input_func,
            "Type YES to confirm the current programme explicitly permits full TCP discovery: ",
        )

    identification_choice = _choice(
        input_func,
        (
            "Traffic identification [1 no custom identifier required, "
            "2 custom request headers, 3 custom User-Agent, "
            "4 headers and User-Agent, 5 requirements not yet confirmed]: "
        ),
        {"1", "2", "3", "4", "5"},
    )
    identification = {
        "1": IDENTIFICATION_NONE,
        "2": IDENTIFICATION_HEADERS,
        "3": IDENTIFICATION_USER_AGENT,
        "4": IDENTIFICATION_HEADERS_AND_USER_AGENT,
        "5": IDENTIFICATION_UNKNOWN,
    }[identification_choice]
    headers: tuple[IdentificationHeader, ...] = ()
    user_agent: str | None = None
    if identification in {IDENTIFICATION_HEADERS, IDENTIFICATION_HEADERS_AND_USER_AGENT}:
        headers = _collect_headers(input_func, print_func, existing)
    if identification in {
        IDENTIFICATION_USER_AGENT,
        IDENTIFICATION_HEADERS_AND_USER_AGENT,
    }:
        user_agent = _collect_user_agent(input_func, print_func, existing)

    policy = build_bug_bounty_policy(
        programme_rules_reviewed=CONFIRMED,
        automated_reconnaissance=AUTOMATION_PERMITTED,
        maximum_http_requests_per_second=rate,
        http_rate_source=rate_source,
        programme_rate_confirmed=rate_confirmed,
        maximum_http_concurrency=concurrency,
        concurrent_automation_confirmed=concurrency_confirmed,
        tcp_discovery_policy=tcp_policy,
        custom_tcp_ports=custom_ports,
        tcp_policy_confirmed=tcp_confirmed,
        identification_requirement=identification,
        identification_headers=headers,
        custom_user_agent=user_agent,
    )
    return _review_and_save(project_file, policy, input_func, print_func)


def show_project_policy(project_file: Path) -> str:
    """Return the normal redacted policy view for an existing project."""

    project = load_project(project_file)
    if project.engagement_context != BUG_BOUNTY_CONTEXT:
        raise ValueError("Engagement-policy view requires a bug bounty project.")
    if project.engagement_policy_file is None:
        return (
            "No engagement policy is configured. Live bug bounty reconnaissance "
            "remains blocked."
        )
    policy_path = Path(project.output_dir) / ENGAGEMENT_POLICY_FILENAME
    if not policy_path.exists() and not policy_path.is_symlink():
        return (
            "No engagement policy is configured. Live bug bounty reconnaissance "
            "remains blocked."
        )
    return render_redacted_policy(load_engagement_policy(Path(project.output_dir)))


def _review_and_save(
    project_file: Path,
    policy: EngagementPolicy,
    input_func: InputFunc,
    print_func: PrintFunc,
) -> PolicySetupResult:
    print_func("")
    print_func(render_redacted_policy(policy))
    if input_func("Type YES to save this policy, or press Enter to cancel: ").strip() != "YES":
        print_func("Engagement-policy setup cancelled. No policy was written.")
        return PolicySetupResult(saved=False, cancelled=True)
    _, policy_path = save_project_engagement_policy(project_file, policy)
    print_func(f"Engagement policy saved privately: {policy_path.name} (mode 0600).")
    print_func("No recon was executed. Live bug bounty reconnaissance remains blocked.")
    return PolicySetupResult(
        saved=True,
        cancelled=False,
        policy=policy,
        policy_path=str(policy_path),
    )


def _collect_headers(
    input_func: InputFunc,
    print_func: PrintFunc,
    existing: EngagementPolicy | None,
) -> tuple[IdentificationHeader, ...]:
    if existing is not None and existing.identification_headers:
        replace_answer = input_func(
            "Press Enter to retain configured header values, or type REPLACE: "
        ).strip()
        if not replace_answer:
            return existing.identification_headers
        if replace_answer != "REPLACE":
            raise ValueError("Header replacement requires the exact word REPLACE.")
    headers: list[IdentificationHeader] = []
    while True:
        name = _validated_prompt(
            input_func,
            print_func,
            "Identification header name: ",
            validate_identification_header_name,
        )
        value = _validated_prompt(
            input_func,
            print_func,
            "Identification header value: ",
            lambda item: validate_identification_value(
                item,
                label="Identification header value",
            ),
        )
        if any(header.name.casefold() == name.casefold() for header in headers):
            print_func("Error: Identification header names must be unique.")
            continue
        headers.append(IdentificationHeader(name=name, value=value))
        if input_func("Add another identification header? Type YES or press Enter: ").strip() != "YES":
            return tuple(headers)


def _collect_user_agent(
    input_func: InputFunc,
    print_func: PrintFunc,
    existing: EngagementPolicy | None,
) -> str:
    prompt = "Custom User-Agent required by the current programme brief: "
    if existing is not None and existing.custom_user_agent is not None:
        value = input_func(
            "Press Enter to retain the configured User-Agent, or enter a replacement: "
        )
        if not value:
            return existing.custom_user_agent
        return validate_identification_value(value, label="Custom User-Agent")
    return _validated_prompt(
        input_func,
        print_func,
        prompt,
        lambda item: validate_identification_value(item, label="Custom User-Agent"),
    )


def _validated_prompt(
    input_func: InputFunc,
    print_func: PrintFunc,
    prompt: str,
    validator: Callable[[str], object],
    *,
    empty_default: str | None = None,
):
    while True:
        value = input_func(prompt)
        if not value and empty_default is not None:
            value = empty_default
        try:
            return validator(value)
        except ValueError as exc:
            print_func(f"Error: {exc}")


def _choice(input_func: InputFunc, prompt: str, allowed: set[str]) -> str:
    while True:
        value = input_func(prompt).strip()
        if value in allowed:
            return value


def _yes_confirmation(input_func: InputFunc, prompt: str) -> str:
    return CONFIRMED if input_func(prompt).strip() == "YES" else NOT_CONFIRMED
