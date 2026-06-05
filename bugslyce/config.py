"""Local .env configuration helpers for BugSlyce."""

from __future__ import annotations

from getpass import getpass
from pathlib import Path
from typing import Callable


DEFAULT_CONFIG = {
    "BUGSLYCE_LLM_PROVIDER": "none",
    "BUGSLYCE_LLM_MODEL": "",
    "BUGSLYCE_SEND_RAW_RECON": "false",
}
API_KEY_NAMES = {
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}
PROVIDERS = ("none", "gemini", "openai", "anthropic", "ollama")


def load_env_config(path: Path = Path(".env")) -> dict[str, str]:
    """Load simple KEY=VALUE entries from .env with BugSlyce defaults."""

    config = dict(DEFAULT_CONFIG)
    if not path.exists():
        return config

    for line in path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_env_line(line)
        if parsed is None:
            continue
        key, value = parsed
        config[key] = value

    return config


def write_env_config(path: Path, updates: dict[str, str | None]) -> None:
    """Update .env values while preserving unrelated lines."""

    if not path.exists() and all(value is None for value in updates.values()):
        return

    existing_lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    seen: set[str] = set()
    output_lines: list[str] = []

    for line in existing_lines:
        parsed = _parse_env_line(line)
        if parsed is None:
            output_lines.append(line)
            continue

        key, _value = parsed
        if key not in updates:
            output_lines.append(line)
            continue

        seen.add(key)
        value = updates[key]
        if value is None:
            continue
        output_lines.append(f"{key}={value}")

    for key, value in updates.items():
        if key in seen or value is None:
            continue
        output_lines.append(f"{key}={value}")

    path.write_text("\n".join(output_lines).rstrip() + "\n", encoding="utf-8")


def mask_secret(value: str) -> str:
    """Mask an API key without exposing the full secret."""

    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return f"{'*' * 12}{value[-4:]}"


def provider_api_key_name(provider: str) -> str | None:
    """Return the API key variable name for a provider, if one is required."""

    return API_KEY_NAMES.get(provider.lower())


def render_config_show(path: Path = Path(".env")) -> str:
    """Render local config for CLI display without exposing full API keys."""

    config = load_env_config(path)
    provider = config.get("BUGSLYCE_LLM_PROVIDER", "none") or "none"
    model = config.get("BUGSLYCE_LLM_MODEL", "") or "unset"
    raw_recon = config.get("BUGSLYCE_SEND_RAW_RECON", "false") or "false"
    key_name = provider_api_key_name(provider)

    if key_name is None:
        api_key_status = "not configured" if provider != "ollama" else "not required"
    else:
        value = config.get(key_name, "")
        api_key_status = (
            f"configured as {key_name}={mask_secret(value)}" if value else "not configured"
        )

    return "\n".join(
        [
            "BugSlyce config",
            f"LLM provider: {provider}",
            f"LLM model: {model}",
            f"API key: {api_key_status}",
            f"Raw recon sharing: {raw_recon}",
        ]
    )


def forget_provider_keys(path: Path = Path(".env")) -> None:
    """Remove provider API key entries from .env while preserving other lines."""

    write_env_config(path, {key: None for key in API_KEY_NAMES.values()})


def reset_config(path: Path = Path(".env")) -> None:
    """Reset BugSlyce LLM config to deterministic no-LLM defaults."""

    write_env_config(
        path,
        {
            "BUGSLYCE_LLM_PROVIDER": "none",
            "BUGSLYCE_LLM_MODEL": "",
            "BUGSLYCE_SEND_RAW_RECON": "false",
            "GEMINI_API_KEY": "",
            "OPENAI_API_KEY": "",
            "ANTHROPIC_API_KEY": "",
        },
    )


def init_config(
    path: Path = Path(".env"),
    input_func: Callable[[str], str] = input,
    secret_func: Callable[[str], str] = getpass,
) -> None:
    """Interactively initialise future LLM provider settings."""

    provider = _prompt_provider(input_func)
    model = input_func("Which model name do you want to use? ").strip()
    updates: dict[str, str | None] = {
        "BUGSLYCE_LLM_PROVIDER": provider,
        "BUGSLYCE_LLM_MODEL": model,
        "BUGSLYCE_SEND_RAW_RECON": "false",
    }

    key_name = provider_api_key_name(provider)
    if key_name:
        answer = input_func("Do you want to store an API key locally in .env? [y/N] ").strip().lower()
        if answer in {"y", "yes"}:
            print(
                "Your API key will be stored locally in your .env file. "
                "BugSlyce does not upload, share, or commit this key. "
                "This is local storage, not perfect security. Anyone with access to this machine "
                "or project folder may be able to read it."
            )
            updates[key_name] = secret_func(f"Enter {key_name}: ").strip()

    write_env_config(path, updates)


def _prompt_provider(input_func: Callable[[str], str]) -> str:
    provider = input_func(
        "Which LLM provider do you want to use? [none/gemini/openai/anthropic/ollama] "
    ).strip().lower()
    if not provider:
        return "none"
    if provider not in PROVIDERS:
        raise ValueError(f"Unsupported LLM provider: {provider}")
    return provider


def _parse_env_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None

    key, value = stripped.split("=", 1)
    key = key.strip()
    if not key:
        return None
    return key, value.strip()
