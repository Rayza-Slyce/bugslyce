"""Tests for local BugSlyce config helpers."""

from __future__ import annotations

from pathlib import Path

from bugslyce.config import (
    forget_provider_keys,
    load_env_config,
    mask_secret,
    provider_api_key_name,
    render_config_show,
    reset_config,
)


def test_default_config_show_when_env_missing(tmp_path: Path) -> None:
    output = render_config_show(tmp_path / ".env")

    assert "LLM provider: none" in output
    assert "LLM model: unset" in output
    assert "API key: not configured" in output
    assert "Raw recon sharing: false" in output


def test_config_show_masks_api_key(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "BUGSLYCE_LLM_PROVIDER=gemini",
                "BUGSLYCE_LLM_MODEL=gemini-flash",
                "GEMINI_API_KEY=super-secret-key-abcd",
                "BUGSLYCE_SEND_RAW_RECON=false",
            ]
        ),
        encoding="utf-8",
    )

    output = render_config_show(env_path)

    assert "LLM provider: gemini" in output
    assert "LLM model: gemini-flash" in output
    assert "GEMINI_API_KEY=************abcd" in output
    assert "super-secret-key-abcd" not in output


def test_mask_secret_never_returns_full_secret() -> None:
    assert mask_secret("abcd") == "****"
    assert mask_secret("secretabcd") == "************abcd"


def test_forget_key_removes_provider_keys_and_preserves_unrelated_lines(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "UNRELATED=value",
                "GEMINI_API_KEY=gemini-secret",
                "OPENAI_API_KEY=openai-secret",
                "ANTHROPIC_API_KEY=anthropic-secret",
                "BUGSLYCE_LLM_PROVIDER=gemini",
            ]
        ),
        encoding="utf-8",
    )

    forget_provider_keys(env_path)
    text = env_path.read_text(encoding="utf-8")

    assert "UNRELATED=value" in text
    assert "BUGSLYCE_LLM_PROVIDER=gemini" in text
    assert "GEMINI_API_KEY" not in text
    assert "OPENAI_API_KEY" not in text
    assert "ANTHROPIC_API_KEY" not in text


def test_reset_sets_no_llm_defaults_and_clears_provider_keys(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "UNRELATED=value",
                "BUGSLYCE_LLM_PROVIDER=openai",
                "BUGSLYCE_LLM_MODEL=gpt-demo",
                "BUGSLYCE_SEND_RAW_RECON=true",
                "OPENAI_API_KEY=openai-secret",
            ]
        ),
        encoding="utf-8",
    )

    reset_config(env_path)
    config = load_env_config(env_path)
    text = env_path.read_text(encoding="utf-8")

    assert config["BUGSLYCE_LLM_PROVIDER"] == "none"
    assert config["BUGSLYCE_LLM_MODEL"] == ""
    assert config["BUGSLYCE_SEND_RAW_RECON"] == "false"
    assert config["GEMINI_API_KEY"] == ""
    assert config["OPENAI_API_KEY"] == ""
    assert config["ANTHROPIC_API_KEY"] == ""
    assert "UNRELATED=value" in text


def test_provider_to_key_name_mapping() -> None:
    assert provider_api_key_name("gemini") == "GEMINI_API_KEY"
    assert provider_api_key_name("openai") == "OPENAI_API_KEY"
    assert provider_api_key_name("anthropic") == "ANTHROPIC_API_KEY"
    assert provider_api_key_name("ollama") is None
    assert provider_api_key_name("none") is None
