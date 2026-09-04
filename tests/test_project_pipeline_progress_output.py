"""Terminal presentation contracts for project-pipeline progress."""

from __future__ import annotations

from dataclasses import dataclass, field
import re

import bugslyce.project_pipeline as project_pipeline


@dataclass
class _OutputStream:
    tty: bool
    writes: list[str] = field(default_factory=list)
    flushes: int = 0

    def isatty(self) -> bool:
        return self.tty

    def write(self, value: str) -> int:
        self.writes.append(value)
        return len(value)

    def flush(self) -> None:
        self.flushes += 1

    @property
    def value(self) -> str:
        return "".join(self.writes)


def _visible_progress(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", value).lstrip("\r")


def test_narrow_tty_progress_fits_and_keeps_essential_state() -> None:
    stream = _OutputStream(tty=True)
    output = project_pipeline.ProjectPipelineProgressOutput(
        stream,
        terminal_width=lambda: 80,
    )

    output.content_discovery_progress(
        "[8/15] bounded content discovery execution: "
        "Content discovery [#########-----------] 48% 849/1753 00:04 "
        "http://127.0.0.1:8765/",
        complete=False,
        compact_message="[8/15] Discovery [#########-----------] 48% 849/1753 00:04",
        origin="http://127.0.0.1:8765/",
    )

    visible = _visible_progress(stream.writes[-1])
    assert len(visible) <= 79
    assert "48%" in visible
    assert "849/1753" in visible
    assert "00:04" in visible
    assert "\n" not in stream.writes[-1]


def test_wide_tty_progress_keeps_full_origin() -> None:
    stream = _OutputStream(tty=True)
    output = project_pipeline.ProjectPipelineProgressOutput(
        stream,
        terminal_width=lambda: 140,
    )

    output.content_discovery_progress(
        "full transcript message",
        complete=False,
        compact_message="[8/15] Discovery [##########----------] 50% 5/10 00:02",
        origin="https://api.example.test:8443/",
    )

    assert "https://api.example.test:8443/" in _visible_progress(stream.value)


def test_very_long_origin_cannot_force_tty_wrapping() -> None:
    stream = _OutputStream(tty=True)
    output = project_pipeline.ProjectPipelineProgressOutput(
        stream,
        terminal_width=lambda: 72,
    )

    output.content_discovery_progress(
        "full transcript message " + "very-long-host." * 20,
        complete=False,
        compact_message="[8/15] Discovery [##########----------] 50% 5/10 00:02",
        origin="https://" + "very-long-host." * 20 + "example.test/",
    )

    visible = _visible_progress(stream.value)
    assert len(visible) <= 71
    assert "50%" in visible
    assert "5/10" in visible
    assert "00:02" in visible


def test_tty_drops_bar_before_essential_progress_fields() -> None:
    stream = _OutputStream(tty=True)
    output = project_pipeline.ProjectPipelineProgressOutput(
        stream,
        terminal_width=lambda: 48,
    )

    output.content_discovery_progress(
        "full transcript message",
        complete=False,
        compact_message="[8/15] Discovery [##########----------] 50% 5/10 00:02",
        essential_message="[8/15] Discovery 50% 5/10 00:02",
        origin="https://api.example.test/",
    )

    visible = _visible_progress(stream.value)
    assert len(visible) <= 47
    assert "[##########----------]" not in visible
    assert "50% 5/10 00:02" in visible


def test_unknown_tty_width_uses_conservative_essential_projection() -> None:
    stream = _OutputStream(tty=True)
    output = project_pipeline.ProjectPipelineProgressOutput(
        stream,
        terminal_width=lambda: None,
    )

    output.content_discovery_progress(
        "full transcript message",
        complete=False,
        compact_message="[8/15] Discovery [##########----------] 50% 5/10 00:02",
        essential_message="[8/15] Discovery 50% 5/10 00:02",
        origin="https://api.example.test/",
    )

    assert _visible_progress(stream.value) == "[8/15] Discovery 50% 5/10 00:02"


def test_non_tty_ignores_compact_projection_and_preserves_full_message() -> None:
    stream = _OutputStream(tty=False)
    output = project_pipeline.ProjectPipelineProgressOutput(
        stream,
        terminal_width=lambda: 24,
    )
    full = (
        "[8/15] bounded content discovery execution: "
        "Content discovery [##########----------] 50% 5/10 00:02 "
        "https://api.example.test/"
    )

    output.content_discovery_progress(
        full,
        complete=False,
        compact_message="[8/15] Discovery 50% 5/10 00:02",
        origin="https://api.example.test/",
    )

    assert stream.value == full + "\n"


def test_tty_content_progress_updates_one_line_and_finishes_cleanly() -> None:
    stream = _OutputStream(tty=True)
    output = project_pipeline.ProjectPipelineProgressOutput(stream)

    output.content_discovery_progress("Content discovery [##--] 50% 1/2", complete=False)
    output.content_discovery_progress("Content discovery [####] 100% 2/2", complete=True)

    assert stream.writes == [
        "\rContent discovery [##--] 50% 1/2\x1b[K",
        "\rContent discovery [####] 100% 2/2\x1b[K",
        "\n",
    ]
    assert stream.value.count("\n") == 1
    assert stream.flushes == 2


def test_tty_shorter_content_progress_clears_stale_trailing_text() -> None:
    stream = _OutputStream(tty=True)
    output = project_pipeline.ProjectPipelineProgressOutput(stream)

    output.content_discovery_progress(
        "Content discovery [active] 00:01 https://long.example.test/",
        complete=False,
    )
    output.content_discovery_progress("Content discovery [active] 00:02 x", complete=False)

    assert stream.writes[-1] == "\rContent discovery [active] 00:02 x\x1b[K"


def test_tty_origin_switch_replaces_instead_of_concatenating() -> None:
    stream = _OutputStream(tty=True)
    output = project_pipeline.ProjectPipelineProgressOutput(stream)

    output.content_discovery_progress("Content discovery origin-a", complete=False)
    output.content_discovery_progress("Content discovery origin-b", complete=False)

    assert stream.writes == [
        "\rContent discovery origin-a\x1b[K",
        "\rContent discovery origin-b\x1b[K",
    ]
    assert "origin-aContent" not in stream.value


def test_non_tty_content_progress_preserves_milestone_lines() -> None:
    stream = _OutputStream(tty=False)
    output = project_pipeline.ProjectPipelineProgressOutput(stream)

    output.content_discovery_progress("Content discovery 1/2", complete=False)
    output.content_discovery_progress("Content discovery 2/2", complete=True)

    assert stream.writes == ["Content discovery 1/2\n", "Content discovery 2/2\n"]
    assert stream.flushes == 2


def test_normal_message_after_live_progress_starts_on_clean_line() -> None:
    stream = _OutputStream(tty=True)
    output = project_pipeline.ProjectPipelineProgressOutput(stream)

    output.content_discovery_progress("Content discovery [active]", complete=False)
    output("[8/15] bounded content discovery execution failed")

    assert stream.writes == [
        "\rContent discovery [active]\x1b[K",
        "\n",
        "[8/15] bounded content discovery execution failed\n",
    ]
    assert stream.flushes == 2


def test_interrupted_live_progress_can_be_finalised_cleanly() -> None:
    stream = _OutputStream(tty=True)
    output = project_pipeline.ProjectPipelineProgressOutput(stream)

    output.content_discovery_progress("Content discovery [active]", complete=False)
    output.finish()

    assert stream.value.endswith("\x1b[K\n")
    assert stream.flushes == 2


def test_pipeline_progress_forwarding_uses_optional_live_rendering_seam() -> None:
    calls: list[tuple[str, bool, str | None, str | None]] = []

    class _Callback:
        def __call__(self, _message: str) -> None:
            raise AssertionError("content progress used the ordinary line callback")

        def content_discovery_progress(
            self,
            message: str,
            *,
            complete: bool,
            compact_message: str | None,
            essential_message: str | None,
            origin: str | None,
        ) -> None:
            calls.append((message, complete, compact_message, origin))

    project_pipeline._emit_content_discovery_progress(
        _Callback(),
        "[8/15] bounded content discovery execution: Content discovery 2/2",
        complete=True,
    )

    assert calls == [
        (
            "[8/15] bounded content discovery execution: Content discovery 2/2",
            True,
            None,
            None,
        )
    ]
