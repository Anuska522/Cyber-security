"""Tests for Antigravity TUI theme, banner, statusline, and zero-emoji compliance."""

from __future__ import annotations

import unicodedata
from pathlib import Path

import pytest

from secretguard.tui.banner import BANNER_ART, SUBTITLE, render_banner
from secretguard.tui.statusline import format_short_path, render_statusline
from secretguard.tui.theme import (
    BOX_BL,
    BOX_BR,
    BOX_H,
    BOX_TL,
    BOX_TR,
    BOX_V,
    GLYPH_ARROW,
    GLYPH_DIAMOND,
    GLYPH_FAILURE,
    GLYPH_PROMPT,
    GLYPH_SEPARATOR,
    GLYPH_SUCCESS,
    RGB_CYBER_CYAN,
    RGB_ELECTRIC_MAGENTA,
    color_text,
    linear_gradient,
    render_box,
    strip_ansi,
)


def _contains_emoji(text: str) -> bool:
    """Check if any character in string is classified as an emoji or picture glyph."""
    for ch in text:
        cat = unicodedata.category(ch)
        name = unicodedata.name(ch, "")
        if "EMOJI" in name or (cat in ("So", "Sk") and ord(ch) > 0x1F000):
            return True
    return False


def test_tui_banner_truecolor_gradient_sequences() -> None:
    """Verify banner outputs 24-bit TrueColor ANSI escape sequences (\033[38;2;R;G;Bm)."""
    banner = render_banner(use_color=True)

    # Must contain TrueColor escape sequences
    assert "\033[38;2;" in banner
    # Must contain Magenta and Cyan RGB boundaries
    assert f"{RGB_ELECTRIC_MAGENTA[0]};{RGB_ELECTRIC_MAGENTA[1]};{RGB_ELECTRIC_MAGENTA[2]}" in banner
    assert f"{RGB_CYBER_CYAN[0]};{RGB_CYBER_CYAN[1]};{RGB_CYBER_CYAN[2]}" in banner
    # Must contain subtitle
    assert SUBTITLE in banner


def test_tui_banner_no_color_mode() -> None:
    """Verify banner outputs clean ASCII without ANSI escape codes when use_color=False."""
    banner = render_banner(use_color=False)
    assert "\033[" not in banner
    for line in BANNER_ART:
        assert line in banner
    assert SUBTITLE in banner


def test_zero_emojis_across_tui_module() -> None:
    """Assert ZERO emojis exist across all string outputs, glyphs, and source files in secretguard.tui."""
    tui_dir = Path("secretguard/tui")
    for py_file in tui_dir.glob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for line_idx, line in enumerate(content.splitlines(), start=1):
            assert not _contains_emoji(line), f"Forbidden emoji detected in {py_file}:{line_idx} -> {line}"

    # Verify rendered components contain zero emojis
    assert not _contains_emoji(render_banner(use_color=True))
    assert not _contains_emoji(render_banner(use_color=False))
    assert not _contains_emoji(render_statusline(use_color=True))
    assert not _contains_emoji(render_statusline(use_color=False))

    # Verify all geometric glyphs are not emojis
    glyphs = [
        GLYPH_PROMPT,
        GLYPH_ARROW,
        GLYPH_DIAMOND,
        GLYPH_SUCCESS,
        GLYPH_FAILURE,
        GLYPH_SEPARATOR,
        BOX_TL,
        BOX_TR,
        BOX_BL,
        BOX_BR,
        BOX_H,
        BOX_V,
    ]
    for g in glyphs:
        assert not _contains_emoji(g), f"Glyph {g} should not be an emoji"


def test_linear_gradient_interpolation() -> None:
    """Verify linear gradient calculates intermediate RGB values correctly."""
    text = "SECRET"
    grad = linear_gradient(text, start_rgb=(255, 0, 0), end_rgb=(0, 0, 255))
    clean = strip_ansi(grad)
    assert clean == text
    assert grad.startswith("\033[38;2;255;0;0m")
    assert "\033[38;2;0;0;255m" in grad


def test_statusline_formatting() -> None:
    """Verify statusline renders repo, branch, profile, and engine status."""
    line = render_statusline(
        repo_path="/test/app",
        branch="feature/guard",
        model_profile="auto (llama-3.1-8b)",
        engine_status="active",
        latency_ms=128.5,
        use_color=False,
    )
    expected_path = format_short_path("/test/app")
    assert f"{expected_path} (feature/guard)" in line
    assert "model: auto (llama-3.1-8b)" in line
    assert "engine: active" in line
    assert "latency: 128.5ms" in line
    assert "::" in line


def test_render_box_rounded_borders() -> None:
    """Verify render_box formats content with rounded corners (╭, ╮, ╰, ╯)."""
    box = render_box(
        title="Setup",
        lines=["Line 1", "Line 2"],
        width=40,
        use_color=False,
    )
    lines = box.splitlines()
    assert lines[0].startswith("╭─ Setup ")
    assert lines[0].endswith("╮")
    assert lines[1].startswith("│ Line 1")
    assert lines[2].startswith("│ Line 2")
    assert lines[3].startswith("╰")
    assert lines[3].endswith("╯")
