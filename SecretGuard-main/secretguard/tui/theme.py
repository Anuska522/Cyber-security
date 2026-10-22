"""Cyber-minimalist TUI theme, TrueColor 24-bit palette, ANSI utilities, and box drawing primitives."""

from __future__ import annotations

import re
from typing import Final, Tuple

# ---------------------------------------------------------------------------
# Strict Cyber-Minimalist Palette (RGB 24-bit TrueColor)
# ---------------------------------------------------------------------------
RGB_ELECTRIC_MAGENTA: Final[Tuple[int, int, int]] = (255, 0, 127)  # #FF007F
RGB_CYBER_CYAN: Final[Tuple[int, int, int]] = (0, 229, 255)        # #00E5FF
RGB_OFF_WHITE: Final[Tuple[int, int, int]] = (240, 240, 240)        # #F0F0F0
RGB_MUTED_ZINC: Final[Tuple[int, int, int]] = (102, 102, 102)      # #666666
RGB_EMERALD: Final[Tuple[int, int, int]] = (16, 185, 129)          # #10B981 (Success)
RGB_AMBER: Final[Tuple[int, int, int]] = (245, 158, 11)            # #F59E0B (Prompt)
RGB_ROSE: Final[Tuple[int, int, int]] = (244, 63, 94)              # #F43F5E (Quarantine)

RESET: Final[str] = "\033[0m"
BOLD: Final[str] = "\033[1m"
DIM: Final[str] = "\033[2m"

# Geometric Unicode symbols (Zero emojis permitted)
GLYPH_PROMPT: Final[str] = "❯"
GLYPH_ARROW: Final[str] = "›"
GLYPH_DIAMOND: Final[str] = "◈"
GLYPH_DIAMOND_FILLED: Final[str] = "◆"
GLYPH_CIRCLE_FILLED: Final[str] = "●"
GLYPH_CIRCLE: Final[str] = "○"
GLYPH_SQUARE: Final[str] = "■"
GLYPH_SUCCESS: Final[str] = "✓"
GLYPH_FAILURE: Final[str] = "✕"
GLYPH_SEPARATOR: Final[str] = "::"

# Box drawing characters
BOX_TL: Final[str] = "╭"
BOX_TR: Final[str] = "╮"
BOX_BL: Final[str] = "╰"
BOX_BR: Final[str] = "╯"
BOX_H: Final[str] = "─"
BOX_V: Final[str] = "│"

ANSI_REGEX: Final[re.Pattern] = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences to compute visible character length accurately."""
    return ANSI_REGEX.sub("", text)


def fg_rgb(rgb: Tuple[int, int, int]) -> str:
    """Return ANSI 24-bit TrueColor foreground sequence."""
    return f"\033[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"


def color_text(text: str, rgb: Tuple[int, int, int], bold: bool = False, dim: bool = False) -> str:
    """Wrap text in TrueColor RGB formatting."""
    prefix = fg_rgb(rgb)
    if bold:
        prefix = f"{BOLD}{prefix}"
    if dim:
        prefix = f"{DIM}{prefix}"
    return f"{prefix}{text}{RESET}"


def linear_gradient(
    text: str,
    start_rgb: Tuple[int, int, int] = RGB_ELECTRIC_MAGENTA,
    end_rgb: Tuple[int, int, int] = RGB_CYBER_CYAN,
    bold: bool = False,
) -> str:
    """Render text with a smooth horizontal 24-bit TrueColor gradient."""
    visible_chars = [ch for ch in text if not ch.isspace()]
    total_steps = max(len(visible_chars) - 1, 1)

    result_parts: list[str] = []
    step_idx = 0

    for ch in text:
        if ch.isspace():
            result_parts.append(ch)
            continue

        ratio = step_idx / total_steps
        r = int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * ratio)
        g = int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * ratio)
        b = int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * ratio)

        prefix = fg_rgb((r, g, b))
        if bold:
            prefix = f"{BOLD}{prefix}"
        result_parts.append(f"{prefix}{ch}{RESET}")
        step_idx += 1

    return "".join(result_parts)


def render_box(
    title: str,
    lines: list[str],
    width: int = 72,
    border_rgb: Tuple[int, int, int] = RGB_CYBER_CYAN,
    title_rgb: Tuple[int, int, int] = RGB_OFF_WHITE,
    use_color: bool = True,
) -> str:
    """Format content lines within a thin, rounded container box (╭─ ... ─╮ / ╰─ ... ─╯)."""
    clean_title = strip_ansi(title)
    inner_width = max(width - 2, len(clean_title) + 4)

    # Top border with title: ╭─ Title ───────╮
    header_dashes_left = 1
    header_dashes_right = max(inner_width - len(clean_title) - header_dashes_left - 2, 1)

    if use_color:
        b_color = fg_rgb(border_rgb)
        t_color = color_text(title, title_rgb, bold=True)
        top_border = f"{b_color}{BOX_TL}{BOX_H * header_dashes_left} {t_color} {b_color}{BOX_H * header_dashes_right}{BOX_TR}{RESET}"
        bottom_border = f"{b_color}{BOX_BL}{BOX_H * inner_width}{BOX_BR}{RESET}"
        vert_edge = f"{b_color}{BOX_V}{RESET}"
    else:
        top_border = f"{BOX_TL}{BOX_H * header_dashes_left} {title} {BOX_H * header_dashes_right}{BOX_TR}"
        bottom_border = f"{BOX_BL}{BOX_H * inner_width}{BOX_BR}"
        vert_edge = BOX_V

    output_lines: list[str] = [top_border]

    for line in lines:
        clean_len = len(strip_ansi(line))
        padding = max(inner_width - clean_len - 1, 0)
        output_lines.append(f"{vert_edge} {line}{' ' * padding}{vert_edge}")

    output_lines.append(bottom_border)
    return "\n".join(output_lines)
