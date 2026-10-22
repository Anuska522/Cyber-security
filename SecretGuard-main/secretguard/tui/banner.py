"""Block-styled TrueColor banner renderer with duotone Magenta-to-Cyan gradient."""

from __future__ import annotations

from typing import Final

from secretguard.tui.theme import (
    RGB_CYBER_CYAN,
    RGB_ELECTRIC_MAGENTA,
    RGB_MUTED_ZINC,
    RGB_OFF_WHITE,
    color_text,
    linear_gradient,
)

BANNER_ART: Final[tuple[str, ...]] = (
    "  ▄█████ █▀▀▀▀ ▄████ █▀▀█▄ █▀▀▀▀ ▀▀█▀▀ ▄████ █  █ ▄▀▀▄ █▀▀█▄ █▀▀█▄",
    "  ▀▀▀▄▄▄ █▄▄▄  █     █▄▄▀█ █▄▄▄    █   █ ▄▄█ █  █ █▄▄█ █▄▄▀█ █  █ ",
    "  █████▀ █▄▄▄▄ ▀████ █  ▀█ █▄▄▄▄   █   ▀████ ▀██▀ █  █ █  ▀█ █▄▄█▀",
)

SUBTITLE: Final[str] = "Autonomous Secret Interception & Quarantine Engine"


def render_banner(use_color: bool = True) -> str:
    """Render the stylized block-shaded ASCII banner with a horizontal TrueColor gradient."""
    output_lines: list[str] = []

    for art_line in BANNER_ART:
        if use_color:
            colored_line = linear_gradient(
                art_line,
                start_rgb=RGB_ELECTRIC_MAGENTA,
                end_rgb=RGB_CYBER_CYAN,
                bold=True,
            )
            output_lines.append(colored_line)
        else:
            output_lines.append(art_line)

    if use_color:
        formatted_sub = f"  {color_text(SUBTITLE, RGB_MUTED_ZINC)}"
    else:
        formatted_sub = f"  {SUBTITLE}"

    output_lines.append(formatted_sub)
    output_lines.append("")
    return "\n".join(output_lines)
