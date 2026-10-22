"""Cyber-minimalist TUI engine for SecretGuard."""

from secretguard.tui.banner import render_banner
from secretguard.tui.statusline import render_statusline
from secretguard.tui.theme import (
    RGB_CYBER_CYAN,
    RGB_ELECTRIC_MAGENTA,
    RGB_EMERALD,
    RGB_MUTED_ZINC,
    RGB_OFF_WHITE,
    RGB_ROSE,
    color_text,
    linear_gradient,
    render_box,
    strip_ansi,
)
from secretguard.tui.wizard import run_autopilot_wizard

__all__ = [
    "render_banner",
    "render_statusline",
    "run_autopilot_wizard",
    "color_text",
    "linear_gradient",
    "render_box",
    "strip_ansi",
    "RGB_ELECTRIC_MAGENTA",
    "RGB_CYBER_CYAN",
    "RGB_OFF_WHITE",
    "RGB_MUTED_ZINC",
    "RGB_EMERALD",
    "RGB_ROSE",
]
