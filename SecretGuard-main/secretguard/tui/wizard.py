"""Minimal 3-Question Autopilot Onboarding wizard with rounded box layout and 0600 config persistence."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from secretguard.tui.banner import render_banner
from secretguard.tui.theme import (
    BOX_BL,
    BOX_BR,
    BOX_H,
    BOX_TL,
    BOX_TR,
    BOX_V,
    GLYPH_ARROW,
    GLYPH_SUCCESS,
    RGB_AMBER,
    RGB_CYBER_CYAN,
    RGB_EMERALD,
    RGB_MUTED_ZINC,
    RGB_OFF_WHITE,
    color_text,
    fg_rgb,
    strip_ansi,
)

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "secretguard" / "config.yaml"

PRE_COMMIT_SCRIPT_TEMPLATE = """#!/usr/bin/env bash
# SecretGuard automated pre-commit hook
set -e
if command -v secretguard >/dev/null 2>&1; then
    exec secretguard scan --pre-commit
elif [ -f .venv/bin/secretguard ]; then
    exec .venv/bin/secretguard scan --pre-commit
else
    python3 -m secretguard.cli scan --pre-commit
fi
"""


def _parse_yes_no(raw: str, default: bool = True) -> bool:
    """Parse user answer with default-to-Yes behavior upon Enter."""
    clean = raw.strip().lower()
    if not clean:
        return default
    if clean in ("y", "yes"):
        return True
    if clean in ("n", "no"):
        return False
    return default


def run_autopilot_wizard(
    repo_path: str = ".",
    config_path: Optional[Path] = None,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[[str], None] = print,
    use_color: bool = True,
) -> dict[str, Any]:
    """Execute the cyber-minimalist 3-question autopilot onboarding flow."""
    # 1. Display Header Banner
    print_fn(render_banner(use_color=use_color))

    # 2. Render Box Frame for Setup
    box_width = 72
    b_color = fg_rgb(RGB_CYBER_CYAN) if use_color else ""
    reset_seq = "\033[0m" if use_color else ""
    v_edge = f"{b_color}{BOX_V}{reset_seq}" if use_color else BOX_V

    header_title = "SecretGuard Autopilot Setup"
    title_str = color_text(header_title, RGB_OFF_WHITE, bold=True) if use_color else header_title
    dashes_right = box_width - len(header_title) - 6

    top_border = f"{b_color}{BOX_TL}{BOX_H} {title_str} {b_color}{BOX_H * dashes_right}{BOX_TR}{reset_seq}"
    bottom_border = f"{b_color}{BOX_BL}{BOX_H * (box_width - 2)}{BOX_BR}{reset_seq}"

    print_fn(top_border)
    print_fn(f"{v_edge}{' ' * (box_width - 2)}{v_edge}")

    def render_row(content: str) -> None:
        clean_len = len(strip_ansi(content))
        pad = max(box_width - 4 - clean_len, 0)
        print_fn(f"{v_edge}  {content}{' ' * pad}{v_edge}")

    # Question 1
    q1_label = "[1/3] Protect this repository before every commit? [Y/n]"
    q1_desc = "Installs silent local git pre-commit hook"
    colored_q1 = color_text(q1_label, RGB_OFF_WHITE, bold=True) if use_color else q1_label
    colored_d1 = color_text(q1_desc, RGB_MUTED_ZINC) if use_color else q1_desc
    glyph_prompt = color_text(f"{GLYPH_ARROW} ", RGB_AMBER) if use_color else f"{GLYPH_ARROW} "

    render_row(f"{colored_q1} {glyph_prompt}")
    render_row(colored_d1)
    render_row("")

    # Prompt user for Q1
    ans1_raw = input_fn(f"  [1/3] Protect repo? [Y/n] › ")
    ans1 = _parse_yes_no(ans1_raw, default=True)

    # Question 2
    q2_label = "[2/3] Enable Adaptive AI routing to eliminate false alarms? [Y/n]"
    q2_desc = "Zero-shot context verification with automatic fallback"
    colored_q2 = color_text(q2_label, RGB_OFF_WHITE, bold=True) if use_color else q2_label
    colored_d2 = color_text(q2_desc, RGB_MUTED_ZINC) if use_color else q2_desc

    render_row(f"{colored_q2} {glyph_prompt}")
    render_row(colored_d2)
    render_row("")

    # Prompt user for Q2
    ans2_raw = input_fn(f"  [2/3] Enable AI routing? [Y/n] › ")
    ans2 = _parse_yes_no(ans2_raw, default=True)

    # Question 3
    q3_label = "[3/3] Automatically quarantine exposed keys into a safe .env? [Y/n]"
    q3_desc = "Replaces raw secrets in code and updates .gitignore"
    colored_q3 = color_text(q3_label, RGB_OFF_WHITE, bold=True) if use_color else q3_label
    colored_d3 = color_text(q3_desc, RGB_MUTED_ZINC) if use_color else q3_desc

    render_row(f"{colored_q3} {glyph_prompt}")
    render_row(colored_d3)
    render_row("")

    # Prompt user for Q3
    ans3_raw = input_fn(f"  [3/3] Auto-quarantine to .env? [Y/n] › ")
    ans3 = _parse_yes_no(ans3_raw, default=True)

    print_fn(bottom_border)
    print_fn("")

    # 3. Persist configuration to ~/.config/secretguard/config.yaml with 0600 permissions
    target_config = config_path or DEFAULT_CONFIG_PATH
    target_config.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target_config.parent, 0o700)
    except OSError:
        pass

    config_data = {
        "version": 1,
        "entropy_threshold": 4.5,
        "min_candidate_length": 16,
        "strict_permissions": True,
        "routing_profile": "auto" if ans2 else "local",
        "auto_quarantine": ans3,
        "provider_keys": {},
    }

    yaml_str = yaml.safe_dump(config_data, sort_keys=False)
    target_config.write_text(yaml_str, encoding="utf-8")
    try:
        os.chmod(target_config, 0o600)
    except OSError:
        pass

    # 4. Install pre-commit hook if approved
    hook_installed = False
    repo_dir = Path(repo_path).resolve()
    git_hooks_dir = repo_dir / ".git" / "hooks"
    if ans1 and git_hooks_dir.is_dir():
        hook_file = git_hooks_dir / "pre-commit"
        hook_file.write_text(PRE_COMMIT_SCRIPT_TEMPLATE, encoding="utf-8")
        try:
            hook_file.chmod(hook_file.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            hook_installed = True
        except OSError:
            hook_installed = False

    # 5. Confirmation message
    check_glyph = color_text(GLYPH_SUCCESS, RGB_EMERALD, bold=True) if use_color else GLYPH_SUCCESS
    msg = f"{check_glyph} Autopilot setup complete. Repository is now guarded."
    print_fn(msg)

    return {
        "protect_repo": ans1,
        "enable_ai": ans2,
        "auto_quarantine": ans3,
        "hook_installed": hook_installed,
        "config_path": str(target_config),
    }
