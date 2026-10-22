"""Persistent TUI statusline renderer displaying repo, branch, active model profile, and engine status."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional

from secretguard.tui.theme import (
    GLYPH_SEPARATOR,
    RGB_CYBER_CYAN,
    RGB_EMERALD,
    RGB_MUTED_ZINC,
    RGB_OFF_WHITE,
    color_text,
)


def get_current_git_branch(target_dir: str = ".") -> Optional[str]:
    """Attempt to resolve active git branch name cleanly without raising errors."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=target_dir,
            capture_output=True,
            text=True,
            check=False,
            timeout=1.0,
        )
        if res.returncode == 0:
            branch = res.stdout.strip()
            return branch if branch else None
        return None
    except Exception:
        return None


def format_short_path(path_str: str) -> str:
    """Format file path with ~ abbreviation for home directory."""
    try:
        resolved = Path(path_str).resolve()
        home = Path.home().resolve()
        if resolved == home:
            return "~"
        if home in resolved.parents:
            rel = resolved.relative_to(home)
            return f"~/{rel}"
        return str(resolved)
    except Exception:
        return path_str


def render_statusline(
    repo_path: str = ".",
    branch: Optional[str] = None,
    model_profile: str = "auto (llama-3.1-8b)",
    engine_status: str = "active",
    latency_ms: Optional[float] = None,
    use_color: bool = True,
) -> str:
    """Render a persistent cyber-minimalist status bar.

    Example output:
    ~/projects/my-app (main)  ::  model: auto (llama-3.1-8b)  ::  engine: active
    """
    resolved_path = format_short_path(repo_path)
    if branch is None:
        branch = get_current_git_branch(repo_path) or "local"

    path_and_branch = f"{resolved_path} ({branch})"
    model_part = f"model: {model_profile}"
    engine_part = f"engine: {engine_status}"

    components = [path_and_branch, model_part, engine_part]
    if latency_ms is not None:
        components.append(f"latency: {latency_ms:.1f}ms")

    if not use_color:
        sep = f"  {GLYPH_SEPARATOR}  "
        return sep.join(components)

    c_path = color_text(path_and_branch, RGB_OFF_WHITE)
    c_sep = color_text(GLYPH_SEPARATOR, RGB_MUTED_ZINC)
    c_model = f"{color_text('model:', RGB_MUTED_ZINC)} {color_text(model_profile, RGB_CYBER_CYAN)}"
    c_engine = f"{color_text('engine:', RGB_MUTED_ZINC)} {color_text(engine_status, RGB_EMERALD)}"

    colored_components = [c_path, c_model, c_engine]
    if latency_ms is not None:
        c_lat = f"{color_text('latency:', RGB_MUTED_ZINC)} {color_text(f'{latency_ms:.1f}ms', RGB_OFF_WHITE)}"
        colored_components.append(c_lat)

    sep_str = f"  {c_sep}  "
    return sep_str.join(colored_components)
