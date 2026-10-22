"""Tests for minimal 3-question Autopilot Onboarding wizard."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from secretguard.tui.theme import strip_ansi
from secretguard.tui.wizard import run_autopilot_wizard


def test_autopilot_wizard_default_enter_answers(tmp_path: Path) -> None:
    """Verify hitting Enter defaults all 3 questions to Yes [Y/n] and generates secure 0600 config."""
    config_file = tmp_path / "config.yaml"
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    git_hooks = repo_dir / ".git" / "hooks"
    git_hooks.mkdir(parents=True)

    # Simulate pressing Enter for all 3 questions
    inputs = iter(["", "", ""])
    printed: list[str] = []

    res = run_autopilot_wizard(
        repo_path=str(repo_dir),
        config_path=config_file,
        input_fn=lambda prompt: next(inputs),
        print_fn=lambda msg: printed.append(msg),
        use_color=False,
    )

    # Assert responses defaulted to True
    assert res["protect_repo"] is True
    assert res["enable_ai"] is True
    assert res["auto_quarantine"] is True
    assert res["hook_installed"] is True

    # Assert config file created and valid
    assert config_file.is_file()
    cfg_data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    assert cfg_data["routing_profile"] == "auto"
    assert cfg_data["auto_quarantine"] is True

    # Assert POSIX 0600 file permissions
    if sys.platform != "win32":
        file_mode = stat.S_IMODE(config_file.stat().st_mode)
        assert file_mode == 0o600

        # Assert pre-commit hook installed with executable 0755 permissions
        hook_file = git_hooks / "pre-commit"
        assert hook_file.is_file()
        hook_mode = stat.S_IMODE(hook_file.stat().st_mode)
        assert bool(hook_mode & stat.S_IXUSR)
    else:
        hook_file = git_hooks / "pre-commit"
        assert hook_file.is_file()


def test_autopilot_wizard_explicit_no_answers(tmp_path: Path) -> None:
    """Verify answering 'n' disables hooks, AI routing, and auto-quarantine."""
    config_file = tmp_path / "custom_config.yaml"
    repo_dir = tmp_path / "no_hook_repo"
    repo_dir.mkdir()
    git_hooks = repo_dir / ".git" / "hooks"
    git_hooks.mkdir(parents=True)

    # Answering 'n' to all 3
    inputs = iter(["n", "no", "N"])
    printed: list[str] = []

    res = run_autopilot_wizard(
        repo_path=str(repo_dir),
        config_path=config_file,
        input_fn=lambda prompt: next(inputs),
        print_fn=lambda msg: printed.append(msg),
        use_color=False,
    )

    assert res["protect_repo"] is False
    assert res["enable_ai"] is False
    assert res["auto_quarantine"] is False
    assert res["hook_installed"] is False

    cfg_data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    assert cfg_data["routing_profile"] == "local"
    assert cfg_data["auto_quarantine"] is False

    # Hook should not be installed
    hook_file = git_hooks / "pre-commit"
    assert not hook_file.exists()


def test_autopilot_wizard_renders_clean_boxes() -> None:
    """Verify autopilot wizard outputs box layout without raw stack traces or exceptions."""
    printed: list[str] = []
    inputs = iter(["y", "y", "y"])

    run_autopilot_wizard(
        repo_path=".",
        config_path=Path("/tmp/test_wizard_box_config.yaml"),
        input_fn=lambda prompt: next(inputs),
        print_fn=lambda msg: printed.append(msg),
        use_color=True,
    )

    clean_output = strip_ansi("\n".join(printed))
    assert "╭─ SecretGuard Autopilot Setup" in clean_output
    assert "[1/3] Protect this repository" in clean_output
    assert "[2/3] Enable Adaptive AI routing" in clean_output
    assert "[3/3] Automatically quarantine exposed keys" in clean_output
    assert "╰" in clean_output
    assert "Autopilot setup complete" in clean_output
