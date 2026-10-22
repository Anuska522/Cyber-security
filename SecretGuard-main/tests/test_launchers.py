"""Tests for zero-friction bootstrap launchers: run.sh, run.bat, and run.py."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import run


def test_launcher_scripts_exist_and_permissions() -> None:
    """Verify run.sh and run.bat exist at workspace root and run.sh has executable mode."""
    workspace = Path(__file__).parent.parent.resolve()

    sh_path = workspace / "run.sh"
    bat_path = workspace / "run.bat"
    py_path = workspace / "run.py"

    assert sh_path.is_file()
    assert bat_path.is_file()
    assert py_path.is_file()

    # POSIX executable permission on run.sh and run.py
    if sys.platform != "win32":
        sh_mode = stat.S_IMODE(sh_path.stat().st_mode)
        assert bool(sh_mode & stat.S_IXUSR)

    # Shell scripts must contain Python bootstrap commands
    sh_content = sh_path.read_text(encoding="utf-8")
    assert "set -euo pipefail" in sh_content
    assert "python3" in sh_content
    assert "secretguard" in sh_content

    bat_content = bat_path.read_text(encoding="utf-8")
    assert "@echo off" in bat_content
    assert ".venv" in bat_content


def test_run_py_version_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify run.py enforces Python >= 3.11 requirement."""
    # Current runtime passes
    run.verify_python_version()

    # Simulate Python 3.10 -> must exit with code 1
    monkeypatch.setattr(sys, "version_info", (3, 10, 0, "final", 0))
    with pytest.raises(SystemExit) as exc:
        run.verify_python_version()
    assert exc.value.code == 1


def test_run_py_get_venv_python_resolution(tmp_path: Path) -> None:
    """Verify venv python executable resolution across platforms."""
    venv_py = run.get_venv_python(tmp_path)
    if sys.platform == "win32":
        assert str(venv_py).endswith("Scripts\\python.exe")
    else:
        assert str(venv_py).endswith(".venv/bin/python3")


def test_run_py_argument_pass_through_execution() -> None:
    """Verify executing run.py --help cleanly outputs SecretGuard CLI help."""
    workspace = Path(__file__).parent.parent.resolve()
    proc = subprocess.run(
        [sys.executable, str(workspace / "run.py"), "--help"],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0
    assert "SecretGuard" in proc.stdout
    assert "scan" in proc.stdout
    assert "autopilot" in proc.stdout
