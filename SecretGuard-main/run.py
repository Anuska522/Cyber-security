#!/usr/bin/env python3
"""SecretGuard universal cross-platform bootstrap runner and launcher."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def verify_python_version() -> None:
    """Ensure runtime Python version meets minimum >= 3.11 requirement."""
    if sys.version_info < (3, 11):
        sys.stderr.write(
            f"Error: SecretGuard requires Python 3.11+, but detected {sys.version_info[0]}.{sys.version_info[1]}.\n"
        )
        sys.exit(1)


def get_venv_python(workspace: Path) -> Path:
    """Return path to virtual environment python executable."""
    if sys.platform == "win32":
        return workspace / ".venv" / "Scripts" / "python.exe"
    return workspace / ".venv" / "bin" / "python3"


def ensure_environment(workspace: Path) -> Path:
    """Provision virtualenv and ensure package is installed in editable mode."""
    venv_dir = workspace / ".venv"
    venv_py = get_venv_python(workspace)

    # 1. Provision venv if absent
    if not venv_dir.is_dir() or not venv_py.is_file():
        sys.stdout.write("Provisioning isolated virtual environment (.venv)...\n")
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)

    # 2. Check if secretguard CLI entrypoint is installed
    cli_bin = workspace / ".venv" / "Scripts" / "secretguard.exe" if sys.platform == "win32" else workspace / ".venv" / "bin" / "secretguard"
    if not cli_bin.is_file():
        sys.stdout.write("Installing dependencies and registering SecretGuard CLI...\n")
        subprocess.run([str(venv_py), "-m", "pip", "install", "-q", "-e", "."], cwd=workspace, check=True)

    return venv_py


def main() -> None:
    """Verify runtime, bootstrap virtualenv if needed, and execute SecretGuard CLI."""
    verify_python_version()
    workspace = Path(__file__).parent.resolve()

    # If running directly inside the workspace virtualenv, dispatch immediately
    if sys.prefix == str(workspace / ".venv"):
        from secretguard.cli import main as cli_main

        cli_main()
        return

    # Otherwise ensure venv and re-execute within it
    venv_py = ensure_environment(workspace)
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = str(workspace) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [str(venv_py), "-m", "secretguard.cli", *sys.argv[1:]]
    try:
        proc = subprocess.run(cmd, env=env)
        sys.exit(proc.returncode)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
