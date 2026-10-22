#!/usr/bin/env python3
"""SecretGuard universal root runner and delegator."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    workspace = Path(__file__).parent.resolve()
    nested_script = workspace / "SecretGuard-main" / "run.py"

    if nested_script.is_file():
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        forwarded_args = []
        for arg in sys.argv[1:]:
            p = Path(arg)
            if p.exists() and not arg.startswith("-"):
                forwarded_args.append(str(p.resolve()))
            else:
                forwarded_args.append(arg)
        try:
            proc = subprocess.run(
                [sys.executable, str(nested_script), *forwarded_args],
                cwd=workspace / "SecretGuard-main",
                env=env,
            )
            sys.exit(proc.returncode)
        except KeyboardInterrupt:
            sys.exit(130)

    # Fallback to local execution if flat
    if sys.version_info < (3, 11):
        sys.stderr.write(
            f"Error: SecretGuard requires Python 3.11+, but detected {sys.version_info[0]}.{sys.version_info[1]}.\n"
        )
        sys.exit(1)

    from secretguard.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
