"""Streaming Git unified diff ingester for pre-commit and staged hunks."""

from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Callable, Optional

from secretguard.core.interfaces import IDiffIngester
from secretguard.core.models import DiffLine, ScanContext

logger = logging.getLogger("secretguard.ingest.git")

HUNK_HEADER_PATTERN = re.compile(r"^@@\s+-(?:\d+)(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@")


class GitDiffParser(IDiffIngester):
    """Parses Git unified diffs to stream only added or modified lines."""

    def __init__(
        self,
        command_runner: Optional[Callable[[list[str], Path], str]] = None,
    ) -> None:
        self._command_runner = command_runner or self._default_command_runner

    @staticmethod
    def _default_command_runner(args: list[str], cwd: Path) -> str:
        """Execute git command via subprocess and return stdout text."""
        result = subprocess.run(
            args,
            cwd=str(cwd),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout

    def parse_diff_stream(self, lines: Iterable[str]) -> Iterator[DiffLine]:
        """Stream DiffLine objects parsed from unified diff lines without full in-memory buffering."""
        current_file = ""
        current_new_line = 0
        in_hunk = False

        for raw_line in lines:
            line = raw_line.rstrip("\r\n")

            # Check for file header lines
            if line.startswith("diff --git "):
                # e.g., diff --git a/path/to/file b/path/to/file
                in_hunk = False
                parts = line.split(" ")
                if len(parts) >= 4 and parts[3].startswith("b/"):
                    current_file = parts[3][2:]
                continue

            if line.startswith("+++ "):
                in_hunk = False
                target = line[4:].strip()
                if target == "/dev/null":
                    current_file = ""
                elif target.startswith("b/"):
                    current_file = target[2:]
                else:
                    current_file = target
                continue

            if line.startswith("--- "):
                in_hunk = False
                continue

            # Check for hunk header @@ -old,count +new,count @@
            hunk_match = HUNK_HEADER_PATTERN.match(line)
            if hunk_match:
                in_hunk = True
                new_start = int(hunk_match.group(1))
                current_new_line = new_start
                continue

            if not in_hunk or not current_file:
                continue

            # Suppress deleted lines and diff comments
            if line.startswith("+++") or line.startswith("---"):
                continue

            if line.startswith("+"):
                # Exclusively added or modified lines
                content = line[1:]
                yield DiffLine(
                    file_path=current_file,
                    line_number=current_new_line,
                    content=content,
                    is_addition=True,
                )
                current_new_line += 1
            elif line.startswith("-"):
                # Historical deleted lines - suppressed
                continue
            elif line.startswith(" "):
                # Unmodified context line (if present)
                current_new_line += 1

    def stream_diff_lines(self, context: ScanContext) -> Iterator[DiffLine]:
        """Stream staged or requested git diff lines for the scan target."""
        target_dir = Path(context.target_path).resolve()
        cmd = ["git", "diff", "--unified=0"]

        if context.is_pre_commit or context.diff_mode:
            cmd.append("--cached")

        try:
            diff_output = self._command_runner(cmd, target_dir)
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as err:
            logger.error("Failed to run git diff command %s: %s", cmd, err)
            return

        yield from self.parse_diff_stream(diff_output.splitlines(keepends=True))
