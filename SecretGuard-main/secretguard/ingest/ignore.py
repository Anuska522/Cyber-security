"""Ignore file evaluation and path filtering using pathspec."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, Sequence

import pathspec

logger = logging.getLogger("secretguard.ingest.ignore")

DEFAULT_IGNORE_PATTERNS = [
    ".git",
    ".git/**",
    ".venv",
    ".venv/**",
    "venv",
    "venv/**",
    "__pycache__",
    "__pycache__/**",
    "*.pyc",
    "node_modules",
    "node_modules/**",
    ".pytest_cache",
    ".pytest_cache/**",
    ".mypy_cache",
    ".mypy_cache/**",
]


class IgnoreMatcher:
    """Evaluates relative file paths against gitignore, customignore, and caller patterns."""

    def __init__(
        self,
        base_dir: Path,
        custom_patterns: Sequence[str] = (),
        ignore_files: Sequence[str] = (".gitignore", ".customignore"),
    ) -> None:
        self.base_dir = base_dir.resolve()
        patterns: list[str] = list(DEFAULT_IGNORE_PATTERNS)

        for filename in ignore_files:
            file_path = self.base_dir / filename
            if file_path.is_file():
                try:
                    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
                        for line in handle:
                            stripped = line.strip()
                            if stripped and not stripped.startswith("#"):
                                patterns.append(stripped)
                except OSError as err:
                    logger.debug("Could not read ignore file %s: %s", file_path, err)

        patterns.extend(custom_patterns)
        self._spec = pathspec.PathSpec.from_lines("gitignore", patterns)

    def is_ignored(self, relative_path: str) -> bool:
        """Check if a relative path matches the aggregated ignore specifications."""
        normalized = relative_path.replace("\\", "/")
        if normalized.startswith("./"):
            normalized = normalized[2:]
        return bool(self._spec.match_file(normalized))
