"""Streaming recursive filesystem scanner with ignore-spec filtering."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from pathlib import Path

from secretguard.core.interfaces import IDiffIngester
from secretguard.core.models import DiffLine, ScanContext
from secretguard.ingest.ignore import IgnoreMatcher

logger = logging.getLogger("secretguard.ingest.fs")


class FileSystemScanner(IDiffIngester):
    """Recursively scans directory files, streaming DiffLine items line by line without memory bloat."""

    def __init__(self, chunk_size: int = 4096) -> None:
        self.chunk_size = chunk_size

    def is_binary_file(self, file_path: Path) -> bool:
        """Inspect beginning of file to detect binary content via null byte heuristic."""
        try:
            with file_path.open("rb") as handle:
                chunk = handle.read(self.chunk_size)
                return b"\x00" in chunk
        except (OSError, PermissionError) as err:
            logger.debug("Failed reading file %s for binary probe: %s", file_path, err)
            return True

    def stream_file_lines(self, file_path: Path, relative_path: str) -> Iterator[DiffLine]:
        """Stream lines from a single text file one by one."""
        try:
            with file_path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    yield DiffLine(
                        file_path=relative_path,
                        line_number=line_number,
                        content=raw_line.rstrip("\r\n"),
                        is_addition=True,
                    )
        except (OSError, PermissionError) as err:
            logger.warning("Could not open file %s for scanning: %s", file_path, err)

    def stream_diff_lines(self, context: ScanContext) -> Iterator[DiffLine]:
        """Stream lines across all non-ignored, non-binary files in the target path."""
        root_dir = Path(context.target_path).resolve()
        if not root_dir.exists():
            logger.error("Target path does not exist: %s", root_dir)
            return

        ignore_matcher = IgnoreMatcher(
            base_dir=root_dir,
            custom_patterns=context.ignore_patterns,
        )

        if root_dir.is_file():
            rel_str = str(root_dir.name)
            if not ignore_matcher.is_ignored(rel_str) and not self.is_binary_file(root_dir):
                yield from self.stream_file_lines(root_dir, rel_str)
            return

        for current_root, dir_names, file_names in os.walk(root_dir):
            current_path = Path(current_root)

            # Prune ignored directories in-place to avoid descending into them
            dir_names[:] = [
                d
                for d in dir_names
                if not ignore_matcher.is_ignored(
                    (current_path / d).relative_to(root_dir).as_posix()
                )
            ]

            for file_name in file_names:
                file_full = current_path / file_name
                try:
                    rel_path = file_full.relative_to(root_dir).as_posix()
                except ValueError:
                    rel_path = file_full.as_posix()

                if ignore_matcher.is_ignored(rel_path):
                    continue

                if self.is_binary_file(file_full):
                    continue

                yield from self.stream_file_lines(file_full, rel_path)
