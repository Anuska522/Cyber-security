"""Tests for ingestion subsystem: Git diff hunk parsing, ignore filtering, and streaming."""

from __future__ import annotations

import inspect
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from secretguard.core.models import DiffLine, ScanContext
from secretguard.ingest.fs_scanner import FileSystemScanner
from secretguard.ingest.git_diff import GitDiffParser
from secretguard.ingest.ignore import IgnoreMatcher

SAMPLE_GIT_DIFF = """diff --git a/src/app.py b/src/app.py
index abcdef1..1234567 100644
--- a/src/app.py
+++ b/src/app.py
@@ -10,3 +10,2 @@
-old_unrelated_code()
-old_secret = "old_pass"
+AWS_KEY = "AKIA1234567890ABCDEF"
+safe_line = "no_secret"
diff --git a/config/settings.yaml b/config/settings.yaml
new file mode 100644
index 0000000..abcdef1
--- /dev/null
+++ b/config/settings.yaml
@@ -0,0 +1,2 @@
+database_url: "postgres://user:pass@localhost:5432/db"
+debug: true
diff --git a/deleted_file.txt b/deleted_file.txt
deleted file mode 100644
index 1234567..0000000
--- a/deleted_file.txt
+++ /dev/null
@@ -1,2 +0,0 @@
-line1
-line2
"""


def test_git_diff_hunk_parsing_streams_additions_only() -> None:
    """Verify GitDiffParser extracts exclusively added lines and suppresses deleted/historical lines."""
    parser = GitDiffParser()
    diff_lines = list(parser.parse_diff_stream(SAMPLE_GIT_DIFF.splitlines(keepends=True)))

    assert len(diff_lines) == 4

    # File 1: src/app.py
    assert diff_lines[0].file_path == "src/app.py"
    assert diff_lines[0].line_number == 10
    assert diff_lines[0].content == 'AWS_KEY = "AKIA1234567890ABCDEF"'
    assert diff_lines[0].is_addition is True

    assert diff_lines[1].file_path == "src/app.py"
    assert diff_lines[1].line_number == 11
    assert diff_lines[1].content == 'safe_line = "no_secret"'
    assert diff_lines[1].is_addition is True

    # File 2: config/settings.yaml
    assert diff_lines[2].file_path == "config/settings.yaml"
    assert diff_lines[2].line_number == 1
    assert diff_lines[2].content == 'database_url: "postgres://user:pass@localhost:5432/db"'
    assert diff_lines[2].is_addition is True

    assert diff_lines[3].file_path == "config/settings.yaml"
    assert diff_lines[3].line_number == 2
    assert diff_lines[3].content == "debug: true"
    assert diff_lines[3].is_addition is True


def test_git_diff_command_runner_injection() -> None:
    """Verify GitDiffParser invokes command_runner with --cached flag in pre-commit mode."""
    mock_runner = MagicMock(return_value=SAMPLE_GIT_DIFF)
    parser = GitDiffParser(command_runner=mock_runner)

    context = ScanContext(target_path="/repo", is_pre_commit=True)
    results = list(parser.stream_diff_lines(context))

    assert len(results) == 4
    mock_runner.assert_called_once_with(["git", "diff", "--unified=0", "--cached"], Path("/repo").resolve())


def test_ignore_matcher_evaluates_gitignore_and_customignore(tmp_path: Path) -> None:
    """Verify IgnoreMatcher respects .gitignore, .customignore, and caller-supplied patterns."""
    gitignore_file = tmp_path / ".gitignore"
    gitignore_file.write_text("*.log\n/build/\nsecret_dir/**\n", encoding="utf-8")

    customignore_file = tmp_path / ".customignore"
    customignore_file.write_text("*.bak\nvendor/\n", encoding="utf-8")

    matcher = IgnoreMatcher(
        base_dir=tmp_path,
        custom_patterns=["inline_ignored.txt"],
    )

    # Patterns from .gitignore
    assert matcher.is_ignored("test.log") is True
    assert matcher.is_ignored("build/bundle.js") is True
    assert matcher.is_ignored("secret_dir/key.pem") is True

    # Patterns from .customignore
    assert matcher.is_ignored("backup.bak") is True
    assert matcher.is_ignored("vendor/lib.py") is True

    # Default builtin ignores
    assert matcher.is_ignored(".git/HEAD") is True
    assert matcher.is_ignored(".venv/bin/python") is True

    # Context custom pattern
    assert matcher.is_ignored("inline_ignored.txt") is True

    # Legitimate non-ignored files
    assert matcher.is_ignored("src/main.py") is False
    assert matcher.is_ignored("README.md") is False


def test_file_system_scanner_streams_lines_without_full_memory_buffering(tmp_path: Path) -> None:
    """Verify FileSystemScanner streams lines as a generator, respecting ignores and binary files."""
    code_dir = tmp_path / "src"
    code_dir.mkdir()

    # Text file 1
    file_1 = code_dir / "service.py"
    file_1.write_text("def run():\n    return 'running'\n", encoding="utf-8")

    # Binary file (contains null byte)
    binary_file = code_dir / "image.png"
    binary_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

    # Ignored file via .gitignore
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("*.ignored\n", encoding="utf-8")
    ignored_file = code_dir / "secret.ignored"
    ignored_file.write_text("SECRET=12345\n", encoding="utf-8")

    scanner = FileSystemScanner()
    context = ScanContext(target_path=str(tmp_path))

    # Assert that stream_diff_lines returns an active generator/iterator
    stream_gen = scanner.stream_diff_lines(context)
    assert inspect.isgenerator(stream_gen)

    streamed_lines = list(stream_gen)

    # Ensure binary file and ignored file were suppressed
    file_paths = {line.file_path for line in streamed_lines}
    assert "src/service.py" in file_paths
    assert "src/image.png" not in file_paths
    assert "src/secret.ignored" not in file_paths

    # Verify line content and indexing
    lines_for_service = [l for l in streamed_lines if l.file_path == "src/service.py"]
    assert len(lines_for_service) == 2
    assert lines_for_service[0].line_number == 1
    assert lines_for_service[0].content == "def run():"
    assert lines_for_service[1].line_number == 2
    assert lines_for_service[1].content == "    return 'running'"


def test_file_system_scanner_stream_file_lines_generator(tmp_path: Path) -> None:
    """Verify single file streaming yields DiffLine objects lazily."""
    scanner = FileSystemScanner()
    test_file = tmp_path / "sample.txt"
    test_file.write_text("line_alpha\nline_beta\n", encoding="utf-8")

    gen = scanner.stream_file_lines(test_file, "sample.txt")
    assert inspect.isgenerator(gen)

    first_item = next(gen)
    assert isinstance(first_item, DiffLine)
    assert first_item.line_number == 1
    assert first_item.content == "line_alpha"

    second_item = next(gen)
    assert second_item.line_number == 2
    assert second_item.content == "line_beta"

    with pytest.raises(StopIteration):
        next(gen)
