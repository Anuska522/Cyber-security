"""Benchmark test: deterministic static scanning across a 100-line synthetic diff in under 1,000 ms."""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from secretguard.core.models import DiffLine, ScanContext
from secretguard.extract.engine import DeterministicExtractionEngine
from secretguard.ingest.git_diff import GitDiffParser


def generate_100_line_synthetic_diff() -> str:
    """Generate a realistic 100-line unified diff containing a realistic mix of code and secrets."""
    lines: list[str] = [
        "diff --git a/services/auth_service.py b/services/auth_service.py",
        "new file mode 100644",
        "index 0000000..abcdef1",
        "--- /dev/null",
        "+++ b/services/auth_service.py",
        "@@ -0,0 +1,100 @@",
    ]

    # Pre-defined lines to reach exactly 100 added lines
    secret_lines = {
        5: '+AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"',
        12: '+GITHUB_TOKEN = "' + "gh" + 'p_1234567890abcdefghijklmnopqrstuvwxyz"',
        20: '+JWT_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"',
        35: '+DB_URI = "postgres://admin_usr:StrongSecretP@ss99@db.prod.internal:5432/main"',
        48: '+OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL"',
        62: '+password = "P@ssw0rdSecureEnterprise99!"',
        75: '+api_key = "YOUR_API_KEY"',
        88: '+auth_secret = "${DB_PASSWORD}"',
        95: '+access_token = "https://api.github.com/v3/repos"',
    }

    for i in range(1, 101):
        if i in secret_lines:
            lines.append(secret_lines[i])
        else:
            lines.append(f"+def calculate_metric_item_{i}(val: int) -> int: return val * {i} + 1")

    return "\n".join(lines) + "\n"


def test_synthetic_diff_benchmark_under_1000ms() -> None:
    """Assert that deterministic static scanning across 100 lines completes in under 1,000 milliseconds."""
    diff_text = generate_100_line_synthetic_diff()
    parser = GitDiffParser()
    engine = DeterministicExtractionEngine()

    start_time = time.perf_counter()

    # 1. Parse unified diff
    parsed_diff_lines = list(parser.parse_diff_stream(diff_text.splitlines(keepends=True)))
    assert len(parsed_diff_lines) == 100

    # 2. Extract and filter candidates
    extracted_candidates = []
    for diff_line in parsed_diff_lines:
        candidates = engine.extract_from_diff_line(diff_line)
        extracted_candidates.extend(candidates)

    end_time = time.perf_counter()
    elapsed_ms = (end_time - start_time) * 1000.0

    # Assertions
    assert elapsed_ms < 1000.0, f"Scanning took {elapsed_ms:.2f} ms, exceeding 1,000 ms SLA!"

    # Verify that valid secrets were accurately detected
    valid_secrets = [c for c in extracted_candidates if not c.is_filtered]
    assert len(valid_secrets) >= 5

    # Verify that placeholders and non-secrets were marked as filtered
    filtered_items = [c for c in extracted_candidates if c.is_filtered]
    assert len(filtered_items) >= 2

    # Check specific rule detections
    rule_ids = {c.rule_id for c in valid_secrets}
    assert "SG-AWS-001" in rule_ids
    assert "SG-GH-001" in rule_ids
    assert "SG-JWT-001" in rule_ids
    assert "SG-DB-001" in rule_ids
    assert "SG-OAI-001" in rule_ids


def test_repeated_synthetic_diff_throughput() -> None:
    """Verify performance consistency across repeated scans without degradation."""
    diff_text = generate_100_line_synthetic_diff()
    parser = GitDiffParser()
    engine = DeterministicExtractionEngine()

    iterations = 10
    start_time = time.perf_counter()

    for _ in range(iterations):
        for diff_line in parser.parse_diff_stream(diff_text.splitlines(keepends=True)):
            engine.extract_from_diff_line(diff_line)

    total_time_ms = (time.perf_counter() - start_time) * 1000.0
    avg_per_iteration_ms = total_time_ms / iterations

    assert avg_per_iteration_ms < 500.0, f"Average iteration took {avg_per_iteration_ms:.2f} ms!"
