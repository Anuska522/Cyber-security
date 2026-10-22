"""Tests for cyber-minimalist TuiReportFormatter."""

from __future__ import annotations

import unicodedata

import pytest

from secretguard.core.models import ScanReport, ScanSummary, SecretCandidate, VerificationResult
from secretguard.reporting.tui_report import TuiReportFormatter
from secretguard.tui.theme import strip_ansi

_SAMPLE_AWS = "AKIA" + "1234567890" + "ABCDEF"


def _contains_emoji(text: str) -> bool:
    """Check if any character in string is classified as an emoji or picture glyph."""
    for ch in text:
        cat = unicodedata.category(ch)
        name = unicodedata.name(ch, "")
        if "EMOJI" in name or (cat in ("So", "Sk") and ord(ch) > 0x1F000):
            return True
    return False


def test_tui_report_clean_calming_notice() -> None:
    """Verify clean scan outputs calming single-line notice with diamond glyph."""
    summary = ScanSummary(
        total_files_scanned=10,
        total_lines_scanned=450,
        candidates_extracted=0,
        candidates_filtered=0,
        ai_verified_count=0,
        true_positive_count=0,
        execution_latency_ms=240.0,
        exit_code=0,
    )
    report = ScanReport(
        findings=[],
        summary=summary,
        scan_target=".",
        timestamp="2026-10-12T12:00:00Z",
        config_used={},
    )

    formatter = TuiReportFormatter(use_color=False)
    rendered = formatter.format_report(report)

    assert "◈ SecretGuard :: Repository verified clean (0.24s)" in rendered
    assert not _contains_emoji(rendered)


def test_tui_report_with_findings_rounded_box() -> None:
    """Verify intercepted secret renders cyber-minimalist rounded box and zero emojis."""
    cand = SecretCandidate(
        literal_value=_SAMPLE_AWS,
        file_path="src/config.py",
        line_number=12,
        surrounding_context=f'AWS_ACCESS_KEY = "{_SAMPLE_AWS}"',
        rule_id="SG-AWS-001",
        entropy_score=3.68,
    )
    res = VerificationResult(
        candidate=cand,
        is_secret=True,
        confidence=0.95,
        model_used="local_deterministic",
        explanation="Unambiguous vendor pattern match.",
        remediation="Rotate and revoke immediately.",
        resolved_locally=True,
        latency_ms=0.0,
    )
    summary = ScanSummary(
        total_files_scanned=1,
        total_lines_scanned=50,
        candidates_extracted=1,
        candidates_filtered=0,
        ai_verified_count=0,
        true_positive_count=1,
        execution_latency_ms=15.4,
        exit_code=1,
    )
    report = ScanReport(
        findings=[res],
        summary=summary,
        scan_target=".",
        timestamp="2026-10-12T12:00:00Z",
        config_used={},
    )

    formatter = TuiReportFormatter(use_color=True)
    rendered = formatter.format_report(report)

    clean_text = strip_ansi(rendered)
    assert "╭─ SecretGuard Interception Report (1 detected)" in clean_text
    assert "Finding #1" in clean_text
    assert "[Regex]" in clean_text
    assert "src/config.py:12" in clean_text
    assert _SAMPLE_AWS not in clean_text  # Credential masked
    assert "AKI...****" in clean_text
    assert "Status:" in clean_text
    assert "Blocked" in clean_text
    assert "╰" in clean_text

    # Strict check: zero emojis anywhere
    assert not _contains_emoji(rendered)
