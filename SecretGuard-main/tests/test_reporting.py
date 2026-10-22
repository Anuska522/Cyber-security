"""Tests for multi-format report serialization: Terminal, JSON, and SARIF v2.1.0."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secretguard.core.models import (
    ScanReport,
    ScanSummary,
    SecretCandidate,
    VerificationResult,
)
from secretguard.reporting.json_formatter import JsonReportFormatter
from secretguard.reporting.sarif import SARIF_SCHEMA_V210, SarifReportFormatter
from secretguard.reporting.terminal import TerminalReportFormatter


@pytest.fixture
def sample_findings() -> list[VerificationResult]:
    """Fixture providing a diverse set of verification findings."""
    cand1 = SecretCandidate(
        literal_value="AKIAIOSFODNN7EXAMPLE",
        file_path="src/aws.py",
        line_number=14,
        surrounding_context='aws_access_key = "AKIAIOSFODNN7EXAMPLE"',
        rule_id="SG-AWS-001",
        entropy_score=3.85,
        heuristic_tags=["aws", "cloud_credential"],
    )
    finding1 = VerificationResult(
        candidate=cand1,
        is_secret=True,
        confidence=0.95,
        explanation="Functional AWS Access Key ID detected.",
        remediation="Revoke and rotate AWS key immediately.",
        model_used="local_deterministic",
        latency_ms=0.0,
        resolved_locally=True,
    )

    cand2 = SecretCandidate(
        literal_value="sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL",
        file_path="src/llm.py",
        line_number=42,
        surrounding_context='api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL"',
        rule_id="SG-OAI-001",
        entropy_score=4.95,
        heuristic_tags=["openai"],
    )
    finding2 = VerificationResult(
        candidate=cand2,
        is_secret=True,
        confidence=0.88,
        explanation="Active OpenAI key identified in code assignment.",
        remediation="Store key in environment variable or secrets manager.",
        model_used="llama-3.1-8b-instant",
        latency_ms=45.2,
        resolved_locally=False,
    )

    return [finding1, finding2]


@pytest.fixture
def sample_report(sample_findings: list[VerificationResult]) -> ScanReport:
    """Fixture providing a complete ScanReport instance."""
    summary = ScanSummary(
        total_files_scanned=5,
        total_lines_scanned=250,
        candidates_extracted=3,
        candidates_filtered=1,
        ai_verified_count=1,
        true_positive_count=2,
        execution_latency_ms=120.5,
        exit_code=1,
    )
    return ScanReport(
        findings=sample_findings,
        summary=summary,
        scan_target="/workspace",
        timestamp="2026-10-12T14:30:00Z",
        config_used={"entropy_threshold": 4.2},
    )


@pytest.fixture
def clean_report() -> ScanReport:
    """Fixture providing a clean scan report with zero true positives."""
    summary = ScanSummary(
        total_files_scanned=10,
        total_lines_scanned=1200,
        candidates_extracted=1,
        candidates_filtered=1,
        ai_verified_count=0,
        true_positive_count=0,
        execution_latency_ms=45.0,
        exit_code=0,
    )
    return ScanReport(
        findings=[],
        summary=summary,
        scan_target="/clean-repo",
        timestamp="2026-10-12T14:35:00Z",
        config_used={"entropy_threshold": 4.2},
    )


def test_terminal_formatter_clean_report(clean_report: ScanReport) -> None:
    """Verify TerminalReportFormatter output for a clean scan without findings."""
    formatter = TerminalReportFormatter(use_color=False)
    rendered = formatter.format_report(clean_report)

    assert "SCAN CLEAN: No hardcoded secrets detected" in rendered
    assert "Files Scanned:               10" in rendered
    assert "Lines Scanned:               1200" in rendered
    assert "Process Exit Status:         0" in rendered


def test_terminal_formatter_with_findings(sample_report: ScanReport) -> None:
    """Verify TerminalReportFormatter renders badges, masked literals, and metrics."""
    formatter = TerminalReportFormatter(use_color=True)
    rendered = formatter.format_report(sample_report)

    assert "DETECTED 2 POTENTIAL SECRET(S)" in rendered
    assert "[Regex]" in rendered
    assert "[AI Verified]" in rendered
    assert "AKIAIOSFODNN7EXAMPLE" not in rendered  # Raw key must be masked
    assert "AKI...****" in rendered
    assert "src/aws.py:14" in rendered
    assert "src/llm.py:42" in rendered
    assert "Process Exit Status:" in rendered


def test_json_formatter_valid_schema(sample_report: ScanReport) -> None:
    """Verify JsonReportFormatter emits machine-readable JSON matching schema structure."""
    formatter = JsonReportFormatter(indent=2)
    rendered = formatter.format_report(sample_report)

    data = json.loads(rendered)
    assert data["version"] == "0.3.0"
    assert data["scan_target"] == "/workspace"
    assert data["summary"]["total_files_scanned"] == 5
    assert data["summary"]["true_positive_count"] == 2
    assert data["summary"]["exit_code"] == 1
    assert len(data["findings"]) == 2

    # Check finding fields
    f1 = data["findings"][0]
    assert f1["is_secret"] is True
    assert f1["confidence"] == 0.95
    assert f1["model_used"] == "local_deterministic"
    assert f1["candidate"]["rule_id"] == "SG-AWS-001"
    assert f1["candidate"]["literal_masked"] == "AKI...****"


def test_sarif_formatter_v210_compliance(sample_report: ScanReport) -> None:
    """Verify SarifReportFormatter produces compliant SARIF v2.1.0 document."""
    formatter = SarifReportFormatter(indent=2)
    rendered = formatter.format_report(sample_report)

    sarif = json.loads(rendered)
    assert sarif["$schema"] == SARIF_SCHEMA_V210
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "SecretGuard"
    assert run["tool"]["driver"]["semanticVersion"] == "0.3.0"

    # Rules
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 2
    rule_ids = {r["id"] for r in rules}
    assert "SG-AWS-001" in rule_ids
    assert "SG-OAI-001" in rule_ids

    # Results
    results = run["results"]
    assert len(results) == 2
    res1 = results[0]
    assert res1["ruleId"] == "SG-AWS-001"
    assert res1["level"] == "error"
    assert res1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/aws.py"
    assert res1["locations"][0]["physicalLocation"]["region"]["startLine"] == 14
