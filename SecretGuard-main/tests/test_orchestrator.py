"""Unit and component tests for end-to-end ScanOrchestrator."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from secretguard.config.manager import ConfigManager
from secretguard.config.models import SecretGuardConfig
from secretguard.core.interfaces import IDiffIngester
from secretguard.core.models import DiffLine, ScanContext, SecretCandidate, VerificationResult
from secretguard.extract.engine import DeterministicExtractionEngine
from secretguard.orchestrator import ScanOrchestrator


class MockDiffIngester(IDiffIngester):
    """Mock IDiffIngester for isolating orchestrator tests."""

    def __init__(self, diff_lines: list[DiffLine]) -> None:
        self.diff_lines = diff_lines

    def stream_diff_lines(self, context: ScanContext) -> Iterator[DiffLine]:
        """Yield preconfigured diff lines."""
        for line in self.diff_lines:
            yield line


def test_orchestrator_initialization_defaults() -> None:
    """Verify ScanOrchestrator initializes with production defaults."""
    orchestrator = ScanOrchestrator()
    assert orchestrator.config_provider is not None
    assert orchestrator.git_ingester is not None
    assert orchestrator.fs_ingester is not None
    assert orchestrator.extraction_engine is not None


def test_orchestrator_clean_fs_scan(tmp_path: Path) -> None:
    """Verify ScanOrchestrator returns clean summary and exit code 0 on clean filesystem."""
    clean_dir = tmp_path / "clean_proj"
    clean_dir.mkdir()
    (clean_dir / "app.py").write_text("print('clean application')\n", encoding="utf-8")

    orchestrator = ScanOrchestrator()
    context = ScanContext(target_path=str(clean_dir), is_pre_commit=False, diff_mode=False)

    report = orchestrator.run_scan(context)

    assert report.summary.exit_code == 0
    assert report.summary.true_positive_count == 0
    assert report.summary.total_lines_scanned >= 1
    assert report.summary.total_files_scanned == 1
    assert report.scan_target == str(clean_dir)
    assert len(report.findings) == 0


def test_orchestrator_dirty_fs_scan(tmp_path: Path) -> None:
    """Verify ScanOrchestrator flags hardcoded credentials and returns exit code 1."""
    dirty_dir = tmp_path / "dirty_proj"
    dirty_dir.mkdir()
    (dirty_dir / "creds.py").write_text(
        'AWS_KEY = "AKIA1234567890ABCDEF"\n',
        encoding="utf-8",
    )

    orchestrator = ScanOrchestrator()
    context = ScanContext(target_path=str(dirty_dir), is_pre_commit=False, diff_mode=False)

    report = orchestrator.run_scan(context)

    assert report.summary.exit_code == 1
    assert report.summary.true_positive_count >= 1
    assert report.summary.candidates_extracted >= 1

    active_findings = [f for f in report.findings if f.is_secret]
    assert len(active_findings) >= 1
    assert active_findings[0].candidate.rule_id == "SG-AWS-001"


def test_orchestrator_git_diff_routing_and_additions() -> None:
    """Verify ScanOrchestrator uses git_ingester when is_pre_commit or diff_mode is enabled."""
    staged_lines = [
        DiffLine(
            file_path="src/config.py",
            line_number=10,
            content='SLACK_TOKEN = "' + "xo" + 'xb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"',
            is_addition=True,
        ),
        DiffLine(
            file_path="src/main.py",
            line_number=5,
            content="logger.info('Started server')",
            is_addition=True,
        ),
    ]

    mock_git = MockDiffIngester(staged_lines)
    orchestrator = ScanOrchestrator(git_ingester=mock_git)

    context = ScanContext(target_path=".", is_pre_commit=True, diff_mode=True)
    report = orchestrator.run_scan(context)

    assert report.summary.exit_code == 1
    assert report.summary.total_lines_scanned == 2
    assert report.summary.total_files_scanned == 2
    assert report.summary.true_positive_count == 1
    assert report.findings[0].candidate.rule_id == "SG-SLACK-001"


def test_orchestrator_filtered_placeholder_accounting() -> None:
    """Verify placeholders are filtered out, counted in candidates_filtered, and exit code is 0."""
    staged_lines = [
        DiffLine(
            file_path="src/settings.py",
            line_number=1,
            content='API_KEY = "YOUR_API_KEY_HERE"',
            is_addition=True,
        ),
    ]

    mock_git = MockDiffIngester(staged_lines)
    orchestrator = ScanOrchestrator(git_ingester=mock_git)

    context = ScanContext(target_path=".", is_pre_commit=True, diff_mode=True)
    report = orchestrator.run_scan(context)

    assert report.summary.exit_code == 0
    assert report.summary.candidates_extracted == 1
    assert report.summary.candidates_filtered == 1
    assert report.summary.true_positive_count == 0


def test_orchestrator_config_injection(tmp_path: Path) -> None:
    """Verify custom SecretGuardConfig parameters are propagated into report metadata."""
    custom_cfg = SecretGuardConfig(
        entropy_threshold=5.2,
        min_candidate_length=12,
        routing_profile="A",
    )

    class CustomConfigManager:
        def get_config(self) -> SecretGuardConfig:
            return custom_cfg

    clean_dir = tmp_path / "cfg_test"
    clean_dir.mkdir()
    (clean_dir / "index.js").write_text("console.log('init');\n", encoding="utf-8")

    orchestrator = ScanOrchestrator(config_provider=CustomConfigManager())
    context = ScanContext(target_path=str(clean_dir))

    report = orchestrator.run_scan(context)

    assert report.config_used["entropy_threshold"] == 5.2
    assert report.config_used["min_candidate_length"] == 12
    assert report.config_used["routing_profile"] == "A"
