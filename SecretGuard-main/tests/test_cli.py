"""Tests for unified Click CLI suite: scan, install-hook, and init onboarding commands."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from secretguard.cli import main


@pytest.fixture
def runner() -> CliRunner:
    """Fixture providing a Click CliRunner instance."""
    return CliRunner()


@pytest.fixture
def clean_repo_dir(tmp_path: Path) -> Path:
    """Fixture creating a temporary repository directory with no secrets."""
    repo = tmp_path / "clean_repo"
    repo.mkdir()
    code_file = repo / "main.py"
    code_file.write_text("def hello():\n    return 'Hello, World!'\n", encoding="utf-8")
    return repo


@pytest.fixture
def dirty_repo_dir(tmp_path: Path) -> Path:
    """Fixture creating a temporary repository directory containing an exposed secret."""
    repo = tmp_path / "dirty_repo"
    repo.mkdir()
    code_file = repo / "config.py"
    code_file.write_text('AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"\n', encoding="utf-8")
    return repo


def test_cli_scan_clean_repository(runner: CliRunner, clean_repo_dir: Path) -> None:
    """Verify secretguard scan exits with code 0 on a clean repository."""
    result = runner.invoke(main, ["scan", str(clean_repo_dir)])
    assert result.exit_code == 0
    assert "SCAN CLEAN" in result.output


def test_cli_scan_exposed_secrets(runner: CliRunner, dirty_repo_dir: Path) -> None:
    """Verify secretguard scan exits with code 1 when hardcoded secrets are detected."""
    result = runner.invoke(main, ["scan", str(dirty_repo_dir)])
    assert result.exit_code == 1
    assert "DETECTED 1 POTENTIAL SECRET(S)" in result.output
    assert "SG-AWS-001" in result.output
    assert "AKIA1234567890ABCDEF" not in result.output  # Raw secret must be masked


def test_cli_scan_format_json(runner: CliRunner, dirty_repo_dir: Path) -> None:
    """Verify secretguard scan --format json emits machine-readable JSON."""
    result = runner.invoke(main, ["scan", str(dirty_repo_dir), "--format", "json"])
    assert result.exit_code == 1

    data = json.loads(result.stdout)
    assert data["version"] == "0.3.0"
    assert data["summary"]["true_positive_count"] == 1
    assert data["summary"]["exit_code"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["candidate"]["rule_id"] == "SG-AWS-001"


def test_cli_scan_format_sarif(runner: CliRunner, dirty_repo_dir: Path) -> None:
    """Verify secretguard scan --format sarif produces valid SARIF v2.1.0 document."""
    result = runner.invoke(main, ["scan", str(dirty_repo_dir), "--format", "sarif"])
    assert result.exit_code == 1

    sarif = json.loads(result.stdout)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "SecretGuard"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "SG-AWS-001"


def test_cli_scan_output_file(runner: CliRunner, dirty_repo_dir: Path, tmp_path: Path) -> None:
    """Verify secretguard scan --output writes the formatted payload to a file."""
    report_file = tmp_path / "out_report.json"
    result = runner.invoke(
        main,
        ["scan", str(dirty_repo_dir), "--format", "json", "--output", str(report_file)],
    )
    assert result.exit_code == 1
    assert report_file.is_file()

    file_data = json.loads(report_file.read_text(encoding="utf-8"))
    assert file_data["summary"]["true_positive_count"] == 1


def test_cli_scan_invalid_path_exits_code_2(runner: CliRunner) -> None:
    """Verify secretguard scan exits with code 2 on nonexistent target paths."""
    result = runner.invoke(main, ["scan", "/nonexistent/phantom/directory/path/999"])
    assert result.exit_code == 2
    assert "Error: Target path does not exist" in result.output


def test_cli_install_hook_success(runner: CliRunner, tmp_path: Path) -> None:
    """Verify secretguard install-hook creates an executable pre-commit script in .git/hooks/."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    result = runner.invoke(main, ["install-hook", "--repo", str(tmp_path)])
    assert result.exit_code == 0
    assert "Successfully installed SecretGuard pre-commit hook" in result.output

    hook_file = git_dir / "hooks" / "pre-commit"
    assert hook_file.is_file()

    content = hook_file.read_text(encoding="utf-8")
    assert "secretguard scan --pre-commit" in content

    # Verify POSIX executable permission
    if os.name != "nt":
        file_mode = stat.S_IMODE(hook_file.stat().st_mode)
        assert bool(file_mode & stat.S_IXUSR) is True


def test_cli_install_hook_non_git_repo_exits_2(runner: CliRunner, tmp_path: Path) -> None:
    """Verify secretguard install-hook exits with code 2 when target directory is not a Git repo."""
    empty_dir = tmp_path / "not_git"
    empty_dir.mkdir()

    result = runner.invoke(main, ["install-hook", "--repo", str(empty_dir)])
    assert result.exit_code == 2
    assert "Error: No Git repository found" in result.output


def test_cli_init_command_creates_secure_config(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify secretguard init wizard writes configuration adhering strictly to 0600 POSIX permissions."""
    fake_home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    user_inputs = (
        "gsk_test_api_key_123\n"  # Groq key
        "sk-or-test_openrouter_key\n"  # OpenRouter key
        "\n"  # Gemini key (skip)
        "\n"  # Together key (skip)
        "A\n"  # Profile
    )

    result = runner.invoke(main, ["init"], input=user_inputs)
    assert result.exit_code == 0
    assert "Configuration saved to" in result.output

    config_file = fake_home / ".config" / "secretguard" / "config.yaml"
    assert config_file.is_file()

    # Verify config structure
    parsed = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    assert parsed["routing_profile"] == "A"
    assert parsed["provider_keys"]["groq"] == ["gsk_test_api_key_123"]
    assert parsed["provider_keys"]["openrouter"] == ["sk-or-test_openrouter_key"]

    # Verify POSIX 0600 mode permissions
    if os.name != "nt":
        file_mode = stat.S_IMODE(config_file.stat().st_mode)
        assert (file_mode & 0o077) == 0  # No group or other permissions


def test_cli_scan_format_tui_clean_and_dirty(runner: CliRunner, clean_repo_dir: Path, dirty_repo_dir: Path) -> None:
    """Verify secretguard scan --format tui outputs cyber-minimalist diamond notice on clean and box on dirty."""
    clean_res = runner.invoke(main, ["scan", str(clean_repo_dir), "--format", "tui"])
    assert clean_res.exit_code == 0
    assert "◈ SecretGuard :: Repository verified clean" in clean_res.output

    dirty_res = runner.invoke(main, ["scan", str(dirty_repo_dir), "--format", "tui"])
    assert dirty_res.exit_code == 1
    assert "SecretGuard Interception Report" in dirty_res.output
    assert "Finding #1" in dirty_res.output


def test_cli_root_invocation_shows_banner_and_statusline(runner: CliRunner) -> None:
    """Verify executing secretguard without arguments outputs banner and statusline."""
    result = runner.invoke(main, [])
    assert result.exit_code == 0
    assert "Autonomous Secret Interception & Quarantine Engine" in result.output
    assert "::" in result.output


def test_cli_autopilot_command_flow(runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify secretguard autopilot executes the 3-question flow."""
    fake_home = tmp_path / "autopilot_home"
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    repo_dir = tmp_path / "app"
    repo_dir.mkdir()
    (repo_dir / ".git" / "hooks").mkdir(parents=True)

    result = runner.invoke(main, ["autopilot", "--repo", str(repo_dir)], input="\n\n\n")
    assert result.exit_code == 0
    assert "Autopilot setup complete" in result.output

