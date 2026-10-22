"""Tests for configuration subsystem: hierarchical loading, permissions, and environment overrides."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from secretguard.config.exceptions import ConfigError, InsecureConfigPermissionsError
from secretguard.config.manager import ConfigManager
from secretguard.config.models import SecretGuardConfig


@pytest.fixture
def temp_config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Fixture providing an isolated temporary directory for config tests."""
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    return tmp_path


def test_default_config_loading(temp_config_dir: Path) -> None:
    """Verify default configuration values when no files or environment variables are provided."""
    manager = ConfigManager(base_dir=temp_config_dir)
    config = manager.get_config()

    assert isinstance(config, SecretGuardConfig)
    assert config.entropy_threshold == 4.2
    assert config.min_candidate_length == 8
    assert config.rules_path is None
    assert config.strict_permissions is False
    assert config.enabled_rules == []
    assert config.ignore_patterns == []
    assert config.custom_placeholders == []
    assert config.max_context_window == 200


def test_hierarchical_yaml_loading(temp_config_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that local workspace config overrides global home directory config."""
    fake_home = temp_config_dir / "home"
    fake_global_config_dir = fake_home / ".config" / "secretguard"
    fake_global_config_dir.mkdir(parents=True)
    global_file = fake_global_config_dir / "config.yaml"

    global_data = {
        "entropy_threshold": 3.8,
        "min_candidate_length": 10,
        "ignore_patterns": ["*.log"],
    }
    with global_file.open("w", encoding="utf-8") as f:
        yaml.safe_dump(global_data, f)
    global_file.chmod(0o600)

    # Local workspace config
    local_workspace = temp_config_dir / "workspace"
    local_workspace.mkdir()
    local_file = local_workspace / "secretguard.yaml"
    local_data = {
        "entropy_threshold": 4.5,
        "custom_placeholders": ["dummy_token"],
    }
    with local_file.open("w", encoding="utf-8") as f:
        yaml.safe_dump(local_data, f)
    local_file.chmod(0o600)

    monkeypatch.setattr(Path, "home", lambda: fake_home)

    manager = ConfigManager(base_dir=local_workspace)
    config = manager.load_config()

    # Local should override global for entropy_threshold
    assert config.entropy_threshold == 4.5
    # Global should supply min_candidate_length
    assert config.min_candidate_length == 10
    # Custom placeholders from local
    assert config.custom_placeholders == ["dummy_token"]
    # Ignore patterns preserved from global
    assert config.ignore_patterns == ["*.log"]


def test_explicit_custom_path_override(temp_config_dir: Path) -> None:
    """Verify that specifying an explicit config file path overrides all defaults."""
    custom_file = temp_config_dir / "custom_rules.yaml"
    custom_data = {
        "entropy_threshold": 5.0,
        "min_candidate_length": 12,
        "max_context_window": 150,
    }
    with custom_file.open("w", encoding="utf-8") as f:
        yaml.safe_dump(custom_data, f)
    custom_file.chmod(0o600)

    manager = ConfigManager(base_dir=temp_config_dir)
    config = manager.load_config(custom_path=str(custom_file))

    assert config.entropy_threshold == 5.0
    assert config.min_candidate_length == 12
    assert config.max_context_window == 150


def test_nonexistent_explicit_path_raises_error(temp_config_dir: Path) -> None:
    """Verify that pointing to a nonexistent config file raises ConfigError."""
    manager = ConfigManager(base_dir=temp_config_dir)
    missing_path = temp_config_dir / "does_not_exist.yaml"

    with pytest.raises(ConfigError, match="Explicit configuration file not found"):
        manager.load_config(custom_path=str(missing_path))


def test_posix_permissions_0600_enforcement_strict(temp_config_dir: Path) -> None:
    """Verify that insecure POSIX permissions trigger InsecureConfigPermissionsError in strict mode."""
    if os.name == "nt":
        pytest.skip("POSIX file permission checks do not apply to Windows")

    insecure_file = temp_config_dir / "insecure.yaml"
    with insecure_file.open("w", encoding="utf-8") as f:
        yaml.safe_dump({"entropy_threshold": 4.0}, f)

    # Set world-readable permissions (0644)
    insecure_file.chmod(0o644)

    manager = ConfigManager(base_dir=temp_config_dir, strict_permissions_default=True)
    with pytest.raises(InsecureConfigPermissionsError, match="Insecure permissions"):
        manager.load_config(custom_path=str(insecure_file))


def test_posix_permissions_0600_enforcement_lenient(
    temp_config_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify that insecure POSIX permissions log a warning in lenient mode without raising error."""
    if os.name == "nt":
        pytest.skip("POSIX file permission checks do not apply to Windows")

    insecure_file = temp_config_dir / "lenient_insecure.yaml"
    with insecure_file.open("w", encoding="utf-8") as f:
        yaml.safe_dump({"entropy_threshold": 4.1}, f)

    # Set group-writable and world-readable (0664)
    insecure_file.chmod(0o664)

    manager = ConfigManager(base_dir=temp_config_dir, strict_permissions_default=False)
    with caplog.at_level("WARNING"):
        config = manager.load_config(custom_path=str(insecure_file))

    assert config.entropy_threshold == 4.1
    assert "Insecure permissions" in caplog.text


def test_secure_0600_permissions_pass(temp_config_dir: Path) -> None:
    """Verify that files with strict 0600 permissions load cleanly without errors or warnings."""
    if os.name == "nt":
        pytest.skip("POSIX file permission checks do not apply to Windows")

    secure_file = temp_config_dir / "secure.yaml"
    with secure_file.open("w", encoding="utf-8") as f:
        yaml.safe_dump({"entropy_threshold": 4.2}, f)

    secure_file.chmod(0o600)
    manager = ConfigManager(base_dir=temp_config_dir, strict_permissions_default=True)
    config = manager.load_config(custom_path=str(secure_file))

    assert config.entropy_threshold == 4.2


def test_environment_variable_overrides(
    temp_config_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that environment variables take precedence over all file settings."""
    config_file = temp_config_dir / "secretguard.yaml"
    with config_file.open("w", encoding="utf-8") as f:
        yaml.safe_dump({"entropy_threshold": 3.0, "min_candidate_length": 6}, f)
    config_file.chmod(0o600)

    monkeypatch.setenv("SECRETGUARD_ENTROPY_THRESHOLD", "4.8")
    monkeypatch.setenv("SECRETGUARD_MIN_CANDIDATE_LENGTH", "14")
    monkeypatch.setenv("SECRETGUARD_RULES_PATH", "/custom/rules.json")
    monkeypatch.setenv("SECRETGUARD_STRICT_PERMISSIONS", "true")
    monkeypatch.setenv("SECRETGUARD_MAX_CONTEXT_WINDOW", "180")

    manager = ConfigManager(base_dir=temp_config_dir)
    config = manager.load_config()

    assert config.entropy_threshold == 4.8
    assert config.min_candidate_length == 14
    assert config.rules_path == "/custom/rules.json"
    assert config.strict_permissions is True
    assert config.max_context_window == 180


def test_invalid_environment_variable_types(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that malformed environment variables raise descriptive ConfigError."""
    monkeypatch.setenv("SECRETGUARD_ENTROPY_THRESHOLD", "not-a-float")
    manager = ConfigManager()

    with pytest.raises(ConfigError, match="Invalid float in SECRETGUARD_ENTROPY_THRESHOLD"):
        manager.load_config()
