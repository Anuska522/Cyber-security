"""Hierarchical configuration loader and validator for SecretGuard."""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from typing import Any, Optional

import yaml

from secretguard.config.exceptions import ConfigError, InsecureConfigPermissionsError
from secretguard.config.models import SecretGuardConfig
from secretguard.core.interfaces import IConfigProvider

logger = logging.getLogger("secretguard.config")


class ConfigManager(IConfigProvider):
    """Manages hierarchical configuration loading, validation, and environment overrides."""

    def __init__(
        self,
        base_dir: Optional[Path] = None,
        strict_permissions_default: bool = False,
    ) -> None:
        self.base_dir = base_dir or Path.cwd()
        self.strict_permissions_default = strict_permissions_default
        self._current_config: Optional[SecretGuardConfig] = None

    def get_config(self) -> SecretGuardConfig:
        """Retrieve current configuration, loading default hierarchy if not yet loaded."""
        if self._current_config is None:
            self._current_config = self.load_config()
        return self._current_config

    def verify_file_permissions(self, file_path: Path, strict_mode: bool) -> None:
        """Check POSIX file permissions to ensure config is not readable/writable by group/others."""
        if os.name == "nt":
            return

        try:
            file_stat = file_path.stat()
        except OSError as err:
            raise ConfigError(f"Unable to read permissions for config file: {file_path}") from err

        file_mode = stat.S_IMODE(file_stat.st_mode)
        # Check if group or others have read, write, or execute bits set (0o077)
        if (file_mode & 0o077) != 0:
            warning_msg = (
                f"Insecure permissions {oct(file_mode)} detected on config file: {file_path}. "
                "Configuration files must adhere to 0600 mode (readable/writable only by owner)."
            )
            logger.warning(warning_msg)
            if strict_mode:
                raise InsecureConfigPermissionsError(warning_msg)

    def load_yaml_file(self, file_path: Path, strict_mode: bool) -> dict[str, Any]:
        """Safely verify permissions and parse a YAML file."""
        self.verify_file_permissions(file_path, strict_mode)
        try:
            with file_path.open("r", encoding="utf-8") as handle:
                parsed = yaml.safe_load(handle)
                if not isinstance(parsed, dict):
                    return {}
                return parsed
        except yaml.YAMLError as err:
            raise ConfigError(f"Failed to parse YAML file at {file_path}: {err}") from err
        except OSError as err:
            raise ConfigError(f"Failed to open config file at {file_path}: {err}") from err

    def load_config(self, custom_path: Optional[str] = None) -> SecretGuardConfig:
        """Load hierarchical configuration combining system, local, and environment overrides."""
        env_strict = os.environ.get("SECRETGUARD_STRICT_PERMISSIONS", "").lower() in {
            "1",
            "true",
            "yes",
        }
        strict_mode = self.strict_permissions_default or env_strict

        merged_data: dict[str, Any] = {
            "entropy_threshold": 4.2,
            "min_candidate_length": 8,
            "rules_path": None,
            "strict_permissions": strict_mode,
            "enabled_rules": [],
            "ignore_patterns": [],
            "custom_placeholders": [],
            "max_context_window": 200,
        }

        # 1. User Global Config (~/.config/secretguard/config.yaml)
        global_path = Path.home() / ".config" / "secretguard" / "config.yaml"
        if global_path.is_file():
            global_data = self.load_yaml_file(global_path, strict_mode)
            merged_data.update(global_data)

        # 2. Local Workspace Config (./secretguard.yaml or ./.secretguard.yaml)
        local_candidates = [
            self.base_dir / "secretguard.yaml",
            self.base_dir / ".secretguard.yaml",
        ]
        for candidate_path in local_candidates:
            if candidate_path.is_file():
                local_data = self.load_yaml_file(candidate_path, strict_mode)
                merged_data.update(local_data)
                break

        # 3. Explicit Custom Path Override
        if custom_path is not None:
            explicit_path = Path(custom_path).expanduser().resolve()
            if not explicit_path.is_file():
                raise ConfigError(f"Explicit configuration file not found: {custom_path}")
            explicit_data = self.load_yaml_file(explicit_path, strict_mode)
            merged_data.update(explicit_data)

        # 4. Environment Variable Overrides
        if "SECRETGUARD_ENTROPY_THRESHOLD" in os.environ:
            try:
                merged_data["entropy_threshold"] = float(os.environ["SECRETGUARD_ENTROPY_THRESHOLD"])
            except ValueError as err:
                raise ConfigError(
                    f"Invalid float in SECRETGUARD_ENTROPY_THRESHOLD: {os.environ['SECRETGUARD_ENTROPY_THRESHOLD']}"
                ) from err

        if "SECRETGUARD_MIN_CANDIDATE_LENGTH" in os.environ:
            try:
                merged_data["min_candidate_length"] = int(os.environ["SECRETGUARD_MIN_CANDIDATE_LENGTH"])
            except ValueError as err:
                raise ConfigError(
                    f"Invalid integer in SECRETGUARD_MIN_CANDIDATE_LENGTH: {os.environ['SECRETGUARD_MIN_CANDIDATE_LENGTH']}"
                ) from err

        if "SECRETGUARD_RULES_PATH" in os.environ:
            merged_data["rules_path"] = os.environ["SECRETGUARD_RULES_PATH"]

        if "SECRETGUARD_STRICT_PERMISSIONS" in os.environ:
            merged_data["strict_permissions"] = env_strict

        if "SECRETGUARD_MAX_CONTEXT_WINDOW" in os.environ:
            try:
                merged_data["max_context_window"] = int(os.environ["SECRETGUARD_MAX_CONTEXT_WINDOW"])
            except ValueError as err:
                raise ConfigError(
                    f"Invalid integer in SECRETGUARD_MAX_CONTEXT_WINDOW: {os.environ['SECRETGUARD_MAX_CONTEXT_WINDOW']}"
                ) from err

        if "SECRETGUARD_ROUTING_PROFILE" in os.environ:
            merged_data["routing_profile"] = os.environ["SECRETGUARD_ROUTING_PROFILE"]

        if "SECRETGUARD_PROFILE_OVERRIDE" in os.environ:
            merged_data["profile_override"] = os.environ["SECRETGUARD_PROFILE_OVERRIDE"]

        config = SecretGuardConfig(
            entropy_threshold=float(merged_data.get("entropy_threshold", 4.2)),
            min_candidate_length=int(merged_data.get("min_candidate_length", 8)),
            rules_path=merged_data.get("rules_path"),
            strict_permissions=bool(merged_data.get("strict_permissions", False)),
            enabled_rules=list(merged_data.get("enabled_rules", [])),
            ignore_patterns=list(merged_data.get("ignore_patterns", [])),
            custom_placeholders=list(merged_data.get("custom_placeholders", [])),
            max_context_window=int(merged_data.get("max_context_window", 200)),
            routing_profile=str(merged_data.get("routing_profile", "Auto")),
            profile_override=merged_data.get("profile_override"),
            provider_keys=dict(merged_data.get("provider_keys", {})),
            auto_quarantine=bool(merged_data.get("auto_quarantine", False)),
        )

        self._current_config = config
        return config
