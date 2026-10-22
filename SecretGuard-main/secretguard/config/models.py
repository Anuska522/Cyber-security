"""Configuration data models for SecretGuard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SecretGuardConfig:
    """Runtime configuration model for SecretGuard scanner."""

    entropy_threshold: float = 4.2
    min_candidate_length: int = 8
    rules_path: Optional[str] = None
    strict_permissions: bool = False
    enabled_rules: list[str] = field(default_factory=list)
    ignore_patterns: list[str] = field(default_factory=list)
    custom_placeholders: list[str] = field(default_factory=list)
    max_context_window: int = 200
    routing_profile: str = "Auto"
    profile_override: Optional[str] = None
    provider_keys: dict[str, list[str]] = field(default_factory=dict)
    auto_quarantine: bool = False

