"""Domain models for SecretGuard core pipeline."""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Optional


def mask_credential(value: str) -> str:
    """Mask sensitive credential literals for safe representation in logs and str/repr."""
    if not value:
        return ""
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:3]}...****"


@dataclass(frozen=True)
class SecretCandidate:
    """Represents an extracted secret candidate identified during analysis."""

    literal_value: str
    file_path: str
    line_number: int
    surrounding_context: str
    rule_id: str
    entropy_score: float
    heuristic_tags: list[str] = field(default_factory=list)
    is_filtered: bool = False
    filter_reason: Optional[str] = None

    def __post_init__(self) -> None:
        """Enforce strict invariant constraints on candidate fields."""
        if len(self.surrounding_context) > 200:
            truncated = self.surrounding_context[:200]
            object.__setattr__(self, "surrounding_context", truncated)

    def with_filter(self, is_filtered: bool, reason: Optional[str] = None) -> SecretCandidate:
        """Return a copy of the candidate with updated filtering state."""
        return replace(self, is_filtered=is_filtered, filter_reason=reason)

    @property
    def masked_literal(self) -> str:
        """Return masked representation of the credential literal."""
        return mask_credential(self.literal_value)

    @property
    def context_window(self) -> str:
        """Alias for surrounding_context."""
        return self.surrounding_context



@dataclass(frozen=True)
class ScanContext:
    """Runtime context passed into scanning and ingestion routines."""

    target_path: str
    is_pre_commit: bool = False
    diff_mode: bool = False
    ignore_patterns: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DiffLine:
    """A single line emitted by diff or file ingestion."""

    file_path: str
    line_number: int
    content: str
    is_addition: bool


@dataclass(frozen=True)
class ModelProfile:
    """Specification of an LLM profile for targeted verification routing."""

    name: str
    provider: str
    model_id: str
    max_tokens: int = 250
    temperature: float = 0.0
    timeout_seconds: float = 2.0


class KeyStatus(str, Enum):
    """Lifecycle states of an API key within a provider pool."""

    ACTIVE = "ACTIVE"
    THROTTLED = "THROTTLED"
    EXHAUSTED = "EXHAUSTED"


@dataclass
class ManagedKey:
    """An API key with active health tracking, rate limit cooldowns, and automatic masking."""

    key_value: str
    provider: str
    status: KeyStatus = KeyStatus.ACTIVE
    cooldown_until: Optional[float] = None
    consecutive_failures: int = 0

    def masked_key(self) -> str:
        """Return masked representation of the underlying secret key value."""
        return mask_credential(self.key_value)

    def is_available(self, current_time: Optional[float] = None) -> bool:
        """Check if key is ready for active dispatch, recovering expired cooldowns."""
        now = current_time if current_time is not None else time.time()
        if self.status == KeyStatus.EXHAUSTED:
            return False
        if self.status == KeyStatus.THROTTLED:
            if self.cooldown_until is not None and now >= self.cooldown_until:
                self.status = KeyStatus.ACTIVE
                self.cooldown_until = None
                return True
            return False
        return self.status == KeyStatus.ACTIVE

    def mark_active(self) -> None:
        """Reset failure counter and set state to ACTIVE."""
        self.status = KeyStatus.ACTIVE
        self.cooldown_until = None
        self.consecutive_failures = 0

    def mark_throttled(self, cooldown_seconds: float = 60.0, current_time: Optional[float] = None) -> None:
        """Transition key into THROTTLED state with backoff cooldown."""
        now = current_time if current_time is not None else time.time()
        self.status = KeyStatus.THROTTLED
        self.cooldown_until = now + max(1.0, cooldown_seconds)
        self.consecutive_failures += 1

    def mark_exhausted(self) -> None:
        """Transition key permanently into EXHAUSTED state for current session."""
        self.status = KeyStatus.EXHAUSTED
        self.cooldown_until = None
        self.consecutive_failures += 1

    def record_failure(self) -> None:
        """Increment consecutive failure counter."""
        self.consecutive_failures += 1

    def __repr__(self) -> str:
        return (
            f"ManagedKey(provider='{self.provider}', key_value='{self.masked_key()}', "
            f"status={self.status.value}, cooldown_until={self.cooldown_until}, "
            f"consecutive_failures={self.consecutive_failures})"
        )

    def __str__(self) -> str:
        return self.__repr__()


@dataclass(frozen=True)
class VerificationResult:
    """Evaluation result emitted after deterministic or LLM-assisted verification."""

    candidate: SecretCandidate
    is_secret: bool
    confidence: float
    explanation: str
    remediation: str
    model_used: str
    latency_ms: float
    resolved_locally: bool


@dataclass(frozen=True)
class ScanSummary:
    """Aggregated numerical execution metrics for a completed scan invocation."""

    total_files_scanned: int
    total_lines_scanned: int
    candidates_extracted: int
    candidates_filtered: int
    ai_verified_count: int
    true_positive_count: int
    execution_latency_ms: float
    exit_code: int


@dataclass(frozen=True)
class ScanReport:
    """Complete structured output containing findings, execution metrics, and context."""

    findings: list[VerificationResult]
    summary: ScanSummary
    scan_target: str
    timestamp: str
    config_used: dict[str, Any] = field(default_factory=dict)
