"""Interfaces and abstract protocols defining core contracts for SecretGuard."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any, Optional

from secretguard.core.models import (
    DiffLine,
    ModelProfile,
    ScanContext,
    ScanReport,
    SecretCandidate,
)


class IConfigProvider(ABC):
    """Interface for loading, validating, and retrieving runtime configurations."""

    @abstractmethod
    def get_config(self) -> Any:
        """Retrieve current cached configuration."""
        raise NotImplementedError("get_config must be implemented by concrete provider")

    @abstractmethod
    def load_config(self, custom_path: Optional[str] = None) -> Any:
        """Load and return configuration from hierarchy or custom file path."""
        raise NotImplementedError("load_config must be implemented by concrete provider")


class IDiffIngester(ABC):
    """Interface for streaming unified diffs and local repository files."""

    @abstractmethod
    def stream_diff_lines(self, context: ScanContext) -> Iterator[DiffLine]:
        """Stream diff lines one at a time for linear memory efficiency."""
        raise NotImplementedError("stream_diff_lines must be implemented by concrete ingester")


class IExtractionRule(ABC):
    """Interface for pattern-matching secret extraction rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier of the rule."""
        raise NotImplementedError("rule_id must be provided")

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this rule detects."""
        raise NotImplementedError("description must be provided")

    @abstractmethod
    def evaluate(
        self,
        line: str,
        file_path: str = "",
        line_number: int = 1,
    ) -> list[SecretCandidate]:
        """Evaluate a code line and extract matching secret candidates."""
        raise NotImplementedError("evaluate must be implemented by concrete rule")


class IEntropyCalculator(ABC):
    """Interface for calculating Shannon entropy and checking entropy thresholds."""

    @abstractmethod
    def calculate(self, text: str) -> float:
        """Calculate Shannon entropy for the supplied input string."""
        raise NotImplementedError("calculate must be implemented by concrete calculator")

    @abstractmethod
    def is_high_entropy(self, text: str, threshold: float = 4.2, min_length: int = 8) -> bool:
        """Determine if text exceeds the entropy threshold and minimum length."""
        raise NotImplementedError("is_high_entropy must be implemented by concrete calculator")


class ICandidateFilter(ABC):
    """Interface for heuristic and placeholder candidate pre-filtering."""

    @abstractmethod
    def should_filter(self, candidate: SecretCandidate) -> tuple[bool, Optional[str]]:
        """Return (True, reason) if candidate is a placeholder/false-positive, otherwise (False, None)."""
        raise NotImplementedError("should_filter must be implemented by concrete filter")

    @abstractmethod
    def filter_candidate(self, candidate: SecretCandidate) -> SecretCandidate:
        """Apply filtering criteria and return candidate with updated filter status."""
        raise NotImplementedError("filter_candidate must be implemented by concrete filter")


class IRoutingPolicy(ABC):
    """Contract for determining whether to resolve a candidate locally or route to an LLM profile."""

    @abstractmethod
    def evaluate_route(
        self,
        candidate: SecretCandidate,
        config: Optional[Any] = None,
    ) -> Optional[ModelProfile]:
        """Evaluate candidate ambiguity and return target ModelProfile, or None for local resolution."""
        raise NotImplementedError("evaluate_route must be implemented by concrete policy")


class IKeyPoolManager(ABC):
    """Contract for rotating, tracking cooldowns, and managing lifecycle states of API keys."""

    @abstractmethod
    def get_active_key(self, provider: str) -> str:
        """Obtain an active, non-throttled API key for the requested provider."""
        raise NotImplementedError("get_active_key must be implemented by concrete key manager")

    @abstractmethod
    def mark_throttled(self, provider: str, key: str, retry_after: float = 60.0) -> None:
        """Transition key to THROTTLED state with backoff cooldown."""
        raise NotImplementedError("mark_throttled must be implemented by concrete key manager")

    @abstractmethod
    def mark_exhausted(self, provider: str, key: str) -> None:
        """Mark key permanently EXHAUSTED for the lifetime of current session."""
        raise NotImplementedError("mark_exhausted must be implemented by concrete key manager")


class ILLMProviderClient(ABC):
    """Contract for issuing privacy-isolated verification requests to external LLM providers."""

    @abstractmethod
    def dispatch_verification(
        self,
        context_snippet: str,
        candidate_value: str,
        profile: ModelProfile,
        api_key: str,
    ) -> dict[str, Any]:
        """Send candidate and bounded snippet to LLM provider and return parsed JSON payload."""
        raise NotImplementedError("dispatch_verification must be implemented by concrete client")


class IReportFormatter(ABC):
    """Interface for rendering scan reports into target serialization formats."""

    @abstractmethod
    def format_report(self, report: ScanReport) -> str:
        """Render ScanReport object into formatted string output."""
        raise NotImplementedError("format_report must be implemented by concrete formatter")


class IScanOrchestrator(ABC):
    """Interface for end-to-end scan pipeline orchestration."""

    @abstractmethod
    def run_scan(self, context: ScanContext) -> ScanReport:
        """Execute full scan lifecycle across ingestion, extraction, verification, and reporting."""
        raise NotImplementedError("run_scan must be implemented by concrete orchestrator")
