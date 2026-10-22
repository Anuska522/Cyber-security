"""Ambiguity scoring engine for calculating candidate risk and routing complexity."""

from __future__ import annotations

import re
from typing import Final

from secretguard.core.models import SecretCandidate

# Structured vendor rule prefixes that possess strict, unambiguous signatures
STRUCTURED_RULE_IDS: Final[set[str]] = {
    "SG-AWS-001",
    "SG-GH-001",
    "SG-GH-002",
    "SG-OAI-001",
    "SG-OAI-002",
    "SG-GCP-001",
    "SG-SLACK-001",
    "SG-JWT-001",
    "SG-KEY-001",
    "SG-AZURE-001",
    "SG-STRIPE-001",
    "SG-TWILIO-001",
    "SG-FB-001",
    "SG-DISCORD-001",
    "SG-DB-001",
}

EXPLICIT_SENSITIVE_KEYWORDS: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "client_secret",
    "access_token",
    "auth",
    "auth_token",
    "private_key",
)

TEST_OR_MOCK_INDICATORS: Final[tuple[str, ...]] = (
    "test",
    "tests",
    "mock",
    "mocks",
    "fixture",
    "fixtures",
    "spec",
    "conftest",
    "dummy",
    "sample",
    "example",
    "stub",
    "fake",
)


class AmbiguityScorer:
    """Calculates mathematical ambiguity score S_amb(c_i) = w1*U_regex + w2*H_norm + w3*A_ctx."""

    def __init__(
        self,
        weight_regex: float = 0.4,
        weight_entropy: float = 0.3,
        weight_context: float = 0.3,
        min_entropy: float = 3.5,
        max_entropy: float = 6.0,
    ) -> None:
        self.w1 = weight_regex
        self.w2 = weight_entropy
        self.w3 = weight_context
        self.min_entropy = min_entropy
        self.max_entropy = max_entropy

    def calculate_regex_uncertainty(self, candidate: SecretCandidate) -> float:
        """Return 0.0 for strict structured vendor signatures, 1.0 for heuristic or generic extraction."""
        if candidate.rule_id in STRUCTURED_RULE_IDS:
            return 0.0
        return 1.0

    def calculate_normalized_entropy(self, candidate: SecretCandidate) -> float:
        """Normalize candidate Shannon entropy to [0.0, 1.0] over [min_entropy, max_entropy]."""
        entropy = candidate.entropy_score
        if entropy <= self.min_entropy:
            return 0.0
        if entropy >= self.max_entropy:
            return 1.0
        normalized = (entropy - self.min_entropy) / (self.max_entropy - self.min_entropy)
        return max(0.0, min(1.0, normalized))

    def calculate_context_ambiguity(self, candidate: SecretCandidate) -> float:
        """Determine context ambiguity: 1.0 in test/mock environments, 0.2 for explicit keywords, 0.8 for generic."""
        file_path_lower = candidate.file_path.lower()
        context_lower = candidate.surrounding_context.lower()

        # 1. Highest ambiguity (1.0): embedded in tests, mocks, fixtures, or samples
        if any(indicator in file_path_lower for indicator in TEST_OR_MOCK_INDICATORS):
            return 1.0
        if any(indicator in context_lower for indicator in ("mock_", "fixture", "faketoken", "dummy_")):
            return 1.0

        # 2. Lowest ambiguity (0.2): assignment matches explicit sensitive keywords
        if any(kw in context_lower for kw in EXPLICIT_SENSITIVE_KEYWORDS):
            return 0.2

        # 3. Intermediate ambiguity (0.8): generic identifier or raw token literal
        return 0.8

    def calculate_ambiguity_score(self, candidate: SecretCandidate) -> float:
        """Compute aggregate weighted ambiguity score clamped between 0.0 and 1.0."""
        u_regex = self.calculate_regex_uncertainty(candidate)
        h_norm = self.calculate_normalized_entropy(candidate)
        a_ctx = self.calculate_context_ambiguity(candidate)

        raw_score = (self.w1 * u_regex) + (self.w2 * h_norm) + (self.w3 * a_ctx)
        clamped_score = max(0.0, min(1.0, round(raw_score, 4)))
        return clamped_score
