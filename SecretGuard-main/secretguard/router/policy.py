"""Adaptive routing policy coordinating ambiguity tiers and model profile selection."""

from __future__ import annotations

from typing import Any, Optional

from secretguard.core.interfaces import IRoutingPolicy
from secretguard.core.models import ModelProfile, SecretCandidate
from secretguard.router.scorer import AmbiguityScorer

PROFILE_A = ModelProfile(
    name="Profile A",
    provider="groq",
    model_id="llama-3.1-8b-instant",
    max_tokens=150,
    temperature=0.0,
    timeout_seconds=2.0,
)

PROFILE_B = ModelProfile(
    name="Profile B",
    provider="openrouter",
    model_id="openai/gpt-4o-mini",
    max_tokens=200,
    temperature=0.0,
    timeout_seconds=2.0,
)

PROFILE_C = ModelProfile(
    name="Profile C",
    provider="openrouter",
    model_id="anthropic/claude-3.5-sonnet",
    max_tokens=250,
    temperature=0.0,
    timeout_seconds=2.0,
)


class AdaptiveRoutingPolicy(IRoutingPolicy):
    """Evaluates candidate ambiguity against three routing tiers with profile override support."""

    def __init__(
        self,
        scorer: Optional[AmbiguityScorer] = None,
        profile_a: ModelProfile = PROFILE_A,
        profile_b: ModelProfile = PROFILE_B,
        profile_c: ModelProfile = PROFILE_C,
    ) -> None:
        self.scorer = scorer or AmbiguityScorer()
        self.profile_a = profile_a
        self.profile_b = profile_b
        self.profile_c = profile_c

    def _extract_override(self, config: Optional[Any]) -> Optional[str]:
        """Extract profile override string from dict, config object, or string."""
        if config is None:
            return None
        if isinstance(config, str):
            candidate = config.strip().upper()
            if candidate in {"A", "B", "C", "PROFILE A", "PROFILE B", "PROFILE C"}:
                return candidate.replace("PROFILE ", "")
            return None

        # Check dict
        if isinstance(config, dict):
            for key in ("profile_override", "routing_profile", "profile"):
                val = config.get(key)
                if isinstance(val, str):
                    candidate = val.strip().upper()
                    if candidate in {"A", "B", "C", "PROFILE A", "PROFILE B", "PROFILE C"}:
                        return candidate.replace("PROFILE ", "")
            return None

        # Check object attributes
        for attr in ("profile_override", "routing_profile"):
            val = getattr(config, attr, None)
            if isinstance(val, str):
                candidate = val.strip().upper()
                if candidate in {"A", "B", "C", "PROFILE A", "PROFILE B", "PROFILE C"}:
                    return candidate.replace("PROFILE ", "")

        return None

    def evaluate_route(
        self,
        candidate: SecretCandidate,
        config: Optional[Any] = None,
    ) -> Optional[ModelProfile]:
        """Determine target model profile based on profile overrides and ambiguity score."""
        # 1. Check explicit profile overrides (non-Auto)
        override = self._extract_override(config)
        if override == "A":
            return self.profile_a
        if override == "B":
            return self.profile_b
        if override == "C":
            return self.profile_c

        # 2. Compute dynamic ambiguity score
        score = self.scorer.calculate_ambiguity_score(candidate)

        # Unambiguous Tier (S_amb < 0.2): Local deterministic resolution
        if score < 0.2:
            return None

        # Low-Complexity Ambiguous Tier (0.2 <= S_amb < 0.6): Ultra-fast Model Profile A
        if score < 0.6:
            return self.profile_a

        # High-Complexity Ambiguous Tier (S_amb >= 0.6): High-reasoning Model Profile B
        return self.profile_b
