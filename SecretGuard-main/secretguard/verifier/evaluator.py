"""Contextual AI verifier coordinating ambiguity routing, key rotation, and fault tolerance."""

from __future__ import annotations

import logging
import time
from typing import Any, Optional, Sequence

from secretguard.core.interfaces import (
    IKeyPoolManager,
    ILLMProviderClient,
    IRoutingPolicy,
)
from secretguard.core.models import SecretCandidate, VerificationResult
from secretguard.gateway.dispatcher import ProviderDispatcher
from secretguard.gateway.key_manager import (
    AllKeysExhaustedException,
    GatewayError,
    KeyRotationManager,
)
from secretguard.router.policy import AdaptiveRoutingPolicy

logger = logging.getLogger("secretguard.verifier.evaluator")

FALLBACK_EXPLANATION = "AI verification bypassed due to provider unavailability; flagged via static rules."
FALLBACK_REMEDIATION = "Manually inspect and rotate credential if active."


class ContextualVerifier:
    """Orchestrates privacy-isolated secret verification across deterministic and LLM tiers."""

    def __init__(
        self,
        routing_policy: Optional[IRoutingPolicy] = None,
        key_manager: Optional[IKeyPoolManager] = None,
        provider_client: Optional[ILLMProviderClient] = None,
    ) -> None:
        self.key_manager = key_manager or KeyRotationManager()
        self.routing_policy = routing_policy or AdaptiveRoutingPolicy()
        self.provider_client = provider_client or ProviderDispatcher(key_manager=self.key_manager)

    def _resolve_deterministic(self, candidate: SecretCandidate) -> VerificationResult:
        """Synthesize local deterministic verification result with zero network cost."""
        is_secret = not candidate.is_filtered
        confidence = 0.95 if is_secret else 0.1
        explanation = (
            "Deterministic extraction confirmed unambiguous credential signature."
            if is_secret
            else f"Filtered candidate: {candidate.filter_reason or 'non-credential pattern'}"
        )
        remediation = (
            "Rotate and revoke this credential immediately; store in a secrets manager."
            if is_secret
            else "No remediation required."
        )

        return VerificationResult(
            candidate=candidate,
            is_secret=is_secret,
            confidence=confidence,
            explanation=explanation,
            remediation=remediation,
            model_used="local_deterministic",
            latency_ms=0.0,
            resolved_locally=True,
        )

    def _build_fallback_result(
        self,
        candidate: SecretCandidate,
        latency_ms: float,
        reason: str,
    ) -> VerificationResult:
        """Build resilient fallback result when LLM verification fails or is unavailable."""
        logger.warning(
            "Engaging fault-tolerant fallback for candidate in %s:%d: %s",
            candidate.file_path,
            candidate.line_number,
            reason,
        )
        return VerificationResult(
            candidate=candidate,
            is_secret=True,
            confidence=0.5,
            explanation=FALLBACK_EXPLANATION,
            remediation=FALLBACK_REMEDIATION,
            model_used="fallback_deterministic",
            latency_ms=latency_ms,
            resolved_locally=True,
        )

    def verify(
        self,
        candidate: SecretCandidate,
        config: Optional[Any] = None,
    ) -> VerificationResult:
        """Verify candidate via local tier or routed LLM provider with complete fault isolation."""
        # 0. Candidates already marked filtered by pre-filtering resolve deterministically
        if candidate.is_filtered:
            return self._resolve_deterministic(candidate)

        # 1. Determine routing tier (None indicates unambiguous local resolution)
        target_profile = self.routing_policy.evaluate_route(candidate, config)
        if target_profile is None:
            return self._resolve_deterministic(candidate)

        # 2. Candidate routed to external LLM provider
        start_time = time.perf_counter()
        try:
            api_key = self.key_manager.get_active_key(target_profile.provider)
        except (AllKeysExhaustedException, GatewayError) as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return self._build_fallback_result(candidate, elapsed_ms, str(exc))

        try:
            response_data = self.provider_client.dispatch_verification(
                context_snippet=candidate.surrounding_context,
                candidate_value=candidate.literal_value,
                profile=target_profile,
                api_key=api_key,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            return VerificationResult(
                candidate=candidate,
                is_secret=bool(response_data.get("is_secret", True)),
                confidence=float(response_data.get("confidence", 0.5)),
                explanation=str(response_data.get("explanation", FALLBACK_EXPLANATION)),
                remediation=str(response_data.get("remediation", FALLBACK_REMEDIATION)),
                model_used=target_profile.model_id,
                latency_ms=round(elapsed_ms, 2),
                resolved_locally=False,
            )

        except (GatewayError, ValueError, KeyError, OSError) as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return self._build_fallback_result(candidate, elapsed_ms, f"{type(exc).__name__}: {exc}")

    def verify_batch(
        self,
        candidates: Sequence[SecretCandidate],
        config: Optional[Any] = None,
    ) -> list[VerificationResult]:
        """Verify a collection of candidates sequentially, returning structured VerificationResult items."""
        return [self.verify(candidate, config) for candidate in candidates]
