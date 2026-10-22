"""Tests for privacy-isolated AI verification: data minimization, JSON parsing, and fault tolerance."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from secretguard.core.models import ModelProfile, SecretCandidate, VerificationResult
from secretguard.gateway.dispatcher import GatewayError, ProviderDispatcher
from secretguard.gateway.key_manager import KeyRotationManager
from secretguard.router.policy import AdaptiveRoutingPolicy
from secretguard.verifier.evaluator import ContextualVerifier
from secretguard.verifier.prompts import (
    APPSEC_SYSTEM_PROMPT,
    assert_payload_privacy_bounds,
    build_verification_prompt,
)


@pytest.fixture
def mock_key_manager() -> KeyRotationManager:
    """Fixture providing a KeyRotationManager populated with a mock key."""
    return KeyRotationManager(initial_keys={"groq": ["gsk_test_mock_key_12345"]})


def test_context_window_privacy_isolation_bounds() -> None:
    """Verify transmitted context window strictly adheres to maximum 200 characters."""
    valid_context = "a" * 200
    oversized_context = "b" * 500

    assert assert_payload_privacy_bounds(valid_context) is True
    assert assert_payload_privacy_bounds(oversized_context) is False

    # Verify build_verification_prompt strictly clamps context to 200 chars
    prompt = build_verification_prompt("AKIA1234567890ABCDEF", oversized_context)
    assert "b" * 200 in prompt
    assert "b" * 201 not in prompt

    # Verify repository metadata and file paths are not included
    assert "src/app/main.py" not in prompt
    assert "git" not in prompt


def test_verifier_deterministic_resolution_bypasses_network() -> None:
    """Verify unambiguous candidates are resolved locally with zero network calls and 0.0ms latency."""
    mock_client = MagicMock()
    verifier = ContextualVerifier(provider_client=mock_client)

    unambiguous_cand = SecretCandidate(
        literal_value="AKIAIOSFODNN7EXAMPLE",
        file_path="src/aws.py",
        line_number=1,
        surrounding_context='aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
        rule_id="SG-AWS-001",
        entropy_score=4.2,
    )

    result = verifier.verify(unambiguous_cand)

    assert result.resolved_locally is True
    assert result.is_secret is True
    assert result.confidence == 0.95
    assert result.model_used == "local_deterministic"
    assert result.latency_ms == 0.0
    mock_client.dispatch_verification.assert_not_called()


@respx.mock
def test_verifier_valid_json_response_parsing(mock_key_manager: KeyRotationManager) -> None:
    """Verify that structured LLM output is parsed accurately into VerificationResult."""
    endpoint = "https://api.groq.com/openai/v1/chat/completions"
    mock_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "is_secret": True,
                            "confidence": 0.92,
                            "explanation": "Active JWT Bearer Token detected.",
                            "remediation": "Revoke token and issue anew.",
                        }
                    )
                }
            }
        ]
    }
    respx.post(endpoint).respond(status_code=200, json=mock_response)

    dispatcher = ProviderDispatcher(key_manager=mock_key_manager)
    verifier = ContextualVerifier(key_manager=mock_key_manager, provider_client=dispatcher)

    # Candidate with ambiguity routed to Profile A
    ambiguous_cand = SecretCandidate(
        literal_value="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.xyz123abc456",
        file_path="src/api.py",
        line_number=10,
        surrounding_context='data = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.xyz123abc456"',
        rule_id="SG-JWT-001",
        entropy_score=5.0,
    )

    result = verifier.verify(ambiguous_cand)

    assert result.resolved_locally is False
    assert result.is_secret is True
    assert result.confidence == 0.92
    assert "Active JWT Bearer" in result.explanation
    assert "Revoke token" in result.remediation
    assert result.model_used == "llama-3.1-8b-instant"
    assert result.latency_ms >= 0.0


@respx.mock
def test_verifier_malformed_json_fallback_resilience(mock_key_manager: KeyRotationManager) -> None:
    """Verify that unparseable or malformed LLM responses trigger graceful fallback without crashing."""
    endpoint = "https://api.groq.com/openai/v1/chat/completions"
    # Malformed response lacking proper JSON structure
    mock_response = {
        "choices": [
            {
                "message": {
                    "content": "I am an AI and cannot evaluate this code properly at this time."
                }
            }
        ]
    }
    respx.post(endpoint).respond(status_code=200, json=mock_response)

    dispatcher = ProviderDispatcher(key_manager=mock_key_manager)
    verifier = ContextualVerifier(key_manager=mock_key_manager, provider_client=dispatcher)

    ambiguous_cand = SecretCandidate(
        literal_value="token_1234567890abcdef",
        file_path="src/api.py",
        line_number=10,
        surrounding_context='data = "token_1234567890abcdef"',
        rule_id="SG-JWT-001",
        entropy_score=5.0,
    )

    result = verifier.verify(ambiguous_cand)

    # Fallback guarantees
    assert result.resolved_locally is True
    assert result.is_secret is True
    assert result.confidence == 0.5
    assert result.model_used == "fallback_deterministic"
    assert "AI verification bypassed" in result.explanation


@respx.mock
def test_verifier_http_timeout_fallback_resilience(mock_key_manager: KeyRotationManager) -> None:
    """Verify that network timeout (>2,000 ms) engages fallback without raising exceptions."""
    endpoint = "https://api.groq.com/openai/v1/chat/completions"
    respx.post(endpoint).mock(side_effect=httpx.ReadTimeout("Read timed out (> 2000 ms)"))

    dispatcher = ProviderDispatcher(key_manager=mock_key_manager, max_retries=1)
    verifier = ContextualVerifier(key_manager=mock_key_manager, provider_client=dispatcher)

    ambiguous_cand = SecretCandidate(
        literal_value="token_timeout_test_val",
        file_path="src/api.py",
        line_number=10,
        surrounding_context='data = "token_timeout_test_val"',
        rule_id="SG-JWT-001",
        entropy_score=5.0,
    )

    result = verifier.verify(ambiguous_cand)

    assert result.resolved_locally is True
    assert result.is_secret is True
    assert result.confidence == 0.5
    assert result.model_used == "fallback_deterministic"


@respx.mock
def test_verifier_server_500_fallback_resilience(mock_key_manager: KeyRotationManager) -> None:
    """Verify that upstream 500 errors engage fallback without raising exceptions."""
    endpoint = "https://api.groq.com/openai/v1/chat/completions"
    respx.post(endpoint).respond(status_code=500, json={"error": "Provider service unavailable"})

    dispatcher = ProviderDispatcher(key_manager=mock_key_manager, max_retries=1)
    verifier = ContextualVerifier(key_manager=mock_key_manager, provider_client=dispatcher)

    ambiguous_cand = SecretCandidate(
        literal_value="token_500_test_val",
        file_path="src/api.py",
        line_number=10,
        surrounding_context='data = "token_500_test_val"',
        rule_id="SG-JWT-001",
        entropy_score=5.0,
    )

    result = verifier.verify(ambiguous_cand)

    assert result.resolved_locally is True
    assert result.is_secret is True
    assert result.confidence == 0.5
    assert result.model_used == "fallback_deterministic"


def test_verifier_all_keys_exhausted_fallback_resilience() -> None:
    """Verify that when no keys are available, verifier falls back deterministically without error."""
    empty_key_manager = KeyRotationManager()
    verifier = ContextualVerifier(key_manager=empty_key_manager)

    ambiguous_cand = SecretCandidate(
        literal_value="token_no_keys_test_val",
        file_path="src/api.py",
        line_number=10,
        surrounding_context='data = "token_no_keys_test_val"',
        rule_id="SG-JWT-001",
        entropy_score=5.0,
    )

    result = verifier.verify(ambiguous_cand)

    assert result.resolved_locally is True
    assert result.is_secret is True
    assert result.confidence == 0.5
    assert result.model_used == "fallback_deterministic"
