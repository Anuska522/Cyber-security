"""Tests for API key rotation gateway: state transitions, cooldowns, pool exhaustion, and masking."""

from __future__ import annotations

import logging
import time
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from secretguard.core.models import KeyStatus, ManagedKey, ModelProfile, mask_credential
from secretguard.gateway.dispatcher import (
    KeyExhaustedException,
    KeyThrottledException,
    ProviderDispatcher,
)
from secretguard.gateway.key_manager import (
    AllKeysExhaustedException,
    KeyRotationManager,
)

SAMPLE_PROFILE = ModelProfile(
    name="Profile A",
    provider="groq",
    model_id="llama-3.1-8b-instant",
    max_tokens=150,
    temperature=0.0,
    timeout_seconds=2.0,
)


def test_key_manager_initialization_and_rotation() -> None:
    """Verify KeyRotationManager initializes pools and retrieves the primary active key."""
    manager = KeyRotationManager(
        initial_keys={
            "groq": ["gsk_key_alpha_12345678", "gsk_key_beta_87654321"],
        }
    )
    active_key = manager.get_active_key("groq")
    assert active_key == "gsk_key_alpha_12345678"


def test_key_manager_http_200_resets_failures() -> None:
    """Verify record_success clears consecutive failure counters and preserves ACTIVE state."""
    raw_key = "gsk_key_alpha_12345678"
    manager = KeyRotationManager(initial_keys={"groq": [raw_key]})

    # Simulate prior failures
    managed = manager._find_managed_key("groq", raw_key)
    assert managed is not None
    managed.consecutive_failures = 3

    manager.record_success("groq", raw_key)
    assert managed.consecutive_failures == 0
    assert managed.status == KeyStatus.ACTIVE


def test_key_manager_http_429_throttles_and_advances_pointer() -> None:
    """Verify HTTP 429 transitions key to THROTTLED, enforces cooldown, and advances to next key."""
    key1 = "gsk_key_one_11111111"
    key2 = "gsk_key_two_22222222"
    manager = KeyRotationManager(initial_keys={"groq": [key1, key2]})

    assert manager.get_active_key("groq") == key1

    # Throttle key 1 with a 30s cooldown
    manager.mark_throttled("groq", key1, retry_after=30.0)

    managed1 = manager._find_managed_key("groq", key1)
    assert managed1 is not None
    assert managed1.status == KeyStatus.THROTTLED
    assert managed1.cooldown_until is not None
    assert managed1.cooldown_until > time.time()

    # Next call should advance pointer to key 2
    assert manager.get_active_key("groq") == key2


def test_key_manager_http_403_marks_permanently_exhausted() -> None:
    """Verify HTTP 403 permanently transitions key to EXHAUSTED and advances pointer."""
    key1 = "gsk_key_one_11111111"
    key2 = "gsk_key_two_22222222"
    manager = KeyRotationManager(initial_keys={"groq": [key1, key2]})

    manager.mark_exhausted("groq", key1)

    managed1 = manager._find_managed_key("groq", key1)
    assert managed1 is not None
    assert managed1.status == KeyStatus.EXHAUSTED
    assert managed1.is_available() is False

    # Pointer rotates to key 2
    assert manager.get_active_key("groq") == key2


def test_key_manager_all_keys_exhausted_raises_exception() -> None:
    """Verify AllKeysExhaustedException is raised when all keys in pool are depleted."""
    key1 = "gsk_single_key_12345"
    manager = KeyRotationManager(initial_keys={"groq": [key1]})

    manager.mark_exhausted("groq", key1)

    with pytest.raises(AllKeysExhaustedException, match="All API keys across all configured providers"):
        manager.get_active_key("groq")


def test_credential_masking_guarantees(caplog: pytest.LogCaptureFixture) -> None:
    """Verify raw API keys are never leaked in logs, repr, or str representations."""
    raw_key = "gsk_super_secret_raw_key_9999"
    managed = ManagedKey(key_value=raw_key, provider="groq")

    # Check repr and str masking
    repr_str = repr(managed)
    str_str = str(managed)
    assert raw_key not in repr_str
    assert raw_key not in str_str
    assert "gsk...****" in repr_str

    # Check mask_credential utility
    masked = mask_credential(raw_key)
    assert raw_key not in masked
    assert masked == "gsk...****"

    # Check logger captures during throttling
    manager = KeyRotationManager(initial_keys={"groq": [raw_key]})
    with caplog.at_level(logging.WARNING):
        manager.mark_throttled("groq", raw_key, retry_after=45.0)

    assert raw_key not in caplog.text
    assert "gsk...****" in caplog.text


@respx.mock
def test_provider_dispatcher_http_200_success() -> None:
    """Verify successful dispatch returns structured verification payload and records success."""
    endpoint = "https://api.groq.com/openai/v1/chat/completions"
    mock_response = {
        "choices": [
            {
                "message": {
                    "content": (
                        '{"is_secret": true, "confidence": 0.95, '
                        '"explanation": "Functional AWS Access Key ID.", '
                        '"remediation": "Rotate AWS credentials immediately."}'
                    )
                }
            }
        ]
    }
    respx.post(endpoint).respond(status_code=200, json=mock_response)

    manager = KeyRotationManager(initial_keys={"groq": ["gsk_key_12345678"]})
    dispatcher = ProviderDispatcher(key_manager=manager)

    result = dispatcher.dispatch_verification(
        context_snippet='AWS_KEY = "AKIA1234567890ABCDEF"',
        candidate_value="AKIA1234567890ABCDEF",
        profile=SAMPLE_PROFILE,
        api_key="gsk_key_12345678",
    )

    assert result["is_secret"] is True
    assert result["confidence"] == 0.95
    assert "Functional AWS" in result["explanation"]
    assert "Rotate" in result["remediation"]


@respx.mock
def test_provider_dispatcher_http_429_triggers_throttled_state() -> None:
    """Verify HTTP 429 raises KeyThrottledException and transitions key state."""
    endpoint = "https://api.groq.com/openai/v1/chat/completions"
    respx.post(endpoint).respond(
        status_code=429,
        headers={"Retry-After": "45"},
        json={"error": {"message": "Rate limit reached"}},
    )

    manager = KeyRotationManager(initial_keys={"groq": ["gsk_key_one", "gsk_key_two"]})
    dispatcher = ProviderDispatcher(key_manager=manager)

    with pytest.raises(KeyThrottledException, match="returned HTTP 429"):
        dispatcher.dispatch_verification(
            context_snippet='secret = "foo"',
            candidate_value="foo",
            profile=SAMPLE_PROFILE,
            api_key="gsk_key_one",
        )

    # Key one is now throttled, next active key should be key two
    assert manager.get_active_key("groq") == "gsk_key_two"


@respx.mock
def test_provider_dispatcher_http_403_triggers_exhaustion() -> None:
    """Verify HTTP 403 raises KeyExhaustedException and permanently exhausts key."""
    endpoint = "https://api.groq.com/openai/v1/chat/completions"
    respx.post(endpoint).respond(
        status_code=403,
        json={"error": {"message": "Invalid API Key or quota exhausted"}},
    )

    manager = KeyRotationManager(initial_keys={"groq": ["gsk_key_one", "gsk_key_two"]})
    dispatcher = ProviderDispatcher(key_manager=manager)

    with pytest.raises(KeyExhaustedException, match="returned HTTP 403"):
        dispatcher.dispatch_verification(
            context_snippet='secret = "foo"',
            candidate_value="foo",
            profile=SAMPLE_PROFILE,
            api_key="gsk_key_one",
        )

    assert manager.get_active_key("groq") == "gsk_key_two"


@respx.mock
def test_provider_dispatcher_retry_on_5xx_transient_error() -> None:
    """Verify automatic retry recovers from transient 500 error before succeeding on attempt 2."""
    endpoint = "https://api.groq.com/openai/v1/chat/completions"
    mock_success = {
        "choices": [
            {
                "message": {
                    "content": '{"is_secret": false, "confidence": 0.85, "explanation": "Test placeholder", "remediation": "None"}'
                }
            }
        ]
    }
    route = respx.post(endpoint)
    route.side_effect = [
        httpx.Response(500, json={"error": "Internal server error"}),
        httpx.Response(200, json=mock_success),
    ]

    manager = KeyRotationManager(initial_keys={"groq": ["gsk_key_test"]})
    dispatcher = ProviderDispatcher(key_manager=manager)

    result = dispatcher.dispatch_verification(
        context_snippet='placeholder = "dummy"',
        candidate_value="dummy",
        profile=SAMPLE_PROFILE,
        api_key="gsk_key_test",
    )

    assert result["is_secret"] is False
    assert result["confidence"] == 0.85
    assert route.call_count == 2
