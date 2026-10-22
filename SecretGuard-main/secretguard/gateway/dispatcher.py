"""HTTP provider dispatcher with strict 2,000 ms timeouts, retry loops, and credential masking."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

import httpx

from secretguard.core.interfaces import IKeyPoolManager, ILLMProviderClient
from secretguard.core.models import ModelProfile, mask_credential
from secretguard.gateway.key_manager import (
    GatewayError,
    KeyRotationManager,
)

logger = logging.getLogger("secretguard.gateway.dispatcher")

PROVIDER_ENDPOINTS: dict[str, str] = {
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "together": "https://api.together.xyz/v1/chat/completions",
    "google": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
}

DEFAULT_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"

SYSTEM_PROMPT = (
    "You are an AppSec code analyzer. Evaluate if the candidate string in the snippet is an "
    "active/functional secret, a mock/test credential, or a false positive. Return JSON only with "
    "keys: is_secret (bool), confidence (float 0.0-1.0), explanation (str <= 30 words), remediation (str)."
)


class KeyThrottledException(GatewayError):
    """Raised when an API key encounters an HTTP 429 rate limit."""


class KeyExhaustedException(GatewayError):
    """Raised when an API key receives an HTTP 403 authorization/quota error."""


class ProviderDispatcher(ILLMProviderClient):
    """Dispatches verification payloads via HTTPX with connection pooling, retries, and strict masking."""

    def __init__(
        self,
        key_manager: Optional[IKeyPoolManager] = None,
        client: Optional[httpx.Client] = None,
        max_retries: int = 2,
        timeout_seconds: float = 2.0,
    ) -> None:
        self.key_manager = key_manager or KeyRotationManager()
        self._max_retries = max_retries
        self._timeout = httpx.Timeout(
            timeout=timeout_seconds,
            connect=timeout_seconds,
            read=timeout_seconds,
            write=timeout_seconds,
        )
        self._client = client

    def _get_client(self) -> httpx.Client:
        """Return injected client or instantiate an internal client."""
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=self._timeout)

    def _resolve_endpoint(self, provider: str) -> str:
        """Resolve API endpoint URL for the designated provider."""
        return PROVIDER_ENDPOINTS.get(provider.lower().strip(), DEFAULT_ENDPOINT)

    def _parse_retry_after(self, response: httpx.Response) -> float:
        """Extract Retry-After header in seconds, defaulting to 60.0s if absent or unparseable."""
        raw_header = response.headers.get("Retry-After", "")
        if raw_header:
            try:
                val = float(raw_header)
                if val > 0:
                    return val
            except ValueError:
                logger.debug("Non-numeric Retry-After header '%s', defaulting to 60.0s", raw_header)
        return 60.0

    def _extract_json_payload(self, raw_content: str) -> dict[str, Any]:
        """Extract and parse strictly valid JSON from model response text."""
        cleaned = raw_content.strip()

        # Handle markdown fences ```json ... ```
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
        if fence_match:
            cleaned = fence_match.group(1).strip()
        else:
            first_brace = cleaned.find("{")
            last_brace = cleaned.rfind("}")
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                cleaned = cleaned[first_brace : last_brace + 1]

        parsed = json.loads(cleaned)
        if not isinstance(parsed, dict):
            raise ValueError("Parsed JSON is not an object mapping")

        # Validate mandatory keys
        if "is_secret" not in parsed:
            raise ValueError("Missing 'is_secret' boolean in response JSON")

        return {
            "is_secret": bool(parsed.get("is_secret")),
            "confidence": float(max(0.0, min(1.0, float(parsed.get("confidence", 0.8))))),
            "explanation": str(parsed.get("explanation", "Evaluated by AI model.")),
            "remediation": str(parsed.get("remediation", "Rotate and revoke if functional.")),
        }

    def dispatch_verification(
        self,
        context_snippet: str,
        candidate_value: str,
        profile: ModelProfile,
        api_key: str,
    ) -> dict[str, Any]:
        """Send verification request to the model provider with retry loops and key rotation."""
        masked_k = mask_credential(api_key)
        masked_c = mask_credential(candidate_value)
        endpoint = self._resolve_endpoint(profile.provider)

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "SecretGuard-Scanner/0.2.0",
        }

        user_content = (
            f"Candidate String: {candidate_value}\n"
            f"Code Context (max 200 chars):\n{context_snippet}\n\n"
            "Analyze this candidate and respond with strictly valid JSON only."
        )

        payload = {
            "model": profile.model_id,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "max_tokens": profile.max_tokens,
            "temperature": profile.temperature,
            "response_format": {"type": "json_object"},
        }

        client = self._get_client()
        attempts = 0

        while attempts <= self._max_retries:
            attempts += 1
            try:
                logger.debug(
                    "Dispatching verification to %s [%s] with key %s (attempt %d/%d)",
                    profile.provider,
                    profile.model_id,
                    masked_k,
                    attempts,
                    self._max_retries + 1,
                )

                response = client.post(endpoint, json=payload, headers=headers)

                # HTTP 200: Success
                if response.status_code == 200:
                    data = response.json()
                    choices = data.get("choices", [])
                    if not choices:
                        raise ValueError("No choices returned in model response")
                    message = choices[0].get("message", {})
                    raw_content = message.get("content", "")

                    parsed_result = self._extract_json_payload(raw_content)
                    if hasattr(self.key_manager, "record_success"):
                        self.key_manager.record_success(profile.provider, api_key)
                    return parsed_result

                # HTTP 429: Rate Limit
                if response.status_code == 429:
                    retry_after = self._parse_retry_after(response)
                    self.key_manager.mark_throttled(profile.provider, api_key, retry_after)
                    raise KeyThrottledException(
                        f"Provider '{profile.provider}' returned HTTP 429 with key {masked_k}. "
                        f"Retry-After: {retry_after:.1f}s."
                    )

                # HTTP 403: Forbidden / Quota Exhaustion
                if response.status_code == 403:
                    self.key_manager.mark_exhausted(profile.provider, api_key)
                    raise KeyExhaustedException(
                        f"Provider '{profile.provider}' returned HTTP 403 for key {masked_k}."
                    )

                # HTTP 5xx: Transient Server Error
                if 500 <= response.status_code < 600:
                    if attempts <= self._max_retries:
                        logger.warning(
                            "Transient HTTP %d from %s with key %s. Retrying...",
                            response.status_code,
                            profile.provider,
                            masked_k,
                        )
                        continue
                    raise GatewayError(
                        f"Provider '{profile.provider}' failed with HTTP {response.status_code} after {attempts} attempts."
                    )

                # Other HTTP errors
                raise GatewayError(
                    f"Unexpected HTTP {response.status_code} from provider '{profile.provider}'."
                )

            except (httpx.TransportError, httpx.NetworkError, httpx.TimeoutException) as exc:
                if attempts <= self._max_retries:
                    logger.warning(
                        "Network failure calling %s with key %s: %s. Retrying (%d/%d)...",
                        profile.provider,
                        masked_k,
                        type(exc).__name__,
                        attempts,
                        self._max_retries,
                    )
                    continue
                raise GatewayError(
                    f"Network communication with provider '{profile.provider}' timed out or disconnected."
                ) from exc
