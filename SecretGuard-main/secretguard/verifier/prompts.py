"""Zero-shot contextual evaluation prompts enforcing strict data minimization."""

from __future__ import annotations

from typing import Final

MAX_ALLOWED_CONTEXT_CHARS: Final[int] = 200

APPSEC_SYSTEM_PROMPT: Final[str] = (
    "You are an AppSec code analyzer. Evaluate if the candidate string in the snippet is an "
    "active/functional secret, a mock/test credential, or a false positive. Return JSON only with "
    "keys: is_secret (bool), confidence (float 0.0-1.0), explanation (str <= 30 words), remediation (str)."
)


def build_verification_prompt(candidate_value: str, context_snippet: str) -> str:
    """Construct minimal prompt transmitting only candidate string and bounded snippet."""
    bounded_snippet = context_snippet[:MAX_ALLOWED_CONTEXT_CHARS]
    return (
        f"Candidate String: {candidate_value}\n"
        f"Code Context (max 200 chars):\n{bounded_snippet}\n\n"
        "Analyze this candidate and respond with strictly valid JSON only."
    )


def assert_payload_privacy_bounds(context_snippet: str, max_chars: int = MAX_ALLOWED_CONTEXT_CHARS) -> bool:
    """Verify that context snippet payload adheres strictly to privacy isolation boundaries."""
    return len(context_snippet) <= max_chars
