"""Pre-filtering heuristics to eliminate placeholders, templated variables, and false positives."""

from __future__ import annotations

import re
from typing import Optional, Sequence
from urllib.parse import urlparse

from secretguard.core.interfaces import ICandidateFilter
from secretguard.core.models import SecretCandidate

DEFAULT_PLACEHOLDER_WORDS = [
    "your_api_key",
    "your_secret",
    "your_password",
    "your_token",
    "dummy_password",
    "example_key",
    "sample_key",
    "test_key",
    "test_secret",
    "test_password",
    "replace_me",
    "changeme",
    "change_me",
    "insert_here",
    "enter_here",
    "placeholder",
    "my_secret",
    "my_api_key",
    "fake_key",
    "fake_token",
]

TEMPLATED_VAR_PATTERN = re.compile(
    r"""(?x)
    ^(?:
        \$\{[a-zA-Z0-9_.-]+\}      # ${ENV_VAR}
        |
        \$\([a-zA-Z0-9_.-]+\)      # $(ENV_VAR)
        |
        \$[a-zA-Z_][a-zA-Z0-9_]*   # $SECRET
        |
        \{\{[a-zA-Z0-9_.-]+\}\}    # {{SECRET}}
        |
        %\{[a-zA-Z0-9_.-]+\}       # %{SECRET}
        |
        <[a-zA-Z0-9_.-]+>          # <API_KEY>
        |
        \[[a-zA-Z0-9_.-]+\]        # [YOUR_KEY]
        |
        process\.env\.[a-zA-Z0-9_]+# process.env.KEY
    )$
    """
)


class CandidatePreFilter(ICandidateFilter):
    """Filters false positives, placeholder strings, and environment templates."""

    def __init__(
        self,
        min_length: int = 8,
        custom_placeholders: Optional[Sequence[str]] = None,
    ) -> None:
        self.min_length = min_length
        self._placeholders = set(w.lower() for w in DEFAULT_PLACEHOLDER_WORDS)
        if custom_placeholders:
            self._placeholders.update(w.lower() for w in custom_placeholders)

    def _is_url_without_credentials(self, value: str) -> bool:
        """Check if literal is an HTTP/HTTPS URL that does not contain embedded user credentials."""
        if not (value.startswith("http://") or value.startswith("https://")):
            return False

        try:
            parsed = urlparse(value)
            # If there is no username/password in netloc, it's a standard URL, not a secret
            if not parsed.username and not parsed.password:
                return True
        except ValueError:
            return False
        return False

    def _is_templated_variable(self, value: str) -> bool:
        """Check if literal matches environment variable substitution or template syntax."""
        stripped = value.strip()
        if TEMPLATED_VAR_PATTERN.match(stripped):
            return True
        if stripped.startswith("${") and stripped.endswith("}"):
            return True
        if stripped.startswith("{{") and stripped.endswith("}}"):
            return True
        if stripped.startswith("<") and stripped.endswith(">"):
            return True
        return False

    def _is_placeholder(self, value: str) -> bool:
        """Check if candidate value matches known placeholder markers."""
        val_lower = value.lower().strip()

        # Direct placeholder lookup
        if val_lower in self._placeholders:
            return True

        # Check for angle bracket placeholder like <YOUR_API_KEY>
        inner = val_lower.strip("<>[]{}\"'")
        if inner in self._placeholders:
            return True

        # Check if contains placeholder fragments
        for placeholder in self._placeholders:
            if placeholder in val_lower:
                return True

        # Check repeating single character strings (e.g., 'xxxxxxxx', '00000000')
        if len(set(val_lower)) == 1 and len(val_lower) >= 4:
            return True

        return False

    def should_filter(self, candidate: SecretCandidate) -> tuple[bool, Optional[str]]:
        """Evaluate if candidate should be filtered out."""
        val = candidate.literal_value.strip()

        # 1. Templated environment variables
        if self._is_templated_variable(val):
            return True, "templated environment variable"

        # 2. Known placeholders
        if self._is_placeholder(val):
            return True, "placeholder literal"

        # 3. Standard HTTP/HTTPS URLs lacking credentials
        if self._is_url_without_credentials(val):
            return True, "standard http url without credentials"

        # 4. Minimum length enforcement (unless private key header)
        if candidate.rule_id != "SG-KEY-001" and len(val) < self.min_length:
            return True, f"length below minimum ({len(val)} < {self.min_length})"

        return False, None

    def filter_candidate(self, candidate: SecretCandidate) -> SecretCandidate:
        """Return candidate with updated filter state."""
        should_drop, reason = self.should_filter(candidate)
        return candidate.with_filter(is_filtered=should_drop, reason=reason)
