"""Logging filter for strict credential sanitization and redaction."""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

# Common structured credential signatures for live log interception
LOG_REDACT_PATTERNS = [
    re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
    re.compile(r"(?<![0-9a-zA-Z])(ghp_[0-9a-zA-Z]{36})(?![0-9a-zA-Z])"),
    re.compile(r"(?<![0-9a-zA-Z])(github_pat_[0-9a-zA-Z_]{22,255})(?![0-9a-zA-Z])"),
    re.compile(r"(?<![a-zA-Z0-9])(sk-[a-zA-Z0-9]{48})(?![a-zA-Z0-9])"),
    re.compile(r"(?<![a-zA-Z0-9])(sk-proj-[a-zA-Z0-9_\-]{48,160})(?![a-zA-Z0-9])"),
    re.compile(r"(?<![0-9A-Za-z_\-])(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"),
    re.compile(r"(?<![0-9a-zA-Z])(xox[baprs]-[0-9a-zA-Z_\-]{10,80})(?![0-9a-zA-Z])"),
    re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
    re.compile(r"(-----BEGIN [A-Z0-9_\-\s]+KEY-----)"),
    re.compile(r"\b((?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,99})\b"),
    re.compile(r"\b((?:AC|SK)[a-f0-9]{32})\b"),
]

REDACTION_TOKEN = "***REDACTED***"


class SecretRedactionFilter(logging.Filter):
    """Logging filter that redacts raw credential literals and registered secret tokens from all logs."""

    def __init__(self, name: str = "") -> None:
        super().__init__(name)
        self._registered_secrets: set[str] = set()

    def register_secret(self, secret: str) -> None:
        """Register a known secret value for exact match redaction."""
        cleaned = secret.strip()
        if len(cleaned) >= 4:
            self._registered_secrets.add(cleaned)

    def register_secrets(self, secrets: Iterable[str]) -> None:
        """Register multiple secret values simultaneously."""
        for s in secrets:
            self.register_secret(s)

    def clear_registered_secrets(self) -> None:
        """Clear all explicitly registered secrets."""
        self._registered_secrets.clear()

    def _mask_text(self, text: str) -> str:
        """Scrub known and pattern-based secrets from text string."""
        if not text:
            return text

        scrubbed = text

        # 1. Exact match registered secrets (longest first to prevent sub-string fragmenting)
        sorted_secrets = sorted(self._registered_secrets, key=len, reverse=True)
        for s in sorted_secrets:
            if s in scrubbed:
                scrubbed = scrubbed.replace(s, REDACTION_TOKEN)

        # 2. Scrub regex structured credential patterns
        for pattern in LOG_REDACT_PATTERNS:
            scrubbed = pattern.sub(REDACTION_TOKEN, scrubbed)

        return scrubbed

    def _sanitize_item(self, item: Any) -> Any:
        """Recursively sanitize strings or items within collections."""
        if isinstance(item, str):
            return self._mask_text(item)
        if isinstance(item, tuple):
            return tuple(self._sanitize_item(v) for v in item)
        if isinstance(item, list):
            return [self._sanitize_item(v) for v in item]
        if isinstance(item, dict):
            return {self._sanitize_item(k): self._sanitize_item(v) for k, v in item.items()}
        return item

    def filter(self, record: logging.LogRecord) -> bool:
        """Inspect and sanitize log record message and arguments in-place before emission."""
        if isinstance(record.msg, str):
            record.msg = self._mask_text(record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = self._sanitize_item(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(self._sanitize_item(arg) for arg in record.args)
            elif isinstance(record.args, list):
                record.args = [self._sanitize_item(arg) for arg in record.args]

        return True
