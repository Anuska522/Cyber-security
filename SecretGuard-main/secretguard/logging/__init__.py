"""Logging subsystem for SecretGuard with credential redaction and event telemetry."""

from secretguard.logging.logger import (
    get_redaction_filter,
    log_diagnostic_event,
    setup_logging,
)
from secretguard.logging.sanitizer import REDACTION_TOKEN, SecretRedactionFilter

__all__ = [
    "REDACTION_TOKEN",
    "SecretRedactionFilter",
    "get_redaction_filter",
    "log_diagnostic_event",
    "setup_logging",
]
