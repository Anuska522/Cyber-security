"""Diagnostic logger setup and pipeline event tracking with sanitization filters."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Optional

from secretguard.logging.sanitizer import SecretRedactionFilter

LOGGER_NAME = "secretguard"

# Global redaction filter singleton
_GLOBAL_REDACTION_FILTER = SecretRedactionFilter()


def get_redaction_filter() -> SecretRedactionFilter:
    """Retrieve the global redaction filter instance."""
    return _GLOBAL_REDACTION_FILTER


def setup_logging(
    verbose: bool = False,
    debug: bool = False,
    log_file: Optional[Path] = None,
) -> logging.Logger:
    """Configure structured diagnostic logging with levels, formatting, and secret redaction."""
    logger = logging.getLogger(LOGGER_NAME)

    # Determine log level
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logger.setLevel(level)

    # Remove pre-existing handlers to prevent duplicated output
    for h in list(logger.handlers):
        logger.removeHandler(h)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(_GLOBAL_REDACTION_FILTER)
    logger.addHandler(console_handler)

    # Optional File Handler
    if log_file is not None:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(file_path), encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(_GLOBAL_REDACTION_FILTER)
        logger.addHandler(file_handler)

    logger.propagate = True
    return logger


def log_diagnostic_event(
    event_type: str,
    details: dict[str, Any],
    level: int = logging.DEBUG,
) -> None:
    """Format and record a pipeline diagnostic event (extraction latency, routing, token metrics)."""
    logger = logging.getLogger(LOGGER_NAME)
    kv_pairs = [f"{k}={v}" for k, v in details.items()]
    details_str = " ".join(kv_pairs)
    logger.log(level, "[EVENT:%s] %s", event_type, details_str)
