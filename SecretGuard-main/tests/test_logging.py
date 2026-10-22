"""Tests for diagnostic logging setup and SecretRedactionFilter credential sanitization."""

from __future__ import annotations

import io
import logging
from pathlib import Path

import pytest

from secretguard.logging.logger import (
    get_redaction_filter,
    log_diagnostic_event,
    setup_logging,
)
from secretguard.logging.sanitizer import REDACTION_TOKEN, SecretRedactionFilter


@pytest.fixture
def filter_instance() -> SecretRedactionFilter:
    """Fixture providing a fresh SecretRedactionFilter instance."""
    return SecretRedactionFilter()


def test_redaction_filter_scrubs_raw_aws_and_openai_tokens(filter_instance: SecretRedactionFilter) -> None:
    """Verify that regex-matched structured tokens are scrubbed from log record messages."""
    aws_key = "AKIA1234567890ABCDEF"
    openai_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL"

    record = logging.LogRecord(
        name="secretguard.test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg=f"Discovered AWS key {aws_key} and OpenAI key {openai_key}",
        args=(),
        exc_info=None,
    )

    filter_instance.filter(record)

    assert aws_key not in record.msg
    assert openai_key not in record.msg
    assert REDACTION_TOKEN in record.msg


def test_redaction_filter_scrubs_registered_secrets(filter_instance: SecretRedactionFilter) -> None:
    """Verify that arbitrary registered secret literals are scrubbed on exact match."""
    custom_secret = "my_custom_super_secret_token_val_999"
    filter_instance.register_secret(custom_secret)

    record = logging.LogRecord(
        name="secretguard.test",
        level=logging.WARNING,
        pathname="test.py",
        lineno=10,
        msg=f"Processing token: {custom_secret} for candidate verification.",
        args=(),
        exc_info=None,
    )

    filter_instance.filter(record)

    assert custom_secret not in record.msg
    assert REDACTION_TOKEN in record.msg


def test_redaction_filter_scrubs_record_args_structures(filter_instance: SecretRedactionFilter) -> None:
    """Verify that log arguments passed as tuples, lists, or dicts are scrubbed in-place."""
    raw_secret_a = "gh" + "p_1234567890abcdefghijklmnopqrstuvwxyz"
    raw_secret_b = "custom_unstructured_secret_abc123"
    filter_instance.register_secret(raw_secret_b)

    # Args as tuple
    record_tuple = logging.LogRecord(
        name="secretguard.test",
        level=logging.ERROR,
        pathname="test.py",
        lineno=20,
        msg="Error verifying key %s with payload %s",
        args=(raw_secret_a, {"token": raw_secret_b}),
        exc_info=None,
    )

    filter_instance.filter(record_tuple)

    assert raw_secret_a not in str(record_tuple.args)
    assert raw_secret_b not in str(record_tuple.args)
    assert REDACTION_TOKEN in str(record_tuple.args)


def test_setup_logging_configures_handlers_and_levels(tmp_path: Path) -> None:
    """Verify setup_logging attaches stream and file handlers with redaction filters."""
    log_file = tmp_path / "secretguard.log"
    logger = setup_logging(verbose=True, debug=False, log_file=log_file)

    assert logger.level == logging.INFO
    assert len(logger.handlers) == 2  # Console and File

    logger.info("Executing SecretGuard scan initialized.")
    assert log_file.is_file()

    content = log_file.read_text(encoding="utf-8")
    assert "Executing SecretGuard scan initialized." in content


def test_log_diagnostic_event_telemetry(caplog: pytest.LogCaptureFixture) -> None:
    """Verify log_diagnostic_event writes telemetry entries formatted as key-value pairs."""
    setup_logging(debug=True)

    with caplog.at_level(logging.DEBUG, logger="secretguard"):
        log_diagnostic_event(
            "routing_decision",
            {"score": "0.45", "tier": "Profile A", "model": "llama-3.1-8b-instant"},
        )

    assert "[EVENT:routing_decision]" in caplog.text
    assert "score=0.45" in caplog.text
    assert "tier=Profile A" in caplog.text
