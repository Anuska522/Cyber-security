"""Tests for Shannon entropy calculator against known mathematical distributions and tokens."""

from __future__ import annotations

import math
import pytest

from secretguard.extract.entropy import ShannonEntropyCalculator


@pytest.fixture
def calculator() -> ShannonEntropyCalculator:
    """Fixture providing an instance of ShannonEntropyCalculator."""
    return ShannonEntropyCalculator()


def test_entropy_edge_cases(calculator: ShannonEntropyCalculator) -> None:
    """Verify entropy calculations on edge-case inputs like empty and single-char strings."""
    assert calculator.calculate("") == 0.0
    assert calculator.calculate("a") == 0.0
    assert calculator.calculate("1") == 0.0


def test_entropy_uniform_repeating_strings(calculator: ShannonEntropyCalculator) -> None:
    """Verify that strings with zero variety have an entropy of 0.0."""
    assert calculator.calculate("aaaaaaaaaa") == 0.0
    assert calculator.calculate("0000000000000000") == 0.0
    assert calculator.calculate("!!!!!!!!!!!!!!!!") == 0.0


def test_entropy_known_mathematical_distributions(calculator: ShannonEntropyCalculator) -> None:
    """Verify Shannon entropy matches theoretically exact values: H = -sum(p * log2(p))."""
    # 2 symbols equally distributed: p=0.5 -> H = -2*(0.5 * -1) = 1.0
    two_symbols = "01010101"
    assert math.isclose(calculator.calculate(two_symbols), 1.0, abs_tol=1e-4)

    # 4 symbols equally distributed: p=0.25 -> H = -4*(0.25 * -2) = 2.0
    four_symbols = "abcdabcd"
    assert math.isclose(calculator.calculate(four_symbols), 2.0, abs_tol=1e-4)

    # 8 symbols equally distributed: p=0.125 -> H = -8*(0.125 * -3) = 3.0
    eight_symbols = "abcdefgh"
    assert math.isclose(calculator.calculate(eight_symbols), 3.0, abs_tol=1e-4)

    # 16 distinct symbols equally distributed -> H = 4.0
    sixteen_symbols = "abcdefghijklmnop"
    assert math.isclose(calculator.calculate(sixteen_symbols), 4.0, abs_tol=1e-4)

    # 32 distinct symbols equally distributed -> H = 5.0
    thirty_two_symbols = "abcdefghijklmnopqrstuvwxyz012345"
    assert math.isclose(calculator.calculate(thirty_two_symbols), 5.0, abs_tol=1e-4)


def test_entropy_cryptographic_and_base64_tokens(calculator: ShannonEntropyCalculator) -> None:
    """Verify that cryptographic secrets and random tokens exceed threshold 4.2."""
    aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert calculator.calculate(aws_secret) >= 4.2
    assert calculator.is_high_entropy(aws_secret, threshold=4.2, min_length=8) is True

    jwt_signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert calculator.calculate(jwt_signature) >= 4.2
    assert calculator.is_high_entropy(jwt_signature, threshold=4.2, min_length=8) is True

    high_entropy_hex = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
    assert calculator.calculate(high_entropy_hex) >= 3.5


def test_entropy_low_randomness_passwords(calculator: ShannonEntropyCalculator) -> None:
    """Verify that human-readable dictionary words fail the entropy threshold."""
    assert calculator.calculate("password") < 3.0
    assert calculator.is_high_entropy("password", threshold=4.2, min_length=8) is False

    assert calculator.calculate("administrator") < 3.5
    assert calculator.is_high_entropy("administrator", threshold=4.2, min_length=8) is False

    assert calculator.calculate("dummy_password") < 3.5
    assert calculator.is_high_entropy("dummy_password", threshold=4.2, min_length=8) is False


def test_is_high_entropy_minimum_length_cutoff(calculator: ShannonEntropyCalculator) -> None:
    """Verify that short tokens are rejected even if all characters are unique."""
    # 6 characters with high variety: "a1!b2@"
    assert calculator.calculate("a1!b2@") > 2.5
    # Should fail because length (6) < min_length (8)
    assert calculator.is_high_entropy("a1!b2@", threshold=2.0, min_length=8) is False
    # Should pass when min_length <= 6
    assert calculator.is_high_entropy("a1!b2@", threshold=2.0, min_length=6) is True
