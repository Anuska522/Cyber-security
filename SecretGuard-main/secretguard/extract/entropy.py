"""Shannon entropy calculator for identifying high-randomness secret candidates."""

from __future__ import annotations

import collections
import math

from secretguard.core.interfaces import IEntropyCalculator


class ShannonEntropyCalculator(IEntropyCalculator):
    """Calculates Shannon entropy H(X) = -sum(P(x) * log2(P(x))) over byte or character distributions."""

    def calculate(self, text: str) -> float:
        """Compute the Shannon entropy of the given string."""
        if not text:
            return 0.0

        length = len(text)
        if length <= 1:
            return 0.0

        frequencies = collections.Counter(text)
        entropy = 0.0
        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    def is_high_entropy(
        self,
        text: str,
        threshold: float = 4.2,
        min_length: int = 8,
    ) -> bool:
        """Determine whether text meets minimum length and exceeds entropy threshold."""
        if len(text) < min_length:
            return False
        return self.calculate(text) >= threshold
