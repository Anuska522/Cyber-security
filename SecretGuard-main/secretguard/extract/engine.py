"""Deterministic secret extraction pipeline engine fulfilling OCP and DIP."""

from __future__ import annotations

import logging
from collections.abc import Iterator, Sequence
from typing import Optional

from secretguard.core.interfaces import (
    ICandidateFilter,
    IDiffIngester,
    IEntropyCalculator,
    IExtractionRule,
)
from secretguard.core.models import DiffLine, ScanContext, SecretCandidate
from secretguard.extract.entropy import ShannonEntropyCalculator
from secretguard.extract.filters import CandidatePreFilter
from secretguard.extract.heuristics import ContextualVariableHeuristic
from secretguard.extract.rules import get_default_rules

logger = logging.getLogger("secretguard.extract.engine")


class DeterministicExtractionEngine:
    """Core extraction engine orchestrating rules, heuristics, filters, and streaming ingesters."""

    def __init__(
        self,
        rules: Optional[Sequence[IExtractionRule]] = None,
        filters: Optional[Sequence[ICandidateFilter]] = None,
        entropy_calculator: Optional[IEntropyCalculator] = None,
    ) -> None:
        self._entropy_calculator = entropy_calculator or ShannonEntropyCalculator()
        self._rules: list[IExtractionRule] = list(
            rules if rules is not None else self._build_default_rules()
        )
        self._filters: list[ICandidateFilter] = list(
            filters if filters is not None else [CandidatePreFilter()]
        )

    def _build_default_rules(self) -> list[IExtractionRule]:
        """Assemble default suite of regex and contextual variable rules."""
        rules: list[IExtractionRule] = []
        rules.extend(get_default_rules(self._entropy_calculator))
        rules.append(ContextualVariableHeuristic(self._entropy_calculator))
        return rules

    def register_rule(self, rule: IExtractionRule) -> None:
        """Register a new extraction rule into the engine without modifying dispatch logic (OCP)."""
        self._rules.append(rule)

    def register_filter(self, filter_component: ICandidateFilter) -> None:
        """Register a new candidate filter into the engine pipeline."""
        self._filters.append(filter_component)

    def extract_from_line(
        self,
        line: str,
        file_path: str = "",
        line_number: int = 1,
    ) -> list[SecretCandidate]:
        """Extract candidates from a single code line and execute candidate filters."""
        raw_candidates: list[SecretCandidate] = []
        for rule in self._rules:
            matches = rule.evaluate(line, file_path=file_path, line_number=line_number)
            raw_candidates.extend(matches)

        # Deduplicate candidates sharing identical literal values on the same line,
        # preferring structured vendor signatures over generic heuristics, or higher confidence.
        deduped_candidates: dict[str, SecretCandidate] = {}
        for candidate in raw_candidates:
            key = candidate.literal_value
            if key not in deduped_candidates:
                deduped_candidates[key] = candidate
            else:
                existing = deduped_candidates[key]
                existing_is_heur = existing.rule_id.startswith("SG-HEUR")
                cand_is_heur = candidate.rule_id.startswith("SG-HEUR")
                if existing_is_heur and not cand_is_heur:
                    deduped_candidates[key] = candidate
                elif existing_is_heur == cand_is_heur and candidate.confidence_score > existing.confidence_score:
                    deduped_candidates[key] = candidate

        processed_candidates: list[SecretCandidate] = []
        for candidate in deduped_candidates.values():
            current = candidate
            for filter_comp in self._filters:
                current = filter_comp.filter_candidate(current)
                if current.is_filtered:
                    break
            processed_candidates.append(current)

        return processed_candidates

    def extract_from_diff_line(self, diff_line: DiffLine) -> list[SecretCandidate]:
        """Extract candidates from a streaming DiffLine object."""
        return self.extract_from_line(
            line=diff_line.content,
            file_path=diff_line.file_path,
            line_number=diff_line.line_number,
        )

    def scan(
        self,
        ingester: IDiffIngester,
        context: ScanContext,
        drop_filtered: bool = True,
    ) -> Iterator[SecretCandidate]:
        """Stream lines from any IDiffIngester and yield extracted SecretCandidate items."""
        for diff_line in ingester.stream_diff_lines(context):
            candidates = self.extract_from_diff_line(diff_line)
            for candidate in candidates:
                if drop_filtered and candidate.is_filtered:
                    continue
                yield candidate
