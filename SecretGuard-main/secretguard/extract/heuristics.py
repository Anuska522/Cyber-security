"""Contextual variable heuristics for identifying sensitive credential assignments."""

from __future__ import annotations

import ast
import re
from typing import Optional

from secretguard.core.interfaces import IEntropyCalculator, IExtractionRule
from secretguard.core.models import SecretCandidate
from secretguard.extract.context import extract_bounded_context
from secretguard.extract.entropy import ShannonEntropyCalculator

SENSITIVE_IDENTIFIER_PATTERN = re.compile(
    r"""(?xi)
    (?P<prefix>
        (?:['"])?
        (?P<identifier>
            \b(?:password|passwd|secret|api_key|apikey|client_secret|access_token|auth|auth_token|api_secret|token|credential|key)\b[a-zA-Z0-9_-]*
        )
        (?:['"])?
        \s*[:=]\s*
    )
    (?P<quote>['"]?)
    (?P<value>[^\r\n'";,\s]+)
    (?P=quote)
    """
)


class ContextualVariableHeuristic(IExtractionRule):
    """Detects credentials assigned to sensitive variable names in line buffers and AST nodes."""

    def __init__(
        self,
        entropy_calculator: Optional[IEntropyCalculator] = None,
        min_length: int = 6,
    ) -> None:
        self._entropy_calculator = entropy_calculator or ShannonEntropyCalculator()
        self._min_length = min_length
        self._rule_id = "SG-HEUR-VAR-001"
        self._description = "Contextual Sensitive Variable Assignment"

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def description(self) -> str:
        return self._description

    def _inspect_ast(self, line: str) -> list[tuple[str, int, int]]:
        """Attempt to parse line as Python AST to extract variable assignment values and indices."""
        results: list[tuple[str, int, int]] = []
        try:
            tree = ast.parse(line.strip())
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        target_id = getattr(target, "id", None)
                        if isinstance(target_id, str):
                            lower_id = target_id.lower()
                            if any(
                                key in lower_id
                                for key in (
                                    "password",
                                    "secret",
                                    "api_key",
                                    "client_secret",
                                    "access_token",
                                    "auth",
                                    "token",
                                    "credential",
                                    "key",
                                )
                            ):
                                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                    val = node.value.value
                                    if len(val) >= self._min_length:
                                        idx = line.find(val)
                                        if idx != -1:
                                            results.append((val, idx, idx + len(val)))
        except (SyntaxError, ValueError):
            return []
        return results

    def evaluate(
        self,
        line: str,
        file_path: str = "",
        line_number: int = 1,
    ) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        seen_spans: set[tuple[int, int]] = set()

        # 1. First probe via AST if line is valid Python syntax
        for val, start_idx, end_idx in self._inspect_ast(line):
            seen_spans.add((start_idx, end_idx))
            entropy = self._entropy_calculator.calculate(val)
            context = extract_bounded_context(line, start_idx, end_idx)
            candidates.append(
                SecretCandidate(
                    literal_value=val,
                    file_path=file_path,
                    line_number=line_number,
                    surrounding_context=context,
                    rule_id=self.rule_id,
                    entropy_score=entropy,
                    heuristic_tags=["contextual_variable", "ast_assignment"],
                    is_filtered=False,
                    filter_reason=None,
                )
            )

        # 2. Inspect line buffer via regex heuristic
        for match in SENSITIVE_IDENTIFIER_PATTERN.finditer(line):
            val = match.group("value")
            if not val or len(val) < self._min_length:
                continue

            start_idx = match.start("value")
            end_idx = match.end("value")

            if (start_idx, end_idx) in seen_spans:
                continue

            seen_spans.add((start_idx, end_idx))
            entropy = self._entropy_calculator.calculate(val)
            context = extract_bounded_context(line, start_idx, end_idx)

            candidates.append(
                SecretCandidate(
                    literal_value=val,
                    file_path=file_path,
                    line_number=line_number,
                    surrounding_context=context,
                    rule_id=self.rule_id,
                    entropy_score=entropy,
                    heuristic_tags=["contextual_variable", "line_buffer_heuristic"],
                    is_filtered=False,
                    filter_reason=None,
                )
            )

        return candidates
