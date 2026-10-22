"""Bounded context window extractor for secret candidates."""

from __future__ import annotations


def extract_bounded_context(
    line: str,
    match_start: int,
    match_end: int,
    max_window: int = 200,
) -> str:
    """Extract a surrounding context window strictly bounded to at most max_window characters.

    Attempts to capture up to 100 characters before and after the candidate while enforcing
    the hard ceiling of max_window (default: 200 characters).
    """
    if len(line) <= max_window:
        return line

    match_start = max(0, min(match_start, len(line)))
    match_end = max(match_start, min(match_end, len(line)))
    match_len = match_end - match_start

    if match_len >= max_window:
        return line[match_start : match_start + max_window]

    remaining = max_window - match_len
    target_before = min(100, remaining // 2)
    target_after = remaining - target_before

    # Desired boundaries
    start_idx = match_start - target_before
    end_idx = match_end + target_after

    if start_idx < 0:
        end_idx += abs(start_idx)
        start_idx = 0
    elif end_idx > len(line):
        start_idx -= end_idx - len(line)
        end_idx = len(line)

    start_idx = max(0, start_idx)
    end_idx = min(len(line), start_idx + max_window)

    context = line[start_idx:end_idx]
    return context[:max_window]
