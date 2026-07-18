"""Analyst feedback aggregation for adaptive intelligence."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from adaptive_intelligence.models import AnalystFeedback


class FeedbackLedger:
    """In-memory feedback ledger with deterministic scoring semantics."""

    def __init__(self, feedback: Iterable[AnalystFeedback] | None = None):
        self._feedback: list[AnalystFeedback] = list(feedback or [])

    def record(self, feedback: AnalystFeedback) -> None:
        self._feedback.append(feedback)

    def for_pattern(self, pattern_key: str) -> list[AnalystFeedback]:
        return [item for item in self._feedback if item.pattern_key == pattern_key]

    def confidence_adjustment(self, pattern_key: str) -> float:
        adjustment = 0.0
        for item in self.for_pattern(pattern_key):
            if item.verdict == "true_positive":
                adjustment += 10.0
            elif item.verdict in {"false_positive", "benign"}:
                adjustment -= 15.0
            adjustment += item.confidence_delta
        return max(-50.0, min(50.0, adjustment))

    def verdict_counts(self) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = defaultdict(lambda: {"true_positive": 0, "false_positive": 0, "benign": 0, "unknown": 0})
        for item in self._feedback:
            counts[item.pattern_key][item.verdict] += 1
        return dict(counts)
