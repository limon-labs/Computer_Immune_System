"""Explainable policy recommendation generation."""

from __future__ import annotations

from adaptive_intelligence.feedback import FeedbackLedger
from adaptive_intelligence.models import LearnedPattern, PolicyRecommendation


class PolicyRecommendationEngine:
    """Creates non-enforcing recommendations from learned patterns and feedback."""

    def __init__(self, repeated_pattern_threshold: int = 2, high_confidence_threshold: float = 75.0):
        self.repeated_pattern_threshold = max(1, int(repeated_pattern_threshold))
        self.high_confidence_threshold = max(0.0, min(100.0, float(high_confidence_threshold)))

    def recommend(self, patterns: list[LearnedPattern], feedback: FeedbackLedger | None = None) -> list[PolicyRecommendation]:
        feedback = feedback or FeedbackLedger()
        verdict_counts = feedback.verdict_counts()
        recommendations: list[PolicyRecommendation] = []
        for pattern in patterns:
            counts = verdict_counts.get(pattern.pattern_key, {})
            false_positive_count = counts.get("false_positive", 0) + counts.get("benign", 0)
            true_positive_count = counts.get("true_positive", 0)
            if false_positive_count >= self.repeated_pattern_threshold:
                recommendations.append(
                    PolicyRecommendation(
                        action="add_allowlist_candidate",
                        confidence=min(100.0, 60.0 + false_positive_count * 10.0),
                        reason="Repeated analyst feedback marks this pattern as benign or false-positive",
                        pattern_key=pattern.pattern_key,
                        evidence={"feedback": counts, "top_features": pattern.top_features},
                    )
                )
                continue
            if pattern.occurrences >= self.repeated_pattern_threshold and pattern.average_confidence >= self.high_confidence_threshold:
                action = "add_blocklist_candidate" if true_positive_count else "raise_priority"
                recommendations.append(
                    PolicyRecommendation(
                        action=action,
                        confidence=min(100.0, pattern.average_confidence + pattern.occurrences * 2.0),
                        reason="Recurring high-confidence behavior pattern observed in immune memory",
                        pattern_key=pattern.pattern_key,
                        evidence={"occurrences": pattern.occurrences, "top_features": pattern.top_features, "feedback": counts},
                    )
                )
        return recommendations
