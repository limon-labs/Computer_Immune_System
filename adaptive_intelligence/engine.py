"""Top-level Phase 6 adaptive intelligence orchestration."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
import json
from typing import Any, Mapping

from adaptive_intelligence.feedback import FeedbackLedger
from adaptive_intelligence.models import AdaptiveAssessment, AnalystFeedback, LearnedPattern, PolicyRecommendation
from adaptive_intelligence.pattern_learning import MemoryPatternLearner
from adaptive_intelligence.policy_recommendations import PolicyRecommendationEngine
from database.immune_memory import BehaviorFingerprint, ImmuneMemoryStore


class AdaptiveIntelligenceEngine:
    """Combines immune memory, feedback, and pattern learning without enforcing policy."""

    def __init__(
        self,
        memory_store: ImmuneMemoryStore,
        feedback: FeedbackLedger | None = None,
        learner: MemoryPatternLearner | None = None,
        recommender: PolicyRecommendationEngine | None = None,
        similarity_limit: int = 10,
    ):
        self.memory_store = memory_store
        self.feedback = feedback or FeedbackLedger()
        self.learner = learner or MemoryPatternLearner()
        self.recommender = recommender or PolicyRecommendationEngine()
        self.similarity_limit = max(1, int(similarity_limit))

    def record_feedback(self, feedback: AnalystFeedback) -> None:
        self.feedback.record(feedback)

    def assess(self, incident_or_fingerprint: Mapping[str, Any] | BehaviorFingerprint, limit: int | None = None) -> AdaptiveAssessment:
        matches = self.memory_store.search_similar_incidents(incident_or_fingerprint, limit=limit or self.similarity_limit)
        if not matches:
            return AdaptiveAssessment(
                adaptive_score=0.0,
                confidence=0.0,
                recurrence_score=0.0,
                similar_incident_count=0,
                reasons=["no similar immune-memory incidents found"],
            )
        strongest = matches[0]
        pattern_key = str(strongest.get("pattern_key") or "")
        feedback_adjustment = self.feedback.confidence_adjustment(pattern_key)
        average_similarity = sum(float(item.get("similarity_score", 0.0)) for item in matches) / len(matches)
        average_confidence = sum(float(item.get("confidence_score", 0.0)) for item in matches) / len(matches)
        recurrence_score = max(float(item.get("recurrence_score", 0.0)) for item in matches)
        confidence = max(0.0, min(100.0, average_confidence + feedback_adjustment))
        adaptive_score = max(0.0, min(100.0, (0.45 * average_similarity) + (0.35 * confidence) + (0.20 * recurrence_score)))
        patterns = self.learn_patterns(matches)
        recommendations = self.recommender.recommend(patterns, self.feedback)
        reasons = [
            f"matched {len(matches)} immune-memory incident(s)",
            f"average similarity {average_similarity:.2f}",
            f"feedback adjustment {feedback_adjustment:.2f}",
        ]
        return AdaptiveAssessment(
            adaptive_score=round(adaptive_score, 2),
            confidence=round(confidence, 2),
            recurrence_score=round(recurrence_score, 2),
            similar_incident_count=len(matches),
            top_matches=matches,
            recommendations=recommendations,
            reasons=reasons,
        )

    def learn_patterns(self, memory_rows: list[Mapping[str, Any]] | None = None) -> list[LearnedPattern]:
        rows = list(memory_rows) if memory_rows is not None else self._recent_memory_rows()
        return self.learner.learn(rows)

    def _recent_memory_rows(self, limit: int = 1000) -> list[dict[str, Any]]:
        rows = []
        for row in self.memory_store._recent_memory_rows(limit):
            item = dict(row)
            for field in ("fingerprint", "attack_graph", "timeline", "evidence"):
                item[field] = json.loads(item[field])
            rows.append(item)
        return rows

    @staticmethod
    def incident_payload(incident: Any) -> dict[str, Any]:
        return asdict(incident) if is_dataclass(incident) else dict(incident)
