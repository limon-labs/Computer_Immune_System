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
from adaptive_intelligence.digital_dna import DigitalDNAEngine


class AdaptiveIntelligenceEngine:
    """Combines immune memory, feedback, and pattern learning without enforcing policy."""

    def __init__(
        self,
        memory_store: ImmuneMemoryStore,
        feedback: FeedbackLedger | None = None,
        learner: MemoryPatternLearner | None = None,
        recommender: PolicyRecommendationEngine | None = None,
        similarity_limit: int = 10,
        digital_dna_engine: DigitalDNAEngine | None = None,
    ):
        self.memory_store = memory_store
        self.feedback = feedback or FeedbackLedger()
        self.learner = learner or MemoryPatternLearner()
        self.recommender = recommender or PolicyRecommendationEngine()
        self.similarity_limit = max(1, int(similarity_limit))
        self.digital_dna_engine = digital_dna_engine

    def record_feedback(self, feedback: AnalystFeedback) -> None:
        self.feedback.record(feedback)

    def assess(self, incident_or_fingerprint: Mapping[str, Any] | BehaviorFingerprint, limit: int | None = None) -> AdaptiveAssessment:
        matches = self.memory_store.search_similar_incidents(incident_or_fingerprint, limit=limit or self.similarity_limit)
        dna_matches = self._digital_dna_matches(incident_or_fingerprint)
        if not matches:
            reasons = ["no similar immune-memory incidents found"]
            if dna_matches:
                reasons.append(f"matched {len(dna_matches)} digital DNA profile(s)")
            return AdaptiveAssessment(
                adaptive_score=round(max((item["digital_dna"]["similarity_score"] for item in dna_matches), default=0.0), 2),
                confidence=round(max((item["digital_dna"]["confidence"] for item in dna_matches), default=0.0), 2),
                recurrence_score=0.0,
                similar_incident_count=0,
                top_matches=dna_matches,
                reasons=reasons,
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
        if dna_matches:
            reasons.append(f"matched {len(dna_matches)} digital DNA profile(s)")
        return AdaptiveAssessment(
            adaptive_score=round(adaptive_score, 2),
            confidence=round(confidence, 2),
            recurrence_score=round(recurrence_score, 2),
            similar_incident_count=len(matches),
            top_matches=[*matches, *dna_matches],
            recommendations=recommendations,
            reasons=reasons,
        )

    def _digital_dna_matches(self, incident_or_fingerprint: Mapping[str, Any] | BehaviorFingerprint) -> list[dict[str, Any]]:
        if self.digital_dna_engine is None or not isinstance(incident_or_fingerprint, Mapping):
            return []
        if not (incident_or_fingerprint.get("executable") or incident_or_fingerprint.get("file_path") or incident_or_fingerprint.get("pid")):
            return []
        dna = self.digital_dna_engine.update_dna(incident_or_fingerprint)
        return [{"digital_dna": item} for item in self.digital_dna_engine.find_similar_dna(dna, limit=3)]

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
