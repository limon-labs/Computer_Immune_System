from __future__ import annotations

from adaptive_intelligence import AdaptiveIntelligenceEngine, default_phase6_architecture
from adaptive_intelligence.feedback import FeedbackLedger
from adaptive_intelligence.models import AnalystFeedback
from adaptive_intelligence.pattern_learning import MemoryPatternLearner
from adaptive_intelligence.policy_recommendations import PolicyRecommendationEngine
from core.correlation_engine import CorrelatedIncident
from core.config import load_config
from database.immune_memory import ImmuneMemoryStore


def make_incident(port: int = 4444, pid: int = 123) -> CorrelatedIncident:
    return CorrelatedIncident(
        observed_at="2026-01-01T00:00:00+00:00",
        incident_type="file_persistence_network_attack_chain",
        severity="critical",
        score_boost=50.0,
        involved_pids=[pid],
        event_types=["file.reputation", "registry.startup_value_created", "network.connection_opened"],
        summary="payload persisted and connected out",
        evidence={
            "events": [
                {
                    "event_type": "file.reputation",
                    "source": "test",
                    "observed_at": "2026-01-01T00:00:00+00:00",
                    "payload": {"pid": pid, "file_path": "C:/Users/Alice/Downloads/payload.exe", "is_new": True},
                },
                {
                    "event_type": "registry.startup_value_created",
                    "source": "test",
                    "observed_at": "2026-01-01T00:00:01+00:00",
                    "payload": {"key_path": "HKCU/Run", "value_name": "Updater"},
                },
                {
                    "event_type": "network.connection_opened",
                    "source": "test",
                    "observed_at": "2026-01-01T00:00:02+00:00",
                    "payload": {"pid": pid, "remote_port": port, "suspicious_port": True},
                },
            ]
        },
    )


def test_phase6_architecture_is_modular_and_non_enforcing():
    architecture = default_phase6_architecture()

    names = {component.name for component in architecture.components}
    assert architecture.phase == "phase_6_adaptive_immune_intelligence"
    assert {"ImmuneMemoryStore", "MemoryPatternLearner", "FeedbackLedger", "PolicyRecommendationEngine", "AdaptiveIntelligenceEngine"}.issubset(names)
    assert "recommend" in architecture.safety_model


def test_feedback_ledger_bounds_confidence_adjustments():
    ledger = FeedbackLedger()
    for _ in range(10):
        ledger.record(AnalystFeedback(pattern_key="p1", verdict="false_positive", confidence_delta=-3.0))

    assert ledger.confidence_adjustment("p1") == -50.0
    assert ledger.verdict_counts()["p1"]["false_positive"] == 10


def test_pattern_learner_aggregates_memory_rows(tmp_path):
    memory = ImmuneMemoryStore(tmp_path / "memory.sqlite3")
    first = memory.remember_incident(make_incident(port=4444))
    second = memory.remember_incident(make_incident(port=4444, pid=456))
    rows = memory.search_similar_incidents(make_incident(port=4444), limit=10)

    patterns = MemoryPatternLearner().learn(rows)

    assert patterns[0].pattern_key == first.pattern_key == second.pattern_key
    assert patterns[0].occurrences >= 2
    assert any(feature.startswith("event_type:network.connection_opened") for feature in patterns[0].top_features)


def test_policy_recommendations_are_explainable_and_non_mutating(tmp_path):
    memory = ImmuneMemoryStore(tmp_path / "memory.sqlite3")
    first = memory.remember_incident(make_incident())
    memory.remember_incident(make_incident(pid=456))
    patterns = MemoryPatternLearner().learn(memory.search_similar_incidents(make_incident(), limit=10))
    ledger = FeedbackLedger([AnalystFeedback(pattern_key=first.pattern_key, verdict="true_positive")])

    recommendations = PolicyRecommendationEngine(repeated_pattern_threshold=2).recommend(patterns, ledger)

    assert recommendations
    assert recommendations[0].action == "add_blocklist_candidate"
    assert recommendations[0].pattern_key == first.pattern_key
    assert recommendations[0].evidence["occurrences"] >= 2


def test_adaptive_engine_assesses_similarity_recurrence_and_feedback(tmp_path):
    memory = ImmuneMemoryStore(tmp_path / "memory.sqlite3")
    first = memory.remember_incident(make_incident())
    memory.remember_incident(make_incident(pid=456))
    engine = AdaptiveIntelligenceEngine(memory)
    engine.record_feedback(AnalystFeedback(pattern_key=first.pattern_key, verdict="true_positive", confidence_delta=5.0))

    assessment = engine.assess(make_incident(), limit=5)

    assert assessment.similar_incident_count >= 2
    assert assessment.adaptive_score > 0
    assert assessment.confidence > 0
    assert assessment.recurrence_score > 0
    assert assessment.recommendations
    assert any("matched" in reason for reason in assessment.reasons)


def test_adaptive_engine_handles_no_matches(tmp_path):
    memory = ImmuneMemoryStore(tmp_path / "memory.sqlite3")
    engine = AdaptiveIntelligenceEngine(memory)

    assessment = engine.assess(make_incident(), limit=5)

    assert assessment.adaptive_score == 0.0
    assert assessment.similar_incident_count == 0
    assert assessment.recommendations == []


def test_default_config_exposes_phase6_without_auto_apply():
    config = load_config()

    phase6 = config["adaptive_intelligence"]
    assert phase6["enabled"] is False
    assert phase6["allow_policy_recommendations"] is True
    assert phase6["auto_apply_recommendations"] is False
