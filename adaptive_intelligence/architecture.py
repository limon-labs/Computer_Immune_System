"""Declarative architecture map for Phase 6 adaptive intelligence."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ArchitectureComponent:
    """A modular Phase 6 component and its extension responsibility."""

    name: str
    responsibility: str
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Phase6Architecture:
    """High-level Phase 6 architecture without runtime side effects."""

    phase: str
    objective: str
    components: list[ArchitectureComponent]
    safety_model: str


def default_phase6_architecture() -> Phase6Architecture:
    """Return the default additive architecture for Adaptive Immune Intelligence."""

    return Phase6Architecture(
        phase="phase_6_adaptive_immune_intelligence",
        objective="Learn from immune memory and analyst feedback without changing enforcement behavior automatically.",
        safety_model="observe-and-recommend only; existing dry-run response enforcement remains authoritative",
        components=[
            ArchitectureComponent(
                name="ImmuneMemoryStore",
                responsibility="Provide long-term incidents, attack graphs, timelines, and behavior fingerprints.",
                inputs=["correlated incidents"],
                outputs=["remembered incidents", "similarity matches"],
            ),
            ArchitectureComponent(
                name="MemoryPatternLearner",
                responsibility="Aggregate repeated immune-memory patterns into reusable learned patterns.",
                inputs=["remembered incidents"],
                outputs=["learned patterns"],
            ),
            ArchitectureComponent(
                name="FeedbackLedger",
                responsibility="Track analyst verdicts and derive confidence adjustments.",
                inputs=["analyst feedback"],
                outputs=["confidence adjustments", "verdict counts"],
            ),
            ArchitectureComponent(
                name="PolicyRecommendationEngine",
                responsibility="Generate explainable policy suggestions without mutating policy files.",
                inputs=["learned patterns", "feedback"],
                outputs=["policy recommendations"],
            ),
            ArchitectureComponent(
                name="AdaptiveIntelligenceEngine",
                responsibility="Combine similarity, recurrence, confidence, feedback, and recommendations into an assessment.",
                inputs=["candidate incident", "immune memory", "feedback"],
                outputs=["adaptive assessment"],
            ),
        ],
    )
