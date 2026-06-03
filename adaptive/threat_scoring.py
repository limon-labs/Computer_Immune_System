"""Threat scoring and severity classification."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from detection.anomaly_detector import AnomalyFinding
from core.policy_engine import PolicyDecision
from detection.heuristic_analysis import BehaviorFinding
from monitor.process_monitor import ProcessSnapshot


@dataclass(slots=True)
class ThreatEvent:
    observed_at: str
    pid: int
    process_name: str
    executable: str | None
    command_line: str
    create_time: float | None
    anomaly_score: float
    behavior_score: float
    threat_score: float
    severity: str
    policy_action: str = "monitor"
    reasons: list[str] = field(default_factory=list)
    action: str = "none"


class ThreatScorer:
    """Combines ML anomaly and behavioral findings into one risk score."""

    def score(
        self,
        snapshot: ProcessSnapshot,
        anomaly: AnomalyFinding,
        behavior: BehaviorFinding,
        policy: PolicyDecision | None = None,
    ) -> ThreatEvent:
        policy = policy or PolicyDecision()
        combined = min(100.0, (0.55 * behavior.score) + (0.45 * anomaly.score))
        if behavior.score >= 70 and anomaly.is_anomaly:
            combined = min(100.0, combined + 15.0)
        combined = max(policy.score_floor, combined + policy.score_adjustment)
        combined = max(0.0, min(100.0, combined))
        severity = self._severity(combined)
        return ThreatEvent(
            observed_at=datetime.now(timezone.utc).isoformat(),
            pid=snapshot.pid,
            process_name=snapshot.name,
            executable=snapshot.executable,
            command_line=snapshot.command_line,
            create_time=snapshot.create_time,
            anomaly_score=round(anomaly.score, 2),
            behavior_score=round(behavior.score, 2),
            threat_score=round(combined, 2),
            severity=severity,
            policy_action=policy.action,
            reasons=[*policy.reasons, *behavior.reasons, *anomaly.reasons],
        )

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 85:
            return "critical"
        if score >= 65:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "informational"
