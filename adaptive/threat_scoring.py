"""Threat scoring and severity classification."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.correlation_engine import CorrelatedIncident
from core.event_queue import SecurityEvent
from core.policy_engine import PolicyDecision
from detection.anomaly_detector import AnomalyFinding
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
    file_reputation_score: float = 0.0
    policy_action: str = "monitor"
    reasons: list[str] = field(default_factory=list)
    action: str = "none"


@dataclass(frozen=True, slots=True)
class ThreatSignal:
    observed_at: str
    signal_type: str
    threat_score: float
    severity: str
    reasons: list[str]
    pid: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)


class ThreatScorer:
    """Combines ML anomaly, behavioral findings, and Phase 3 signals."""

    def score(
        self,
        snapshot: ProcessSnapshot,
        anomaly: AnomalyFinding,
        behavior: BehaviorFinding,
        policy: PolicyDecision | None = None,
        signal_boost: float = 0.0,
        file_reputation_score: float = 0.0,
        signal_reasons: list[str] | None = None,
    ) -> ThreatEvent:
        policy = policy or PolicyDecision()
        signal_reasons = signal_reasons or []
        combined = min(100.0, (0.55 * behavior.score) + (0.45 * anomaly.score) + (0.35 * file_reputation_score) + signal_boost)
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
            file_reputation_score=round(file_reputation_score, 2),
            policy_action=policy.action,
            reasons=[*policy.reasons, *behavior.reasons, *anomaly.reasons, *signal_reasons],
        )

    def score_security_event(self, event: SecurityEvent) -> ThreatSignal | None:
        if event.event_type.startswith("registry.startup_value_"):
            score = 45.0 if event.event_type.endswith("created") else 35.0
            return ThreatSignal(
                observed_at=event.observed_at,
                signal_type=event.event_type,
                threat_score=score,
                severity=self._severity(score),
                reasons=["startup registry persistence changed"],
                payload=dict(event.payload),
            )
        if event.event_type in {"file.reputation", "file.integrity_change"}:
            score = float(event.payload.get("file_reputation_score", 0.0))
            pid = event.payload.get("pid")
            return ThreatSignal(
                observed_at=event.observed_at,
                signal_type=event.event_type,
                threat_score=max(0.0, min(100.0, score)),
                severity=self._severity(score),
                reasons=list(event.payload.get("reasons", [])),
                pid=int(pid) if isinstance(pid, int) else None,
                payload=dict(event.payload),
            )
        if event.event_type == "network.connection_opened" and event.payload.get("suspicious_port"):
            score = 40.0
            pid = event.payload.get("pid")
            return ThreatSignal(
                observed_at=event.observed_at,
                signal_type=event.event_type,
                threat_score=score,
                severity=self._severity(score),
                reasons=[f"network connection uses suspicious port {event.payload.get('remote_port')}"],
                pid=int(pid) if isinstance(pid, int) else None,
                payload=dict(event.payload),
            )
        return None

    def score_correlated_incident(self, incident: CorrelatedIncident) -> ThreatSignal:
        return ThreatSignal(
            observed_at=incident.observed_at,
            signal_type=f"correlation.{incident.incident_type}",
            threat_score=min(100.0, 50.0 + incident.score_boost),
            severity=incident.severity,
            reasons=[incident.summary],
            pid=incident.involved_pids[0] if incident.involved_pids else None,
            payload={
                "incident_type": incident.incident_type,
                "event_types": incident.event_types,
                "evidence": incident.evidence,
            },
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
