"""Simple policy rule evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from adaptive.threat_scoring import ThreatEvent, ThreatSignal


@dataclass(frozen=True, slots=True)
class RuleDecision:
    should_record: bool
    should_alert: bool
    should_respond: bool


class RuleEngine:
    """Converts threat events and Phase 3 signals into decisions."""

    def __init__(self, record_threshold: float = 20.0, alert_threshold: float = 40.0, response_threshold: float = 85.0):
        self.record_threshold = record_threshold
        self.alert_threshold = alert_threshold
        self.response_threshold = response_threshold

    def decide(self, event: ThreatEvent) -> RuleDecision:
        return self._decision_for_score(event.threat_score)

    def decide_signal(self, signal: ThreatSignal) -> RuleDecision:
        # Signals are telemetry-derived in Phase 3; responses remain process-threat-event driven.
        decision = self._decision_for_score(signal.threat_score)
        return RuleDecision(decision.should_record, decision.should_alert, False)

    def filter_events(self, events: Iterable[ThreatEvent]) -> list[ThreatEvent]:
        return [event for event in events if self.decide(event).should_record]

    def _decision_for_score(self, score: float) -> RuleDecision:
        return RuleDecision(
            should_record=score >= self.record_threshold,
            should_alert=score >= self.alert_threshold,
            should_respond=score >= self.response_threshold,
        )
