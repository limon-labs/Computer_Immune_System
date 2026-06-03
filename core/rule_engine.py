"""Simple policy rule evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from adaptive.threat_scoring import ThreatEvent


@dataclass(frozen=True, slots=True)
class RuleDecision:
    should_record: bool
    should_alert: bool
    should_respond: bool


class RuleEngine:
    """Converts threat events into record/alert/response decisions."""

    def __init__(self, record_threshold: float = 20.0, alert_threshold: float = 40.0, response_threshold: float = 85.0):
        self.record_threshold = record_threshold
        self.alert_threshold = alert_threshold
        self.response_threshold = response_threshold

    def decide(self, event: ThreatEvent) -> RuleDecision:
        return RuleDecision(
            should_record=event.threat_score >= self.record_threshold,
            should_alert=event.threat_score >= self.alert_threshold,
            should_respond=event.threat_score >= self.response_threshold,
        )

    def filter_events(self, events: Iterable[ThreatEvent]) -> list[ThreatEvent]:
        return [event for event in events if self.decide(event).should_record]
