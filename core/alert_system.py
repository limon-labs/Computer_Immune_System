"""Alert formatting and dispatch."""

from __future__ import annotations

import logging

from adaptive.threat_scoring import ThreatEvent, ThreatSignal


class AlertSystem:
    """Emits structured alerts through the configured logger."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def emit(self, event: ThreatEvent) -> None:
        self.logger.warning(
            "Threat %s pid=%s name=%s score=%.2f action=%s reasons=%s",
            event.severity,
            event.pid,
            event.process_name,
            event.threat_score,
            event.action,
            "; ".join(event.reasons) or "none",
        )

    def emit_signal(self, signal: ThreatSignal) -> None:
        self.logger.warning(
            "Signal %s type=%s pid=%s score=%.2f reasons=%s",
            signal.severity,
            signal.signal_type,
            signal.pid,
            signal.threat_score,
            "; ".join(signal.reasons) or "none",
        )
