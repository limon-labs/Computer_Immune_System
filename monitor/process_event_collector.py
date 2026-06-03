"""Process lifecycle collector that publishes normalized security events."""

from __future__ import annotations

from dataclasses import asdict

from core.event_queue import SecurityEvent, SecurityEventQueue
from monitor.realtime_monitor import ProcessLifecycleEvent, RealTimeProcessMonitor


class ProcessEventCollector:
    """Converts real-time process lifecycle deltas into queue events."""

    def __init__(self, realtime_monitor: RealTimeProcessMonitor, event_queue: SecurityEventQueue):
        self.realtime_monitor = realtime_monitor
        self.event_queue = event_queue

    def poll_once(self) -> list[SecurityEvent]:
        events = [self._to_security_event(event) for event in self.realtime_monitor.poll_events()]
        self.event_queue.extend(events)
        return events

    @staticmethod
    def _to_security_event(event: ProcessLifecycleEvent) -> SecurityEvent:
        payload = {
            "pid": event.pid,
            "lifecycle_event": event.event_type,
        }
        if event.snapshot is not None:
            payload["snapshot"] = asdict(event.snapshot)
        if event.previous is not None:
            payload["previous"] = asdict(event.previous)
        return SecurityEvent(
            event_type=f"process.{event.event_type}",
            source="process_monitor",
            payload=payload,
        )
