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
        self.dropped_events = 0

    def poll_once(self) -> list[SecurityEvent]:
        accepted: list[SecurityEvent] = []
        for lifecycle_event in self.realtime_monitor.poll_events():
            event = self._to_security_event(lifecycle_event)
            if self.event_queue.publish(event):
                accepted.append(event)
            else:
                self.dropped_events += 1
        return accepted

    @staticmethod
    def _to_security_event(event: ProcessLifecycleEvent) -> SecurityEvent:
        payload = {
            "pid": event.pid,
            "identity": event.identity,
            "lifecycle_event": event.event_type,
        }
        if event.snapshot is not None:
            payload["snapshot"] = asdict(event.snapshot)
        if event.previous is not None:
            payload["previous"] = asdict(event.previous)
        priority = 8 if event.event_type in {"started", "changed"} else 4
        return SecurityEvent(
            event_type=f"process.{event.event_type}",
            source="process_monitor",
            payload=payload,
            priority=priority,
        )
