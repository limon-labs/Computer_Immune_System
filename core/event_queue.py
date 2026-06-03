"""Bounded event queue shared by telemetry collectors and detection engine."""

from __future__ import annotations

import queue
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Normalized event emitted by endpoint telemetry collectors."""

    event_type: str
    source: str
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    payload: dict[str, Any] = field(default_factory=dict)


class SecurityEventQueue:
    """Thread-safe bounded queue with explicit drop accounting."""

    def __init__(self, maxsize: int = 10_000):
        self._queue: queue.Queue[SecurityEvent] = queue.Queue(maxsize=maxsize)
        self.dropped_events = 0

    def publish(self, event: SecurityEvent) -> bool:
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            self.dropped_events += 1
            return False

    def drain(self, limit: int = 100) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        for _ in range(limit):
            try:
                events.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return events

    def extend(self, events: Iterable[SecurityEvent]) -> int:
        accepted = 0
        for event in events:
            if self.publish(event):
                accepted += 1
        return accepted

    def qsize(self) -> int:
        return self._queue.qsize()
