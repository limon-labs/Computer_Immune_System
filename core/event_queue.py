"""Bounded event queue shared by telemetry collectors and detection engine."""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Iterable, Mapping


class DropPolicy(StrEnum):
    """Overflow behavior for SecurityEventQueue."""

    DROP_NEWEST = "drop_newest"
    DROP_OLDEST = "drop_oldest"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class QueueMetrics:
    """Thread-safe snapshot of event queue counters."""

    queued: int
    published: int
    dropped: int
    dropped_newest: int
    dropped_oldest: int
    blocked: int


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Normalized event emitted by endpoint telemetry collectors."""

    event_type: str
    source: str
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    payload: Mapping[str, Any] = field(default_factory=dict)
    priority: int = 5

    def __post_init__(self) -> None:
        # Freeze only the top-level mapping to prevent accidental mutation after publication.
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))


class SecurityEventQueue:
    """Thread-safe bounded queue with explicit overflow accounting."""

    def __init__(self, maxsize: int = 10_000, drop_policy: str | DropPolicy = DropPolicy.DROP_NEWEST, block_timeout: float = 0.25):
        if maxsize < 1:
            raise ValueError("SecurityEventQueue maxsize must be >= 1")
        self._queue: queue.Queue[SecurityEvent] = queue.Queue(maxsize=maxsize)
        self.drop_policy = DropPolicy(drop_policy)
        self.block_timeout = block_timeout
        self._lock = threading.Lock()
        self._published = 0
        self._dropped_newest = 0
        self._dropped_oldest = 0
        self._blocked = 0

    @property
    def dropped_events(self) -> int:
        return self.metrics().dropped

    def publish(self, event: SecurityEvent) -> bool:
        if self.drop_policy is DropPolicy.BLOCK:
            try:
                self._queue.put(event, block=True, timeout=self.block_timeout)
            except queue.Full:
                self._increment("_dropped_newest")
                return False
            self._increment("_published")
            self._increment("_blocked")
            return True

        try:
            self._queue.put_nowait(event)
            self._increment("_published")
            return True
        except queue.Full:
            if self.drop_policy is DropPolicy.DROP_OLDEST:
                return self._drop_oldest_and_publish(event)
            self._increment("_dropped_newest")
            return False

    def drain(self, limit: int = 100) -> list[SecurityEvent]:
        if limit < 1:
            return []
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

    def metrics(self) -> QueueMetrics:
        with self._lock:
            dropped = self._dropped_newest + self._dropped_oldest
            return QueueMetrics(
                queued=self._queue.qsize(),
                published=self._published,
                dropped=dropped,
                dropped_newest=self._dropped_newest,
                dropped_oldest=self._dropped_oldest,
                blocked=self._blocked,
            )

    def _drop_oldest_and_publish(self, event: SecurityEvent) -> bool:
        try:
            oldest = self._queue.get_nowait()
        except queue.Empty:
            oldest = None
        if oldest is not None and oldest.priority < event.priority:
            self._increment("_dropped_oldest")
            try:
                self._queue.put_nowait(event)
                self._increment("_published")
                return True
            except queue.Full:
                self._increment("_dropped_newest")
                return False
        if oldest is not None:
            # Preserve older event when it is at least as important as the new event.
            try:
                self._queue.put_nowait(oldest)
            except queue.Full:
                pass
        self._increment("_dropped_newest")
        return False

    def _increment(self, attr: str) -> None:
        with self._lock:
            setattr(self, attr, getattr(self, attr) + 1)
