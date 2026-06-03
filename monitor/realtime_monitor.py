"""Portable real-time process lifecycle monitoring."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable

from monitor.process_monitor import ProcessMonitor, ProcessSnapshot


ProcessIdentity = tuple[int, float | None]


@dataclass(frozen=True, slots=True)
class ProcessLifecycleEvent:
    """Process lifecycle delta emitted by RealTimeProcessMonitor."""

    event_type: str
    snapshot: ProcessSnapshot | None = None
    pid: int | None = None
    previous: ProcessSnapshot | None = None
    identity: ProcessIdentity | None = None


class RealTimeProcessMonitor:
    """Polls process snapshots and emits lifecycle deltas.

    Process identity uses PID plus create_time to avoid conflating different
    processes after PID reuse. The first poll seeds a baseline by default to
    avoid startup event floods.
    """

    def __init__(self, process_monitor: ProcessMonitor, poll_interval: float = 1.0, seed_baseline: bool = True):
        if poll_interval <= 0:
            raise ValueError("poll_interval must be > 0")
        self.process_monitor = process_monitor
        self.poll_interval = poll_interval
        self.seed_baseline = seed_baseline
        self._known: dict[ProcessIdentity, ProcessSnapshot] = {}
        self._initialized = False
        self._lock = threading.RLock()

    def poll_events(self) -> list[ProcessLifecycleEvent]:
        snapshots = self.process_monitor.snapshot()
        current = {self.identity(snapshot): snapshot for snapshot in snapshots}
        events: list[ProcessLifecycleEvent] = []

        with self._lock:
            if self.seed_baseline and not self._initialized:
                self._known = current
                self._initialized = True
                return []

            known_by_pid = {identity[0]: (identity, snapshot) for identity, snapshot in self._known.items()}
            current_by_pid = {identity[0]: (identity, snapshot) for identity, snapshot in current.items()}

            for identity, snapshot in current.items():
                previous = self._known.get(identity)
                if previous is None:
                    old_for_pid = known_by_pid.get(identity[0])
                    if old_for_pid is not None and old_for_pid[0] not in current:
                        events.append(ProcessLifecycleEvent("stopped", pid=identity[0], previous=old_for_pid[1], identity=old_for_pid[0]))
                    events.append(ProcessLifecycleEvent("started", snapshot=snapshot, pid=identity[0], identity=identity))
                elif self._significant_change(previous, snapshot):
                    events.append(ProcessLifecycleEvent("changed", snapshot=snapshot, pid=identity[0], previous=previous, identity=identity))

            for identity, previous in self._known.items():
                if identity not in current and identity[0] not in current_by_pid:
                    events.append(ProcessLifecycleEvent("stopped", pid=identity[0], previous=previous, identity=identity))

            self._known = current
            self._initialized = True
        return events

    def watch(self, callback: Callable[[ProcessLifecycleEvent], None], max_iterations: int | None = None) -> None:
        iterations = 0
        while max_iterations is None or iterations < max_iterations:
            for event in self.poll_events():
                callback(event)
            iterations += 1
            time.sleep(self.poll_interval)

    @staticmethod
    def interesting_snapshots(events: Iterable[ProcessLifecycleEvent]) -> list[ProcessSnapshot]:
        return [event.snapshot for event in events if event.snapshot is not None and event.event_type in {"started", "changed"}]

    @staticmethod
    def identity(snapshot: ProcessSnapshot) -> ProcessIdentity:
        return (snapshot.pid, snapshot.create_time)

    @staticmethod
    def _significant_change(previous: ProcessSnapshot, current: ProcessSnapshot) -> bool:
        if previous.executable != current.executable or previous.command_line != current.command_line:
            return True
        if abs(current.cpu_percent - previous.cpu_percent) >= 50:
            return True
        if abs(current.memory_percent - previous.memory_percent) >= 10:
            return True
        if set(previous.listening_ports) != set(current.listening_ports):
            return True
        return False
