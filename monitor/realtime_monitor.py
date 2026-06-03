"""Portable real-time process lifecycle monitoring."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Iterable

from monitor.process_monitor import ProcessMonitor, ProcessSnapshot


@dataclass(frozen=True, slots=True)
class ProcessLifecycleEvent:
    """Process lifecycle delta emitted by RealTimeProcessMonitor."""

    event_type: str
    snapshot: ProcessSnapshot | None = None
    pid: int | None = None
    previous: ProcessSnapshot | None = None


class RealTimeProcessMonitor:
    """Polls process snapshots and emits lifecycle deltas.

    Native OS process event APIs differ significantly across platforms. This
    class provides a deterministic portable real-time mode by maintaining a PID
    cache and emitting start, stop, and significant-change events every poll.
    """

    def __init__(self, process_monitor: ProcessMonitor, poll_interval: float = 1.0):
        self.process_monitor = process_monitor
        self.poll_interval = poll_interval
        self._known: dict[int, ProcessSnapshot] = {}

    def poll_events(self) -> list[ProcessLifecycleEvent]:
        current = {snapshot.pid: snapshot for snapshot in self.process_monitor.snapshot()}
        events: list[ProcessLifecycleEvent] = []

        for pid, snapshot in current.items():
            previous = self._known.get(pid)
            if previous is None:
                events.append(ProcessLifecycleEvent("started", snapshot=snapshot, pid=pid))
            elif self._significant_change(previous, snapshot):
                events.append(ProcessLifecycleEvent("changed", snapshot=snapshot, pid=pid, previous=previous))

        for pid, previous in self._known.items():
            if pid not in current:
                events.append(ProcessLifecycleEvent("stopped", pid=pid, previous=previous))

        self._known = current
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
