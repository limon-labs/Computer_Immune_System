from __future__ import annotations

from monitor.process_monitor import ProcessSnapshot
from monitor.realtime_monitor import RealTimeProcessMonitor


class FakeProcessMonitor:
    def __init__(self):
        self.snapshots = [
            [ProcessSnapshot(pid=1, name="a", command_line="a")],
            [ProcessSnapshot(pid=1, name="a", command_line="a --new"), ProcessSnapshot(pid=2, name="b")],
            [ProcessSnapshot(pid=2, name="b")],
        ]

    def snapshot(self):
        return self.snapshots.pop(0)


def test_realtime_monitor_emits_lifecycle_deltas():
    monitor = RealTimeProcessMonitor(FakeProcessMonitor(), poll_interval=0.01, seed_baseline=False)

    first = monitor.poll_events()
    second = monitor.poll_events()
    third = monitor.poll_events()

    assert [event.event_type for event in first] == ["started"]
    assert sorted(event.event_type for event in second) == ["changed", "started"]
    assert [event.event_type for event in third] == ["stopped"]
