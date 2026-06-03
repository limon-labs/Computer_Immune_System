from __future__ import annotations

from core.event_queue import SecurityEvent, SecurityEventQueue
from monitor.etw_monitor import WindowsETWCollector
from monitor.process_event_collector import ProcessEventCollector
from monitor.process_monitor import ProcessSnapshot
from monitor.realtime_monitor import RealTimeProcessMonitor


class FakeProcessMonitor:
    def __init__(self):
        self.snapshots = [[ProcessSnapshot(pid=10, name="demo", command_line="demo")]]

    def snapshot(self):
        return self.snapshots.pop(0)


def test_event_queue_tracks_dropped_events_when_full():
    event_queue = SecurityEventQueue(maxsize=1)

    assert event_queue.publish(SecurityEvent("one", "test"))
    assert not event_queue.publish(SecurityEvent("two", "test"))
    assert event_queue.dropped_events == 1


def test_process_event_collector_publishes_started_event():
    event_queue = SecurityEventQueue()
    collector = ProcessEventCollector(RealTimeProcessMonitor(FakeProcessMonitor(), poll_interval=0.01, seed_baseline=False), event_queue)

    events = collector.poll_once()
    drained = event_queue.drain(10)

    assert events[0].event_type == "process.started"
    assert drained[0].payload["snapshot"]["pid"] == 10


def test_etw_collector_reports_unsupported_on_non_windows():
    event_queue = SecurityEventQueue()
    collector = WindowsETWCollector(event_queue, {"etw": {"enabled": True}})

    if collector.supported():
        assert collector.start() in {"backend_unavailable", "missing_pywin32_dependency"}
    else:
        assert collector.start() == "unsupported_platform"


def test_etw_ingest_normalizes_event_payload():
    event_queue = SecurityEventQueue()
    collector = WindowsETWCollector(event_queue, {"etw": {"enabled": False}})

    event = collector.ingest_event("Provider", 1, {"pid": 42})

    assert event.event_type == "etw.event"
    assert event_queue.drain(1)[0].payload["data"]["pid"] == 42
