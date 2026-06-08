from __future__ import annotations

import logging
import threading

import pytest
from watchdog.events import FileCreatedEvent

from core.event_queue import DropPolicy, SecurityEvent, SecurityEventQueue
from core.orchestrator import ImmuneSystemOrchestrator
from monitor.etw_monitor import ETWProvider, WindowsETWCollector
from monitor.file_monitor import FileEventHandler, FileSystemEventCollector
from monitor.process_monitor import ProcessSnapshot
from monitor.realtime_monitor import RealTimeProcessMonitor
from service_windows import run_service_foreground


class SequenceProcessMonitor:
    def __init__(self, snapshots):
        self.snapshots = list(snapshots)

    def snapshot(self):
        return self.snapshots.pop(0)


def test_realtime_monitor_uses_pid_and_create_time_for_identity():
    monitor = RealTimeProcessMonitor(
        SequenceProcessMonitor(
            [
                [ProcessSnapshot(pid=7, name="old", create_time=1.0)],
                [ProcessSnapshot(pid=7, name="new", create_time=2.0)],
            ]
        ),
        poll_interval=0.01,
        seed_baseline=True,
    )

    assert monitor.poll_events() == []
    events = monitor.poll_events()

    assert [event.event_type for event in events] == ["stopped", "started"]
    assert events[0].identity == (7, 1.0)
    assert events[1].identity == (7, 2.0)


def test_realtime_monitor_seeds_baseline_to_prevent_startup_flood():
    monitor = RealTimeProcessMonitor(
        SequenceProcessMonitor([[ProcessSnapshot(pid=i, name=f"p{i}", create_time=float(i)) for i in range(100)]]),
        poll_interval=0.01,
        seed_baseline=True,
    )

    assert monitor.poll_events() == []


def test_security_event_queue_drop_oldest_preserves_higher_priority_event():
    event_queue = SecurityEventQueue(maxsize=1, drop_policy=DropPolicy.DROP_OLDEST)

    assert event_queue.publish(SecurityEvent("low", "test", priority=1))
    assert event_queue.publish(SecurityEvent("high", "test", priority=10))

    assert event_queue.drain(1)[0].event_type == "high"
    assert event_queue.metrics().dropped_oldest == 1


def test_security_event_queue_rejects_unbounded_size():
    with pytest.raises(ValueError):
        SecurityEventQueue(maxsize=0)


def test_security_event_queue_counters_are_thread_safe_under_contention():
    event_queue = SecurityEventQueue(maxsize=1, drop_policy=DropPolicy.DROP_NEWEST)
    event_queue.publish(SecurityEvent("seed", "test"))

    def publish_many():
        for _ in range(100):
            event_queue.publish(SecurityEvent("overflow", "test"))

    threads = [threading.Thread(target=publish_many) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert event_queue.metrics().dropped_newest == 500


def test_file_event_handler_rate_limits_and_tracks_drops(tmp_path):
    event_queue = SecurityEventQueue(maxsize=100)
    handler = FileEventHandler(event_queue, max_events_per_second=1, coalesce_window_seconds=0)

    assert handler.to_security_event(FileCreatedEvent(str(tmp_path / "a.txt"))) is not None
    assert handler.to_security_event(FileCreatedEvent(str(tmp_path / "b.txt"))) is None
    assert handler.dropped_events == 1


def test_file_event_handler_coalesces_duplicate_events(tmp_path):
    event_queue = SecurityEventQueue(maxsize=100)
    handler = FileEventHandler(event_queue, max_events_per_second=10, coalesce_window_seconds=10)
    event = FileCreatedEvent(str(tmp_path / "a.txt"))

    assert handler.to_security_event(event) is not None
    assert handler.to_security_event(event) is None
    assert handler.coalesced_events == 1


def test_file_collector_does_not_create_missing_paths_by_default(tmp_path):
    with pytest.raises(FileNotFoundError):
        FileSystemEventCollector(SecurityEventQueue(), [tmp_path / "missing"])


def test_etw_collector_does_not_claim_ready_without_backend(monkeypatch):
    event_queue = SecurityEventQueue()
    collector = WindowsETWCollector(event_queue, {"etw": {"enabled": True}})
    monkeypatch.setattr(collector, "supported", lambda: True)
    monkeypatch.setattr(collector, "dependency_available", lambda: True)

    assert collector.start() == "backend_unavailable"
    assert event_queue.drain(1) == []


def test_etw_collector_backend_can_start_and_ingest():
    class FakeBackend:
        def __init__(self):
            self.started = False
            self.stopped = False

        def start(self, providers: list[ETWProvider], collector: WindowsETWCollector) -> None:
            self.started = True
            collector.ingest_event(providers[0].name, 1, {"pid": 1})

        def stop(self) -> None:
            self.stopped = True

    event_queue = SecurityEventQueue(maxsize=10)
    backend = FakeBackend()
    collector = WindowsETWCollector(event_queue, {"etw": {"enabled": True}}, backend=backend)
    collector.supported = lambda: True  # type: ignore[method-assign]
    collector.dependency_available = lambda: True  # type: ignore[method-assign]

    assert collector.start() == "collecting"
    collector.stop()
    events = event_queue.drain(10)

    assert backend.started and backend.stopped
    assert any(event.event_type == "etw.event" for event in events)
    assert events[0].payload["data"]["pid"] == 1


def test_orchestrator_forces_dry_run_even_if_config_disables_it(tmp_path):
    orchestrator = ImmuneSystemOrchestrator(
        {
            "database": {"path": str(tmp_path / "history.sqlite3")},
            "response": {"dry_run": False},
            "filesystem": {"enabled": False, "watch_paths": []},
            "event_queue": {"maxsize": 10},
        },
        logging.getLogger("test.phase_v2"),
    )

    assert orchestrator.config["response"]["dry_run"] is True
    assert orchestrator.isolation.dry_run is True


def test_service_foreground_forces_dry_run_config(tmp_path, monkeypatch):
    captured = {}

    class FakeOrchestrator:
        def __init__(self, config, logger):
            captured["config"] = config

        def run_event_loop(self, max_iterations=None, stop_event=None):
            captured["max_iterations"] = max_iterations

    config_file = tmp_path / "config.json"
    config_file.write_text('{"response": {"dry_run": false}, "logging": {"file": "test.log"}}', encoding="utf-8")
    monkeypatch.setattr("service_windows.ImmuneSystemOrchestrator", FakeOrchestrator)

    run_service_foreground(str(config_file), max_iterations=1)

    assert captured["config"]["response"]["dry_run"] is True
    assert captured["max_iterations"] == 1
