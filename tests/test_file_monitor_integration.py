from __future__ import annotations

from core.event_queue import SecurityEventQueue
from monitor.file_monitor import FileSystemEventCollector


def test_watchdog_file_collector_emits_file_events(tmp_path):
    event_queue = SecurityEventQueue(maxsize=20)
    watch_dir = tmp_path / "watch"

    with FileSystemEventCollector(event_queue, [watch_dir], recursive=True) as collector:
        created = watch_dir / "created.txt"
        created.write_text("hello", encoding="utf-8")
        assert collector.wait_for_events(minimum=1, timeout=5)

    events = event_queue.drain(20)
    assert any(event.event_type.startswith("file.") for event in events)
    assert any("created.txt" in str(event.payload.get("src_path")) for event in events)
