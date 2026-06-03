"""Real-time filesystem monitoring built on watchdog."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Iterable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from core.event_queue import SecurityEvent, SecurityEventQueue


def ensure_watch_path(path: str | Path) -> Path:
    watch_path = Path(path)
    watch_path.mkdir(parents=True, exist_ok=True)
    return watch_path


class FileEventHandler(FileSystemEventHandler):
    """Publishes watchdog filesystem events to the security event queue."""

    def __init__(self, event_queue: SecurityEventQueue):
        super().__init__()
        self.event_queue = event_queue

    def on_any_event(self, event: FileSystemEvent) -> None:
        self.event_queue.publish(
            SecurityEvent(
                event_type=f"file.{event.event_type}",
                source="watchdog",
                payload={
                    "src_path": event.src_path,
                    "dest_path": getattr(event, "dest_path", None),
                    "is_directory": event.is_directory,
                },
            )
        )


class FileSystemEventCollector:
    """Manages watchdog observers for configured paths."""

    def __init__(self, event_queue: SecurityEventQueue, paths: Iterable[str | Path], recursive: bool = True):
        self.event_queue = event_queue
        self.paths = [ensure_watch_path(path) for path in paths]
        self.recursive = recursive
        self.handler = FileEventHandler(event_queue)
        self.observer = Observer()
        self.started = False

    def start(self) -> None:
        if self.started:
            return
        for path in self.paths:
            self.observer.schedule(self.handler, str(path), recursive=self.recursive)
        self.observer.start()
        self.started = True

    def stop(self, timeout: float = 5.0) -> None:
        if not self.started:
            return
        self.observer.stop()
        self.observer.join(timeout)
        self.started = False

    def __enter__(self) -> "FileSystemEventCollector":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def wait_for_events(self, minimum: int = 1, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.event_queue.qsize() >= minimum:
                return True
            time.sleep(0.05)
        return self.event_queue.qsize() >= minimum
