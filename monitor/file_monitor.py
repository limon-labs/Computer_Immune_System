"""Real-time filesystem monitoring built on watchdog."""

from __future__ import annotations

import fnmatch
import hashlib
import platform
import subprocess
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from core.event_queue import SecurityEvent, SecurityEventQueue


def ensure_watch_path(path: str | Path, create_missing: bool = False) -> Path:
    watch_path = Path(path)
    if create_missing:
        watch_path.mkdir(parents=True, exist_ok=True)
    if not watch_path.exists():
        raise FileNotFoundError(f"watch path does not exist: {watch_path}")
    return watch_path


class FileEventHandler(FileSystemEventHandler):
    """Publishes watchdog filesystem events to the security event queue."""

    def __init__(
        self,
        event_queue: SecurityEventQueue,
        allowed_event_types: Iterable[str] | None = None,
        ignored_patterns: Iterable[str] | None = None,
        max_events_per_second: int = 500,
        coalesce_window_seconds: float = 0.25,
    ):
        super().__init__()
        self.event_queue = event_queue
        self.allowed_event_types = set(allowed_event_types or {"created", "modified", "deleted", "moved"})
        self.ignored_patterns = [str(pattern) for pattern in (ignored_patterns or [])]
        self.max_events_per_second = max(1, int(max_events_per_second))
        self.coalesce_window_seconds = max(0.0, float(coalesce_window_seconds))
        self.dropped_events = 0
        self.coalesced_events = 0
        self._recent_timestamps: deque[float] = deque()
        self._last_seen: dict[tuple[str, str | None, str], float] = {}
        self._lock = threading.RLock()

    def on_any_event(self, event: FileSystemEvent) -> None:
        security_event = self.to_security_event(event)
        if security_event is None:
            return
        if not self.event_queue.publish(security_event):
            with self._lock:
                self.dropped_events += 1

    def to_security_event(self, event: FileSystemEvent) -> SecurityEvent | None:
        now = time.monotonic()
        src_path = event.src_path
        dest_path = getattr(event, "dest_path", None)
        with self._lock:
            if event.event_type not in self.allowed_event_types:
                return None
            if self._ignored(src_path) or (dest_path and self._ignored(dest_path)):
                return None
            if not self._within_rate_limit(now):
                self.dropped_events += 1
                return None
            key = (src_path, dest_path, event.event_type)
            last_seen = self._last_seen.get(key)
            if last_seen is not None and now - last_seen < self.coalesce_window_seconds:
                self.coalesced_events += 1
                return None
            self._last_seen[key] = now
        return SecurityEvent(
            event_type=f"file.{event.event_type}",
            source="watchdog",
            payload={
                "src_path": src_path,
                "dest_path": dest_path,
                "is_directory": event.is_directory,
            },
            priority=3,
        )

    def _ignored(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, pattern) for pattern in self.ignored_patterns)

    def _within_rate_limit(self, now: float) -> bool:
        while self._recent_timestamps and now - self._recent_timestamps[0] >= 1.0:
            self._recent_timestamps.popleft()
        if len(self._recent_timestamps) >= self.max_events_per_second:
            return False
        self._recent_timestamps.append(now)
        return True


class FileSystemEventCollector:
    """Manages watchdog observers for configured paths."""

    def __init__(
        self,
        event_queue: SecurityEventQueue,
        paths: Iterable[str | Path],
        recursive: bool = True,
        create_missing: bool = False,
        allowed_event_types: Iterable[str] | None = None,
        ignored_patterns: Iterable[str] | None = None,
        max_events_per_second: int = 500,
        coalesce_window_seconds: float = 0.25,
    ):
        self.event_queue = event_queue
        self.paths = [ensure_watch_path(path, create_missing=create_missing) for path in paths]
        self.recursive = recursive
        self.handler = FileEventHandler(
            event_queue,
            allowed_event_types=allowed_event_types,
            ignored_patterns=ignored_patterns,
            max_events_per_second=max_events_per_second,
            coalesce_window_seconds=coalesce_window_seconds,
        )
        self.observer: Observer | None = None
        self.started = False
        self._lock = threading.RLock()

    def start(self) -> None:
        with self._lock:
            if self.started:
                return
            self.observer = Observer()
            for path in self.paths:
                self.observer.schedule(self.handler, str(path), recursive=self.recursive)
            self.observer.start()
            self.started = True

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            if not self.started or self.observer is None:
                return
            observer = self.observer
            observer.stop()
            observer.join(timeout)
            self.observer = None
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


@dataclass(frozen=True, slots=True)
class ExecutableFileMetadata:
    """Stable metadata collected for an executable used by a process."""

    file_path: str
    file_size: int
    creation_time: float
    modification_time: float
    sha256: str | None
    signature_status: str
    pid: int | None
    process_create_time: float | None
    observed_at: str


class ExecutableFileCollector:
    """Collect and publish executable metadata for process snapshots."""

    def __init__(
        self,
        event_queue: SecurityEventQueue,
        hash_algorithm: str = "sha256",
        signature_verifier=None,
        chunk_size: int = 1024 * 1024,
    ):
        if hash_algorithm.lower() != "sha256":
            raise ValueError("Phase 4 currently supports only sha256")
        self.event_queue = event_queue
        self.hash_algorithm = hash_algorithm.lower()
        self.signature_verifier = signature_verifier or executable_signature_status
        self.chunk_size = max(4096, int(chunk_size))
        self.dropped_events = 0

    def inspect(self, executable: str | Path | None, pid: int | None = None, process_create_time: float | None = None) -> SecurityEvent | None:
        metadata = self.collect(executable, pid=pid, process_create_time=process_create_time)
        if metadata is None:
            return None
        return SecurityEvent(
            event_type="file.executable_observed",
            source="executable_file_monitor",
            payload=asdict(metadata),
            priority=5,
        )

    def publish(self, executable: str | Path | None, pid: int | None = None, process_create_time: float | None = None) -> SecurityEvent | None:
        event = self.inspect(executable, pid=pid, process_create_time=process_create_time)
        if event is None:
            return None
        if not self.event_queue.publish(event):
            self.dropped_events += 1
            return None
        return event

    def collect(self, executable: str | Path | None, pid: int | None = None, process_create_time: float | None = None) -> ExecutableFileMetadata | None:
        if not executable:
            return None
        path = Path(executable)
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_file():
                return None
            stat_before = resolved.stat()
            digest = hashlib.new(self.hash_algorithm)
            with resolved.open("rb") as handle:
                for chunk in iter(lambda: handle.read(self.chunk_size), b""):
                    digest.update(chunk)
            stat_after = resolved.stat()
            if (stat_before.st_size, stat_before.st_mtime_ns) != (stat_after.st_size, stat_after.st_mtime_ns):
                return None
        except (OSError, PermissionError, ValueError):
            return None
        return ExecutableFileMetadata(
            file_path=str(resolved),
            file_size=int(stat_after.st_size),
            creation_time=float(stat_after.st_ctime),
            modification_time=float(stat_after.st_mtime),
            sha256=digest.hexdigest(),
            signature_status=str(self.signature_verifier(resolved)),
            pid=pid,
            process_create_time=process_create_time,
            observed_at=datetime.now(timezone.utc).isoformat(),
        )


def executable_signature_status(path: Path) -> str:
    """Return Authenticode status on Windows and ``unknown`` elsewhere.

    PowerShell is invoked without a shell and receives the path as a positional
    argument, avoiding command interpolation. Failure is treated as unknown,
    never as proof that a file is unsigned.
    """

    if platform.system().lower() != "windows":
        return "unknown"
    command = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "(Get-AuthenticodeSignature -LiteralPath $args[0]).Status.ToString()",
        str(path),
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    status = result.stdout.strip().lower()
    if status == "valid":
        return "signed"
    if status == "notsigned":
        return "unsigned"
    if status in {"hashmismatch", "nottrusted"}:
        return "invalid"
    return "unknown"
