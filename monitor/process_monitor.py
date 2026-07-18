"""Efficient process telemetry collection based on psutil."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

import psutil
import hashlib
from pathlib import Path

from core.sanitization import redact_command_line


@dataclass(slots=True)
class ProcessSnapshot:
    """Normalized process telemetry used by detection engines."""

    pid: int
    name: str
    executable: str | None = None
    command_line: str = ""
    username: str | None = None
    status: str | None = None
    create_time: float | None = None
    parent_pid: int | None = None
    parent_name: str | None = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    num_threads: int = 0
    open_files: int = 0
    connections: int = 0
    listening_ports: list[int] = field(default_factory=list)
    remote_ports: list[int] = field(default_factory=list)
    executable_sha256: str | None = None

    def feature_vector(self) -> list[float]:
        """Return numeric features suitable for anomaly detection."""

        return [
            self.cpu_percent,
            self.memory_percent,
            float(self.num_threads),
            float(self.open_files),
            float(self.connections),
            float(len(self.listening_ports)),
            float(len(self.remote_ports)),
            float(len(self.command_line)),
        ]


class ProcessMonitor:
    """Collect process snapshots with one-pass psutil iteration.

    psutil.process_iter(attrs=...) is substantially faster than creating a
    Process object and making separate syscalls for each attribute.
    """

    ATTRS = ["pid", "name", "exe", "cmdline", "username", "status", "create_time", "ppid", "cpu_percent", "memory_percent", "num_threads", "open_files"]

    def __init__(self, config: Mapping[str, Any] | None = None):
        self.config = config or {}
        monitoring_config = self.config.get("monitoring", {}) if isinstance(self.config.get("monitoring"), Mapping) else {}
        self.max_processes = int(monitoring_config.get("max_processes_per_scan", 1000))
        self.connection_sample_limit = int(monitoring_config.get("connection_sample_limit", 256))
        self.open_file_sample_limit = int(monitoring_config.get("open_file_sample_limit", 128))
        self.command_line_max_length = int(monitoring_config.get("command_line_max_length", 4096))
        self.hash_executables = bool(monitoring_config.get("hash_executables", False))

    def snapshot(self) -> list[ProcessSnapshot]:
        """Return a list of current process snapshots."""

        snapshots: list[ProcessSnapshot] = []
        for index, process in enumerate(psutil.process_iter(attrs=self.ATTRS, ad_value=None)):
            if index >= self.max_processes:
                break
            info = process.info
            try:
                snapshots.append(self._snapshot_process(process, info))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return snapshots

    def _snapshot_process(self, process: psutil.Process, info: Mapping[str, Any]) -> ProcessSnapshot:
        connections = self._safe_connections(process)
        listening_ports: list[int] = []
        remote_ports: list[int] = []
        for connection in connections[: self.connection_sample_limit]:
            if connection.laddr and connection.status == psutil.CONN_LISTEN:
                listening_ports.append(int(connection.laddr.port))
            if connection.raddr:
                remote_ports.append(int(connection.raddr.port))

        cmdline = info.get("cmdline") or []
        if isinstance(cmdline, Iterable) and not isinstance(cmdline, str):
            command_line = " ".join(str(part) for part in cmdline)
        else:
            command_line = str(cmdline or "")

        open_files = info.get("open_files") or []
        open_file_count = min(len(open_files), self.open_file_sample_limit)
        command_line = redact_command_line(command_line, self.command_line_max_length)
        parent_pid = self._safe_parent_pid(process, info)
        return ProcessSnapshot(
            pid=int(info.get("pid") or process.pid),
            name=str(info.get("name") or "unknown"),
            executable=info.get("exe"),
            command_line=command_line,
            username=info.get("username"),
            status=info.get("status"),
            create_time=info.get("create_time"),
            parent_pid=parent_pid,
            parent_name=self._safe_parent_name(parent_pid),
            cpu_percent=float(info.get("cpu_percent") or 0.0),
            memory_percent=float(info.get("memory_percent") or 0.0),
            num_threads=int(info.get("num_threads") or 0),
            open_files=open_file_count,
            connections=len(connections),
            listening_ports=list(sorted(set(listening_ports))),
            remote_ports=list(sorted(set(remote_ports))),
            executable_sha256=self._hash_file(info.get("exe")) if self.hash_executables else None,
        )

    @staticmethod
    def _safe_parent_pid(process: psutil.Process, info: Mapping[str, Any]) -> int | None:
        try:
            parent_pid = info.get("ppid")
            if parent_pid is None:
                parent_pid = process.ppid()
            return int(parent_pid) if parent_pid is not None else None
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, ValueError, TypeError):
            return None

    @staticmethod
    def _safe_parent_name(parent_pid: int | None) -> str | None:
        if parent_pid is None:
            return None
        try:
            return psutil.Process(parent_pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    @staticmethod
    def _safe_connections(process: psutil.Process):
        net_connections = getattr(process, "net_connections", None)
        try:
            if net_connections is not None:
                return net_connections(kind="inet")
            return process.connections(kind="inet")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return []


    @staticmethod
    def _hash_file(path: str | None, chunk_size: int = 1024 * 1024) -> str | None:
        if not path:
            return None
        try:
            digest = hashlib.sha256()
            with Path(path).open("rb") as handle:
                for chunk in iter(lambda: handle.read(chunk_size), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except (OSError, PermissionError):
            return None
