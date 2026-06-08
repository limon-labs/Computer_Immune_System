"""System-wide network monitoring helpers using psutil."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, Mapping

import psutil

from core.event_queue import SecurityEvent, SecurityEventQueue


@dataclass(frozen=True, slots=True)
class NetworkConnectionSnapshot:
    pid: int | None
    local_address: str | None
    local_port: int | None
    remote_address: str | None
    remote_port: int | None
    status: str
    family: str
    type: str
    observed_at: str

    @property
    def identity(self) -> tuple[int | None, str | None, int | None, str | None, int | None, str]:
        return (self.pid, self.local_address, self.local_port, self.remote_address, self.remote_port, self.status)


def active_inet_connections(limit: int = 512):
    """Return active inet connections, capped for predictable scan cost."""

    try:
        return psutil.net_connections(kind="inet")[:limit]
    except (psutil.AccessDenied, OSError):
        return []


def collect_network_snapshots(limit: int = 512) -> list[NetworkConnectionSnapshot]:
    observed_at = datetime.now(timezone.utc).isoformat()
    snapshots: list[NetworkConnectionSnapshot] = []
    for connection in active_inet_connections(limit):
        local_address = connection.laddr.ip if connection.laddr else None
        local_port = int(connection.laddr.port) if connection.laddr else None
        remote_address = connection.raddr.ip if connection.raddr else None
        remote_port = int(connection.raddr.port) if connection.raddr else None
        snapshots.append(
            NetworkConnectionSnapshot(
                pid=connection.pid,
                local_address=local_address,
                local_port=local_port,
                remote_address=remote_address,
                remote_port=remote_port,
                status=str(connection.status),
                family=str(connection.family),
                type=str(connection.type),
                observed_at=observed_at,
            )
        )
    return snapshots


class NetworkEventCollector:
    """Publishes new and changed network connection telemetry."""

    def __init__(
        self,
        event_queue: SecurityEventQueue,
        snapshot_provider: Callable[[], list[NetworkConnectionSnapshot]] | None = None,
        dangerous_ports: Iterable[int] = (),
        seed_baseline: bool = True,
    ):
        self.event_queue = event_queue
        self.snapshot_provider = snapshot_provider or collect_network_snapshots
        self.dangerous_ports = {int(port) for port in dangerous_ports}
        self.seed_baseline = seed_baseline
        self._known: set[tuple[int | None, str | None, int | None, str | None, int | None, str]] = set()
        self._initialized = False
        self.dropped_events = 0

    def poll_once(self) -> list[SecurityEvent]:
        snapshots = self.snapshot_provider()
        current = {snapshot.identity: snapshot for snapshot in snapshots}
        accepted: list[SecurityEvent] = []
        if self.seed_baseline and not self._initialized:
            self._known = set(current)
            self._initialized = True
            return []

        for identity, snapshot in current.items():
            if identity in self._known:
                continue
            event = self._to_event(snapshot)
            if self.event_queue.publish(event):
                accepted.append(event)
            else:
                self.dropped_events += 1

        self._known = set(current)
        self._initialized = True
        return accepted

    def _to_event(self, snapshot: NetworkConnectionSnapshot) -> SecurityEvent:
        suspicious = snapshot.remote_port in self.dangerous_ports if snapshot.remote_port is not None else False
        return SecurityEvent(
            event_type="network.connection_opened",
            source="network_monitor",
            payload={**asdict(snapshot), "suspicious_port": suspicious},
            priority=7 if suspicious else 4,
        )
