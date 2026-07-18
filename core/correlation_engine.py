"""Correlate endpoint telemetry into attack-chain incidents."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import threading
from typing import Any

from core.event_queue import SecurityEvent


@dataclass(frozen=True, slots=True)
class CorrelatedIncident:
    observed_at: str
    incident_type: str
    severity: str
    score_boost: float
    involved_pids: list[int] = field(default_factory=list)
    event_types: list[str] = field(default_factory=list)
    summary: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


class CorrelationEngine:
    """In-memory correlation engine for process, file, registry, and network events."""

    def __init__(self, window_seconds: int = 300):
        self.window = timedelta(seconds=window_seconds)
        self.events: list[SecurityEvent] = []
        self._lock = threading.RLock()

    def observe(self, event: SecurityEvent) -> list[CorrelatedIncident]:
        with self._lock:
            self.events.append(event)
            self._prune()
            incidents: list[CorrelatedIncident] = []
            if event.event_type.startswith("registry.startup_value_"):
                incidents.append(self._registry_persistence_incident(event))
            if event.event_type == "network.connection_opened" and event.payload.get("suspicious_port"):
                incidents.append(self._network_suspicious_port_incident(event))
            if event.event_type == "file.integrity_change":
                incidents.append(self._file_integrity_incident(event))
            if event.event_type == "digital_dna.high_similarity":
                incidents.append(self._digital_dna_similarity_incident(event))
            chain = self._process_registry_network_chain(event)
            if chain is not None:
                incidents.append(chain)
            file_chain = self._file_registry_network_chain(event)
            if file_chain is not None:
                incidents.append(file_chain)
            return incidents

    def _registry_persistence_incident(self, event: SecurityEvent) -> CorrelatedIncident:
        return CorrelatedIncident(
            observed_at=datetime.now(timezone.utc).isoformat(),
            incident_type="registry_persistence",
            severity="medium",
            score_boost=25.0,
            event_types=[event.event_type],
            summary=f"Startup registry persistence changed: {event.payload.get('key_path')}\\{event.payload.get('value_name')}",
            evidence={"registry_event": dict(event.payload)},
        )

    def _network_suspicious_port_incident(self, event: SecurityEvent) -> CorrelatedIncident:
        pid = event.payload.get("pid")
        return CorrelatedIncident(
            observed_at=datetime.now(timezone.utc).isoformat(),
            incident_type="suspicious_network_connection",
            severity="medium",
            score_boost=20.0,
            involved_pids=[int(pid)] if isinstance(pid, int) else [],
            event_types=[event.event_type],
            summary=f"Network connection to suspicious port {event.payload.get('remote_port')}",
            evidence={"network_event": dict(event.payload)},
        )


    def _digital_dna_similarity_incident(self, event: SecurityEvent) -> CorrelatedIncident:
        return CorrelatedIncident(
            observed_at=datetime.now(timezone.utc).isoformat(),
            incident_type="digital_dna_similarity",
            severity="medium",
            score_boost=float(event.payload.get("similarity_score", 0.0)) / 2.0,
            event_types=[event.event_type],
            summary="Digital DNA resembles a known behavioral identity",
            evidence={"digital_dna_event": dict(event.payload)},
        )

    def _file_integrity_incident(self, event: SecurityEvent) -> CorrelatedIncident:
        pid = event.payload.get("pid")
        return CorrelatedIncident(
            observed_at=datetime.now(timezone.utc).isoformat(),
            incident_type="executable_integrity_change",
            severity="high",
            score_boost=35.0,
            involved_pids=[int(pid)] if isinstance(pid, int) else [],
            event_types=[event.event_type],
            summary=f"Known executable changed hash: {event.payload.get('file_path')}",
            evidence={"file_event": dict(event.payload)},
        )

    def _file_registry_network_chain(self, event: SecurityEvent) -> CorrelatedIncident | None:
        relevant = {
            "file.reputation", "file.integrity_change", "network.connection_opened",
            "registry.startup_value_created", "registry.startup_value_modified",
        }
        if event.event_type not in relevant:
            return None
        file_events = [
            item for item in self.events
            if item.event_type in {"file.reputation", "file.integrity_change"}
            and (item.payload.get("is_new") or item.payload.get("integrity_changed"))
        ]
        registry_events = [item for item in self.events if item.event_type.startswith("registry.startup_value_")]
        network_events = [
            item for item in self.events
            if item.event_type == "network.connection_opened" and item.payload.get("suspicious_port")
        ]
        if not (file_events and registry_events and network_events):
            return None
        pids = sorted({
            int(item.payload["pid"]) for item in [*file_events, *network_events]
            if isinstance(item.payload.get("pid"), int)
        })
        evidence_events = [*file_events[-5:], *registry_events[-5:], *network_events[-5:]]
        return CorrelatedIncident(
            observed_at=datetime.now(timezone.utc).isoformat(),
            incident_type="file_persistence_network_attack_chain",
            severity="critical",
            score_boost=50.0,
            involved_pids=pids,
            event_types=sorted({item.event_type for item in evidence_events}),
            summary="New or modified executable combined with startup persistence and suspicious network activity",
            evidence={"events": [self._event_summary(item) for item in evidence_events]},
        )

    def _process_registry_network_chain(self, event: SecurityEvent) -> CorrelatedIncident | None:
        if event.event_type not in {"network.connection_opened", "registry.startup_value_created", "registry.startup_value_modified"}:
            return None
        has_process = any(item.event_type in {"process.started", "process.changed"} for item in self.events)
        registry_events = [item for item in self.events if item.event_type.startswith("registry.startup_value_")]
        network_events = [item for item in self.events if item.event_type == "network.connection_opened"]
        if not (has_process and registry_events and network_events):
            return None
        pids = sorted({int(item.payload.get("pid")) for item in network_events if isinstance(item.payload.get("pid"), int)})
        return CorrelatedIncident(
            observed_at=datetime.now(timezone.utc).isoformat(),
            incident_type="process_persistence_network_chain",
            severity="high",
            score_boost=35.0,
            involved_pids=pids,
            event_types=sorted({item.event_type for item in self.events}),
            summary="Process activity followed by startup persistence and network connection",
            evidence={"events": [self._event_summary(item) for item in self.events[-20:]]},
        )

    def _prune(self) -> None:
        cutoff = datetime.now(timezone.utc) - self.window
        self.events = [event for event in self.events if self._observed_at(event) >= cutoff]

    @staticmethod
    def _observed_at(event: SecurityEvent) -> datetime:
        try:
            return datetime.fromisoformat(event.observed_at)
        except ValueError:
            return datetime.now(timezone.utc)

    @staticmethod
    def _event_summary(event: SecurityEvent) -> dict[str, Any]:
        return {"event_type": event.event_type, "source": event.source, "observed_at": event.observed_at, "payload": dict(event.payload)}
