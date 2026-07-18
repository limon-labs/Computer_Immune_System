"""Digital DNA data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class DigitalDNAObservation:
    executable_path: str | None = None
    sha256: str | None = None
    publisher: str | None = None
    file_reputation: float = 0.0
    pid: int | None = None
    process_name: str | None = None
    parent_pid: int | None = None
    parent_executable: str | None = None
    ancestry: list[str] = field(default_factory=list)
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    thread_count: int = 0
    handle_count: int = 0
    lifetime_seconds: float = 0.0
    startup_behavior: bool = False
    remote_ports: list[int] = field(default_factory=list)
    connection_count: int = 0
    protocols: list[str] = field(default_factory=list)
    accessed_directories: list[str] = field(default_factory=list)
    temporary_file_usage: bool = False
    file_modification_count: int = 0
    registry_persistence: bool = False
    registry_patterns: list[str] = field(default_factory=list)
    threat_score: float = 0.0
    incident_types: list[str] = field(default_factory=list)
    confidence: float = 50.0
    recurrence: float = 0.0
    risk: float = 0.0
    observed_at: str = field(default_factory=utc_now)


@dataclass(frozen=True, slots=True)
class DigitalDNA:
    dna_id: str
    version: int
    identity: dict[str, Any]
    process_lineage: dict[str, Any]
    behavior_profile: dict[str, Any]
    network_profile: dict[str, Any]
    filesystem_profile: dict[str, Any]
    registry_profile: dict[str, Any]
    security_profile: dict[str, Any]
    first_seen: str
    last_seen: str
    confidence: float
    evolution_timestamp: str
    change_history: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class DigitalDNAComparison:
    left_dna_id: str
    right_dna_id: str
    similarity_score: float
    confidence: float
    matched_features: list[str]
    different_features: list[str]
    evolution_history: list[dict[str, Any]]

    def to_json(self) -> dict[str, Any]:
        return {
            "left_dna_id": self.left_dna_id,
            "right_dna_id": self.right_dna_id,
            "similarity_score": self.similarity_score,
            "confidence": self.confidence,
            "matched_features": self.matched_features,
            "different_features": self.different_features,
            "evolution_history": self.evolution_history,
        }
