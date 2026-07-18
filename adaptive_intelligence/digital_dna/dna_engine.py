"""High-level Digital DNA generation, evolution, and matching APIs."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
import hashlib
from pathlib import Path
from typing import Any, Mapping

from adaptive_intelligence.digital_dna.dna_evolution import DigitalDNAEvolution
from adaptive_intelligence.digital_dna.dna_models import DigitalDNA, DigitalDNAComparison, DigitalDNAObservation
from adaptive_intelligence.digital_dna.dna_similarity import DigitalDNASimilarity
from adaptive_intelligence.digital_dna.dna_storage import DigitalDNAStore


class DigitalDNAEngine:
    """Creates and evolves persistent behavioral identities for executables/processes."""

    def __init__(
        self,
        store: DigitalDNAStore,
        evolution: DigitalDNAEvolution | None = None,
        similarity: DigitalDNASimilarity | None = None,
    ):
        self.store = store
        self.evolution = evolution or DigitalDNAEvolution()
        self.similarity = similarity or DigitalDNASimilarity()

    def generate_dna(self, observation: DigitalDNAObservation | Mapping[str, Any] | Any) -> DigitalDNA:
        normalized = self._normalize_observation(observation)
        dna_id = self._dna_id(normalized)
        existing = self.store.get(dna_id)
        if existing is not None:
            return existing
        dna = self.evolution.create(dna_id, normalized)
        self.store.save(dna)
        return dna

    def update_dna(self, observation: DigitalDNAObservation | Mapping[str, Any] | Any) -> DigitalDNA:
        normalized = self._normalize_observation(observation)
        dna_id = self._dna_id(normalized)
        existing = self.store.get(dna_id)
        dna = self.evolution.create(dna_id, normalized) if existing is None else self.merge_behavior(existing, normalized)
        self.store.save(dna)
        return dna

    def update_from_incident(self, incident: Mapping[str, Any] | Any) -> list[DigitalDNA]:
        payload = asdict(incident) if is_dataclass(incident) else dict(incident)
        evidence = payload.get("evidence", {}) if isinstance(payload.get("evidence", {}), Mapping) else {}
        events = evidence.get("events", []) if isinstance(evidence.get("events", []), list) else []
        updated: list[DigitalDNA] = []
        for event in events:
            event_payload = event.get("payload", {}) if isinstance(event, Mapping) and isinstance(event.get("payload", {}), Mapping) else {}
            if event_payload.get("file_path") or event_payload.get("executable") or event_payload.get("pid"):
                observation = self._observation_from_mapping(
                    {
                        **event_payload,
                        "incident_types": [payload.get("incident_type")],
                        "confidence": payload.get("score_boost", 50.0),
                        "recurrence": payload.get("recurrence_score", 0.0),
                        "risk": payload.get("score_boost", 0.0),
                    }
                )
                updated.append(self.update_dna(observation))
        return updated

    def compare_dna(self, left: DigitalDNA | str, right: DigitalDNA | str) -> dict[str, Any]:
        left_dna = self._resolve(left)
        right_dna = self._resolve(right)
        comparison = self.similarity.compare(left_dna, right_dna)
        self.store.record_similarity(comparison)
        return comparison.to_json()

    def find_similar_dna(self, dna: DigitalDNA | str, limit: int = 10, minimum_score: float = 1.0) -> list[dict[str, Any]]:
        target = self._resolve(dna)
        matches: list[dict[str, Any]] = []
        for candidate in self.store.list_dna(limit=1000):
            if candidate.dna_id == target.dna_id:
                continue
            comparison = self.similarity.compare(target, candidate)
            if comparison.similarity_score >= minimum_score:
                self.store.record_similarity(comparison)
                matches.append(comparison.to_json())
        matches.sort(key=lambda item: (item["similarity_score"], item["confidence"]), reverse=True)
        return matches[: max(0, int(limit))]

    def merge_behavior(self, existing: DigitalDNA, observation: DigitalDNAObservation | Mapping[str, Any] | Any) -> DigitalDNA:
        return self.evolution.merge_behavior(existing, self._normalize_observation(observation))

    def get_dna_history(self, dna_id: str) -> list[dict[str, Any]]:
        return self.store.get_history(dna_id)

    def _resolve(self, dna: DigitalDNA | str) -> DigitalDNA:
        if isinstance(dna, DigitalDNA):
            return dna
        resolved = self.store.get(dna)
        if resolved is None:
            raise KeyError(f"unknown digital DNA id: {dna}")
        return resolved

    def _normalize_observation(self, observation: DigitalDNAObservation | Mapping[str, Any] | Any) -> DigitalDNAObservation:
        if isinstance(observation, DigitalDNAObservation):
            return observation
        payload = asdict(observation) if is_dataclass(observation) else dict(observation)
        return self._observation_from_mapping(payload)

    def _observation_from_mapping(self, payload: Mapping[str, Any]) -> DigitalDNAObservation:
        executable = payload.get("executable_path") or payload.get("executable") or payload.get("file_path")
        remote_ports = payload.get("remote_ports") or ([] if payload.get("remote_port") is None else [payload.get("remote_port")])
        directories = payload.get("accessed_directories") or self._directory_from_path(payload.get("file_path") or payload.get("executable"))
        return DigitalDNAObservation(
            executable_path=str(executable) if executable else None,
            sha256=payload.get("sha256") or payload.get("executable_sha256"),
            publisher=payload.get("publisher") or payload.get("signature_status"),
            file_reputation=float(payload.get("file_reputation", payload.get("file_reputation_score", 0.0)) or 0.0),
            pid=payload.get("pid"),
            process_name=payload.get("process_name") or payload.get("name"),
            parent_pid=payload.get("parent_pid"),
            parent_executable=payload.get("parent_executable") or payload.get("parent_name"),
            ancestry=list(payload.get("ancestry", [])),
            cpu_percent=float(payload.get("cpu_percent", 0.0) or 0.0),
            memory_percent=float(payload.get("memory_percent", 0.0) or 0.0),
            thread_count=int(payload.get("thread_count", payload.get("num_threads", 0)) or 0),
            handle_count=int(payload.get("handle_count", payload.get("open_files", 0)) or 0),
            lifetime_seconds=float(payload.get("lifetime_seconds", 0.0) or 0.0),
            startup_behavior=bool(payload.get("startup_behavior", False)),
            remote_ports=[int(port) for port in remote_ports if port is not None],
            connection_count=int(payload.get("connection_count", payload.get("connections", 0)) or 0),
            protocols=list(payload.get("protocols", [])),
            accessed_directories=list(directories),
            temporary_file_usage=bool(payload.get("temporary_file_usage", False)),
            file_modification_count=int(payload.get("file_modification_count", 0) or 0),
            registry_persistence=bool(payload.get("registry_persistence", payload.get("startup_persistence", False))),
            registry_patterns=list(payload.get("registry_patterns", [])),
            threat_score=float(payload.get("threat_score", 0.0) or 0.0),
            incident_types=[str(item) for item in payload.get("incident_types", []) if item],
            confidence=float(payload.get("confidence", 50.0) or 50.0),
            recurrence=float(payload.get("recurrence", payload.get("recurrence_score", 0.0)) or 0.0),
            risk=float(payload.get("risk", payload.get("threat_score", 0.0)) or 0.0),
            observed_at=str(payload.get("observed_at") or DigitalDNAObservation().observed_at),
        )

    @staticmethod
    def _directory_from_path(path: Any) -> list[str]:
        if not path:
            return []
        try:
            return [str(Path(str(path)).parent)]
        except (OSError, ValueError):
            return []

    @staticmethod
    def _dna_id(observation: DigitalDNAObservation) -> str:
        identity = observation.sha256 or observation.executable_path or observation.process_name or str(observation.pid)
        return hashlib.sha256(str(identity).lower().encode("utf-8")).hexdigest()
