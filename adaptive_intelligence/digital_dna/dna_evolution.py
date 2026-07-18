"""Digital DNA evolution logic."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from adaptive_intelligence.digital_dna.dna_models import DigitalDNA, DigitalDNAObservation, utc_now


class DigitalDNAEvolution:
    """Merges observations into versioned Digital DNA without destroying history."""

    def create(self, dna_id: str, observation: DigitalDNAObservation) -> DigitalDNA:
        now = observation.observed_at or utc_now()
        return DigitalDNA(
            dna_id=dna_id,
            version=1,
            identity={
                "executable_path": observation.executable_path,
                "sha256": observation.sha256,
                "publisher": observation.publisher or "unknown",
                "file_reputation": observation.file_reputation,
                "first_seen": now,
                "last_seen": now,
            },
            process_lineage={
                "parent_pid": observation.parent_pid,
                "parent_executable": observation.parent_executable,
                "child_relationships": [],
                "process_ancestry": list(observation.ancestry),
            },
            behavior_profile={
                "typical_cpu_usage": observation.cpu_percent,
                "memory_usage": observation.memory_percent,
                "thread_count": observation.thread_count,
                "handle_count": observation.handle_count,
                "lifetime_seconds": observation.lifetime_seconds,
                "startup_behavior": observation.startup_behavior,
            },
            network_profile={
                "common_remote_ports": sorted(set(observation.remote_ports)),
                "connection_frequency": observation.connection_count,
                "protocol_usage": sorted(set(observation.protocols)),
            },
            filesystem_profile={
                "frequently_accessed_directories": sorted(set(observation.accessed_directories)),
                "temporary_file_usage": observation.temporary_file_usage,
                "file_modification_behavior": observation.file_modification_count,
            },
            registry_profile={
                "startup_persistence": observation.registry_persistence,
                "registry_modification_patterns": sorted(set(observation.registry_patterns)),
            },
            security_profile={
                "threat_history": [observation.threat_score] if observation.threat_score else [],
                "previous_incidents": sorted(set(observation.incident_types)),
                "confidence": observation.confidence,
                "recurrence": observation.recurrence,
                "risk_history": [observation.risk] if observation.risk else [],
            },
            first_seen=now,
            last_seen=now,
            confidence=observation.confidence,
            evolution_timestamp=now,
            change_history=[{"version": 1, "timestamp": now, "changes": ["initial DNA generated"], "observation": asdict(observation)}],
        )

    def merge_behavior(self, existing: DigitalDNA, observation: DigitalDNAObservation) -> DigitalDNA:
        changes: list[str] = []
        now = observation.observed_at or utc_now()
        identity = dict(existing.identity)
        self._set_if_changed(identity, "last_seen", now, changes)
        self._set_if_changed(identity, "sha256", observation.sha256 or identity.get("sha256"), changes)
        self._set_if_changed(identity, "publisher", observation.publisher or identity.get("publisher") or "unknown", changes)
        identity["file_reputation"] = self._max_float(identity.get("file_reputation"), observation.file_reputation)

        lineage = dict(existing.process_lineage)
        self._set_if_changed(lineage, "parent_pid", observation.parent_pid if observation.parent_pid is not None else lineage.get("parent_pid"), changes)
        self._set_if_changed(lineage, "parent_executable", observation.parent_executable or lineage.get("parent_executable"), changes)
        lineage["process_ancestry"] = self._merge_list(lineage.get("process_ancestry", []), observation.ancestry)

        behavior = dict(existing.behavior_profile)
        behavior["typical_cpu_usage"] = self._rolling_average(behavior.get("typical_cpu_usage", 0.0), observation.cpu_percent)
        behavior["memory_usage"] = self._rolling_average(behavior.get("memory_usage", 0.0), observation.memory_percent)
        behavior["thread_count"] = round(self._rolling_average(behavior.get("thread_count", 0.0), observation.thread_count), 2)
        behavior["handle_count"] = round(self._rolling_average(behavior.get("handle_count", 0.0), observation.handle_count), 2)
        behavior["lifetime_seconds"] = self._max_float(behavior.get("lifetime_seconds"), observation.lifetime_seconds)
        behavior["startup_behavior"] = bool(behavior.get("startup_behavior") or observation.startup_behavior)

        network = dict(existing.network_profile)
        network["common_remote_ports"] = self._merge_list(network.get("common_remote_ports", []), observation.remote_ports)
        network["connection_frequency"] = self._rolling_average(network.get("connection_frequency", 0.0), observation.connection_count)
        network["protocol_usage"] = self._merge_list(network.get("protocol_usage", []), observation.protocols)

        filesystem = dict(existing.filesystem_profile)
        filesystem["frequently_accessed_directories"] = self._merge_list(filesystem.get("frequently_accessed_directories", []), observation.accessed_directories)
        filesystem["temporary_file_usage"] = bool(filesystem.get("temporary_file_usage") or observation.temporary_file_usage)
        filesystem["file_modification_behavior"] = self._rolling_average(filesystem.get("file_modification_behavior", 0.0), observation.file_modification_count)

        registry = dict(existing.registry_profile)
        registry["startup_persistence"] = bool(registry.get("startup_persistence") or observation.registry_persistence)
        registry["registry_modification_patterns"] = self._merge_list(registry.get("registry_modification_patterns", []), observation.registry_patterns)

        security = dict(existing.security_profile)
        security["threat_history"] = self._append_limited(security.get("threat_history", []), observation.threat_score)
        security["previous_incidents"] = self._merge_list(security.get("previous_incidents", []), observation.incident_types)
        security["confidence"] = round(self._rolling_average(security.get("confidence", existing.confidence), observation.confidence), 2)
        security["recurrence"] = self._max_float(security.get("recurrence"), observation.recurrence)
        security["risk_history"] = self._append_limited(security.get("risk_history", []), observation.risk)

        if not changes:
            changes.append("behavior profile evolved incrementally")
        confidence = round(float(security.get("confidence", existing.confidence)), 2)
        return DigitalDNA(
            dna_id=existing.dna_id,
            version=existing.version + 1,
            identity=identity,
            process_lineage=lineage,
            behavior_profile=behavior,
            network_profile=network,
            filesystem_profile=filesystem,
            registry_profile=registry,
            security_profile=security,
            first_seen=existing.first_seen,
            last_seen=now,
            confidence=confidence,
            evolution_timestamp=now,
            change_history=[*existing.change_history[-20:], {"version": existing.version + 1, "timestamp": now, "changes": changes, "observation": asdict(observation)}],
        )

    def _set_if_changed(self, payload: dict[str, Any], key: str, value: Any, changes: list[str]) -> None:
        if payload.get(key) != value:
            payload[key] = value
            changes.append(f"{key} changed")

    @staticmethod
    def _rolling_average(old: Any, new: Any) -> float:
        return round((float(old or 0.0) + float(new or 0.0)) / 2.0, 2)

    @staticmethod
    def _max_float(old: Any, new: Any) -> float:
        return max(float(old or 0.0), float(new or 0.0))

    @staticmethod
    def _merge_list(old: Any, new: Any, limit: int = 50) -> list[Any]:
        values = []
        for item in [*(old or []), *(new or [])]:
            if item not in values and item not in (None, ""):
                values.append(item)
        return values[:limit]

    @staticmethod
    def _append_limited(old: Any, value: Any, limit: int = 50) -> list[Any]:
        values = list(old or [])
        if value not in (None, "", 0, 0.0):
            values.append(value)
        return values[-limit:]
