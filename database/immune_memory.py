"""Long-term immune memory for incidents, timelines, and behavior fingerprints."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from core.correlation_engine import CorrelatedIncident
from database.threat_history import SCHEMA_PATH


@dataclass(frozen=True, slots=True)
class AttackGraphNode:
    id: str
    node_type: str
    label: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AttackGraphEdge:
    source: str
    target: str
    relationship: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AttackGraph:
    nodes: list[AttackGraphNode]
    edges: list[AttackGraphEdge]


@dataclass(frozen=True, slots=True)
class BehaviorFingerprint:
    fingerprint_hash: str
    features: list[str]
    feature_count: int


@dataclass(frozen=True, slots=True)
class RememberedIncident:
    memory_id: int
    observed_at: str
    incident_type: str
    severity: str
    summary: str
    confidence_score: float
    recurrence_score: float
    pattern_key: str
    fingerprint: BehaviorFingerprint
    attack_graph: AttackGraph
    timeline: list[dict[str, Any]]
    evidence: dict[str, Any]


class ImmuneMemoryStore:
    """SQLite-backed long-term attack memory."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))

    def remember_incident(self, incident: CorrelatedIncident | Mapping[str, Any], source_incident_id: int | None = None) -> RememberedIncident:
        payload = asdict(incident) if is_dataclass(incident) else dict(incident)
        timeline = self._build_timeline(payload)
        attack_graph = self._build_attack_graph(payload, timeline)
        fingerprint = self._build_fingerprint(payload, timeline)
        pattern_key = self._pattern_key(payload, fingerprint)
        prior_count = self._count_pattern(pattern_key)
        recurrence_score = min(100.0, prior_count * 20.0)
        confidence_score = self._confidence_score(payload, timeline, fingerprint, recurrence_score)
        observed_at = str(payload.get("observed_at") or datetime.now(timezone.utc).isoformat())
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO immune_memory_incidents (
                    source_incident_id, observed_at, incident_type, severity, summary, confidence_score,
                    recurrence_score, pattern_key, fingerprint, attack_graph, timeline, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_incident_id,
                    observed_at,
                    payload.get("incident_type", "unknown"),
                    payload.get("severity", "unknown"),
                    payload.get("summary", ""),
                    confidence_score,
                    recurrence_score,
                    pattern_key,
                    json.dumps(asdict(fingerprint)),
                    json.dumps(asdict(attack_graph)),
                    json.dumps(timeline),
                    json.dumps(payload.get("evidence", {})),
                ),
            )
            memory_id = int(cursor.lastrowid)
            connection.execute(
                """
                INSERT INTO behavior_fingerprints (memory_id, fingerprint_hash, feature_count, features, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (memory_id, fingerprint.fingerprint_hash, fingerprint.feature_count, json.dumps(fingerprint.features), datetime.now(timezone.utc).isoformat()),
            )
        return RememberedIncident(
            memory_id=memory_id,
            observed_at=observed_at,
            incident_type=str(payload.get("incident_type", "unknown")),
            severity=str(payload.get("severity", "unknown")),
            summary=str(payload.get("summary", "")),
            confidence_score=confidence_score,
            recurrence_score=recurrence_score,
            pattern_key=pattern_key,
            fingerprint=fingerprint,
            attack_graph=attack_graph,
            timeline=timeline,
            evidence=dict(payload.get("evidence", {})),
        )

    def search_similar_incidents(self, incident_or_fingerprint: CorrelatedIncident | Mapping[str, Any] | BehaviorFingerprint, limit: int = 10) -> list[dict[str, Any]]:
        query_fingerprint = self._coerce_fingerprint(incident_or_fingerprint)
        query_features = set(query_fingerprint.features)
        rows = self._recent_memory_rows(limit=1000)
        scored: list[dict[str, Any]] = []
        for row in rows:
            stored = json.loads(row["fingerprint"])
            features = set(stored.get("features", []))
            similarity = self._jaccard(query_features, features)
            if similarity <= 0:
                continue
            item = dict(row)
            item["fingerprint"] = stored
            item["attack_graph"] = json.loads(row["attack_graph"])
            item["timeline"] = json.loads(row["timeline"])
            item["evidence"] = json.loads(row["evidence"])
            item["similarity_score"] = round(similarity * 100.0, 2)
            scored.append(item)
        scored.sort(key=lambda item: (item["similarity_score"], item["confidence_score"], item["observed_at"]), reverse=True)
        return scored[: max(0, int(limit))]

    def get_attack_timeline(self, memory_id: int) -> list[dict[str, Any]]:
        row = self._memory_row(memory_id)
        return json.loads(row["timeline"]) if row is not None else []

    def get_behavior_fingerprint(self, memory_id: int) -> BehaviorFingerprint | None:
        row = self._memory_row(memory_id)
        if row is None:
            return None
        payload = json.loads(row["fingerprint"])
        return BehaviorFingerprint(
            fingerprint_hash=payload["fingerprint_hash"],
            features=list(payload.get("features", [])),
            feature_count=int(payload.get("feature_count", 0)),
        )

    def get_attack_graph(self, memory_id: int) -> AttackGraph | None:
        row = self._memory_row(memory_id)
        if row is None:
            return None
        payload = json.loads(row["attack_graph"])
        return AttackGraph(
            nodes=[AttackGraphNode(**node) for node in payload.get("nodes", [])],
            edges=[AttackGraphEdge(**edge) for edge in payload.get("edges", [])],
        )

    def _count_pattern(self, pattern_key: str) -> int:
        with self.connect() as connection:
            row = connection.execute("SELECT COUNT(*) FROM immune_memory_incidents WHERE pattern_key = ?", (pattern_key,)).fetchone()
        return int(row[0]) if row else 0

    def _memory_row(self, memory_id: int) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute("SELECT * FROM immune_memory_incidents WHERE id = ?", (memory_id,)).fetchone()

    def _recent_memory_rows(self, limit: int) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(connection.execute("SELECT * FROM immune_memory_incidents ORDER BY observed_at DESC, id DESC LIMIT ?", (limit,)).fetchall())

    def _coerce_fingerprint(self, value: CorrelatedIncident | Mapping[str, Any] | BehaviorFingerprint) -> BehaviorFingerprint:
        if isinstance(value, BehaviorFingerprint):
            return value
        payload = asdict(value) if is_dataclass(value) else dict(value)
        return self._build_fingerprint(payload, self._build_timeline(payload))

    def _build_timeline(self, incident: Mapping[str, Any]) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        evidence = incident.get("evidence", {}) if isinstance(incident.get("evidence", {}), Mapping) else {}
        raw_events = evidence.get("events") if isinstance(evidence, Mapping) else None
        if isinstance(raw_events, Sequence) and not isinstance(raw_events, (str, bytes)):
            for index, raw in enumerate(raw_events):
                if isinstance(raw, Mapping):
                    events.append(self._timeline_item(raw, index))
        for key in ("file_event", "registry_event", "network_event", "process_event"):
            raw = evidence.get(key) if isinstance(evidence, Mapping) else None
            if isinstance(raw, Mapping):
                event_type = str(raw.get("event_type") or key.removesuffix("_event"))
                events.append(self._timeline_item({"event_type": event_type, "source": key, "observed_at": incident.get("observed_at"), "payload": raw}, len(events)))
        if not events:
            events.append({
                "sequence": 0,
                "observed_at": str(incident.get("observed_at") or datetime.now(timezone.utc).isoformat()),
                "event_type": str(incident.get("incident_type", "incident")),
                "source": "correlation_engine",
                "payload": dict(evidence) if isinstance(evidence, Mapping) else {},
            })
        events.sort(key=lambda item: (str(item.get("observed_at", "")), int(item.get("sequence", 0))))
        for index, item in enumerate(events):
            item["sequence"] = index
        return events

    @staticmethod
    def _timeline_item(raw: Mapping[str, Any], sequence: int) -> dict[str, Any]:
        return {
            "sequence": sequence,
            "observed_at": str(raw.get("observed_at") or datetime.now(timezone.utc).isoformat()),
            "event_type": str(raw.get("event_type") or "unknown"),
            "source": str(raw.get("source") or "unknown"),
            "payload": dict(raw.get("payload", {})) if isinstance(raw.get("payload", {}), Mapping) else {},
        }

    def _build_attack_graph(self, incident: Mapping[str, Any], timeline: list[dict[str, Any]]) -> AttackGraph:
        nodes: dict[str, AttackGraphNode] = {}
        edges: set[tuple[str, str, str]] = set()
        incident_id = f"incident:{incident.get('incident_type', 'unknown')}"
        nodes[incident_id] = AttackGraphNode(incident_id, "incident", str(incident.get("incident_type", "unknown")), {"severity": incident.get("severity"), "summary": incident.get("summary")})
        last_event_id: str | None = None
        for item in timeline:
            event_id = f"event:{item['sequence']}:{item['event_type']}"
            nodes[event_id] = AttackGraphNode(event_id, "event", item["event_type"], {"source": item.get("source"), "observed_at": item.get("observed_at")})
            edges.add((event_id, incident_id, "supports"))
            if last_event_id is not None:
                edges.add((last_event_id, event_id, "precedes"))
            last_event_id = event_id
            payload = item.get("payload", {}) if isinstance(item.get("payload", {}), Mapping) else {}
            self._add_entity_nodes(nodes, edges, event_id, payload)
        return AttackGraph(
            nodes=sorted(nodes.values(), key=lambda node: node.id),
            edges=[AttackGraphEdge(source, target, relationship) for source, target, relationship in sorted(edges)],
        )

    @staticmethod
    def _add_entity_nodes(nodes: dict[str, AttackGraphNode], edges: set[tuple[str, str, str]], event_id: str, payload: Mapping[str, Any]) -> None:
        pid = payload.get("pid")
        if isinstance(pid, int):
            process_id = f"process:{pid}"
            nodes.setdefault(process_id, AttackGraphNode(process_id, "process", str(pid), {"pid": pid, "name": payload.get("name") or payload.get("process_name")}))
            edges.add((process_id, event_id, "emits"))
        parent_pid = payload.get("parent_pid")
        if isinstance(parent_pid, int) and isinstance(pid, int):
            parent_id = f"process:{parent_pid}"
            child_id = f"process:{pid}"
            nodes.setdefault(parent_id, AttackGraphNode(parent_id, "process", str(parent_pid), {"pid": parent_pid, "name": payload.get("parent_name")}))
            edges.add((parent_id, child_id, "spawned"))
        file_path = payload.get("file_path") or payload.get("executable")
        if file_path:
            file_id = f"file:{hashlib.sha256(str(file_path).lower().encode()).hexdigest()[:16]}"
            nodes.setdefault(file_id, AttackGraphNode(file_id, "file", str(file_path), {"sha256": payload.get("sha256") or payload.get("executable_sha256")}))
            edges.add((event_id, file_id, "references_file"))
        if payload.get("key_path") or payload.get("value_name"):
            label = f"{payload.get('key_path', '')}\\{payload.get('value_name', '')}"
            reg_id = f"registry:{hashlib.sha256(label.lower().encode()).hexdigest()[:16]}"
            nodes.setdefault(reg_id, AttackGraphNode(reg_id, "registry", label, {"hive": payload.get("hive")}))
            edges.add((event_id, reg_id, "modifies_registry"))
        remote = payload.get("remote_address") or payload.get("remote_port")
        if remote:
            label = f"{payload.get('remote_address', '')}:{payload.get('remote_port', '')}"
            net_id = f"network:{hashlib.sha256(label.encode()).hexdigest()[:16]}"
            nodes.setdefault(net_id, AttackGraphNode(net_id, "network", label, {"remote_port": payload.get("remote_port")}))
            edges.add((event_id, net_id, "connects"))

    def _build_fingerprint(self, incident: Mapping[str, Any], timeline: list[dict[str, Any]]) -> BehaviorFingerprint:
        features: set[str] = {f"incident:{incident.get('incident_type', 'unknown')}", f"severity:{incident.get('severity', 'unknown')}"}
        for event_type in incident.get("event_types", []) or []:
            features.add(f"event_type:{event_type}")
        for item in timeline:
            event_type = item.get("event_type", "unknown")
            features.add(f"event_type:{event_type}")
            payload = item.get("payload", {}) if isinstance(item.get("payload", {}), Mapping) else {}
            self._add_payload_features(features, payload)
        ordered = sorted(features)
        digest = hashlib.sha256("\n".join(ordered).encode("utf-8")).hexdigest()
        return BehaviorFingerprint(fingerprint_hash=digest, features=ordered, feature_count=len(ordered))

    @staticmethod
    def _add_payload_features(features: set[str], payload: Mapping[str, Any]) -> None:
        for key in ("pid", "parent_pid", "remote_port", "key_path", "value_name", "file_path", "sha256", "previous_sha256", "integrity_changed", "is_new"):
            value = payload.get(key)
            if value not in (None, "", [], {}):
                if key == "file_path":
                    value = str(value).lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
                features.add(f"{key}:{value}")
        for reason in payload.get("reasons", []) if isinstance(payload.get("reasons"), list) else []:
            features.add(f"reason:{str(reason).lower()}")

    @staticmethod
    def _pattern_key(incident: Mapping[str, Any], fingerprint: BehaviorFingerprint) -> str:
        coarse = [feature for feature in fingerprint.features if feature.startswith(("incident:", "event_type:", "remote_port:", "key_path:", "integrity_changed:"))]
        return hashlib.sha256("\n".join(sorted(coarse)).encode("utf-8")).hexdigest()

    @staticmethod
    def _confidence_score(incident: Mapping[str, Any], timeline: list[dict[str, Any]], fingerprint: BehaviorFingerprint, recurrence_score: float) -> float:
        severity_weight = {"informational": 5, "low": 15, "medium": 35, "high": 55, "critical": 70}.get(str(incident.get("severity", "")).lower(), 20)
        evidence_weight = min(20.0, len(timeline) * 5.0)
        feature_weight = min(10.0, fingerprint.feature_count / 2.0)
        recurrence_weight = min(10.0, recurrence_score / 10.0)
        return round(min(100.0, severity_weight + evidence_weight + feature_weight + recurrence_weight), 2)

    @staticmethod
    def _jaccard(left: set[str], right: set[str]) -> float:
        if not left or not right:
            return 0.0
        return len(left & right) / len(left | right)
