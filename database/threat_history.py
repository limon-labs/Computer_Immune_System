"""SQLite persistence for threat observations and endpoint telemetry."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from core.correlation_engine import CorrelatedIncident
from core.event_queue import SecurityEvent

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


class ThreatHistoryStore:
    """Small SQLite repository used by the immune-system orchestrator."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        with self.connect() as connection:
            connection.executescript(schema)
            self._ensure_columns(connection)

    @staticmethod
    def _ensure_columns(connection: sqlite3.Connection) -> None:
        existing = {row[1] for row in connection.execute("PRAGMA table_info(threats)").fetchall()}
        migrations = {
            "create_time": "ALTER TABLE threats ADD COLUMN create_time REAL",
            "policy_action": "ALTER TABLE threats ADD COLUMN policy_action TEXT NOT NULL DEFAULT 'monitor'",
            "file_reputation_score": "ALTER TABLE threats ADD COLUMN file_reputation_score REAL NOT NULL DEFAULT 0",
            "parent_pid": "ALTER TABLE threats ADD COLUMN parent_pid INTEGER",
            "parent_name": "ALTER TABLE threats ADD COLUMN parent_name TEXT",
        }
        for column, statement in migrations.items():
            if column not in existing:
                connection.execute(statement)

    def record_threat(self, event: Any) -> int:
        payload = asdict(event) if is_dataclass(event) else dict(event)
        reasons = payload.get("reasons", [])
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO threats (
                    observed_at, pid, process_name, executable, command_line, create_time, parent_pid, parent_name,
                    anomaly_score, behavior_score, file_reputation_score, threat_score, severity, policy_action, reasons, action
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.get("observed_at"),
                    payload.get("pid"),
                    payload.get("process_name"),
                    payload.get("executable"),
                    payload.get("command_line"),
                    payload.get("create_time"),
                    payload.get("parent_pid"),
                    payload.get("parent_name"),
                    float(payload.get("anomaly_score", 0.0)),
                    float(payload.get("behavior_score", 0.0)),
                    float(payload.get("file_reputation_score", 0.0)),
                    float(payload.get("threat_score", 0.0)),
                    payload.get("severity", "unknown"),
                    payload.get("policy_action", "monitor"),
                    json.dumps(reasons),
                    payload.get("action", "none"),
                ),
            )
            return int(cursor.lastrowid)

    def record_registry_event(self, event: SecurityEvent) -> int:
        payload = dict(event.payload)
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO registry_events (observed_at, event_type, key_path, value_name, value_data, hive, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.observed_at,
                    event.event_type,
                    payload.get("key_path", ""),
                    payload.get("value_name", ""),
                    payload.get("value_data"),
                    payload.get("hive"),
                    json.dumps(payload),
                ),
            )
            return int(cursor.lastrowid)

    def record_network_event(self, event: SecurityEvent) -> int:
        payload = dict(event.payload)
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO network_events (
                    observed_at, event_type, pid, local_address, local_port, remote_address, remote_port, status,
                    suspicious_port, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.observed_at,
                    event.event_type,
                    payload.get("pid"),
                    payload.get("local_address"),
                    payload.get("local_port"),
                    payload.get("remote_address"),
                    payload.get("remote_port"),
                    payload.get("status"),
                    1 if payload.get("suspicious_port") else 0,
                    json.dumps(payload),
                ),
            )
            return int(cursor.lastrowid)

    def record_correlated_incident(self, incident: CorrelatedIncident | Mapping[str, Any]) -> int:
        payload = asdict(incident) if is_dataclass(incident) else dict(incident)
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO correlated_incidents (
                    observed_at, incident_type, severity, score_boost, involved_pids, event_types, summary, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.get("observed_at"),
                    payload.get("incident_type"),
                    payload.get("severity"),
                    float(payload.get("score_boost", 0.0)),
                    json.dumps(payload.get("involved_pids", [])),
                    json.dumps(payload.get("event_types", [])),
                    payload.get("summary", ""),
                    json.dumps(payload.get("evidence", {})),
                ),
            )
            return int(cursor.lastrowid)


    def get_file_inventory(self, file_path: str) -> dict[str, Any] | None:
        normalized_path = self._normalize_file_path(file_path)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM file_inventory WHERE normalized_path = ?", (normalized_path,)
            ).fetchone()
        return dict(row) if row is not None else None

    def record_file_observation(self, payload: Mapping[str, Any], previous_sha256: str | None = None) -> int:
        file_path = str(payload.get("file_path") or "")
        normalized_path = self._normalize_file_path(file_path)
        observed_at = str(payload.get("observed_at") or "")
        current_hash = payload.get("sha256")
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT id, sha256, first_observed_at FROM file_inventory WHERE normalized_path = ?",
                (normalized_path,),
            ).fetchone()
            first_observed_at = existing["first_observed_at"] if existing else observed_at
            connection.execute(
                """
                INSERT INTO file_inventory (
                    normalized_path, file_path, file_size, creation_time, modification_time, sha256,
                    signature_status, first_observed_at, last_observed_at, last_pid, process_create_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(normalized_path) DO UPDATE SET
                    file_path=excluded.file_path, file_size=excluded.file_size, creation_time=excluded.creation_time,
                    modification_time=excluded.modification_time, sha256=excluded.sha256,
                    signature_status=excluded.signature_status, last_observed_at=excluded.last_observed_at,
                    last_pid=excluded.last_pid, process_create_time=excluded.process_create_time
                """,
                (
                    normalized_path, file_path, int(payload.get("file_size", 0)),
                    float(payload.get("creation_time", 0.0)), float(payload.get("modification_time", 0.0)),
                    current_hash, payload.get("signature_status", "unknown"), first_observed_at, observed_at,
                    payload.get("pid"), payload.get("process_create_time"),
                ),
            )
            changed = bool(previous_sha256 and current_hash and previous_sha256 != current_hash)
            if existing is None or changed:
                change_type = "integrity_change" if changed else "first_observation"
                cursor = connection.execute(
                    """
                    INSERT INTO file_hash_history
                        (normalized_path, file_path, sha256, previous_sha256, observed_at, change_type, pid)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (normalized_path, file_path, current_hash, previous_sha256, observed_at, change_type, payload.get("pid")),
                )
                return int(cursor.lastrowid)
            return int(existing["id"])

    def record_file_reputation_event(self, event: SecurityEvent) -> int:
        payload = dict(event.payload)
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO file_reputation_events (
                    observed_at, event_type, file_path, sha256, pid, file_reputation_score,
                    integrity_changed, reasons, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.observed_at, event.event_type, payload.get("file_path", ""), payload.get("sha256"),
                    payload.get("pid"), float(payload.get("file_reputation_score", 0.0)),
                    1 if payload.get("integrity_changed") else 0, json.dumps(payload.get("reasons", [])),
                    json.dumps(payload),
                ),
            )
            return int(cursor.lastrowid)

    def recent_file_inventory(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._recent_rows("file_inventory", limit, json_fields=set(), order_by="last_observed_at")

    def recent_file_hash_history(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._recent_rows("file_hash_history", limit, json_fields=set())

    def recent_file_reputation_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._recent_rows("file_reputation_events", limit, json_fields={"reasons", "payload"})

    @staticmethod
    def _normalize_file_path(file_path: str) -> str:
        import os

        return os.path.normcase(os.path.abspath(file_path)).replace("\\", "/").lower()

    def recent_threats(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._recent_rows("threats", limit, json_fields={"reasons"})

    def recent_registry_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._recent_rows("registry_events", limit, json_fields={"payload"})

    def recent_network_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._recent_rows("network_events", limit, json_fields={"payload"})

    def recent_correlated_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._recent_rows("correlated_incidents", limit, json_fields={"involved_pids", "event_types", "evidence"})

    def _recent_rows(self, table: str, limit: int, json_fields: set[str], order_by: str = "observed_at") -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows: Iterable[sqlite3.Row] = connection.execute(
                f"SELECT * FROM {table} ORDER BY {order_by} DESC, id DESC LIMIT ?", (limit,)
            ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            for field in json_fields:
                item[field] = json.loads(item.get(field) or "[]")
            results.append(item)
        return results
