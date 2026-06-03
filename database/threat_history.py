"""SQLite persistence for threat observations."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable

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
                    observed_at, pid, process_name, executable, command_line, create_time,
                    anomaly_score, behavior_score, threat_score, severity, policy_action, reasons, action
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.get("observed_at"),
                    payload.get("pid"),
                    payload.get("process_name"),
                    payload.get("executable"),
                    payload.get("command_line"),
                    payload.get("create_time"),
                    float(payload.get("anomaly_score", 0.0)),
                    float(payload.get("behavior_score", 0.0)),
                    float(payload.get("threat_score", 0.0)),
                    payload.get("severity", "unknown"),
                    payload.get("policy_action", "monitor"),
                    json.dumps(reasons),
                    payload.get("action", "none"),
                ),
            )
            return int(cursor.lastrowid)

    def recent_threats(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows: Iterable[sqlite3.Row] = connection.execute(
                "SELECT * FROM threats ORDER BY observed_at DESC, id DESC LIMIT ?", (limit,)
            ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["reasons"] = json.loads(item.get("reasons") or "[]")
            results.append(item)
        return results
