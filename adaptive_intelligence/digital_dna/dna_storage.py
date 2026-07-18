"""SQLite storage and low-memory cache for Digital DNA."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict
import json
import sqlite3
from pathlib import Path
from typing import Any

from adaptive_intelligence.digital_dna.dna_models import DigitalDNA, DigitalDNAComparison, utc_now
from database.threat_history import SCHEMA_PATH


class DigitalDNAStore:
    """Persists current DNA, version history, and comparison explanations."""

    def __init__(self, path: str | Path, cache_size: int = 128):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_size = max(1, int(cache_size))
        self._cache: OrderedDict[str, DigitalDNA] = OrderedDict()
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            self._ensure_legacy_threat_columns(connection)
            connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))

    @staticmethod
    def _ensure_legacy_threat_columns(connection: sqlite3.Connection) -> None:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "threats" not in tables:
            return
        existing = {row[1] for row in connection.execute("PRAGMA table_info(threats)").fetchall()}
        migrations = {
            "pid": "ALTER TABLE threats ADD COLUMN pid INTEGER",
            "process_name": "ALTER TABLE threats ADD COLUMN process_name TEXT",
            "executable": "ALTER TABLE threats ADD COLUMN executable TEXT",
            "command_line": "ALTER TABLE threats ADD COLUMN command_line TEXT",
            "create_time": "ALTER TABLE threats ADD COLUMN create_time REAL",
            "parent_pid": "ALTER TABLE threats ADD COLUMN parent_pid INTEGER",
            "parent_name": "ALTER TABLE threats ADD COLUMN parent_name TEXT",
            "file_reputation_score": "ALTER TABLE threats ADD COLUMN file_reputation_score REAL NOT NULL DEFAULT 0",
            "policy_action": "ALTER TABLE threats ADD COLUMN policy_action TEXT NOT NULL DEFAULT 'monitor'",
        }
        for column, statement in migrations.items():
            if column not in existing:
                connection.execute(statement)

    def get(self, dna_id: str) -> DigitalDNA | None:
        cached = self._cache_get(dna_id)
        if cached is not None:
            return cached
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM digital_dna WHERE dna_id = ?", (dna_id,)).fetchone()
        if row is None:
            return None
        dna = self._row_to_dna(row)
        self._cache_put(dna)
        return dna

    def save(self, dna: DigitalDNA) -> None:
        payload = self._dna_payload(dna)
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO digital_dna (
                    dna_id, version, identity, process_lineage, behavior_profile, network_profile,
                    filesystem_profile, registry_profile, security_profile, first_seen, last_seen,
                    confidence, evolution_timestamp, change_history
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dna_id) DO UPDATE SET
                    version=excluded.version,
                    identity=excluded.identity,
                    process_lineage=excluded.process_lineage,
                    behavior_profile=excluded.behavior_profile,
                    network_profile=excluded.network_profile,
                    filesystem_profile=excluded.filesystem_profile,
                    registry_profile=excluded.registry_profile,
                    security_profile=excluded.security_profile,
                    first_seen=excluded.first_seen,
                    last_seen=excluded.last_seen,
                    confidence=excluded.confidence,
                    evolution_timestamp=excluded.evolution_timestamp,
                    change_history=excluded.change_history
                """,
                payload,
            )
            connection.execute(
                """
                INSERT INTO digital_dna_history (dna_id, version, evolved_at, dna_snapshot, change_summary)
                VALUES (?, ?, ?, ?, ?)
                """,
                (dna.dna_id, dna.version, dna.evolution_timestamp, json.dumps(asdict(dna)), json.dumps(dna.change_history[-1:])),
            )
        self._cache_put(dna)

    def list_dna(self, limit: int = 1000) -> list[DigitalDNA]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM digital_dna ORDER BY last_seen DESC LIMIT ?", (max(0, int(limit)),)).fetchall()
        records = [self._row_to_dna(row) for row in rows]
        for dna in records:
            self._cache_put(dna)
        return records

    def get_history(self, dna_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM digital_dna_history WHERE dna_id = ? ORDER BY version ASC, id ASC", (dna_id,)
            ).fetchall()
        return [
            {
                "id": int(row["id"]),
                "dna_id": row["dna_id"],
                "version": int(row["version"]),
                "evolved_at": row["evolved_at"],
                "dna_snapshot": json.loads(row["dna_snapshot"]),
                "change_summary": json.loads(row["change_summary"]),
            }
            for row in rows
        ]

    def record_similarity(self, comparison: DigitalDNAComparison) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO digital_dna_similarity (
                    left_dna_id, right_dna_id, similarity_score, confidence, matched_features,
                    different_features, evolution_history, compared_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    comparison.left_dna_id,
                    comparison.right_dna_id,
                    comparison.similarity_score,
                    comparison.confidence,
                    json.dumps(comparison.matched_features),
                    json.dumps(comparison.different_features),
                    json.dumps(comparison.evolution_history),
                    utc_now(),
                ),
            )
            return int(cursor.lastrowid)

    @property
    def cache_keys(self) -> list[str]:
        return list(self._cache.keys())

    def _cache_get(self, dna_id: str) -> DigitalDNA | None:
        dna = self._cache.get(dna_id)
        if dna is None:
            return None
        self._cache.move_to_end(dna_id)
        return dna

    def _cache_put(self, dna: DigitalDNA) -> None:
        self._cache[dna.dna_id] = dna
        self._cache.move_to_end(dna.dna_id)
        while len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)

    @staticmethod
    def _dna_payload(dna: DigitalDNA) -> tuple[Any, ...]:
        return (
            dna.dna_id,
            dna.version,
            json.dumps(dna.identity),
            json.dumps(dna.process_lineage),
            json.dumps(dna.behavior_profile),
            json.dumps(dna.network_profile),
            json.dumps(dna.filesystem_profile),
            json.dumps(dna.registry_profile),
            json.dumps(dna.security_profile),
            dna.first_seen,
            dna.last_seen,
            dna.confidence,
            dna.evolution_timestamp,
            json.dumps(dna.change_history),
        )

    @staticmethod
    def _row_to_dna(row: sqlite3.Row) -> DigitalDNA:
        return DigitalDNA(
            dna_id=row["dna_id"],
            version=int(row["version"]),
            identity=json.loads(row["identity"]),
            process_lineage=json.loads(row["process_lineage"]),
            behavior_profile=json.loads(row["behavior_profile"]),
            network_profile=json.loads(row["network_profile"]),
            filesystem_profile=json.loads(row["filesystem_profile"]),
            registry_profile=json.loads(row["registry_profile"]),
            security_profile=json.loads(row["security_profile"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            confidence=float(row["confidence"]),
            evolution_timestamp=row["evolution_timestamp"],
            change_history=json.loads(row["change_history"]),
        )
