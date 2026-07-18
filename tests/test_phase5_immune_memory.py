from __future__ import annotations

import logging
import sqlite3
from dataclasses import asdict

from core.correlation_engine import CorrelatedIncident
from core.event_queue import SecurityEvent
from core.orchestrator import ImmuneSystemOrchestrator
from database.immune_memory import BehaviorFingerprint, ImmuneMemoryStore
from database.threat_history import ThreatHistoryStore
from monitor.process_monitor import ProcessSnapshot


def make_attack_chain(port: int = 4444, pid: int = 123, parent_pid: int = 1) -> CorrelatedIncident:
    return CorrelatedIncident(
        observed_at="2026-01-01T00:00:00+00:00",
        incident_type="file_persistence_network_attack_chain",
        severity="critical",
        score_boost=50.0,
        involved_pids=[pid],
        event_types=["file.reputation", "process.started", "registry.startup_value_created", "network.connection_opened"],
        summary="new executable persisted and beaconed",
        evidence={
            "events": [
                {
                    "event_type": "process.started",
                    "source": "test",
                    "observed_at": "2026-01-01T00:00:00+00:00",
                    "payload": {"pid": pid, "name": "payload.exe", "parent_pid": parent_pid, "parent_name": "powershell.exe"},
                },
                {
                    "event_type": "file.reputation",
                    "source": "test",
                    "observed_at": "2026-01-01T00:00:01+00:00",
                    "payload": {"pid": pid, "file_path": "C:/Users/Alice/Downloads/payload.exe", "sha256": "abc", "is_new": True},
                },
                {
                    "event_type": "registry.startup_value_created",
                    "source": "test",
                    "observed_at": "2026-01-01T00:00:02+00:00",
                    "payload": {"key_path": "HKCU/Run", "value_name": "Updater", "value_data": "payload.exe"},
                },
                {
                    "event_type": "network.connection_opened",
                    "source": "test",
                    "observed_at": "2026-01-01T00:00:03+00:00",
                    "payload": {"pid": pid, "remote_address": "10.0.0.5", "remote_port": port, "suspicious_port": True},
                },
            ]
        },
    )


def test_remember_incident_builds_timeline_graph_and_fingerprint(tmp_path):
    memory = ImmuneMemoryStore(tmp_path / "memory.sqlite3")

    remembered = memory.remember_incident(make_attack_chain(), source_incident_id=99)

    assert remembered.memory_id == 1
    assert remembered.confidence_score >= 90
    assert remembered.recurrence_score == 0.0
    assert remembered.fingerprint.feature_count > 8
    assert memory.get_behavior_fingerprint(remembered.memory_id) == remembered.fingerprint
    timeline = memory.get_attack_timeline(remembered.memory_id)
    assert [item["event_type"] for item in timeline] == [
        "process.started",
        "file.reputation",
        "registry.startup_value_created",
        "network.connection_opened",
    ]
    graph = memory.get_attack_graph(remembered.memory_id)
    assert graph is not None
    node_types = {node.node_type for node in graph.nodes}
    relationships = {edge.relationship for edge in graph.edges}
    assert {"incident", "event", "process", "file", "registry", "network"}.issubset(node_types)
    assert {"spawned", "references_file", "modifies_registry", "connects", "supports"}.issubset(relationships)


def test_search_similar_incidents_and_recurrence_scores(tmp_path):
    memory = ImmuneMemoryStore(tmp_path / "memory.sqlite3")
    first = memory.remember_incident(make_attack_chain(port=4444))
    second = memory.remember_incident(make_attack_chain(port=4444, pid=222))
    memory.remember_incident(make_attack_chain(port=9999, pid=333))

    assert second.recurrence_score > first.recurrence_score
    matches = memory.search_similar_incidents(make_attack_chain(port=4444), limit=2)

    assert len(matches) == 2
    assert matches[0]["similarity_score"] >= matches[1]["similarity_score"]
    assert matches[0]["pattern_key"] == first.pattern_key


def test_search_accepts_behavior_fingerprint(tmp_path):
    memory = ImmuneMemoryStore(tmp_path / "memory.sqlite3")
    remembered = memory.remember_incident(make_attack_chain())
    fingerprint = memory.get_behavior_fingerprint(remembered.memory_id)

    matches = memory.search_similar_incidents(fingerprint, limit=1)

    assert matches[0]["id"] == remembered.memory_id
    assert matches[0]["similarity_score"] == 100.0


def test_orchestrator_remembers_correlated_incidents(tmp_path):
    orchestrator = ImmuneSystemOrchestrator(
        {
            "database": {"path": str(tmp_path / "history.sqlite3")},
            "response": {"dry_run": False},
            "filesystem": {"enabled": False, "watch_paths": []},
            "file_monitor": {"enabled": False},
            "event_queue": {"maxsize": 20},
        },
        logging.getLogger("test.phase5.orchestrator"),
    )

    orchestrator.process_security_event(
        SecurityEvent("process.started", "test", payload={"snapshot": asdict(ProcessSnapshot(pid=123, name="payload.exe", parent_pid=1, parent_name="powershell.exe"))})
    )
    orchestrator.process_security_event(SecurityEvent("registry.startup_value_created", "test", payload={"key_path": "Run", "value_name": "Updater"}))
    orchestrator.process_security_event(SecurityEvent("network.connection_opened", "test", payload={"pid": 123, "remote_port": 4444, "suspicious_port": True}))

    matches = orchestrator.immune_memory.search_similar_incidents(make_attack_chain(), limit=5)

    assert matches
    assert orchestrator.immune_memory.get_attack_timeline(matches[0]["id"])
    assert orchestrator.config["response"]["dry_run"] is True


def test_legacy_database_gets_immune_memory_tables_and_parent_columns(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT, observed_at TEXT NOT NULL, pid INTEGER,
                process_name TEXT, executable TEXT, command_line TEXT, anomaly_score REAL NOT NULL,
                behavior_score REAL NOT NULL, threat_score REAL NOT NULL, severity TEXT NOT NULL,
                reasons TEXT NOT NULL, action TEXT NOT NULL
            )
            """
        )

    ThreatHistoryStore(path)
    ImmuneMemoryStore(path)
    with sqlite3.connect(path) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        columns = {row[1] for row in connection.execute("PRAGMA table_info(threats)")}

    assert {"immune_memory_incidents", "behavior_fingerprints"}.issubset(tables)
    assert {"parent_pid", "parent_name"}.issubset(columns)
