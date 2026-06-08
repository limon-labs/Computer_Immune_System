from __future__ import annotations

import hashlib
import logging
import sqlite3
from dataclasses import asdict

import pytest

from adaptive.threat_scoring import ThreatScorer
from core.correlation_engine import CorrelationEngine
from core.event_queue import SecurityEvent, SecurityEventQueue
from core.orchestrator import ImmuneSystemOrchestrator
from database.threat_history import ThreatHistoryStore
from detection.anomaly_detector import AnomalyFinding
from detection.file_reputation import FileReputationAnalyzer
from detection.heuristic_analysis import BehaviorFinding
from monitor.file_monitor import ExecutableFileCollector
from monitor.process_monitor import ProcessSnapshot


def test_executable_collector_collects_metadata_and_sha256(tmp_path):
    executable = tmp_path / "demo.exe"
    executable.write_bytes(b"phase-four")
    queue = SecurityEventQueue(maxsize=4)
    collector = ExecutableFileCollector(queue, signature_verifier=lambda _path: "unsigned")

    event = collector.publish(executable, pid=42, process_create_time=12.5)

    assert event is not None
    assert event.payload["file_path"] == str(executable.resolve())
    assert event.payload["file_size"] == len(b"phase-four")
    assert event.payload["creation_time"] > 0
    assert event.payload["modification_time"] > 0
    assert event.payload["sha256"] == hashlib.sha256(b"phase-four").hexdigest()
    assert event.payload["signature_status"] == "unsigned"
    assert event.payload["pid"] == 42
    assert queue.drain(1)[0] == event


def test_executable_collector_rejects_unsupported_hash_algorithm():
    with pytest.raises(ValueError, match="sha256"):
        ExecutableFileCollector(SecurityEventQueue(), hash_algorithm="md5")


def test_file_reputation_combines_transparent_signals():
    analyzer = FileReputationAnalyzer({"monitor_temp_execution": True, "suspicious_filename_patterns": ["*payload*"]})
    metadata = {
        "file_path": "C:/Users/Alice/Downloads/temp/payload.exe",
        "sha256": "new-hash",
        "signature_status": "unsigned",
    }

    finding = analyzer.analyze(metadata, {"sha256": "old-hash"})

    assert finding.score == 100.0
    assert finding.integrity_changed
    assert not finding.is_new
    assert len(finding.reasons) >= 5


def test_threat_scorer_includes_file_reputation_component():
    snapshot = ProcessSnapshot(pid=7, name="demo", executable="demo.exe", command_line="demo")
    event = ThreatScorer().score(
        snapshot,
        AnomalyFinding(score=0.0, is_anomaly=False, reasons=[]),
        BehaviorFinding(score=0.0, reasons=[]),
        file_reputation_score=80.0,
        signal_reasons=["file reputation test"],
    )

    assert event.file_reputation_score == 80.0
    assert event.threat_score == 28.0
    assert "file reputation test" in event.reasons


def test_orchestrator_detects_and_persists_integrity_change(tmp_path):
    executable = tmp_path / "agent.exe"
    executable.write_bytes(b"version-one")
    orchestrator = ImmuneSystemOrchestrator(
        {
            "database": {"path": str(tmp_path / "history.sqlite3")},
            "response": {"dry_run": False},
            "event_queue": {"maxsize": 20},
            "filesystem": {"enabled": False, "watch_paths": []},
            "file_monitor": {
                "enabled": True,
                "hash_algorithm": "sha256",
                "track_hash_changes": True,
                "monitor_temp_execution": True,
            },
            "detection": {"minimum_training_samples": 99},
        },
        logging.getLogger("test.phase4.integrity"),
    )
    snapshot = ProcessSnapshot(pid=99, name="agent", executable=str(executable), command_line=str(executable))

    orchestrator._evaluate_snapshots([snapshot])
    executable.write_bytes(b"version-two")
    orchestrator._evaluate_snapshots([snapshot])

    reputation = orchestrator.history.recent_file_reputation_events(10)
    history = orchestrator.history.recent_file_hash_history(10)
    assert any(item["event_type"] == "file.integrity_change" for item in reputation)
    assert any(item["change_type"] == "integrity_change" for item in history)
    assert orchestrator.config["response"]["dry_run"] is True


def test_track_hash_changes_can_be_disabled_without_losing_inventory(tmp_path):
    executable = tmp_path / "stable.exe"
    executable.write_bytes(b"one")
    orchestrator = ImmuneSystemOrchestrator(
        {
            "database": {"path": str(tmp_path / "history.sqlite3")},
            "response": {"dry_run": True},
            "filesystem": {"enabled": False, "watch_paths": []},
            "file_monitor": {"enabled": True, "track_hash_changes": False},
        },
        logging.getLogger("test.phase4.disabled-change"),
    )
    snapshot = ProcessSnapshot(pid=10, name="stable", executable=str(executable), command_line="stable")
    orchestrator._evaluate_snapshots([snapshot])
    executable.write_bytes(b"two")
    orchestrator._evaluate_snapshots([snapshot])

    assert orchestrator.history.recent_file_inventory(1)[0]["sha256"] == hashlib.sha256(b"two").hexdigest()
    assert not any(item["event_type"] == "file.integrity_change" for item in orchestrator.history.recent_file_reputation_events(10))


def test_correlation_engine_builds_file_persistence_network_chain():
    engine = CorrelationEngine(window_seconds=300)
    file_event = SecurityEvent(
        "file.reputation", "test", payload={"pid": 123, "file_path": "payload.exe", "is_new": True}
    )
    registry_event = SecurityEvent(
        "registry.startup_value_created", "test", payload={"key_path": "Run", "value_name": "Updater"}
    )
    network_event = SecurityEvent(
        "network.connection_opened", "test", payload={"pid": 123, "remote_port": 4444, "suspicious_port": True}
    )

    engine.observe(file_event)
    engine.observe(registry_event)
    incidents = engine.observe(network_event)

    chain = next(item for item in incidents if item.incident_type == "file_persistence_network_attack_chain")
    assert chain.severity == "critical"
    assert chain.score_boost == 50.0
    assert chain.involved_pids == [123]


def test_legacy_database_migrates_phase4_schema_and_score_column(tmp_path):
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

    store = ThreatHistoryStore(path)
    with store.connect() as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        columns = {row[1] for row in connection.execute("PRAGMA table_info(threats)")}

    assert {"file_inventory", "file_hash_history", "file_reputation_events"}.issubset(tables)
    assert "file_reputation_score" in columns


def test_legacy_config_without_file_monitor_remains_disabled(tmp_path):
    orchestrator = ImmuneSystemOrchestrator(
        {
            "database": {"path": str(tmp_path / "history.sqlite3")},
            "response": {"dry_run": True},
            "filesystem": {"enabled": False, "watch_paths": []},
        },
        logging.getLogger("test.phase4.compat"),
    )

    assert orchestrator.executable_file_collector is None
