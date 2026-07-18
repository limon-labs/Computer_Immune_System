from __future__ import annotations

import logging
import sqlite3
from dataclasses import asdict

from adaptive.threat_scoring import ThreatScorer
from adaptive_intelligence import AdaptiveIntelligenceEngine
from adaptive_intelligence.digital_dna import DigitalDNAEngine, DigitalDNAObservation, DigitalDNAStore
from core.correlation_engine import CorrelationEngine
from core.event_queue import SecurityEvent
from core.orchestrator import ImmuneSystemOrchestrator
from database.immune_memory import ImmuneMemoryStore
from monitor.process_monitor import ProcessSnapshot


def make_engine(tmp_path, cache_size: int = 4) -> DigitalDNAEngine:
    return DigitalDNAEngine(DigitalDNAStore(tmp_path / "dna.sqlite3", cache_size=cache_size))


def observation(path: str = "C:/Tools/payload.exe", sha: str = "abc", pid: int = 123, port: int = 4444) -> DigitalDNAObservation:
    return DigitalDNAObservation(
        executable_path=path,
        sha256=sha,
        publisher="unsigned",
        file_reputation=70.0,
        pid=pid,
        process_name="payload.exe",
        parent_pid=1,
        parent_executable="powershell.exe",
        ancestry=["explorer.exe", "powershell.exe"],
        cpu_percent=10.0,
        memory_percent=5.0,
        thread_count=4,
        handle_count=8,
        lifetime_seconds=30.0,
        startup_behavior=True,
        remote_ports=[port],
        connection_count=3,
        protocols=["tcp"],
        accessed_directories=["C:/Users/Alice/AppData/Temp"],
        temporary_file_usage=True,
        file_modification_count=2,
        registry_persistence=True,
        registry_patterns=["HKCU/Run/Updater"],
        threat_score=80.0,
        incident_types=["file_persistence_network_attack_chain"],
        confidence=75.0,
        recurrence=20.0,
        risk=80.0,
    )


def test_generate_dna_persists_complete_profile(tmp_path):
    engine = make_engine(tmp_path)

    dna = engine.generate_dna(observation())
    stored = engine.store.get(dna.dna_id)

    assert stored == dna
    assert dna.version == 1
    assert dna.identity["executable_path"] == "C:/Tools/payload.exe"
    assert dna.identity["sha256"] == "abc"
    assert dna.process_lineage["parent_executable"] == "powershell.exe"
    assert dna.behavior_profile["startup_behavior"] is True
    assert dna.network_profile["common_remote_ports"] == [4444]
    assert dna.filesystem_profile["temporary_file_usage"] is True
    assert dna.registry_profile["startup_persistence"] is True
    assert dna.security_profile["previous_incidents"] == ["file_persistence_network_attack_chain"]


def test_update_dna_evolves_without_overwriting_history(tmp_path):
    engine = make_engine(tmp_path)
    first = engine.generate_dna(observation(sha="abc", port=4444))
    second = engine.update_dna(observation(sha="abc", port=5555, pid=456))

    history = engine.get_dna_history(first.dna_id)

    assert second.version == 2
    assert len(history) == 2
    assert history[0]["version"] == 1
    assert history[1]["version"] == 2
    assert {4444, 5555}.issubset(set(second.network_profile["common_remote_ports"]))
    assert second.change_history[-1]["changes"]


def test_compare_dna_returns_explainable_json_and_records_similarity(tmp_path):
    engine = make_engine(tmp_path)
    left = engine.generate_dna(observation(path="C:/Tools/a.exe", sha="same", pid=1))
    right = engine.generate_dna(observation(path="C:/Tools/b.exe", sha="other", pid=2))

    comparison = engine.compare_dna(left, right)

    assert comparison["similarity_score"] > 0
    assert comparison["confidence"] > 0
    assert comparison["matched_features"]
    assert comparison["different_features"]
    assert comparison["evolution_history"]
    with engine.store.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM digital_dna_similarity").fetchone()[0] == 1


def test_find_similar_dna_and_cache_eviction(tmp_path):
    engine = make_engine(tmp_path, cache_size=2)
    target = engine.generate_dna(observation(path="C:/Tools/a.exe", sha="a", pid=1))
    engine.generate_dna(observation(path="C:/Tools/b.exe", sha="b", pid=2))
    engine.generate_dna(observation(path="C:/Tools/c.exe", sha="c", pid=3, port=5555))

    matches = engine.find_similar_dna(target, limit=2, minimum_score=1.0)

    assert matches
    assert len(engine.store.cache_keys) <= 2
    assert all("matched_features" in match for match in matches)


def test_legacy_database_migrates_digital_dna_tables(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE threats (id INTEGER PRIMARY KEY AUTOINCREMENT, observed_at TEXT NOT NULL, anomaly_score REAL NOT NULL, behavior_score REAL NOT NULL, threat_score REAL NOT NULL, severity TEXT NOT NULL, reasons TEXT NOT NULL, action TEXT NOT NULL)")

    store = DigitalDNAStore(path)

    with store.connect() as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"digital_dna", "digital_dna_history", "digital_dna_similarity"}.issubset(tables)


def test_orchestrator_creates_dna_for_process_snapshots(tmp_path):
    orchestrator = ImmuneSystemOrchestrator(
        {
            "database": {"path": str(tmp_path / "history.sqlite3")},
            "response": {"dry_run": False},
            "filesystem": {"enabled": False, "watch_paths": []},
            "file_monitor": {"enabled": False},
            "adaptive_intelligence": {"digital_dna": {"enabled": True, "cache_size": 8}},
            "detection": {"minimum_training_samples": 99},
        },
        logging.getLogger("test.phase61.orchestrator"),
    )
    snapshot = ProcessSnapshot(pid=99, name="payload.exe", executable="C:/Tools/payload.exe", parent_pid=1, parent_name="powershell.exe", remote_ports=[4444], connections=1)

    orchestrator._evaluate_snapshots([snapshot])

    assert orchestrator.digital_dna_engine is not None
    assert orchestrator.digital_dna_engine.store.list_dna(10)
    assert orchestrator.config["response"]["dry_run"] is True


def test_digital_dna_updates_from_correlated_incident(tmp_path):
    engine = make_engine(tmp_path)
    incident = {
        "incident_type": "file_persistence_network_attack_chain",
        "severity": "critical",
        "score_boost": 50.0,
        "evidence": {
            "events": [
                {"event_type": "file.reputation", "payload": {"pid": 1, "file_path": "C:/Tools/payload.exe", "sha256": "abc", "is_new": True}},
                {"event_type": "network.connection_opened", "payload": {"pid": 1, "remote_port": 4444, "suspicious_port": True}},
            ]
        },
    }

    updated = engine.update_from_incident(incident)

    assert updated
    assert updated[0].security_profile["previous_incidents"] == ["file_persistence_network_attack_chain"]


def test_threat_scorer_and_correlation_accept_digital_dna_signal():
    event = SecurityEvent("digital_dna.high_similarity", "test", payload={"similarity_score": 80.0, "reasons": ["matched known DNA"]})

    signal = ThreatScorer().score_security_event(event)
    incidents = CorrelationEngine().observe(event)

    assert signal is not None
    assert signal.threat_score == 80.0
    assert incidents[0].incident_type == "digital_dna_similarity"


def test_adaptive_intelligence_engine_includes_digital_dna_matches(tmp_path):
    memory = ImmuneMemoryStore(tmp_path / "memory.sqlite3")
    dna_engine = DigitalDNAEngine(DigitalDNAStore(tmp_path / "memory.sqlite3"))
    dna_engine.generate_dna(observation(path="C:/Tools/a.exe", sha="a", pid=1))
    dna_engine.generate_dna(observation(path="C:/Tools/b.exe", sha="b", pid=2))
    engine = AdaptiveIntelligenceEngine(memory, digital_dna_engine=dna_engine)

    assessment = engine.assess({"file_path": "C:/Tools/c.exe", "sha256": "c", "pid": 3, "remote_port": 4444}, limit=5)

    assert assessment.top_matches
    assert any("digital DNA" in reason for reason in assessment.reasons)
