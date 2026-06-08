from __future__ import annotations

import logging

from core.correlation_engine import CorrelationEngine
from core.event_queue import SecurityEvent, SecurityEventQueue
from core.orchestrator import ImmuneSystemOrchestrator
from database.threat_history import ThreatHistoryStore
from monitor.network_monitor import NetworkConnectionSnapshot, NetworkEventCollector
from monitor.registry_monitor import RegistryEventCollector, RegistryStartupEntry


def registry_entry(value_data: str = "evil.exe") -> RegistryStartupEntry:
    return RegistryStartupEntry(
        key_path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        value_name="Updater",
        value_data=value_data,
        hive="HKCU",
        observed_at="2026-01-01T00:00:00+00:00",
    )


def network_snapshot(port: int = 4444) -> NetworkConnectionSnapshot:
    return NetworkConnectionSnapshot(
        pid=123,
        local_address="127.0.0.1",
        local_port=50000,
        remote_address="10.0.0.5",
        remote_port=port,
        status="ESTABLISHED",
        family="AF_INET",
        type="SOCK_STREAM",
        observed_at="2026-01-01T00:00:00+00:00",
    )


def test_registry_collector_emits_startup_value_changes():
    snapshots = [[registry_entry("old.exe")], [registry_entry("new.exe")]]
    event_queue = SecurityEventQueue()
    collector = RegistryEventCollector(event_queue, reader=lambda: snapshots.pop(0))

    assert collector.poll_once() == []
    events = collector.poll_once()

    assert events[0].event_type == "registry.startup_value_modified"
    assert event_queue.drain(1)[0].payload["value_data"] == "new.exe"


def test_network_collector_emits_suspicious_connection():
    snapshots = [[network_snapshot(4444)]]
    event_queue = SecurityEventQueue()
    collector = NetworkEventCollector(event_queue, snapshot_provider=lambda: snapshots.pop(0), dangerous_ports=[4444], seed_baseline=False)

    events = collector.poll_once()

    assert events[0].event_type == "network.connection_opened"
    assert events[0].payload["suspicious_port"] is True


def test_correlation_engine_links_process_registry_network_chain():
    engine = CorrelationEngine(window_seconds=300)
    process_event = SecurityEvent("process.started", "test", payload={"snapshot": {"pid": 123}})
    registry_event = SecurityEvent("registry.startup_value_created", "test", payload={"key_path": "Run", "value_name": "Updater"})
    network_event = SecurityEvent("network.connection_opened", "test", payload={"pid": 123, "remote_port": 4444, "suspicious_port": True})

    assert engine.observe(process_event) == []
    assert any(item.incident_type == "registry_persistence" for item in engine.observe(registry_event))
    incidents = engine.observe(network_event)

    assert any(item.incident_type == "process_persistence_network_chain" for item in incidents)


def test_threat_history_persists_phase3_events(tmp_path):
    store = ThreatHistoryStore(tmp_path / "history.sqlite3")
    registry_event = SecurityEvent("registry.startup_value_created", "test", payload={"key_path": "Run", "value_name": "Updater", "value_data": "evil", "hive": "HKCU"})
    network_event = SecurityEvent("network.connection_opened", "test", payload={"pid": 123, "remote_address": "10.0.0.5", "remote_port": 4444, "suspicious_port": True})
    incident = CorrelationEngine().observe(registry_event)[0]

    store.record_registry_event(registry_event)
    store.record_network_event(network_event)
    store.record_correlated_incident(incident)

    assert store.recent_registry_events(1)[0]["value_name"] == "Updater"
    assert store.recent_network_events(1)[0]["remote_port"] == 4444
    assert store.recent_correlated_incidents(1)[0]["incident_type"] == "registry_persistence"


def test_orchestrator_records_registry_network_and_correlation(tmp_path):
    config = {
        "database": {"path": str(tmp_path / "history.sqlite3")},
        "response": {"dry_run": True},
        "filesystem": {"enabled": False, "watch_paths": []},
        "event_queue": {"maxsize": 100},
        "correlation": {"window_seconds": 300},
    }
    orchestrator = ImmuneSystemOrchestrator(config, logging.getLogger("test.phase3"))

    orchestrator.process_security_event(SecurityEvent("process.started", "test", payload={"snapshot": {"pid": 123, "name": "evil", "command_line": "evil"}}))
    orchestrator.process_security_event(SecurityEvent("registry.startup_value_created", "test", payload={"key_path": "Run", "value_name": "Updater", "value_data": "evil", "hive": "HKCU"}))
    orchestrator.process_security_event(SecurityEvent("network.connection_opened", "test", payload={"pid": 123, "remote_address": "10.0.0.5", "remote_port": 4444, "suspicious_port": True}))

    assert orchestrator.history.recent_registry_events(1)
    assert orchestrator.history.recent_network_events(1)
    assert orchestrator.history.recent_correlated_incidents(1)


def test_phase3_signal_scoring_and_rules():
    from adaptive.threat_scoring import ThreatScorer
    from core.rule_engine import RuleEngine

    event = SecurityEvent("network.connection_opened", "test", payload={"pid": 123, "remote_port": 4444, "suspicious_port": True})
    signal = ThreatScorer().score_security_event(event)

    assert signal is not None
    assert signal.threat_score == 40.0
    decision = RuleEngine().decide_signal(signal)
    assert decision.should_record
    assert decision.should_alert
    assert not decision.should_respond


def test_legacy_database_is_extended_with_phase3_tables(tmp_path):
    import sqlite3

    path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                observed_at TEXT NOT NULL,
                pid INTEGER,
                process_name TEXT,
                executable TEXT,
                command_line TEXT,
                anomaly_score REAL NOT NULL,
                behavior_score REAL NOT NULL,
                threat_score REAL NOT NULL,
                severity TEXT NOT NULL,
                reasons TEXT NOT NULL,
                action TEXT NOT NULL
            )
            """
        )
    store = ThreatHistoryStore(path)

    with store.connect() as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    assert {"registry_events", "network_events", "correlated_incidents"}.issubset(tables)


def test_legacy_config_without_phase3_sections_remains_supported(tmp_path):
    orchestrator = ImmuneSystemOrchestrator(
        {
            "database": {"path": str(tmp_path / "history.sqlite3")},
            "response": {"dry_run": True},
            "filesystem": {"enabled": False, "watch_paths": []},
            "event_queue": {"maxsize": 10},
        },
        logging.getLogger("test.phase3.compat"),
    )

    assert orchestrator.registry_collector is None
    assert orchestrator.network_collector is None
    assert orchestrator.config["response"]["dry_run"] is True
