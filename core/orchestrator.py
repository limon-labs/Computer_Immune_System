"""Top-level orchestration for monitoring, detection, scoring, and response."""

from __future__ import annotations

import logging
import time
from dataclasses import asdict
from typing import Any, Callable, Mapping

from adaptive.threat_scoring import ThreatEvent, ThreatScorer
from core.alert_system import AlertSystem
from core.correlation_engine import CorrelatedIncident, CorrelationEngine
from core.event_queue import SecurityEvent, SecurityEventQueue
from core.policy_engine import PolicyEngine
from core.rule_engine import RuleEngine
from core.safety import enforce_response_dry_run
from database.threat_history import ThreatHistoryStore
from database.immune_memory import ImmuneMemoryStore
from detection.anomaly_detector import AnomalyDetector
from detection.heuristic_analysis import BehaviorAnalyzer
from detection.file_reputation import FileReputationAnalyzer, FileReputationFinding
from monitor.etw_monitor import WindowsETWCollector
from monitor.file_monitor import ExecutableFileCollector, FileSystemEventCollector
from monitor.network_monitor import NetworkEventCollector
from monitor.process_event_collector import ProcessEventCollector
from monitor.process_monitor import ProcessMonitor, ProcessSnapshot
from monitor.realtime_monitor import RealTimeProcessMonitor
from monitor.registry_monitor import RegistryEventCollector, registry_monitor_supported
from self_healing.process_isolation import ProcessIsolationEngine


class ImmuneSystemOrchestrator:
    """Coordinates one-shot and continuous immune-system scans."""

    def __init__(self, config: Mapping[str, Any], logger: logging.Logger):
        self.config = enforce_response_dry_run(config)
        config = self.config
        self.logger = logger
        database = config.get("database", {}) if isinstance(config.get("database"), Mapping) else {}
        monitoring = config.get("monitoring", {}) if isinstance(config.get("monitoring"), Mapping) else {}
        response = config.get("response", {}) if isinstance(config.get("response"), Mapping) else {}
        queue_config = config.get("event_queue", {}) if isinstance(config.get("event_queue"), Mapping) else {}
        filesystem = config.get("filesystem", {}) if isinstance(config.get("filesystem"), Mapping) else {}
        file_monitor = config.get("file_monitor", {}) if isinstance(config.get("file_monitor"), Mapping) else {}
        registry = config.get("registry", {}) if isinstance(config.get("registry"), Mapping) else {}
        network = config.get("network", {}) if isinstance(config.get("network"), Mapping) else {}
        correlation = config.get("correlation", {}) if isinstance(config.get("correlation"), Mapping) else {}

        self.poll_interval = float(monitoring.get("process_poll_interval_seconds", 5))
        self.event_queue = SecurityEventQueue(
            maxsize=int(queue_config.get("maxsize", 10_000)),
            drop_policy=str(queue_config.get("drop_policy", "drop_newest")),
            block_timeout=float(queue_config.get("block_timeout_seconds", 0.25)),
        )
        self.event_drain_limit = int(queue_config.get("drain_limit", 250))
        self.monitor = ProcessMonitor(config)
        self.realtime_monitor = RealTimeProcessMonitor(self.monitor, poll_interval=self.poll_interval)
        self.process_collector = ProcessEventCollector(self.realtime_monitor, self.event_queue)
        self.etw_collector = WindowsETWCollector(self.event_queue, config)
        self.executable_file_collector = ExecutableFileCollector(
            self.event_queue,
            hash_algorithm=str(file_monitor.get("hash_algorithm", "sha256")),
        ) if file_monitor.get("enabled", False) else None
        self.file_reputation_analyzer = FileReputationAnalyzer(file_monitor)
        self.track_hash_changes = bool(file_monitor.get("track_hash_changes", True))
        self.file_collector = FileSystemEventCollector(
            self.event_queue,
            filesystem.get("watch_paths", []),
            recursive=bool(filesystem.get("recursive", True)),
            create_missing=bool(filesystem.get("create_missing", False)),
            allowed_event_types=filesystem.get("allowed_event_types"),
            ignored_patterns=filesystem.get("ignored_patterns"),
            max_events_per_second=int(filesystem.get("max_events_per_second", 500)),
            coalesce_window_seconds=float(filesystem.get("coalesce_window_seconds", 0.25)),
        ) if filesystem.get("enabled", False) else None
        self.registry_collector = RegistryEventCollector(self.event_queue) if registry.get("enabled", False) and registry_monitor_supported() else None
        self.network_collector = NetworkEventCollector(
            self.event_queue,
            dangerous_ports=network.get("dangerous_ports", config.get("detection", {}).get("dangerous_ports", [])),
            seed_baseline=bool(network.get("seed_baseline", True)),
        ) if network.get("enabled", False) else None
        self.correlation_engine = CorrelationEngine(window_seconds=int(correlation.get("window_seconds", 300)))
        self.anomaly_detector = AnomalyDetector(config)
        self.behavior_analyzer = BehaviorAnalyzer(config)
        self.policy_engine = PolicyEngine(config)
        self.threat_scorer = ThreatScorer()
        self.rule_engine = RuleEngine(response_threshold=float(response.get("isolate_score_threshold", 85)))
        self.alerts = AlertSystem(logger)
        self.history = ThreatHistoryStore(database.get("path", "data/threat_history.sqlite3"))
        self.immune_memory = ImmuneMemoryStore(database.get("path", "data/threat_history.sqlite3"))
        self.isolation = ProcessIsolationEngine(config, logger=logger)

    def scan_once(self) -> list[ThreatEvent]:
        snapshots = self.monitor.snapshot()
        self.logger.info("Collected %s process snapshot(s)", len(snapshots))
        return self._evaluate_snapshots(snapshots)

    def _evaluate_snapshots(self, snapshots: list[ProcessSnapshot]) -> list[ThreatEvent]:
        events: list[ThreatEvent] = []
        trusted_baseline_candidates = []
        file_findings: dict[str, FileReputationFinding] = {}
        for snapshot in snapshots:
            file_finding = FileReputationFinding(score=0.0)
            if self.executable_file_collector is not None and snapshot.executable:
                cache_key = str(snapshot.executable).lower()
                file_finding = file_findings.get(cache_key) or self._inspect_executable(snapshot)
                file_findings[cache_key] = file_finding
            policy = self.policy_engine.evaluate(snapshot)
            anomaly = self.anomaly_detector.score(snapshot)
            behavior = self.behavior_analyzer.analyze(snapshot)
            event = self.threat_scorer.score(
                snapshot, anomaly, behavior, policy,
                file_reputation_score=file_finding.score,
                signal_reasons=file_finding.reasons,
            )
            decision = self.rule_engine.decide(event)
            if event.threat_score < 20 and policy.action in {"monitor", "allow", "protected"}:
                trusted_baseline_candidates.append(snapshot)
            if not decision.should_record:
                continue
            if decision.should_respond and not policy.suppress_response:
                event.action = self.isolation.respond(event)
            self.history.record_threat(event)
            if decision.should_alert:
                self.alerts.emit(event)
            events.append(event)
        self.anomaly_detector.observe_trusted(trusted_baseline_candidates)
        return events

    def run_forever(self) -> None:
        self.logger.info("Computer Immune System started")
        while True:
            self.scan_once()
            time.sleep(self.poll_interval)

    def process_security_event(self, event: SecurityEvent) -> list[ThreatEvent]:
        self.logger.debug("Processing security event type=%s source=%s", event.event_type, event.source)
        threat_events: list[ThreatEvent] = []
        if event.event_type in {"process.started", "process.changed"}:
            snapshot_payload = event.payload.get("snapshot")
            if isinstance(snapshot_payload, Mapping):
                threat_events.extend(self._evaluate_snapshots([ProcessSnapshot(**dict(snapshot_payload))]))
        elif event.event_type.startswith("registry."):
            self.history.record_registry_event(event)
        elif event.event_type.startswith("network."):
            self.history.record_network_event(event)
        elif event.event_type == "file.executable_observed":
            derived_event, _finding = self._analyze_executable_event(event)
            self.process_security_event(derived_event)
        elif event.event_type in {"file.reputation", "file.integrity_change"}:
            self.history.record_file_reputation_event(event)

        signal = self.threat_scorer.score_security_event(event)
        if signal is not None and self.rule_engine.decide_signal(signal).should_alert:
            self.alerts.emit_signal(signal)

        for incident in self.correlation_engine.observe(event):
            self._handle_correlated_incident(incident)
        return threat_events


    def _inspect_executable(self, snapshot: ProcessSnapshot) -> FileReputationFinding:
        if self.executable_file_collector is None:
            return FileReputationFinding(score=0.0)
        event = self.executable_file_collector.inspect(
            snapshot.executable, pid=snapshot.pid, process_create_time=snapshot.create_time
        )
        if event is None:
            return FileReputationFinding(score=0.0, reasons=["executable metadata could not be collected"])
        derived_event, finding = self._analyze_executable_event(event)
        self.process_security_event(derived_event)
        return finding

    def _analyze_executable_event(self, event: SecurityEvent) -> tuple[SecurityEvent, FileReputationFinding]:
        payload = dict(event.payload)
        previous = self.history.get_file_inventory(str(payload.get("file_path") or ""))
        previous_hash = str(previous.get("sha256") or "") if previous else None
        analysis_previous = previous
        if previous is not None and not self.track_hash_changes:
            analysis_previous = {**previous, "sha256": payload.get("sha256")}
        finding = self.file_reputation_analyzer.analyze(payload, analysis_previous)
        history_previous_hash = previous_hash if self.track_hash_changes else None
        self.history.record_file_observation(payload, previous_sha256=history_previous_hash)
        integrity_changed = finding.integrity_changed and self.track_hash_changes
        derived_payload = {
            **payload,
            "file_reputation_score": finding.score,
            "reasons": finding.reasons,
            "is_new": finding.is_new,
            "integrity_changed": integrity_changed,
            "previous_sha256": previous_hash,
        }
        derived_event = SecurityEvent(
            event_type="file.integrity_change" if integrity_changed else "file.reputation",
            source="file_reputation_engine",
            observed_at=event.observed_at,
            payload=derived_payload,
            priority=8 if integrity_changed else 5,
        )
        return derived_event, finding

    def _handle_correlated_incident(self, incident: CorrelatedIncident) -> None:
        source_incident_id = self.history.record_correlated_incident(incident)
        self.immune_memory.remember_incident(incident, source_incident_id=source_incident_id)
        signal = self.threat_scorer.score_correlated_incident(incident)
        decision = self.rule_engine.decide_signal(signal)
        if decision.should_alert:
            self.alerts.emit_signal(signal)

    def drain_event_queue(self) -> list[ThreatEvent]:
        detected: list[ThreatEvent] = []
        for event in self.event_queue.drain(self.event_drain_limit):
            detected.extend(self.process_security_event(event))
        return detected

    def start_collectors(self) -> None:
        etw_status = self.etw_collector.start()
        self.logger.info("ETW collector status: %s", etw_status)
        if self.file_collector is not None:
            self.file_collector.start()
            self.logger.info("Filesystem collector started")

    def stop_collectors(self) -> None:
        if self.file_collector is not None:
            self.file_collector.stop()

    def run_event_loop(self, stop_event: Callable[[], bool] | None = None, max_iterations: int | None = None) -> None:
        self.logger.info("Computer Immune System event loop started")
        self.start_collectors()
        iterations = 0
        try:
            while stop_event is None or not stop_event():
                self.process_collector.poll_once()
                if self.registry_collector is not None:
                    self.registry_collector.poll_once()
                if self.network_collector is not None:
                    self.network_collector.poll_once()
                self.drain_event_queue()
                iterations += 1
                if max_iterations is not None and iterations >= max_iterations:
                    break
                time.sleep(self.poll_interval)
        finally:
            self.stop_collectors()

    def run_realtime(self) -> None:
        self.run_event_loop()
