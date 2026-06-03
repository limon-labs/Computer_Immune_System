"""Top-level orchestration for monitoring, detection, scoring, and response."""

from __future__ import annotations

import logging
import time
from dataclasses import asdict
from typing import Any, Callable, Mapping

from adaptive.threat_scoring import ThreatEvent, ThreatScorer
from core.alert_system import AlertSystem
from core.event_queue import SecurityEvent, SecurityEventQueue
from core.policy_engine import PolicyEngine
from core.rule_engine import RuleEngine
from core.safety import enforce_response_dry_run
from database.threat_history import ThreatHistoryStore
from detection.anomaly_detector import AnomalyDetector
from detection.heuristic_analysis import BehaviorAnalyzer
from monitor.etw_monitor import WindowsETWCollector
from monitor.file_monitor import FileSystemEventCollector
from monitor.process_event_collector import ProcessEventCollector
from monitor.process_monitor import ProcessMonitor, ProcessSnapshot
from monitor.realtime_monitor import RealTimeProcessMonitor
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
        self.anomaly_detector = AnomalyDetector(config)
        self.behavior_analyzer = BehaviorAnalyzer(config)
        self.policy_engine = PolicyEngine(config)
        self.threat_scorer = ThreatScorer()
        self.rule_engine = RuleEngine(response_threshold=float(response.get("isolate_score_threshold", 85)))
        self.alerts = AlertSystem(logger)
        self.history = ThreatHistoryStore(database.get("path", "data/threat_history.sqlite3"))
        self.isolation = ProcessIsolationEngine(config, logger=logger)

    def scan_once(self) -> list[ThreatEvent]:
        snapshots = self.monitor.snapshot()
        self.logger.info("Collected %s process snapshot(s)", len(snapshots))
        return self._evaluate_snapshots(snapshots)

    def _evaluate_snapshots(self, snapshots: list[ProcessSnapshot]) -> list[ThreatEvent]:
        events: list[ThreatEvent] = []
        trusted_baseline_candidates = []
        for snapshot in snapshots:
            policy = self.policy_engine.evaluate(snapshot)
            anomaly = self.anomaly_detector.score(snapshot)
            behavior = self.behavior_analyzer.analyze(snapshot)
            event = self.threat_scorer.score(snapshot, anomaly, behavior, policy)
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
        if event.event_type in {"process.started", "process.changed"}:
            snapshot_payload = event.payload.get("snapshot")
            if isinstance(snapshot_payload, Mapping):
                return self._evaluate_snapshots([ProcessSnapshot(**dict(snapshot_payload))])
        return []

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
                self.drain_event_queue()
                iterations += 1
                if max_iterations is not None and iterations >= max_iterations:
                    break
                time.sleep(self.poll_interval)
        finally:
            self.stop_collectors()

    def run_realtime(self) -> None:
        self.run_event_loop()
