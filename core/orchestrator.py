"""Top-level orchestration for monitoring, detection, scoring, and response."""

from __future__ import annotations

import logging
import time
from typing import Any, Mapping

from adaptive.threat_scoring import ThreatEvent, ThreatScorer
from core.alert_system import AlertSystem
from core.policy_engine import PolicyEngine
from core.rule_engine import RuleEngine
from database.threat_history import ThreatHistoryStore
from detection.anomaly_detector import AnomalyDetector
from detection.heuristic_analysis import BehaviorAnalyzer
from monitor.process_monitor import ProcessMonitor, ProcessSnapshot
from monitor.realtime_monitor import RealTimeProcessMonitor
from self_healing.process_isolation import ProcessIsolationEngine


class ImmuneSystemOrchestrator:
    """Coordinates one-shot and continuous immune-system scans."""

    def __init__(self, config: Mapping[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        database = config.get("database", {}) if isinstance(config.get("database"), Mapping) else {}
        monitoring = config.get("monitoring", {}) if isinstance(config.get("monitoring"), Mapping) else {}
        response = config.get("response", {}) if isinstance(config.get("response"), Mapping) else {}

        self.poll_interval = float(monitoring.get("process_poll_interval_seconds", 5))
        self.monitor = ProcessMonitor(config)
        self.realtime_monitor = RealTimeProcessMonitor(self.monitor, poll_interval=self.poll_interval)
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

    def run_realtime(self) -> None:
        self.logger.info("Computer Immune System real-time monitoring started")
        while True:
            lifecycle_events = self.realtime_monitor.poll_events()
            for lifecycle_event in lifecycle_events:
                self.logger.debug("Process lifecycle event: %s pid=%s", lifecycle_event.event_type, lifecycle_event.pid)
            snapshots = RealTimeProcessMonitor.interesting_snapshots(lifecycle_events)
            if snapshots:
                self._evaluate_snapshots(snapshots)
            time.sleep(self.poll_interval)
