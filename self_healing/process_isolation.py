"""Self-healing actions for isolating suspicious processes."""

from __future__ import annotations

import logging
from typing import Any, Mapping

import psutil

from adaptive.threat_scoring import ThreatEvent
from response.kill_process import ProcessTerminator
from self_healing.recovery import RecoveryManager


class ProcessIsolationEngine:
    """Isolates suspicious processes using suspend/terminate actions.

    The default configuration is dry-run to avoid disrupting developer machines.
    Set response.dry_run=false to enforce isolation.
    """

    def __init__(self, config: Mapping[str, Any], logger: logging.Logger | None = None):
        response = config.get("response", {}) if isinstance(config.get("response"), Mapping) else {}
        recovery = config.get("recovery", {}) if isinstance(config.get("recovery"), Mapping) else {}
        self.dry_run = bool(response.get("dry_run", True))
        self.isolate_threshold = float(response.get("isolate_score_threshold", 85))
        self.terminate_threshold = float(response.get("terminate_score_threshold", 95))
        self.logger = logger or logging.getLogger("computer_immune_system.self_healing")
        self.terminator = ProcessTerminator(dry_run=self.dry_run, logger=self.logger)
        self.recovery = RecoveryManager(recovery.get("journal_path", "data/recovery_journal.jsonl"), dry_run=self.dry_run)

    def respond(self, event: ThreatEvent) -> str:
        if event.threat_score < self.isolate_threshold:
            return "none"
        if event.threat_score >= self.terminate_threshold:
            action = self.terminator.terminate(event.pid, expected_create_time=event.create_time)
            self.recovery.record(action, event.pid, event.process_name, create_time=event.create_time, score=event.threat_score)
            return action
        return self.suspend(event.pid, event.process_name, event.create_time, event.threat_score)

    def suspend(self, pid: int, process_name: str | None = None, expected_create_time: float | None = None, score: float | None = None) -> str:
        if self.dry_run:
            self.logger.warning("Dry-run: would suspend process pid=%s", pid)
            self.recovery.record("dry_run_suspend", pid, process_name, create_time=expected_create_time, score=score)
            return "dry_run_suspend"
        try:
            process = psutil.Process(pid)
            if expected_create_time is not None and abs(process.create_time() - expected_create_time) > 0.01:
                self.logger.error("Refusing to suspend pid=%s because PID appears to have been reused", pid)
                return "pid_reuse_detected"
            process.suspend()
            self.recovery.record("suspended", pid, process_name, create_time=expected_create_time, score=score)
            return "suspended"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
            self.logger.error("Unable to suspend process pid=%s: %s", pid, exc)
            return "isolation_failed"
