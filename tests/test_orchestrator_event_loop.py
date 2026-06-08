from __future__ import annotations

import logging
from dataclasses import asdict

from core.event_queue import SecurityEvent
from core.orchestrator import ImmuneSystemOrchestrator
from monitor.process_monitor import ProcessSnapshot


def test_orchestrator_processes_process_security_event(tmp_path):
    config = {
        "database": {"path": str(tmp_path / "history.sqlite3")},
        "logging": {"file": str(tmp_path / "test.log")},
        "response": {"dry_run": True, "isolate_score_threshold": 85},
        "event_queue": {"maxsize": 10, "drain_limit": 10},
        "filesystem": {"enabled": False, "watch_paths": []},
        "policy": {"allowlist": {}, "blocklist": {}, "protected": {}},
        "detection": {"minimum_training_samples": 99},
    }
    orchestrator = ImmuneSystemOrchestrator(config, logging.getLogger("test.orchestrator"))
    snapshot = ProcessSnapshot(pid=99, name="bad", command_line="bad --token=<redacted>", cpu_percent=99.0)

    events = orchestrator.process_security_event(
        SecurityEvent("process.started", "test", payload={"snapshot": asdict(snapshot)})
    )

    assert isinstance(events, list)
