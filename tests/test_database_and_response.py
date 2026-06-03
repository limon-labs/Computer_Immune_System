from __future__ import annotations

from adaptive.threat_scoring import ThreatEvent
from database.threat_history import ThreatHistoryStore
from self_healing.process_isolation import ProcessIsolationEngine


def make_event(score: float = 90.0) -> ThreatEvent:
    return ThreatEvent(
        observed_at="2026-01-01T00:00:00+00:00",
        pid=123456,
        process_name="demo",
        executable=None,
        command_line="demo",
        create_time=None,
        anomaly_score=70.0,
        behavior_score=90.0,
        threat_score=score,
        severity="critical",
        reasons=["test reason"],
    )


def test_threat_history_round_trip(tmp_path):
    store = ThreatHistoryStore(tmp_path / "history.sqlite3")

    row_id = store.record_threat(make_event())
    rows = store.recent_threats(1)

    assert row_id == 1
    assert rows[0]["process_name"] == "demo"
    assert rows[0]["reasons"] == ["test reason"]


def test_process_isolation_defaults_to_dry_run_suspend(tmp_path):
    engine = ProcessIsolationEngine({"response": {"dry_run": True, "isolate_score_threshold": 85, "terminate_score_threshold": 95}, "recovery": {"journal_path": str(tmp_path / "journal.jsonl")}})

    action = engine.respond(make_event(90.0))

    assert action == "dry_run_suspend"


def test_recovery_manager_records_and_dry_run_rolls_back(tmp_path):
    from self_healing.recovery import RecoveryManager

    manager = RecoveryManager(tmp_path / "journal.jsonl", dry_run=True)
    record = manager.record("suspended", 1, "demo", create_time=1.0)

    assert manager.latest(1)[0] == record
    assert manager.rollback(record) == "dry_run_rollback:suspended"
