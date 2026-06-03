"""Automatic rollback and recovery primitives."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil


@dataclass(frozen=True, slots=True)
class RecoveryRecord:
    """Auditable record of a reversible response action."""

    recorded_at: str
    action: str
    pid: int | None
    process_name: str | None
    metadata: dict[str, Any]


class RecoveryManager:
    """Stores response metadata and performs best-effort rollback."""

    def __init__(self, journal_path: str | Path = "data/recovery_journal.jsonl", dry_run: bool = True):
        self.journal_path = Path(journal_path)
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        self.dry_run = dry_run
        self._ensure_private_file()

    def record(self, action: str, pid: int | None, process_name: str | None, **metadata: Any) -> RecoveryRecord:
        record = RecoveryRecord(
            recorded_at=datetime.now(timezone.utc).isoformat(),
            action=action,
            pid=pid,
            process_name=process_name,
            metadata=metadata,
        )
        self._append_private(json.dumps(asdict(record), sort_keys=True) + "\n")
        return record

    def latest(self, limit: int = 20) -> list[RecoveryRecord]:
        if not self.journal_path.exists():
            return []
        lines = self.journal_path.read_text(encoding="utf-8").splitlines()[-limit:]
        records: list[RecoveryRecord] = []
        for line in lines:
            try:
                payload = json.loads(line)
                records.append(RecoveryRecord(**payload))
            except (json.JSONDecodeError, TypeError):
                continue
        return records

    def rollback(self, record: RecoveryRecord) -> str:
        """Best-effort rollback for reversible actions.

        Suspended processes can be resumed. Terminated processes cannot be
        safely resurrected, so rollback reports the recovery limitation.
        """

        if self.dry_run:
            return f"dry_run_rollback:{record.action}"
        if record.action == "suspended" and record.pid is not None:
            process = psutil.Process(record.pid)
            expected_create_time = record.metadata.get("create_time")
            if expected_create_time and abs(float(process.create_time()) - float(expected_create_time)) > 0.01:
                return "rollback_skipped_pid_reused"
            process.resume()
            return "resumed"
        if record.action == "terminated":
            return "rollback_unavailable_process_terminated"
        return "rollback_not_required"

    def _ensure_private_file(self) -> None:
        if not self.journal_path.exists():
            fd = os.open(self.journal_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
            os.close(fd)
        else:
            try:
                os.chmod(self.journal_path, 0o600)
            except OSError:
                pass

    def _append_private(self, payload: str) -> None:
        fd = os.open(self.journal_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(payload)
        finally:
            try:
                os.chmod(self.journal_path, 0o600)
            except OSError:
                pass
