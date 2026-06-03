"""Safe process termination helpers."""

from __future__ import annotations

import logging

import psutil


class ProcessTerminator:
    def __init__(self, dry_run: bool = True, logger: logging.Logger | None = None):
        self.dry_run = dry_run
        self.logger = logger or logging.getLogger("computer_immune_system.response")

    def terminate(self, pid: int, expected_create_time: float | None = None) -> str:
        if self.dry_run:
            self.logger.warning("Dry-run: would terminate process pid=%s", pid)
            return "dry_run_terminate"
        process = psutil.Process(pid)
        if expected_create_time is not None and abs(process.create_time() - expected_create_time) > 0.01:
            self.logger.error("Refusing to terminate pid=%s because PID appears to have been reused", pid)
            return "pid_reuse_detected"
        process.terminate()
        return "terminated"
