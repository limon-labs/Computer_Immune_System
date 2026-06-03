"""Sandbox command runner interface."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(slots=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str


class SandboxRunner:
    def run(self, command: list[str], timeout: int = 30) -> SandboxResult:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return SandboxResult(completed.returncode, completed.stdout, completed.stderr)
