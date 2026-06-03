"""Policy evaluation for allowlists, blocklists, and protected processes."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import PureWindowsPath
from typing import Any, Mapping

from monitor.process_monitor import ProcessSnapshot


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Result of evaluating a process snapshot against local policy."""

    action: str = "monitor"
    score_adjustment: float = 0.0
    score_floor: float = 0.0
    suppress_response: bool = False
    reasons: list[str] = field(default_factory=list)


class PolicyEngine:
    """Applies explicit trust and deny policy before automated response.

    Policy deliberately supports simple glob patterns rather than regular
    expressions so administrators can write portable JSON without regex hazards.
    """

    def __init__(self, config: Mapping[str, Any] | None = None):
        self.config = config or {}
        policy = self.config.get("policy", {}) if isinstance(self.config.get("policy"), Mapping) else {}
        self.allowlist = policy.get("allowlist", {}) if isinstance(policy.get("allowlist"), Mapping) else {}
        self.blocklist = policy.get("blocklist", {}) if isinstance(policy.get("blocklist"), Mapping) else {}
        self.protected = policy.get("protected", {}) if isinstance(policy.get("protected"), Mapping) else {}
        self.allowlist_score_reduction = float(policy.get("allowlist_score_reduction", 30.0))
        self.blocklist_score_floor = float(policy.get("blocklist_score_floor", 95.0))

    def evaluate(self, snapshot: ProcessSnapshot) -> PolicyDecision:
        reasons: list[str] = []
        if self._matches_section(snapshot, self.protected, "protected", reasons):
            return PolicyDecision(
                action="protected",
                score_adjustment=-100.0,
                suppress_response=True,
                reasons=reasons,
            )
        if self._matches_section(snapshot, self.blocklist, "blocklist", reasons):
            return PolicyDecision(
                action="block",
                score_floor=self.blocklist_score_floor,
                suppress_response=False,
                reasons=reasons,
            )
        if self._matches_section(snapshot, self.allowlist, "allowlist", reasons):
            return PolicyDecision(
                action="allow",
                score_adjustment=-self.allowlist_score_reduction,
                suppress_response=True,
                reasons=reasons,
            )
        return PolicyDecision()

    def _matches_section(self, snapshot: ProcessSnapshot, section: Mapping[str, Any], label: str, reasons: list[str]) -> bool:
        matched = False
        name = snapshot.name.lower()
        executable = self._normalize_path(snapshot.executable or "")
        command_line = snapshot.command_line.lower()

        for pattern in self._patterns(section, "process_names"):
            if fnmatch(name, pattern.lower()):
                reasons.append(f"{label} process name match: {pattern}")
                matched = True
        for pattern in self._patterns(section, "executable_paths"):
            if fnmatch(executable, self._normalize_path(pattern)):
                reasons.append(f"{label} executable path match: {pattern}")
                matched = True
        for pattern in self._patterns(section, "command_line_patterns"):
            if fnmatch(command_line, pattern.lower()) or pattern.lower() in command_line:
                reasons.append(f"{label} command line match: {pattern}")
                matched = True
        if snapshot.executable_sha256:
            for digest in self._patterns(section, "hashes"):
                if snapshot.executable_sha256.lower() == digest.lower():
                    reasons.append(f"{label} hash match: {digest}")
                    matched = True
        return matched

    @staticmethod
    def _patterns(section: Mapping[str, Any], key: str) -> list[str]:
        value = section.get(key, [])
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]

    @staticmethod
    def _normalize_path(path: str) -> str:
        if not path:
            return ""
        return PureWindowsPath(path).as_posix().lower()
