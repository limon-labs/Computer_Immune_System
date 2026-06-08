"""Executable file reputation and integrity analysis."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class FileReputationFinding:
    """Transparent reputation result for an observed executable."""

    score: float
    reasons: list[str] = field(default_factory=list)
    is_new: bool = False
    integrity_changed: bool = False


class FileReputationAnalyzer:
    """Scores executable metadata without performing response actions."""

    DEFAULT_SUSPICIOUS_PATTERNS = (
        "*.scr",
        "*.com",
        "*crack*",
        "*keygen*",
        "*payload*",
        "*reverse_shell*",
        "*mimikatz*",
    )

    def __init__(self, config: Mapping[str, Any] | None = None):
        config = config or {}
        self.monitor_temp_execution = bool(config.get("monitor_temp_execution", True))
        patterns = config.get("suspicious_filename_patterns", self.DEFAULT_SUSPICIOUS_PATTERNS)
        self.suspicious_patterns = tuple(str(pattern).lower() for pattern in patterns)

    def analyze(
        self,
        metadata: Mapping[str, Any],
        previous: Mapping[str, Any] | None = None,
    ) -> FileReputationFinding:
        path = str(metadata.get("file_path") or "")
        normalized = self._normalized_path(path)
        filename = normalized.rsplit("/", 1)[-1]
        reasons: list[str] = []
        score = 0.0
        is_new = previous is None
        previous_hash = str(previous.get("sha256") or "") if previous else ""
        current_hash = str(metadata.get("sha256") or "")
        integrity_changed = bool(previous_hash and current_hash and previous_hash != current_hash)

        if metadata.get("signature_status") in {"unsigned", "invalid"}:
            score += 25.0
            reasons.append("executable is unsigned or has an invalid digital signature")
        if self.monitor_temp_execution and self._is_temp_path(normalized):
            score += 25.0
            reasons.append("executable launched from a temporary directory")
        if self._is_download_path(normalized):
            score += 20.0
            reasons.append("executable launched from a user download directory")
        if is_new:
            score += 10.0
            reasons.append("executable was not previously observed")
        if integrity_changed:
            score += 45.0
            reasons.append("executable hash changed since the previous observation")
        if any(fnmatch.fnmatch(filename, pattern) for pattern in self.suspicious_patterns):
            score += 25.0
            reasons.append("executable filename matches a suspicious pattern")
        if not current_hash:
            score += 10.0
            reasons.append("executable could not be hashed")

        return FileReputationFinding(
            score=min(100.0, score),
            reasons=reasons,
            is_new=is_new,
            integrity_changed=integrity_changed,
        )

    @staticmethod
    def _normalized_path(path: str) -> str:
        return os.path.normcase(os.path.normpath(path)).replace("\\", "/").lower()

    @staticmethod
    def _is_temp_path(path: str) -> bool:
        segments = {segment for segment in path.split("/") if segment}
        return bool(segments.intersection({"temp", "tmp"}))

    @staticmethod
    def _is_download_path(path: str) -> bool:
        return "downloads" in {segment for segment in path.split("/") if segment}
