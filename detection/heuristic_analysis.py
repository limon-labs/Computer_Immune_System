"""Behavioral process analysis heuristics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from monitor.process_monitor import ProcessSnapshot


@dataclass(slots=True)
class BehaviorFinding:
    score: float
    reasons: list[str] = field(default_factory=list)


class BehaviorAnalyzer:
    """Scores suspicious process behavior using transparent heuristics."""

    def __init__(self, config: Mapping[str, Any] | None = None):
        self.config = config or {}
        detection = self.config.get("detection", {}) if isinstance(self.config.get("detection"), Mapping) else {}
        monitoring = self.config.get("monitoring", {}) if isinstance(self.config.get("monitoring"), Mapping) else {}
        self.suspicious_names = [str(item).lower() for item in detection.get("suspicious_names", [])]
        self.suspicious_cmdline_patterns = [str(item).lower() for item in detection.get("suspicious_cmdline_patterns", [])]
        self.dangerous_ports = {int(port) for port in detection.get("dangerous_ports", [])}
        self.high_cpu_percent = float(monitoring.get("high_cpu_percent", 80.0))
        self.high_memory_percent = float(monitoring.get("high_memory_percent", 20.0))

    def analyze(self, snapshot: ProcessSnapshot) -> BehaviorFinding:
        score = 0.0
        reasons: list[str] = []
        name = snapshot.name.lower()
        command_line = snapshot.command_line.lower()

        if any(indicator in name for indicator in self.suspicious_names):
            score += 30
            reasons.append("process name matches a known suspicious indicator")

        matched_patterns = [pattern for pattern in self.suspicious_cmdline_patterns if pattern in command_line]
        if matched_patterns:
            score += min(35, 15 + (5 * len(matched_patterns)))
            reasons.append(f"command line contains suspicious pattern(s): {', '.join(matched_patterns)}")

        risky_ports = sorted((set(snapshot.listening_ports) | set(snapshot.remote_ports)) & self.dangerous_ports)
        if risky_ports:
            score += 20
            reasons.append(f"uses suspicious network port(s): {', '.join(str(port) for port in risky_ports)}")

        if snapshot.cpu_percent >= self.high_cpu_percent:
            score += 15
            reasons.append(f"high CPU usage: {snapshot.cpu_percent:.1f}%")

        if snapshot.memory_percent >= self.high_memory_percent:
            score += 15
            reasons.append(f"high memory usage: {snapshot.memory_percent:.1f}%")

        if snapshot.connections >= 50:
            score += 15
            reasons.append(f"large number of network connections: {snapshot.connections}")

        if snapshot.open_files >= 500:
            score += 10
            reasons.append(f"large number of open files: {snapshot.open_files}")

        if snapshot.num_threads >= 200:
            score += 10
            reasons.append(f"large thread count: {snapshot.num_threads}")

        return BehaviorFinding(score=min(score, 100.0), reasons=reasons)
