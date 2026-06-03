"""Runtime policy helpers."""

from __future__ import annotations

from typing import Any, Mapping


class PolicyManager:
    """Reads operational policy from configuration."""

    def __init__(self, config: Mapping[str, Any]):
        self.config = config

    @property
    def dry_run(self) -> bool:
        response = self.config.get("response", {}) if isinstance(self.config.get("response"), Mapping) else {}
        return bool(response.get("dry_run", True))

    def response_threshold(self) -> float:
        response = self.config.get("response", {}) if isinstance(self.config.get("response"), Mapping) else {}
        return float(response.get("isolate_score_threshold", 85))
