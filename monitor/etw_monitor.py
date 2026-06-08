"""Windows ETW telemetry collector interface.

The collector is Windows-only. It exposes a concrete queue-producing interface
and avoids claiming live ETW collection unless a backend adapter is supplied.
"""

from __future__ import annotations

import importlib.util
import platform
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from core.event_queue import SecurityEvent, SecurityEventQueue


@dataclass(frozen=True, slots=True)
class ETWProvider:
    name: str
    event_types: list[str]


class ETWBackend(Protocol):
    """Protocol implemented by platform-specific ETW session adapters."""

    def start(self, providers: list[ETWProvider], collector: "WindowsETWCollector") -> None:
        ...

    def stop(self) -> None:
        ...


class WindowsETWCollector:
    """Windows ETW collector facade for process/image/network telemetry."""

    DEFAULT_PROVIDERS = [
        ETWProvider("Microsoft-Windows-Kernel-Process", ["process_start", "process_stop", "image_load"]),
        ETWProvider("Microsoft-Windows-Kernel-Network", ["connection", "dns"]),
        ETWProvider("Microsoft-Windows-PowerShell", ["script_block", "module"]),
    ]

    def __init__(self, event_queue: SecurityEventQueue, config: Mapping[str, Any] | None = None, backend: ETWBackend | None = None):
        self.event_queue = event_queue
        self.config = config or {}
        self.backend = backend
        etw_config = self.config.get("etw", {}) if isinstance(self.config.get("etw"), Mapping) else {}
        self.enabled = bool(etw_config.get("enabled", platform.system().lower() == "windows"))
        self.providers = self._load_providers(etw_config.get("providers", [])) or self.DEFAULT_PROVIDERS
        self.status = "initialized"

    def supported(self) -> bool:
        return platform.system().lower() == "windows"

    def dependency_available(self) -> bool:
        return importlib.util.find_spec("win32evtlog") is not None

    def start(self) -> str:
        if not self.enabled:
            self.status = "disabled"
            return self.status
        if not self.supported():
            self.status = "unsupported_platform"
            return self.status
        if not self.dependency_available():
            self.status = "missing_pywin32_dependency"
            return self.status
        if self.backend is None:
            self.status = "backend_unavailable"
            return self.status
        self.backend.start(self.providers, self)
        self.status = "collecting"
        self.event_queue.publish(
            SecurityEvent(
                event_type="etw.collector_started",
                source="windows_etw",
                payload={"providers": [provider.name for provider in self.providers]},
                priority=8,
            )
        )
        return self.status

    def stop(self) -> None:
        if self.backend is not None and self.status == "collecting":
            self.backend.stop()
        self.status = "stopped"

    def ingest_event(self, provider: str, event_id: int, payload: Mapping[str, Any]) -> SecurityEvent:
        """Normalize an ETW event produced by a platform-specific adapter."""

        event = SecurityEvent(
            event_type="etw.event",
            source="windows_etw",
            payload={"provider": provider, "event_id": event_id, "data": dict(payload)},
            priority=7,
        )
        self.event_queue.publish(event)
        return event

    @staticmethod
    def _load_providers(raw_providers: Any) -> list[ETWProvider]:
        if not isinstance(raw_providers, list):
            return []
        providers: list[ETWProvider] = []
        for item in raw_providers:
            if isinstance(item, Mapping) and item.get("name"):
                event_types = item.get("event_types", [])
                if not isinstance(event_types, list):
                    event_types = []
                providers.append(ETWProvider(str(item.get("name")), [str(event) for event in event_types]))
        return providers
