"""Windows ETW telemetry collector interface.

The collector is Windows-only. It exposes a concrete queue-producing interface
now and is intentionally conservative: when optional native ETW dependencies are
not installed, it reports an explicit status instead of silently pretending to
collect telemetry.
"""

from __future__ import annotations

import importlib
import importlib.util
import platform
from dataclasses import dataclass
from typing import Any, Mapping

from core.event_queue import SecurityEvent, SecurityEventQueue


@dataclass(frozen=True, slots=True)
class ETWProvider:
    name: str
    event_types: list[str]


class WindowsETWCollector:
    """Windows ETW collector facade for process/image/network telemetry."""

    DEFAULT_PROVIDERS = [
        ETWProvider("Microsoft-Windows-Kernel-Process", ["process_start", "process_stop", "image_load"]),
        ETWProvider("Microsoft-Windows-Kernel-Network", ["connection", "dns"]),
        ETWProvider("Microsoft-Windows-PowerShell", ["script_block", "module"]),
    ]

    def __init__(self, event_queue: SecurityEventQueue, config: Mapping[str, Any] | None = None):
        self.event_queue = event_queue
        self.config = config or {}
        etw_config = self.config.get("etw", {}) if isinstance(self.config.get("etw"), Mapping) else {}
        self.enabled = bool(etw_config.get("enabled", platform.system().lower() == "windows"))
        self.providers = [
            ETWProvider(str(item.get("name")), [str(event) for event in item.get("event_types", [])])
            for item in etw_config.get("providers", [])
            if isinstance(item, Mapping) and item.get("name")
        ] or self.DEFAULT_PROVIDERS
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
        # pywin32 is imported lazily so non-Windows environments can import this module.
        importlib.import_module("win32evtlog")
        self.status = "ready"
        self.event_queue.publish(
            SecurityEvent(
                event_type="etw.collector_ready",
                source="windows_etw",
                payload={"providers": [provider.name for provider in self.providers]},
            )
        )
        return self.status

    def ingest_event(self, provider: str, event_id: int, payload: Mapping[str, Any]) -> SecurityEvent:
        """Normalize an ETW event produced by a platform-specific adapter."""

        event = SecurityEvent(
            event_type="etw.event",
            source="windows_etw",
            payload={"provider": provider, "event_id": event_id, **dict(payload)},
        )
        self.event_queue.publish(event)
        return event
