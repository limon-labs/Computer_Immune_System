"""Windows registry startup-persistence monitoring."""

from __future__ import annotations

import platform
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, Mapping

from core.event_queue import SecurityEvent, SecurityEventQueue

STARTUP_RUN_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
]


@dataclass(frozen=True, slots=True)
class RegistryStartupEntry:
    key_path: str
    value_name: str
    value_data: str
    hive: str
    observed_at: str

    @property
    def identity(self) -> tuple[str, str]:
        return (self.key_path.lower(), self.value_name.lower())


def registry_monitor_supported() -> bool:
    return platform.system().lower() == "windows"


class WindowsStartupRegistryReader:
    """Reads common Windows startup persistence registry locations."""

    ROOTS = {
        "HKCU": "HKEY_CURRENT_USER",
        "HKLM": "HKEY_LOCAL_MACHINE",
    }

    def read_entries(self, keys: Iterable[str] = STARTUP_RUN_KEYS) -> list[RegistryStartupEntry]:
        if not registry_monitor_supported():
            return []
        import winreg  # type: ignore[import-not-found]

        observed_at = datetime.now(timezone.utc).isoformat()
        entries: list[RegistryStartupEntry] = []
        for key_path in keys:
            hive_name, subkey = key_path.split("\\", 1)
            root = getattr(winreg, self.ROOTS[hive_name])
            try:
                with winreg.OpenKey(root, subkey) as key:
                    index = 0
                    while True:
                        try:
                            value_name, value_data, _value_type = winreg.EnumValue(key, index)
                        except OSError:
                            break
                        entries.append(
                            RegistryStartupEntry(
                                key_path=key_path,
                                value_name=str(value_name),
                                value_data=str(value_data),
                                hive=hive_name,
                                observed_at=observed_at,
                            )
                        )
                        index += 1
            except OSError:
                continue
        return entries


class RegistryEventCollector:
    """Publishes registry startup persistence changes to SecurityEventQueue."""

    def __init__(
        self,
        event_queue: SecurityEventQueue,
        reader: WindowsStartupRegistryReader | Callable[[], list[RegistryStartupEntry]] | None = None,
        keys: Iterable[str] = STARTUP_RUN_KEYS,
    ):
        self.event_queue = event_queue
        self.reader = reader or WindowsStartupRegistryReader()
        self.keys = list(keys)
        self._known: dict[tuple[str, str], RegistryStartupEntry] = {}
        self._initialized = False
        self.dropped_events = 0

    def poll_once(self) -> list[SecurityEvent]:
        entries = self._read_entries()
        current = {entry.identity: entry for entry in entries}
        accepted: list[SecurityEvent] = []

        if not self._initialized:
            self._known = current
            self._initialized = True
            return []

        for identity, entry in current.items():
            previous = self._known.get(identity)
            if previous is None:
                event = self._to_event("registry.startup_value_created", entry)
            elif previous.value_data != entry.value_data:
                event = self._to_event("registry.startup_value_modified", entry, previous)
            else:
                continue
            if self.event_queue.publish(event):
                accepted.append(event)
            else:
                self.dropped_events += 1

        for identity, previous in self._known.items():
            if identity not in current:
                event = self._to_event("registry.startup_value_deleted", previous)
                if self.event_queue.publish(event):
                    accepted.append(event)
                else:
                    self.dropped_events += 1

        self._known = current
        return accepted

    def _read_entries(self) -> list[RegistryStartupEntry]:
        if callable(self.reader) and not hasattr(self.reader, "read_entries"):
            return self.reader()
        return self.reader.read_entries(self.keys)  # type: ignore[union-attr]

    @staticmethod
    def _to_event(event_type: str, entry: RegistryStartupEntry, previous: RegistryStartupEntry | None = None) -> SecurityEvent:
        payload = asdict(entry)
        if previous is not None:
            payload["previous_value_data"] = previous.value_data
        return SecurityEvent(event_type=event_type, source="registry_monitor", payload=payload, priority=8)
