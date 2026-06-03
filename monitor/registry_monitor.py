"""Windows registry monitoring placeholder with platform-safe behavior."""

from __future__ import annotations

import platform


def registry_monitor_supported() -> bool:
    return platform.system().lower() == "windows"
