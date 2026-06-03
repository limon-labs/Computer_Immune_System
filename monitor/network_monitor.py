"""System-wide network monitoring helpers."""

from __future__ import annotations

import psutil


def active_inet_connections(limit: int = 512):
    """Return active inet connections, capped for predictable scan cost."""

    return psutil.net_connections(kind="inet")[:limit]
