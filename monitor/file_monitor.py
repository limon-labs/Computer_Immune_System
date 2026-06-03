"""File monitoring hooks built on watchdog when used by applications."""

from __future__ import annotations

from pathlib import Path


def ensure_watch_path(path: str | Path) -> Path:
    watch_path = Path(path)
    watch_path.mkdir(parents=True, exist_ok=True)
    return watch_path
