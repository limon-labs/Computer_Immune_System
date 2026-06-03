"""Self-healing file repair helpers."""

from __future__ import annotations

import shutil
from pathlib import Path


def restore_from_backup(target: str | Path, backup: str | Path) -> Path:
    destination = Path(target)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(backup, destination)
    return destination
