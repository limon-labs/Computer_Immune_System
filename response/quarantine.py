"""File quarantine utilities."""

from __future__ import annotations

import shutil
from pathlib import Path


class QuarantineManager:
    def __init__(self, quarantine_directory: str | Path = "quarantine"):
        self.quarantine_directory = Path(quarantine_directory)
        self.quarantine_directory.mkdir(parents=True, exist_ok=True)

    def quarantine(self, path: str | Path) -> Path:
        source = Path(path)
        destination = self.quarantine_directory / source.name
        counter = 1
        while destination.exists():
            destination = self.quarantine_directory / f"{source.stem}.{counter}{source.suffix}"
            counter += 1
        return shutil.move(str(source), str(destination))
