"""Cross-platform snapshot restore helper."""

from __future__ import annotations

import shutil
from pathlib import Path


def restore_snapshot(snapshot: str | Path, destination: str | Path, dry_run: bool = True) -> str:
    source = Path(snapshot)
    target = Path(destination)
    if dry_run:
        return f"dry_run_restore:{source}->{target}"
    if source.is_dir():
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return f"restored:{target}"
