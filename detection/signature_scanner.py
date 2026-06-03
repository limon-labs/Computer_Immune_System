"""Lightweight signature scanner for command lines and filenames."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable


class SignatureScanner:
    def __init__(self, signatures: Iterable[str] | None = None):
        self.signatures = [signature.lower() for signature in (signatures or [])]

    def scan_text(self, text: str) -> list[str]:
        lowered = text.lower()
        return [signature for signature in self.signatures if signature in lowered]

    def scan_file_name(self, path: str | Path) -> list[str]:
        return self.scan_text(Path(path).name)
