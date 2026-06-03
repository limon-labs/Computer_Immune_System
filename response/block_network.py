"""Network blocking abstraction.

The project intentionally does not shell out to firewall tools by default. A
production deployment can subclass this interface for platform-specific rules.
"""

from __future__ import annotations


class NetworkBlocker:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    def block_remote(self, host: str, port: int | None = None) -> str:
        target = f"{host}:{port}" if port is not None else host
        return f"dry_run_block:{target}" if self.dry_run else f"blocked:{target}"
