"""Cross-platform service restart abstraction with safe dry-run defaults."""

from __future__ import annotations

import platform
import re
import subprocess

_SERVICE_NAME = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")


def _validate_service_name(service_name: str) -> None:
    if not _SERVICE_NAME.fullmatch(service_name):
        raise ValueError("service_name contains unsupported characters")


def restart_service(service_name: str, dry_run: bool = True) -> str:
    _validate_service_name(service_name)
    if dry_run:
        return f"dry_run_restart:{service_name}"
    system = platform.system().lower()
    if system == "windows":
        subprocess.run(["sc", "stop", service_name], check=False)
        subprocess.run(["sc", "start", service_name], check=True)
    elif system == "darwin":
        subprocess.run(["launchctl", "kickstart", f"system/{service_name}"], check=True)
    else:
        subprocess.run(["systemctl", "restart", service_name], check=True)
    return f"restarted:{service_name}"
