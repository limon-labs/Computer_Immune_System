"""Cross-platform service restart abstraction with safe dry-run defaults."""

from __future__ import annotations

import platform
import subprocess


def restart_service(service_name: str, dry_run: bool = True) -> str:
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
