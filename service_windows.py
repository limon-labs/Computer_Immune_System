"""Windows Service wrapper for the Computer Immune System.

This module is import-safe on non-Windows platforms. Installing/running the
actual service requires Windows and pywin32.
"""

from __future__ import annotations

import importlib
import importlib.util
import platform

from core.config import load_config
from core.logging_config import configure_logging
from core.orchestrator import ImmuneSystemOrchestrator


SERVICE_NAME = "ComputerImmuneSystem"
SERVICE_DISPLAY_NAME = "Computer Immune System"
SERVICE_DESCRIPTION = "AI-assisted endpoint immune system telemetry and response agent."


def supported() -> bool:
    return platform.system().lower() == "windows"


def pywin32_available() -> bool:
    return all(importlib.util.find_spec(name) is not None for name in ("win32serviceutil", "win32service", "win32event", "servicemanager"))


def run_service_foreground(config_path: str | None = None, max_iterations: int | None = None) -> None:
    """Run the service workload in the foreground for debugging."""

    config = load_config(config_path)
    logger = configure_logging(config)
    logger.info("Starting %s in foreground mode", SERVICE_DISPLAY_NAME)
    ImmuneSystemOrchestrator(config, logger).run_event_loop(max_iterations=max_iterations)


def install_or_dispatch(argv: list[str] | None = None) -> str:
    """Install/start/stop the Windows service through pywin32 when available."""

    if not supported():
        return "unsupported_platform"
    if not pywin32_available():
        return "missing_pywin32_dependency"
    win32serviceutil = importlib.import_module("win32serviceutil")
    win32serviceutil.HandleCommandLine(_build_service_class(), argv=argv)
    return "handled"


def _build_service_class():  # pragma: no cover - exercised on Windows hosts with pywin32
    win32serviceutil = importlib.import_module("win32serviceutil")
    win32service = importlib.import_module("win32service")
    win32event = importlib.import_module("win32event")
    servicemanager = importlib.import_module("servicemanager")

    class ComputerImmuneSystemService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args: list[str]):
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.orchestrator: ImmuneSystemOrchestrator | None = None

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self) -> None:
            servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} starting")
            config = load_config()
            logger = configure_logging(config)
            self.orchestrator = ImmuneSystemOrchestrator(config, logger)
            self.orchestrator.run_event_loop(stop_event=self._stop_requested)
            servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} stopped")

        def _stop_requested(self) -> bool:
            return win32event.WaitForSingleObject(self.stop_event, 0) == win32event.WAIT_OBJECT_0

    return ComputerImmuneSystemService


if __name__ == "__main__":
    install_or_dispatch()
