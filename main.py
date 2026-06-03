"""Command-line entry point for the Computer Immune System."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from core.config import load_config
from core.logging_config import configure_logging
from core.orchestrator import ImmuneSystemOrchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI-driven local computer immune system")
    parser.add_argument("--config", help="Path to JSON configuration override")
    parser.add_argument("--once", action="store_true", help="Run one process scan and exit")
    parser.add_argument("--history", type=int, metavar="N", help="Print the N most recent stored threats")
    parser.add_argument("--realtime", action="store_true", help="Run queue-driven real-time process and file monitoring")
    parser.add_argument("--windows-service", nargs="*", metavar="SERVICE_ARG", help="Dispatch the Windows Service wrapper when running on Windows")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config = load_config(args.config)
    logger = configure_logging(config)
    orchestrator = ImmuneSystemOrchestrator(config, logger)

    if args.windows_service is not None:
        from service_windows import install_or_dispatch

        print(install_or_dispatch(args.windows_service))
        return 0
    if args.history:
        print(json.dumps(orchestrator.history.recent_threats(args.history), indent=2))
        return 0
    if args.realtime:
        orchestrator.run_realtime()
        return 0
    if args.once:
        events = orchestrator.scan_once()
        print(json.dumps([asdict(event) for event in events], indent=2))
        return 0
    orchestrator.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
