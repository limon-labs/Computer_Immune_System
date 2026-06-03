"""Logging setup for the Computer Immune System."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Mapping, Any


def configure_logging(config: Mapping[str, Any]) -> logging.Logger:
    """Configure console and rotating file logging."""

    logging_config = config.get("logging", {}) if isinstance(config.get("logging"), Mapping) else {}
    level_name = str(logging_config.get("level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    log_file = Path(str(logging_config.get("file", "logs/immune_system.log")))
    log_file.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("computer_immune_system")
    logger.setLevel(level)
    logger.propagate = False
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(level)

    file_handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    return logger
