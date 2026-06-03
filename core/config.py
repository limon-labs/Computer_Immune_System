"""Configuration loading for the Computer Immune System."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "default_config.json"


class ConfigurationError(ValueError):
    """Raised when configuration cannot be parsed or validated."""


def _deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"Invalid JSON configuration in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"Configuration root must be an object: {path}")
    return data


def load_config(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Load default configuration, optionally merged with a user config file.

    JSON is intentionally used to avoid requiring an additional YAML parser while
    still supporting a portable, human-editable configuration file.
    """

    config = _load_json(DEFAULT_CONFIG_PATH)
    selected_path = path or os.environ.get("CIS_CONFIG")
    if selected_path:
        config = _deep_merge(config, _load_json(Path(selected_path)))
    return config


def get_nested(config: Mapping[str, Any], dotted_key: str, default: Any = None) -> Any:
    """Fetch a nested value using dot notation."""

    current: Any = config
    for part in dotted_key.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return default
        current = current[part]
    return current
