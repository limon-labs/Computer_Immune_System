from __future__ import annotations

import json

from core.config import get_nested, load_config


def test_load_config_merges_override(tmp_path):
    override = tmp_path / "config.json"
    override.write_text(json.dumps({"response": {"dry_run": False}, "logging": {"level": "DEBUG"}}), encoding="utf-8")

    config = load_config(override)

    assert get_nested(config, "response.dry_run") is False
    assert get_nested(config, "logging.level") == "DEBUG"
    assert get_nested(config, "monitoring.max_processes_per_scan") == 1000
