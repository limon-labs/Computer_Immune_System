"""Adaptive policy update helpers."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping


def with_dry_run(config: Mapping[str, Any], dry_run: bool) -> dict[str, Any]:
    updated = deepcopy(dict(config))
    updated.setdefault("response", {})["dry_run"] = dry_run
    return updated
