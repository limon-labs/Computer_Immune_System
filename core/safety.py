"""Central runtime safety controls."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping


def enforce_response_dry_run(config: Mapping[str, Any]) -> dict[str, Any]:
    """Return a config copy with response actions forced to dry-run.

    Phase v2 is observe-first. Enforcement can be implemented later behind an
    explicit, audited production gate, but all current orchestration/service
    paths should be dry-run regardless of user override files.
    """

    safe_config = deepcopy(dict(config))
    response = safe_config.setdefault("response", {})
    if isinstance(response, dict):
        response["dry_run"] = True
        response["forced_dry_run"] = True
    return safe_config
