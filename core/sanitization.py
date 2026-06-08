"""Data sanitization helpers for telemetry and persistence."""

from __future__ import annotations

import re

_SECRET_PATTERNS = [
    re.compile(r"(?i)(--?(?:password|passwd|pwd|token|secret|apikey|api-key|access-token)=)([^\s]+)"),
    re.compile(r"(?i)((?:password|passwd|pwd|token|secret|apikey|api_key|access_token)\s+)([^\s]+)"),
]


def redact_command_line(command_line: str, max_length: int = 4096) -> str:
    """Redact common inline secrets and cap persisted command-line length."""

    redacted = command_line[:max_length]
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(r"\1<redacted>", redacted)
    if len(command_line) > max_length:
        redacted += " …<truncated>"
    return redacted
