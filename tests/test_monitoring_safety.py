from __future__ import annotations

from core.sanitization import redact_command_line


def test_redact_command_line_masks_common_secrets_and_truncates():
    value = redact_command_line("tool --token=abc123 --password hunter2 " + "x" * 20, max_length=40)

    assert "abc123" not in value
    assert "hunter2" not in value
    assert "<redacted>" in value
    assert "<truncated>" in value
