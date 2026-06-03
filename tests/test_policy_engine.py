from __future__ import annotations

from core.policy_engine import PolicyEngine
from monitor.process_monitor import ProcessSnapshot


def test_name_only_allowlist_does_not_suppress_response_by_default():
    decision = PolicyEngine({"policy": {"allowlist": {"process_names": ["trusted.exe"]}}}).evaluate(
        ProcessSnapshot(pid=1, name="trusted.exe")
    )

    assert decision.action == "allow"
    assert not decision.suppress_response
    assert any("name/cmdline-only" in reason for reason in decision.reasons)


def test_path_allowlist_suppresses_response():
    decision = PolicyEngine({"policy": {"allowlist": {"executable_paths": ["C:/Program Files/Trusted/*"]}}}).evaluate(
        ProcessSnapshot(pid=1, name="trusted.exe", executable="C:\\Program Files\\Trusted\\trusted.exe")
    )

    assert decision.action == "allow"
    assert decision.suppress_response


def test_blocklist_takes_precedence_over_allowlist():
    config = {"policy": {"allowlist": {"executable_paths": ["*"]}, "blocklist": {"process_names": ["bad.exe"]}}}

    decision = PolicyEngine(config).evaluate(ProcessSnapshot(pid=1, name="bad.exe", executable="C:/Trusted/bad.exe"))

    assert decision.action == "block"
    assert not decision.suppress_response
