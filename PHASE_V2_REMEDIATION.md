# Phase v2 Critical/High Remediation Report

## Summary

This remediation pass addresses all Critical and High findings from `CODE_AUDIT_REPORT.md` while preserving Phase v2's observe-first posture. Response actions are now centrally forced to dry-run through orchestration and service entry points.

## Remediated findings

| Audit ID | Finding | Remediation |
| --- | --- | --- |
| C-1 | ETW collector could claim readiness without real ETW collection. | `WindowsETWCollector` now requires an explicit backend adapter before reporting `collecting`; otherwise it reports `backend_unavailable`. Manual ingestion remains available for backend adapters and stores raw ETW payload under `data` to protect reserved metadata. |
| C-2 | Process identity was PID-only. | `RealTimeProcessMonitor` now keys identity by `(pid, create_time)`, emits `stopped` + `started` when PID is reused with a different create time, and includes identity in lifecycle events. |
| H-1 | Queue overflow silently dropped newest events without priority handling. | `SecurityEventQueue` now supports configurable `drop_newest`, `drop_oldest`, and `block` policies, priority-aware oldest dropping, explicit metrics, and rejected unbounded sizes. |
| H-2 | Shared mutable state was unsynchronized. | Queue counters use a lock; real-time monitor state uses an `RLock`; filesystem collector start/stop and handler counters use locks. |
| H-3 | First process poll could flood the queue. | `RealTimeProcessMonitor` now seeds a baseline by default and emits no events on the initial baseline poll. Tests can opt out with `seed_baseline=False`. |
| H-4 | Filesystem event handling was unbounded and ignored publish failures. | `FileEventHandler` now supports allowed event types, ignored patterns, rate limiting, duplicate coalescing, publish-failure accounting, and event priorities. Collector no longer creates missing watch paths by default and safely recreates observers on restart. |
| H-5 | Windows Service wrapper did not enforce dry-run mode. | Added central `enforce_response_dry_run()` and applied it in orchestrator and Windows Service foreground/SCM startup paths. |

## New tests

Added `tests/test_phase_v2_remediation.py` covering:

- PID + create-time process identity.
- Startup baseline seeding to prevent event floods.
- Priority-aware queue overflow behavior.
- Queue size validation.
- Thread-safe drop accounting under producer contention.
- Filesystem rate limiting and coalescing.
- Missing watch-path refusal by default.
- ETW backend-unavailable status and backend-driven ingestion.
- Orchestrator/service dry-run enforcement.

Updated existing tests for the new baseline behavior, ETW payload nesting, and filesystem path creation rules.

## Remaining non-critical work

The following medium/low items from `CODE_AUDIT_REPORT.md` are either partially addressed or remain future hardening tasks:

- Implement a production ETW backend using native session APIs or a maintained ETW library.
- Add service-specific configuration path support and Windows SCM status/error transition tests on a Windows CI runner.
- Add privacy controls for filesystem path redaction/hashing.
- Add per-source queue quotas and external metrics export.
- Add typed payload schemas for every event source.
