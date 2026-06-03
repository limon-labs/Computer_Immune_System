# Phase v2 Code Audit Report

## Scope and constraints

Audited the Phase v2 telemetry and service files listed below. This report intentionally does **not** implement fixes; it documents code-level findings for follow-up remediation.

Reviewed files:

1. `core/event_queue.py`
2. `monitor/process_event_collector.py`
3. `monitor/realtime_monitor.py`
4. `monitor/etw_monitor.py`
5. `monitor/file_monitor.py`
6. `service_windows.py`

## Remediation status

Critical and High findings in this report were remediated in the follow-up Phase v2 remediation pass. See `PHASE_V2_REMEDIATION.md` for implementation details, tests, and remaining non-critical work.

## Executive summary

Phase v2 establishes a useful event-driven foundation, but several production-impacting issues remain:

- ETW support is currently a facade, not a real ETW session consumer.
- Process identity is keyed only by PID in the real-time monitor, creating PID-reuse ambiguity.
- Queue overflow behavior silently drops newest events and has no priority or critical-event preservation.
- Filesystem monitoring can create directories as a side effect, silently drop events under load, and cannot safely restart the same watchdog observer after stop.
- The Windows Service wrapper relies on external configuration for dry-run behavior and does not harden service account/configuration paths.
- Several counters/state flags are not synchronized even though collectors are intended to interact with queue/observer threads.

## Critical findings

### C-1: ETW collector does not actually collect ETW events

**Files:** `monitor/etw_monitor.py`

`WindowsETWCollector.start()` validates platform/dependency and publishes an `etw.collector_ready` event, but it does not create an ETW trace session, subscribe to providers, process callbacks, or stop a session. `ingest_event()` can normalize events only if another adapter provides them.

**Evidence:** `start()` returns `ready` after importing `win32evtlog` and publishing collector readiness; no ETW session or callback loop is created. `ingest_event()` is a manual normalization hook.

**Impact:** Operators may believe ETW process/image/network/PowerShell telemetry is active when no ETW events are being consumed. This is a false-negative risk for Phase v2's primary Windows telemetry goal.

**Recommendation:** Implement a real ETW backend using a supported library or native bindings, with provider session creation, callback processing, stop handling, event-loss metrics, provider enable failures, and integration tests on Windows.

### C-2: Real-time process identity is PID-only, causing PID-reuse ambiguity

**Files:** `monitor/realtime_monitor.py`

`RealTimeProcessMonitor` stores known processes in `_known` keyed only by PID. If one process exits and another process reuses the same PID between polls, the monitor may emit `changed` instead of `stopped` + `started`.

**Evidence:** Current snapshots are keyed by `snapshot.pid`, and `_known` is looked up using only `pid`.

**Impact:** A malicious short-lived process can evade accurate lifecycle reconstruction, and response/audit logic may associate telemetry with the wrong process lineage.

**Recommendation:** Key process identity by `(pid, create_time)` where available, emit stop/start on create-time mismatch, and include process ancestry metadata when available.

## High findings

### H-1: Queue overflow silently drops newest events without priority handling

**Files:** `core/event_queue.py`, `monitor/process_event_collector.py`, `monitor/file_monitor.py`, `monitor/etw_monitor.py`

`SecurityEventQueue.publish()` drops events when full and increments `dropped_events`, but callers generally ignore the return value. There is no priority queue, no critical-event bypass, no oldest-event eviction policy, and no alert when drops occur.

**Evidence:** `publish()` returns `False` on `queue.Full`; collector calls publish/extend without acting on failed publication.

**Impact:** Burst activity from process creation, filesystem churn, or ETW events can drop the most recent and potentially most important telemetry. Attackers can intentionally flood lower-value events to hide high-value events.

**Recommendation:** Add severity/priority, backpressure metrics, drop alerts, bounded per-source quotas, optional drop-oldest behavior for low-priority events, and tests for critical-event preservation.

### H-2: Drop counter and collector state are not thread-safe

**Files:** `core/event_queue.py`, `monitor/file_monitor.py`, `monitor/realtime_monitor.py`

The underlying `queue.Queue` is thread-safe, but `dropped_events += 1`, `FileSystemEventCollector.started`, and `RealTimeProcessMonitor._known` are unsynchronized mutable state.

**Evidence:** `dropped_events` is a plain integer incremented outside a lock; `started` is checked and changed without a lock; `_known` is replaced during polling without synchronization.

**Impact:** Concurrent producers and service control operations can lose drop counts, double-start or double-stop observers, or corrupt process lifecycle state if accessed from multiple threads.

**Recommendation:** Add locks around mutable counters/state, treat `RealTimeProcessMonitor` as single-threaded or enforce synchronization, and document thread ownership.

### H-3: Initial real-time process poll can flood the queue

**Files:** `monitor/realtime_monitor.py`, `monitor/process_event_collector.py`

On first poll, every existing process is emitted as `started` because `_known` starts empty.

**Evidence:** `previous is None` maps directly to `ProcessLifecycleEvent("started")` for every current process on first poll.

**Impact:** Large hosts can generate hundreds or thousands of startup events at agent start, filling the queue and dropping subsequent high-value events.

**Recommendation:** Add a baseline initialization mode that seeds `_known` without emitting events, or mark first-scan events as `process.baseline` with lower priority.

### H-4: Filesystem collector has unbounded event-volume risk and ignores publish failures

**Files:** `monitor/file_monitor.py`

`FileEventHandler.on_any_event()` publishes every watchdog event with no filtering, deduplication, throttling, path suppression, or handling of queue-full failures.

**Evidence:** The handler publishes all `on_any_event` callbacks directly to the shared queue.

**Impact:** Recursive watches on busy directories can overwhelm the event queue and memory/CPU, causing detection blind spots.

**Recommendation:** Add include/exclude path policy, extension filters, per-path rate limits, event coalescing, queue-full handling, and metrics.

### H-5: Windows Service wrapper does not enforce dry-run mode

**Files:** `service_windows.py`

The service wrapper loads normal configuration and starts `ImmuneSystemOrchestrator`. If an override config sets `response.dry_run=false`, the service will run with enforcement enabled.

**Evidence:** `SvcDoRun()` and foreground mode call `load_config()`/`load_config(config_path)` and pass the result directly into the orchestrator.

**Impact:** This conflicts with Phase v2's migration posture if a service deployment accidentally points at an enforcement config.

**Recommendation:** Add a service-safe mode that refuses enforcement unless an explicit, audited service flag is set; log effective response mode at startup.

## Medium findings

### M-1: `SecurityEvent` is frozen but contains a mutable payload dictionary

**Files:** `core/event_queue.py`

`SecurityEvent` is declared frozen, but `payload` is a mutable `dict`. Producers or consumers can mutate payload content after event creation or queue publication.

**Impact:** Audit integrity and deterministic testing are weakened; downstream consumers may see changed data.

**Recommendation:** Use immutable mappings, deep-copy payloads at construction/publication, or define typed event payload dataclasses.

### M-2: Invalid queue sizes can create unbounded queues

**Files:** `core/event_queue.py`

`queue.Queue(maxsize=0)` or negative values create effectively unbounded queues. `SecurityEventQueue` does not validate `maxsize`.

**Impact:** Misconfiguration can turn the event queue into a memory exhaustion vector.

**Recommendation:** Validate `maxsize >= 1` at configuration load or queue construction.

### M-3: ETW event payload can override reserved fields

**Files:** `monitor/etw_monitor.py`

`ingest_event()` builds payload with `{"provider": provider, "event_id": event_id, **dict(payload)}`. If `payload` includes `provider` or `event_id`, it overrides the reserved values.

**Impact:** A buggy or compromised adapter can spoof provider metadata and weaken audit trust.

**Recommendation:** Reject reserved key collisions or nest raw payload under a `data` key.

### M-4: ETW provider configuration lacks type hardening

**Files:** `monitor/etw_monitor.py`

The provider list comprehension assumes `etw_config.get("providers", [])` is iterable. If configuration sets `providers` to `null`, an integer, or another invalid value, initialization can raise.

**Impact:** A malformed config can prevent agent startup.

**Recommendation:** Validate config schema and coerce invalid provider lists to an empty list with an explicit warning.

### M-5: Filesystem collector creates watched directories as a side effect

**Files:** `monitor/file_monitor.py`

`ensure_watch_path()` creates the requested path with `mkdir(parents=True, exist_ok=True)`.

**Impact:** A typo or malicious config can create unexpected directories, possibly in sensitive locations if the service runs privileged.

**Recommendation:** Separate validation from creation. Require explicit `create_missing_watch_paths=true` for development scenarios and deny privileged/system paths by default.

### M-6: Watchdog observer restart lifecycle is unsafe

**Files:** `monitor/file_monitor.py`

`FileSystemEventCollector.stop()` sets `started=False`, but the same `Observer` instance is retained. Watchdog observers are thread-backed and are generally not safe to restart after being stopped.

**Impact:** Service reloads or collector restart attempts may fail or leak observer state.

**Recommendation:** Create a fresh `Observer` on each `start()` after a prior stop, or make collectors single-use and enforce that invariant.

### M-7: Service wrapper lacks robust status/error reporting

**Files:** `service_windows.py`

`SvcDoRun()` does not catch and report orchestrator startup/runtime exceptions. It logs start/stop messages but does not explicitly report `SERVICE_RUNNING` after initialization or `SERVICE_STOPPED` on exit.

**Impact:** Windows Service Control Manager and operators may see ambiguous service state, and runtime failures may be difficult to diagnose.

**Recommendation:** Add structured exception handling, `ReportServiceStatus` transitions, Windows event log error details, and service health reporting.

### M-8: Process collector reports returned events even when publication failed

**Files:** `monitor/process_event_collector.py`

`poll_once()` returns the events it attempted to publish, not the subset accepted by the queue. `SecurityEventQueue.extend()` returns accepted count, but the collector ignores it.

**Impact:** Tests/callers can believe events were queued when they were dropped.

**Recommendation:** Return publication results or accepted events, and expose per-collector drop counts.

## Low findings and observations

### L-1: `qsize()` is approximate

**Files:** `core/event_queue.py`, `monitor/file_monitor.py`

`qsize()` is used for filesystem test/helper waiting. Python queue size is approximate in multithreaded contexts.

**Recommendation:** Avoid using `qsize()` for correctness in production logic; prefer explicit acknowledgements or condition variables.

### L-2: Callback exceptions terminate `RealTimeProcessMonitor.watch()`

**Files:** `monitor/realtime_monitor.py`

`watch()` calls callbacks directly and does not catch exceptions.

**Recommendation:** Catch/log callback failures and continue, or document fail-fast behavior.

### L-3: Negative `poll_interval` is not validated

**Files:** `monitor/realtime_monitor.py`

A negative interval will eventually cause `time.sleep()` to raise; zero can create tight loops.

**Recommendation:** Validate `poll_interval > 0` and enforce a minimum interval.

### L-4: Sensitive filesystem paths are emitted without redaction

**Files:** `monitor/file_monitor.py`

Filesystem events publish raw `src_path` and `dest_path` values.

**Recommendation:** Add configurable path redaction or hashing for privacy-sensitive environments.

## Race condition summary

- `SecurityEventQueue.dropped_events` can race under multiple producers.
- `RealTimeProcessMonitor._known` can race if `poll_events()`/`watch()` are called concurrently.
- `FileSystemEventCollector.started` can race between service lifecycle and observer thread operations.
- Service stop can occur while collectors are starting; current service wrapper delegates stop checks to the orchestrator loop but does not coordinate collector startup with service status transitions.

## Queue overflow summary

The current overflow strategy is drop-newest with a counter. This is simple but not sufficient for endpoint security because attackers can flood low-signal filesystem events to cause high-signal process/ETW events to be dropped. The queue needs prioritization, source quotas, drop alerts, and metrics.

## Memory leak / resource lifecycle summary

- Unvalidated `maxsize <= 0` can create an unbounded queue.
- Watchdog observers are not rebuilt after stop and may not restart safely.
- File monitoring with broad recursive paths can generate sustained high-volume events.
- Process event conversion uses `asdict()` on snapshots and previous snapshots, duplicating event payload memory during bursts.

## Windows compatibility summary

- ETW collection is not yet implemented beyond dependency/status checks and manual event ingestion.
- `pywin32_available()` checks service modules, while ETW checks only `win32evtlog`; real ETW may need different dependencies.
- The service wrapper does not set service account, recovery options, delayed auto-start, failure actions, or ACL hardening.
- The service wrapper relies on default config discovery and does not accept a service-specific config path during SCM startup.

## Security weakness summary

- ETW `ingest_event()` trusts adapter-provided payload and lets it override reserved metadata.
- Queue flooding can blind detection.
- Raw filesystem paths may expose sensitive usernames/project names.
- Windows Service mode does not force dry-run during Phase v2.
- Missing service hardening leaves production deployments dependent on installer/operator choices.

## Recommended remediation order

1. Implement real ETW session management or rename the current class as an ETW facade/stub to prevent operator confusion.
2. Fix process identity to use `(pid, create_time)` and add baseline seeding to avoid startup event storms.
3. Harden `SecurityEventQueue`: validate max size, lock drop counters, add priority/quotas/drop alerts.
4. Harden filesystem collector: filters, coalescing, publish-failure handling, no implicit directory creation, safe observer restart.
5. Harden Windows Service: enforce dry-run in Phase v2, add status/error transitions, service-specific config, and documented account/ACL requirements.
6. Add targeted regression tests for PID reuse, queue priority, invalid config, observer restart, and reserved ETW payload key collisions.
