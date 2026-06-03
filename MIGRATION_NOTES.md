# Migration Notes

## Phase v2: Event-driven Windows-ready telemetry

Phase v2 introduces queue-driven real-time telemetry collectors while preserving the existing scan APIs and dry-run response defaults.

### What changed

- Added `SecurityEventQueue` as the event bus between collectors and the detection engine.
- Added `ProcessEventCollector` to emit `process.started`, `process.changed`, and `process.stopped` events from the existing real-time process monitor.
- Added `WindowsETWCollector` as the Windows ETW collector facade. It is disabled by default and reports `unsupported_platform` or `missing_pywin32_dependency` when unavailable.
- Added watchdog-based `FileSystemEventCollector` for real-time file events.
- Added `service_windows.py` for Windows Service install/dispatch and foreground debugging.
- Updated `ImmuneSystemOrchestrator.run_realtime()` to use the queue-driven event loop.

### Configuration additions

```json
{
  "event_queue": {
    "maxsize": 10000,
    "drain_limit": 250
  },
  "etw": {
    "enabled": false,
    "providers": []
  },
  "filesystem": {
    "enabled": false,
    "watch_paths": [],
    "recursive": true
  }
}
```

### Upgrade guidance

1. Existing `python main.py --once` behavior is unchanged.
2. `python main.py --realtime` now starts the queue-driven event loop.
3. Keep `response.dry_run` set to `true` during migration and validation.
4. On Windows hosts, install optional Windows dependencies with `pip install -r requirements.txt`; `pywin32` is installed only on Windows by its platform marker.
5. Enable ETW only after confirming service account privileges and provider availability.
6. Enable filesystem monitoring gradually with a small allowlisted path set before broad recursive monitoring.

### Operational notes

- ETW support is intentionally conservative in this phase: the collector facade normalizes events and validates dependencies, but production-grade provider session management is still a later roadmap item.
- Filesystem monitoring can generate high volume. Tune `event_queue.maxsize`, `event_queue.drain_limit`, and watched paths before deployment.
- Response actions remain dry-run by default and should stay that way until alert quality is validated.
