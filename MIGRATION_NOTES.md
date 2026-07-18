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

## Phase 3: Visibility expansion

Phase 3 adds optional Windows startup registry monitoring, psutil network connection telemetry, event correlation, and three SQLite tables: `registry_events`, `network_events`, and `correlated_incidents`.

### Compatibility

- Existing configuration files remain valid. Missing `registry`, `network`, and `correlation` sections use safe defaults and leave new collectors disabled.
- Existing SQLite databases are upgraded by `CREATE TABLE IF NOT EXISTS` and the existing threat-column migration logic; existing threat rows are not rewritten.
- Response behavior remains centrally forced to dry-run.

### Suggested rollout

1. Enable network telemetry first with `seed_baseline: true` to avoid emitting all existing connections at startup.
2. On Windows, enable registry monitoring after validating service account registry read access.
3. Review `registry_events`, `network_events`, and `correlated_incidents` before tuning signal thresholds.
4. Keep all response actions in dry-run while validating correlation quality and false-positive rates.


## Phase 4: File reputation and integrity

Phase 4 adds executable inventory and SHA-256 integrity history. `ThreatHistoryStore` applies additive migrations automatically:

- adds `threats.file_reputation_score` with a zero default;
- creates `file_inventory`;
- creates `file_hash_history`; and
- creates `file_reputation_events`.

No existing threat, registry, network, or incident records are rewritten. The default configuration enables executable inventory, while programmatic/legacy configurations that omit `file_monitor` continue with the feature disabled. To stage rollout explicitly, add:

```json
{
  "file_monitor": {
    "enabled": true,
    "hash_algorithm": "sha256",
    "track_hash_changes": true,
    "monitor_temp_execution": true
  }
}
```

Operational considerations:

1. Validate hashing overhead on representative endpoints before broad deployment.
2. Expect `signature_status=unknown` outside Windows and whenever Authenticode cannot be queried.
3. Review the first-observation baseline before treating novelty as malicious.
4. Keep response dry-run enabled; the current runtime forces this centrally.
5. Back up the SQLite database before upgrading, even though migrations are additive.


## Phase 5: Immune memory engine

Phase 5 introduces durable attack memory while keeping existing event tables intact. Additive migrations create:

- `immune_memory_incidents` for remembered incidents, confidence/recurrence scores, timelines, fingerprints, and attack graphs;
- `behavior_fingerprints` for searchable fingerprint hashes and feature sets; and
- `threats.parent_pid` / `threats.parent_name` so process lineage can appear in timelines and graphs.

Existing `correlated_incidents` rows remain the audit log. New correlated incidents are also written to immune memory by the orchestrator. Programmatic users can instantiate `ImmuneMemoryStore` against the same SQLite file and call:

- `remember_incident()`
- `search_similar_incidents()`
- `get_attack_timeline()`
- `get_behavior_fingerprint()`

Operational considerations:

1. Similarity search uses local behavioral fingerprint overlap; it is intended for analyst context and future matching, not automatic enforcement.
2. Recurrence scores increase when the same coarse pattern key reappears.
3. Parent-process fields are best-effort because OS permissions may hide parent details.
4. Back up the SQLite database before upgrading, even though migrations are additive.
