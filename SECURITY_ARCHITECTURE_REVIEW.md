# Security and Architecture Review

## Executive summary

The project is now a safer prototype for a local AI-assisted endpoint defense agent. The latest changes address the most important flaws found during review: lack of explicit policy controls, self-training on the same data being scored, missing real-time lifecycle monitoring, incomplete recovery metadata, PID-reuse response risk, and Unix-only service recovery.

This is still not production EDR software. It needs signed policy distribution, kernel/ETW/eBPF telemetry, tamper resistance, authenticated update channels, model governance, and enterprise-scale observability before use on sensitive systems.

## Findings and mitigations

| Area | Finding | Risk | Mitigation added |
| --- | --- | --- | --- |
| Detection baseline | The detector trained on the same process set it scored. | Active malicious processes could be normalized and missed. | Added rolling trusted baselines and score-before-observe orchestration. |
| False positives | No allowlist/protected-process policy existed. | Trusted tools or OS-critical services could be scored and isolated. | Added `PolicyEngine` for allowlists, blocklists, protected processes, hash/path/name/cmdline matching, and response suppression. |
| Response race | A PID could be reused between detection and response. | The wrong process could be suspended or terminated. | Added create-time validation before suspend/terminate and rollback resume. |
| Recovery | Suspends/terminations lacked auditable recovery records. | Operators could not understand or reverse actions. | Added JSONL recovery journal and rollback for reversible suspension actions. |
| Real-time mode | Only full periodic scans existed. | New processes were not surfaced as lifecycle events. | Added portable real-time process lifecycle polling with start/change/stop events. |
| Windows support | Service restart assumed `systemctl`; path matching was Unix-centric. | Windows hosts could not use recovery and policy reliably. | Added Windows-aware `sc` service restart and case-insensitive normalized path matching. |
| Expensive hashing | Executable hashes can be expensive across all processes. | Monitoring overhead and lock contention. | Added opt-in `monitoring.hash_executables` defaulting to false. |
| Storage migration | SQLite schema changes could break existing databases. | Upgrades would fail for users with old threat history. | Added column migration checks in `ThreatHistoryStore.initialize`. |

## Remaining design risks

1. **Privilege boundary** - A user-space Python process can be tampered with by local admin or malware running with similar privilege.
2. **Telemetry depth** - Process polling misses short-lived process chains, memory-only behavior, kernel events, registry writes, and script interpreter internals.
3. **Model poisoning** - Low-risk samples are added to the trusted baseline. Production systems need signed/trusted baseline windows and quarantine review.
4. **Policy governance** - Local JSON policy has no signing, RBAC, versioning, or audit approval workflow.
5. **Response blast radius** - Termination remains dangerous. Production should stage responses: alert, network isolation, token/session isolation, suspend, then terminate.
6. **Forensics** - Process isolation should snapshot process metadata, loaded modules, handles, network state, and relevant files before action.
7. **Privacy** - Command-line capture can include secrets. Production deployments need redaction and retention controls.

## Production roadmap

### Phase 1: Harden the local agent

- Add signed configuration and policy bundles.
- Add a protected service supervisor and tamper-evident logs.
- Persist ML baselines with checksums and rollback.
- Add privacy redaction for command lines and environment data.
- Add richer unit/integration tests with mocked psutil processes.

### Phase 2: Improve telemetry and detection

- Windows: consume ETW/Sysmon-style process, network, registry, and PowerShell events.
- Linux: add eBPF/auditd process/network/file telemetry.
- macOS: add Endpoint Security Framework integration.
- Add process ancestry, signer reputation, file hash reputation, DNS, and module-load features.
- Add supervised model support with offline evaluation and drift monitoring.

### Phase 3: Enterprise operations

- Add central management APIs with mutual TLS.
- Add signed update pipeline for models, policies, and response playbooks.
- Add SOC workflows: case creation, evidence bundles, analyst approval, suppression rules.
- Add metrics dashboards for false positives, detection latency, response outcomes, and model drift.

### Phase 4: Autonomous response safety

- Add response simulation and canary enforcement.
- Add automatic rollback playbooks for service recovery, file restoration, firewall rule removal, and process resume.
- Add safety constraints that require multiple independent signals before destructive actions.
- Add formal allow/protect rules for OS-critical processes per platform.

## Phase v2 security update

Phase v2 introduces a bounded event queue and real-time collectors. This improves detection latency but adds new operational risks:

- **Event flooding:** process and filesystem bursts can fill the queue. The queue now has max-size and drop accounting, but production deployments still need telemetry shedding policy and metrics export.
- **ETW dependency and privilege drift:** ETW collection is Windows-only and depends on pywin32/provider availability. The collector reports explicit status instead of failing silently.
- **Filesystem volume:** recursive watchdog monitoring can generate high volume; enable narrow watch paths first.
- **Service control:** the Windows Service wrapper keeps response dry-run by default and delegates stop handling through the orchestrator event loop. Production service hardening still requires signed binaries, ACL-protected directories, and tamper protection.

Response actions remain dry-run by default. Phase v2 should be validated in observe-only mode before enabling any containment.
