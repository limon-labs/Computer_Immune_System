# Production Readiness Checklist

## Agent hardening

- [ ] Package as a signed, versioned binary/service rather than raw Python scripts.
- [ ] Run with least privilege and a dedicated service account.
- [ ] Add tamper protection for service files, logs, policies, and model artifacts.
- [ ] Add secure auto-update with signed artifacts and rollback.
- [ ] Add health checks, watchdog supervision, and crash reporting.

## Policy and governance

- [ ] Sign policy bundles and verify signatures before load.
- [ ] Add policy schema validation and semantic linting for dangerous wildcards.
- [ ] Add RBAC, approvals, versioning, audit trails, and emergency rollback.
- [ ] Maintain OS-specific protected-process baselines.
- [ ] Require path/hash/signature anchors for response-suppressing allowlists.

## Telemetry

- [ ] Windows: integrate ETW/Sysmon/AMSI/PowerShell Script Block Logging and code-signing metadata.
- [ ] Linux: integrate eBPF/auditd and package-manager integrity sources.
- [ ] macOS: integrate Endpoint Security Framework and notarization/signing metadata.
- [ ] Capture process ancestry, network DNS context, module loads, file writes, registry changes, and service persistence.
- [ ] Add privacy redaction and retention controls for sensitive telemetry.

## Detection engineering

- [ ] Persist baselines with integrity checks and controlled promotion workflows.
- [ ] Track model drift, feature distributions, and false-positive/false-negative rates.
- [ ] Add supervised detections, YARA/Sigma rules, LOLBin rules, and reputation feeds.
- [ ] Validate models offline before deployment with known-good and malicious corpora.
- [ ] Add adversarial testing for spoofed names, encoded commands, low-and-slow behavior, and resource exhaustion.

## Response and recovery

- [ ] Prefer staged response: alert, collect evidence, network isolate, suspend, terminate.
- [ ] Require multiple independent signals before destructive response.
- [ ] Capture forensic evidence before isolation/termination.
- [ ] Implement platform-specific firewall isolation with rollback.
- [ ] Test rollback for suspended processes, service restarts, quarantined files, and firewall rules.

## Persistence and audit

- [ ] Move critical audit logs to append-only or remote tamper-evident storage.
- [ ] Encrypt sensitive local databases at rest where supported.
- [ ] Add migration tests for every schema change.
- [ ] Add retention and secure deletion policies.
- [ ] Monitor for log/journal corruption and unauthorized changes.

## Operations

- [ ] Add structured metrics for scan latency, event volume, response outcomes, and errors.
- [ ] Add dashboards and alert routing to SOC tooling.
- [ ] Add safe-mode configuration for incident recovery.
- [ ] Document break-glass procedures.
- [ ] Run tabletop exercises and red-team validation before enforcement mode.
