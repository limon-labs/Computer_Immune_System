# Red-Team Security Review

## Scope

Reviewed the detection engine, policy engine, monitoring system, recovery system, and self-healing response system for bypasses, false positives/negatives, privilege issues, exhaustion, races, persistence weaknesses, recovery weaknesses, and Windows-specific security issues.

## Findings and mitigations implemented

| Category | Red-team technique or weakness | Impact | Mitigation implemented |
| --- | --- | --- | --- |
| Detection bypass | Train-on-current-scan can normalize resident malware. | False negatives for already-running threats. | Existing rolling baseline retained; orchestrator scores before adding low-risk samples to baseline. |
| Detection bypass | Process-name spoofing such as naming malware `python.exe` or `svchost.exe`. | Name-only allowlists can suppress response. | Name-only/cmdline-only allowlists now reduce score but do not suppress response by default; path/hash allowlists are required for suppression. |
| Detection bypass | Command-line secret or payload obfuscation can evade literal patterns. | False negatives for encoded or staged attacks. | Remaining risk; production needs script-content inspection, AMSI/ETW/PowerShell events, and YARA/Sigma-style rules. |
| False positives | Common developer processes and OS services can look anomalous. | Unwanted alerts or isolation. | Added protected users/processes, policy score reductions, and response guardrails. |
| False positives | Long command lines with secrets persisted in the database. | Privacy and credential exposure. | Added command-line redaction and length caps before snapshots are persisted or scored. |
| Resource exhaustion | Large process tables, huge connection lists, many open files, or hashing every executable. | Slow scans and high CPU/I/O. | Added bounded process/connection/open-file sampling and opt-in executable hashing. |
| Race condition | PID reuse between scoring and response. | Wrong process could be suspended or terminated. | Existing create-time validation retained before suspend/terminate and rollback. |
| Race condition | Agent could suspend itself or PID 1. | Denial of service. | Added guardrails against current process, PID <= 1, and configured protected usernames. |
| Persistence weakness | Recovery journal could be world-readable or corrupted. | Leakage, audit loss, rollback failures. | Added restrictive `0600` creation/chmod and corruption-tolerant reads. |
| Privilege escalation | Service restart arguments could include unsafe strings. | Platform tool misuse or operator error. | Added strict service-name validation before invoking service managers. |
| Windows-specific | Policy path matching with backslashes/case differences. | Policy bypass or false positives. | Existing normalization via `PureWindowsPath(...).as_posix().lower()` retained. |
| Windows-specific | Critical Windows processes can be protected only by local policy. | Dangerous response if policy is incomplete. | Default protected process names and protected usernames include common Windows service identities. |

## Remaining risks that cannot be fixed automatically

1. **User-space tampering** - Malware with equivalent or higher privileges can disable or patch this Python agent. Production requires service hardening, tamper protection, signed binaries, and OS security controls.
2. **Telemetry gaps** - Polling misses very short-lived processes and memory-only techniques. Production needs ETW/Sysmon on Windows, eBPF/auditd on Linux, and Endpoint Security Framework on macOS.
3. **Model poisoning** - Attackers can slowly introduce low-risk-looking malicious behavior. Production needs signed baseline windows, analyst-approved baseline promotion, and drift monitoring.
4. **Payload visibility** - Command-line heuristics cannot reliably detect obfuscated scripts, packed binaries, injected code, or LOLBin abuse. Production needs script telemetry, memory/module inspection, signer reputation, and content scanning.
5. **Response safety** - Termination is inherently risky and often not reversible. Production should prefer staged containment, analyst approval, and evidence capture before destructive response.
6. **Policy trust** - Local JSON policy is not signed or centrally managed. Production requires signed policy bundles, RBAC, version history, and emergency rollback.
7. **Forensics integrity** - SQLite and JSONL files are useful locally but not tamper-evident. Production requires append-only remote logs or cryptographic sealing.
8. **Windows identity complexity** - Windows service accounts, protected processes, PPL, UAC, AppLocker/WDAC, and code-signing semantics require native Windows integrations beyond `psutil`.
9. **Network isolation** - `response/block_network.py` remains an abstraction. Production needs platform-specific firewall/WFP/pf/nftables integrations with rollback.

## Red-team scenarios to keep testing

- Malware named like a trusted process but running from a user-writable path.
- Blocklisted command line hidden behind script interpreters or base64 fragments.
- Thousands of short-lived processes created between polling intervals.
- Processes with huge connection/open-file counts to stress scanners.
- PID reuse after a suspicious process exits before response.
- Corrupted recovery journal lines and partially written records.
- Windows path variants: drive-letter case changes, backslashes, spaces, and 8.3-style paths.
- Attempts to isolate the current agent, PID 1, root/system-owned processes, or Windows service identities.
