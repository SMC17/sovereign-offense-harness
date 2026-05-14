# THREAT_COVERAGE — sovereign-offense-harness

## Honest summary

This repository ships **12 TTP descriptors + 1 ART YAML adapter example**
covering **6 of MITRE ATT&CK Enterprise's 14 tactic columns**.

Reference matrix: **MITRE ATT&CK Enterprise v17.1** (April 2026 release;
14 tactic columns, ~200 top-level techniques, ~450 sub-techniques as
counted on the public Navigator).

**Counted coverage: 12 / ~650 technique+sub-technique entries ≈ 1.8%.**

The honest framing is the only credible one. This repo is not a
breadth-coverage tool and does not claim to be. Atomic Red Team
(~1,500+ atomics, MIT) and MITRE Caldera (~600 abilities, Apache 2.0)
cover the breadth. This repo's contribution is the *audit-envelope
shape per TTP run* and a *single-binary Zig runner with no agent /
server / runtime deps*. The coverage matrix below exists to make the
breadth gap auditable, not to hide it.

Evidence level: every covered TTP is `unit-tested` (the parser handles
the descriptor) plus `integration-tested` (smoke-run produced a
`jq`-parseable envelope with `verdict=PASS` on the maintainer's
workstation as of 2026-05-14). The TTPs are NOT `audited` against an
adversary baseline; they are read-only enumeration / dry-run /
loopback-scoped emulation suitable for a localhost lab.

Safety posture: every TTP below inherits the v0.2 refuse-by-default
gate. `run` exits 3 unless `--target <whitelisted_IP>` matches the
lab-targets whitelist OR `--unsafe-local` is explicitly passed. See
[`THREAT_MODEL.md`](THREAT_MODEL.md) for the gate's scope and limits.

## Coverage matrix

Legend:
- **yes** — TTP descriptor ships and runs end-to-end on a single
  localhost machine, producing a valid audit envelope.
- **partial** — TTP descriptor ships but covers a narrow slice of the
  technique (e.g. localhost-only, dry-run-only, single sub-technique).
- **no** — not covered; named here only when an attempted slice was
  considered and explicitly deferred for safety reasons.

### Reconnaissance (TA0043)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| — | (no entries) | no | — | Network-active recon is out of scope on a localhost-only harness. Use Atomic Red Team for breadth here. |

### Resource Development (TA0042)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| — | (no entries) | no | — | Out of scope: this repo is a TTP-runner, not an infrastructure-stand-up tool. |

### Initial Access (TA0001)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| — | (no entries) | no | — | Initial-access TTPs require either a real target or a credible spoof harness. Out of scope for v0.4. |

### Execution (TA0002)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| — | (no entries) | no | — | The harness *itself* is an execution primitive (`bash -c`); no dedicated execution-tactic TTP descriptors ship yet. |

### Persistence (TA0003)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| T1053.003 | Scheduled Task/Job — Cron | partial (read-only) | [`ttps/examples/t1053-003-cron-job.json`](ttps/examples/t1053-003-cron-job.json) | Read-only enumeration of `/etc/crontab`, `/etc/cron.d`, `/etc/cron.{hourly,daily,weekly,monthly}`, and the runner's own crontab. NEVER writes a crontab entry. Refuse-by-default unless `--target` whitelist OR `--unsafe-local`. |
| T1037.004 | Boot/Logon Init Scripts — RC Scripts | partial (read-only) | [`ttps/examples/t1037-004-rc-scripts.json`](ttps/examples/t1037-004-rc-scripts.json) | Read-only enumeration of `/etc/rc.local`, `/etc/init.d`, `/etc/systemd/system`, `/usr/lib/systemd/system`. NEVER writes a script, enables a service, or creates a systemd unit. Refuse-by-default. |

### Privilege Escalation (TA0004)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| — | (no entries) | no | — | PrivEsc TTPs are explicitly deferred. Adding them safely requires sandbox isolation the harness does not provide. |

### Defense Evasion (TA0005)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| T1070.002 | Indicator Removal — Clear Linux Logs | partial (DRY-RUN ONLY) | [`ttps/examples/t1070-002-clear-linux-logs-dryrun.json`](ttps/examples/t1070-002-clear-linux-logs-dryrun.json) | **DRY-RUN ONLY.** The `exec` field uses `stat` / `ls -la` to enumerate log paths and sizes; it contains NO `rm`, NO `truncate`, NO `>`, NO `journalctl --vacuum-*`. The `stdout_excludes` field asserts the absence of those commands as a structural guardrail. Modifying the `exec` line to actually clear logs is visible verbatim in the audit envelope. Refuse-by-default. |

### Credential Access (TA0006)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| T1003.008 | OS Credential Dumping — /etc/passwd and /etc/shadow | partial (read-only, no cracking) | [`ttps/examples/t1003-008-etc-passwd-shadow.json`](ttps/examples/t1003-008-etc-passwd-shadow.json) | Reads `/etc/passwd` (world-readable). Attempts `/etc/shadow`; if the runner is not root, the read fails and the envelope honestly records `shadow-readable=false (not authorized to read)`. No privilege escalation. No hash cracking. Refuse-by-default. |
| T1552.001 | Unsecured Credentials in Files | partial (counts only, contents redacted) | [`ttps/examples/t1552-001-unsecured-credentials-in-files.json`](ttps/examples/t1552-001-unsecured-credentials-in-files.json) | Pattern-matches credential-shaped lines in `$HOME` top-level dotfiles only (no recursion, no other users' homes, no `/etc`). Reports match COUNTS not contents. Secret-shaped lines never enter the envelope verbatim. Refuse-by-default. |

### Discovery (TA0007)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| T1082 | System Information Discovery | yes | [`ttps/examples/t1082-system-information-discovery.json`](ttps/examples/t1082-system-information-discovery.json) | Original example: `uname -a` + `/etc/os-release`. Refuse-by-default. |
| T1082 | System Information Discovery (extended) | yes | [`ttps/examples/t1082-system-information-discovery-extended.json`](ttps/examples/t1082-system-information-discovery-extended.json) | Extended fingerprint: kernel, distro, `lscpu`, `free -h`, top 10 mount points. Refuse-by-default. |
| T1057 | Process Discovery | yes | [`ttps/examples/t1057-process-discovery.json`](ttps/examples/t1057-process-discovery.json) | `ps -eo pid,ppid,user,comm` + `/proc` PID count. Read-only. Refuse-by-default. |
| T1018 | Remote System Discovery | yes | [`ttps/examples/t1018-remote-system-discovery.json`](ttps/examples/t1018-remote-system-discovery.json) | Original example: `ip neigh show`. Refuse-by-default. |
| T1018 | Remote System Discovery (loopback only) | partial (loopback-scoped) | [`ttps/examples/t1018-remote-system-discovery-loopback.json`](ttps/examples/t1018-remote-system-discovery-loopback.json) | One `ping -c 1` to `127.0.0.1` + existing ARP cache dump. NEVER scans external networks. Refuse-by-default. |
| T1016 | System Network Configuration Discovery (via ART adapter) | partial (ART example) | [`ttps/examples/art-t1082-system-info.yml`](ttps/examples/art-t1082-system-info.yml) | Shipped as the ART YAML adapter example. Refuse-by-default. |

### Lateral Movement (TA0008)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| — | (no entries) | no | — | Lateral-movement TTPs need a real second host. Out of scope for v0.4. |

### Collection (TA0009)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| T1005 | Data from Local System | partial (small read-only sample) | [`ttps/examples/t1005-local-system-data.json`](ttps/examples/t1005-local-system-data.json) | Reads `/etc/hostname`, `/etc/timezone`, `/etc/issue`, `$HOME/.profile` (size only). Captures into envelope stdout (which IS the audit record). No network exfil. Refuse-by-default. |

### Command and Control (TA0011)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| T1071.001 | Application Layer Protocol — Web Protocols | partial (loopback heartbeat) | [`ttps/examples/t1071-001-loopback-http-heartbeat.json`](ttps/examples/t1071-001-loopback-http-heartbeat.json) | Single `curl` to `http://127.0.0.1:65001/heartbeat`. Loopback-only. NO real C2 server, NO off-host network traffic. If no listener is running, the failure IS the audit evidence. Changing `127.0.0.1` to a routable address is visible verbatim in the envelope. Refuse-by-default. |

### Exfiltration (TA0010)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| — | (no entries) | no | — | Real exfil channels are explicitly out of scope. The README's authorized-use boundary forbids adding them. |

### Impact (TA0040)

| TTP ID | TTP name | Covered | Evidence | Safety-gate notes |
|---|---|---|---|---|
| — | (no entries) | no | — | Destructive TTPs (T1485 Data Destruction, T1486 Encryption, T1490 Inhibit Recovery, etc.) are explicitly out of scope. No path to safe localhost demos. |

## Tactic-column tally

| Column | Tactic ID | TTPs |
|---|---|---|
| Reconnaissance | TA0043 | 0 |
| Resource Development | TA0042 | 0 |
| Initial Access | TA0001 | 0 |
| Execution | TA0002 | 0 |
| Persistence | TA0003 | **2** |
| Privilege Escalation | TA0004 | 0 |
| Defense Evasion | TA0005 | **1** (dry-run) |
| Credential Access | TA0006 | **2** |
| Discovery | TA0007 | **6** (4 native + 1 ART + 1 extended) |
| Lateral Movement | TA0008 | 0 |
| Collection | TA0009 | **1** |
| Command and Control | TA0011 | **1** (loopback) |
| Exfiltration | TA0010 | 0 |
| Impact | TA0040 | 0 |

**Total: 12 TTPs + 1 ART adapter example, across 6 of 14 tactic columns.**

## Type I / Type II honest audit

### Type I — accepting a false claim as real

- **"covers MITRE ATT&CK"** — would be a Type I overclaim. This repo
  ships 12 TTPs against MITRE Enterprise v17.1's ~650 entries; that's
  ~1.8% coverage. The matrix above states the count explicitly.
- **"verified offensive tooling"** — would be a Type I overclaim. The
  TTPs are `unit-tested` and `integration-tested` on a single
  workstation; they are not `audited` against a red-team baseline or
  `hardware-verified` across multiple Linux distributions.
- **"detection-ready"** — would be a Type I overclaim. The harness
  emits envelopes; it does not emit Sigma rules, Velociraptor
  artifacts, or any detection-engineering output (v0.4 roadmap).
- **"the dry-run is impossible to misuse"** — would be a Type I
  overclaim. The structural guardrail (no `rm` in the `exec` field,
  `stdout_excludes` assertion) catches accident, not intent. An
  operator can edit the descriptor to turn T1070.002 into a real
  log-wipe, and the envelope would record the edit verbatim. That's
  the audit story; it is not a sandbox.
- **"loopback-only C2 cannot become real C2"** — would be a Type I
  overclaim. Changing `127.0.0.1` to a routable IP in the T1071.001
  descriptor is a one-line edit. Refuse-by-default catches the wrong
  *target IP*; it does not catch the wrong *descriptor*.

### Type II — missing real value or real risk

- **Real risk: shadow-file readability is environment-dependent.**
  The T1003.008 descriptor PASSes whether or not `/etc/shadow` is
  readable, because reading `/etc/passwd` succeeds either way. A
  defender consuming envelopes must read the stdout to find out
  whether the shadow file was reached. The envelope's `verdict=PASS`
  alone does not answer the question.
- **Real risk: T1552.001 pattern-scan only checks $HOME top-level
  dotfiles.** Recursive scans would find more credentials but also
  walk into project directories with valid secrets-in-config patterns
  (e.g. `.env` files in active projects). The narrow scope is a
  deliberate safety choice; the limitation is real.
- **Real value missed: the harness's envelope shape composes well
  with blue-team SIEM ingestion**, but no consumer-side schema
  validator ships yet (v0.4 roadmap). Until then, downstream
  pipelines must trust the writer.
- **Real value missed: 6 of 14 ATT&CK tactic columns are empty.**
  The omissions are listed honestly in the matrix above. Future
  passes should consider Initial Access, Execution, Lateral
  Movement, Exfiltration, and Impact slices — but each will require
  a fresh safety review, because the safe-on-localhost framing the
  current TTPs use does not generalize to those tactics.

## How to extend this matrix

1. Pick a tactic column that interests your lab.
2. Identify one MITRE technique or sub-technique whose safest possible
   demo runs end-to-end on a single localhost machine without producing
   external network traffic, writing persistence artifacts, or
   modifying logs.
3. Write the TTP descriptor as `ttps/examples/t<id>-<slug>.json`,
   matching the schema in `src/main.zig` (`id`, `name`, `description`,
   `platforms`, `exec`, `expected.{exit_code,stdout_contains,stdout_excludes}`).
4. Include the safety-gate posture in the `description` field
   verbatim — every shipped descriptor names refuse-by-default.
5. Validate with `sovereign-offense-harness validate <path>` and
   smoke-run with `--unsafe-local` to confirm the envelope shape.
6. Add a row to the matrix above with the evidence link.

---

*Last reconciled: 2026-05-14. Reference: MITRE ATT&CK Enterprise v17.1.*
