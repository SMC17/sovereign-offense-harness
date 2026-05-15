## Unreleased

### Added — documentation tests

- **`tools/doctest.sh`** — 20-check documentation-test harness, wired
  into `build.zig` as `zig build doctest`. Models the same discipline
  shipped on `zig-cobs`, `zig-frame-protocol`, `zig-graph`, and
  `zig-h3`. Doctest is concerned with README *drift*, not safety-gate
  *behavior* (the latter is covered by `tests/safety_gate_integration.sh`,
  unchanged at 6 / 6 passing). Checks:
  - README documents `run` and `validate` subcommands AND they both
    appear in the binary's `--help` output.
  - Every documented CLI flag (`--ttp`, `--art`, `--art-test`,
    `--target`, `--unsafe-local`, `--lab-targets`) appears in `--help`.
    Drift on a flag — added to README, removed from `--help`, or
    vice-versa — fails doctest.
  - The README's quoted `refused by safety gate` message in the Safety
    section matches what the binary actually prints to stderr on a
    no-auth `run`, and the exit code is 3 (the documented "refused by
    safety gate" code in `--help`'s exit-codes table).
  - The README Demo block's envelope shape (top-level `schema`, `ttp.id`,
    `execution.exit_code`, `host.hostname`, `verdict`) matches a real
    `--unsafe-local` run of the shipped T1082 enumeration TTP, and the
    schema URI is `sovereign-offense-harness/envelope/v1`.
  - The Authorized-Use-Only notice + THREAT_MODEL.md reference remain
    present in the README. The threat model claims that notice is
    non-negotiable; doctest treats it as such — deletion fails the test.
- The check uses `--unsafe-local` against a benign read-only TTP
  (`t1082-system-information-discovery.json` — `uname -a` + `cat
  /etc/os-release`) targeted at a scratch envelope dir; doctest does
  not write outside `mktemp -d`.
- Honest scope: doctest verifies that the README's *executable* claims
  match the binary's *observable* behavior. It does NOT verify prose
  claims (e.g. "no third-party deps", "single-author project"). Those
  are properties of the build system and the repo, not of the
  documentation-vs-code contract.
- `zig build test` is unchanged at 24 unit tests + 6 safety-gate
  integration cases (9 / 9 mutation operators still killed).

### Added — mutation testing discipline

- `tools/mutation-test.sh` — stylized mutation-testing harness applying
  9 hand-picked operators across `src/main.zig` (safety gate, IPv4/CIDR
  parser, parseTtp strict-type checks) and `src/art.zig` (ART executor
  allowlist). Initial run reported **3 / 9 killed** — a **major signal**:
  the load-bearing safety claim of this tool (refuse-by-default unless
  `--target <IP>` ∈ whitelist OR `--unsafe-local`) had **zero direct
  test coverage** of the gate logic. Mutation testing surfaced this
  precisely.

### Fixed via mutation-driven regression tests (closed in this commit)

- **M05** — parseIpv4 octet-count check `!= 4` → `== 4` killed by new
  `parseIpv4 rejects too few octets` test (lines 1.2.3 / 1.2 / 1 / empty).
- **M06** — parseIpv4 octet-overflow `>= 4` → `> 4` killed by new
  `parseIpv4 rejects too many octets` test (1.2.3.4.5 / 1.2.3.4.5.6).
- Plus value-range tests: parseIpv4 of 0.0.0.0 / 127.0.0.1 /
  255.255.255.255 round-trip correctly; octet > 255 rejected;
  non-numeric / empty-octet rejected. **4 new tests, 24 → 28 total.**

### Fixed via subprocess integration test (closes the load-bearing safety-gate gap)

- **`tests/safety_gate_integration.sh`** — 5-case subprocess test of the
  installed binary, modeled on `mast/tests/strict_mode_integration.sh`.
  Wired into `zig build test` via `addSystemCommand`. Cases:
  - No `--target` / `--unsafe-local` → exit 3 + "refused by safety gate"
    on stderr **(kills M02 — the load-bearing refuse-by-default check)**
  - `--unsafe-local` → passes gate, envelope writer engages
  - `--target X --unsafe-local` → exit 2 + "mutually exclusive"
    **(kills M03)**
  - `--ttp X --art Y` → exit 2 + "mutually exclusive" **(kills M01)**
  - `--art-test X` without `--art` → exit 2 + "--art-test requires --art"

**Mutation score after this commit: 8 / 9 killed (88.9 %)**. Up from
the initial 3 / 9. The only remaining survivor (M04 — CIDR `/32`
boundary in `checkWhitelist`) requires a temp-whitelist-file test
fixture and is filed below.

### Also closed: M04 CIDR /32 boundary

- `tests/safety_gate_integration.sh` extended with a 6th case that
  writes a temp whitelist `127.0.0.1/32` and verifies `--target
  127.0.0.1 --lab-targets <tmp>` is accepted. Kills M04 (under the
  mutation, `/32` lines are dropped and the target is refused).

### Final mutation score on the stylized operator set: 9 / 9 killed (100 %)

Progression across this session:
- Initial: 3/9 (parseTtp checks only)
- After parseIpv4 boundary tests: 5/9
- After safety-gate integration test: 8/9
- After /32 boundary test: **9/9**

Honest scope: 9 hand-picked operators is far from exhaustive. 100 % on
this script certifies that **the listed mutation classes are caught** —
it does not certify universal bug-catching. The discipline's job here
was to surface that the safety-gate logic had zero direct test
coverage; that goal is achieved and the gate is now end-to-end verified
in the production binary.

## [0.4.0] — 2026-05-14

### Added

- **`THREAT_COVERAGE.md`** — MITRE ATT&CK Enterprise coverage matrix
  structured by tactic column. Counts 12 TTPs across 6 of 14 tactic
  columns (~1.8% of ATT&CK Enterprise v17.1 entries), names what is
  not covered, and includes a Type-I / Type-II honest audit at the
  bottom. The matrix is the audit surface for the breadth gap — not
  a marketing surface.
- **10 new TTP descriptors** under `ttps/examples/`, all defaulting to
  refuse-by-default and gated by `--target <whitelisted_IP>` OR
  `--unsafe-local`:
  - **Discovery (TA0007):** `t1082-system-information-discovery-extended.json`
    (kernel + distro + `lscpu` + `free -h` + mounts),
    `t1057-process-discovery.json` (`ps` + `/proc` PID count),
    `t1018-remote-system-discovery-loopback.json` (ping 127.0.0.1 +
    ARP cache, no external scans).
  - **Credential Access (TA0006):** `t1003-008-etc-passwd-shadow.json`
    (reads `/etc/passwd`, attempts `/etc/shadow` — records
    `shadow-readable=false (not authorized to read)` when not root,
    that refusal IS the audit evidence),
    `t1552-001-unsecured-credentials-in-files.json` (pattern-counts
    credential-shaped lines in `$HOME` top-level dotfiles; contents
    redacted, counts only).
  - **Persistence (TA0003):** `t1053-003-cron-job.json` (read-only
    enumeration of cron paths; NEVER writes a crontab),
    `t1037-004-rc-scripts.json` (read-only enumeration of
    `/etc/rc.local`, init.d, systemd units; NEVER writes a script
    or enables a service).
  - **Defense Evasion (TA0005):** `t1070-002-clear-linux-logs-dryrun.json`
    — **DRY-RUN ONLY**. The `exec` line uses `stat` / `ls -la` to
    enumerate log paths and sizes only; no `rm`, no `truncate`, no
    `>`, no `journalctl --vacuum-*`. The descriptor's
    `stdout_excludes` asserts the absence of those commands as a
    structural guardrail.
  - **Collection (TA0009):** `t1005-local-system-data.json`
    (reads `/etc/hostname`, `/etc/timezone`, `/etc/issue`,
    `$HOME/.profile` size; captures to envelope stdout, no network
    exfil).
  - **Command and Control (TA0011):** `t1071-001-loopback-http-heartbeat.json`
    (single `curl` to `http://127.0.0.1:65001/heartbeat`;
    loopback-only, no real C2 server, no off-host traffic).
- README status block bumped from `v1.0.0 — stable surface` to
  `v0.4.0 — coverage matrix + expanded TTP corpus`. The README's
  prior `v1.0.0` tag was flagged in [`FLEET.md`](https://github.com/SMC17/SMC17/blob/main/FLEET.md)
  as a vanity claim relative to the actual surface; v0.4.0 brings the
  README under the version the work actually earns. Honest comparison
  table updated: TTP library size now `12 example TTPs across 6 of 14
  ATT&CK tactic columns` (was `2 example TTPs`).

### Notes

- CLI surface unchanged. The v0.2 safety gate
  (`--target <whitelisted_IP>` / `--unsafe-local`) and the
  `sovereign-offense-harness/envelope/v1` schema URI are stable
  across this release.
- Every new TTP smoke-runs end-to-end with `--unsafe-local` on the
  maintainer's workstation as of 2026-05-14: 10 / 10 produced a
  valid `jq`-parseable envelope with `verdict=PASS`.
- Type-I posture: this release does NOT claim "ATT&CK coverage." It
  claims 12 / ~650 ATT&CK Enterprise v17.1 entries (~1.8%) and the
  coverage matrix is the receipts.

### Fixed

- **`parseTtp` safety bug** — three unchecked `.string` accesses on
  `std.json.Value` (`id`, `name`, `exec`) would UB-panic in Debug /
  ReleaseSafe when fed an adversarial descriptor whose required-string
  field was a non-string JSON type (e.g. `{"id": 42}`). The existing
  19-test suite covered happy paths and missing-field paths but not
  wrong-type-field paths; the project's own `SECURITY_REVIEW.md`
  explicitly named adversarial descriptor fuzzing as a follow-on
  workstream. Each access now type-checks before reaching for the
  union field and returns `error.TtpIdNotString` /
  `error.TtpNameNotString` / `error.TtpExecNotString`.

### Added

- **Three wrong-type unit tests** + a **3000-trial adversarial fuzz
  harness** for `parseTtp` in `src/main.zig`. The fuzz harness applies
  bit-flip / byte-insert / byte-delete / truncate / type-substitute
  mutations to a known-valid descriptor (1–4 ops per trial, seeded
  PRNG `0xADF7_2026_0514_C0DE`) and asserts only that the parser
  returns — either a `Ttp` or a clean error — never panics. Cross-check
  asserts both ok-count and err-count are positive, so a broken
  mutator that produces only-valid or only-invalid inputs would also
  fail the test.
- Total in-source tests: 20 → 24. `zig build test` ~1 s.

## v1.0.0 — 2026-05-13

**Production-grade milestone.**

- SECURITY.md present (coordinated disclosure policy).
- LICENSE, README, CONTRIBUTING, CI workflow verified.
- v1.x cycle: API/surface stable; breaking changes bump to v2.x.
- Engineering posture: Virgil work-in-progress convention adapted for OSS — v1.0 means we stand behind the existing surface; v1.x refines without breaking.

# Changelog

All notable changes to `sovereign-offense-harness` will be documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [0.3.2] — 2026-05-12

### Other

- v0.3.2: route security reports to GitHub private advisory

## [0.3.1] — 2026-05-11

### Other

- v0.3.1: publish-readiness polish — WS6 SECURITY_REVIEW remediation
- publish: full AGPL-3.0 text + correct GH namespace + CoC

## [0.3.0] — 2026-05-11

### Other

- v0.3.0: Atomic Red Team adapter (EXPERIMENTAL) + envelope JSON-escape fix

## [0.2.0] — 2026-05-07

### Docs

- docs+meta: bump README + STATUS + build.zig.zon to v0.2.0 (pass-2)

### Other

- v0.2.0: refuse-by-default safety gate
- CONTRIBUTING.md: fix the 'no third-party deps' overclaim
- launch polish, second pass: type-1/type-2 fixes across README + SECURITY + CONTRIBUTING
- launch polish: README rewrite + SECURITY + CONTRIBUTING + CI

## [0.1.0] — 2026-05-06

### Other

- v0.1.0: scaffold + TTP runner + envelope emitter
