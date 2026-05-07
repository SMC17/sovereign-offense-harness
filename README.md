# sovereign-offense-harness

> A small Zig CLI that runs a TTP descriptor (JSON, ATT&CK-shaped) via
> `bash -c`, captures stdout/stderr + exit + duration + per-stream
> SHA-256 + host fingerprint, and writes a structured JSON audit
> envelope. Single binary. No third-party Zig deps.
>
> **Status: v0.1.0 — early; primitive, not a tool.** Two example TTPs
> shipped. No safety gate (target whitelist) yet — see Safety section.
> No Atomic Red Team library compatibility yet (planned). The Zig
> binary is real; the surrounding "tool" claims most adversary-
> emulation products make are not yet supported here.

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Zig 0.16](https://img.shields.io/badge/Zig-0.16-orange.svg)](https://ziglang.org/)

Part of the [Sovereign Stack](https://stax.dev/sovereign-stack). Companion
to [`sentinel-sbom`](https://github.com/stax/sentinel-sbom) and
[`sovereign-edge`](https://github.com/stax/sovereign-edge).

## Why this exists

The big-name adversary-emulation products — AttackIQ, SafeBreach, XBOW,
MITRE Caldera, Red Canary's Atomic Red Team — solve different problems
at very different scales than this project does.

- **Atomic Red Team** is a *library* of ~1,500+ atomic tests with a
  PowerShell + cross-platform runner. If you want comprehensive
  technique coverage, use Atomic Red Team. This project's v0.4 plans
  to read ART's JSON schema directly, not replace it.
- **MITRE Caldera** is a full agent-orchestration framework: server,
  agents, adversary playbooks, planners. If you need multi-host
  orchestration, use Caldera.
- **AttackIQ / SafeBreach** are commercial platforms with proprietary
  TTP libraries, ML scoring, and enterprise-grade UIs. If you have
  budget and want SOC-grade reporting, use those.

The narrow thing this project does that the others don't: emit a
*deterministic-shape* JSON envelope per TTP run, in a single
audit-friendly Zig binary, with no agent, server, or runtime
dependencies beyond Zig at build-time and `bash` at runtime. That's
useful when you're building a small, auditable purple-team flywheel and
you want the runner itself to not be part of your supply-chain attack
surface.

It's a primitive, not a platform.

## Demo

```sh
$ cat ttps/examples/t1082-system-information-discovery.json
{
  "id": "T1082",
  "name": "System Information Discovery",
  "description": "Read /etc/os-release and uname output to fingerprint the host. MITRE ATT&CK T1082 — typically the first technique post-foothold.",
  "platforms": ["linux"],
  "exec": "uname -a; cat /etc/os-release 2>/dev/null || true",
  "expected": {
    "exit_code": 0,
    "stdout_contains": "Linux",
    "stdout_excludes": []
  }
}

$ sovereign-offense-harness run --ttp ttps/examples/t1082-system-information-discovery.json
[PASS] T1082: System Information Discovery
  envelope: envelopes/T1082-1778111282.json
  duration: 12ms exit=0

$ jq < envelopes/T1082-1778111282.json
{
  "schema": "sovereign-offense-harness/envelope/v1",
  "ttp": {
    "id": "T1082",
    "name": "System Information Discovery",
    "exec": "uname -a; cat /etc/os-release 2>/dev/null || true"
  },
  "execution": {
    "started_at_unix": 1778111282,
    "duration_ms": 12,
    "exit_code": 0,
    "stdout_bytes": 480,
    "stderr_bytes": 0,
    "stdout_sha256": "10f0d0d7b016cd94ab0d877015448ea88ad8cc1d7d7edbe2365b33cdef9c0afa",
    "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "host": { "hostname": "edge" },
  "verdict": "PASS"
}
```

## Honest comparison

| | sovereign-offense-harness | Atomic Red Team | MITRE Caldera | AttackIQ |
|---|---|---|---|---|
| What it is today | small TTP runner + envelope writer | TTP library + cross-platform runner | full agent-orchestration framework | enterprise platform |
| TTP library size | 2 example TTPs | ~1,500+ atomics | ~600 abilities | proprietary, not public |
| Runtime form | single Zig binary | PowerShell + cross-platform runner; the library itself is YAML/JSON | server + agents + UI | hosted SaaS + agents |
| Multi-host orchestration | none | manual (run on each host) | yes (built-in agent framework) | yes |
| Bring your own TTPs | yes (JSON descriptor) | yes (their schema) | yes (abilities) | mostly proprietary library |
| Detection / blue-team integration | envelope JSON consumed by your own pipeline | none built-in | reporting + tagging | enterprise-grade reporting |
| Open source | AGPL | MIT | Apache 2.0 | proprietary |
| Maturity | v0.1, 1 author, ~3 days of work | mature, large community | mature, MITRE-backed | mature commercial |
| Single-binary supply chain | yes (Zig binary, no third-party runtime) | no (PowerShell or runner toolchain required) | no (Python + Go + UI) | n/a (cloud) |

**Where this fits today**: a small team that wants to run a handful of
TTPs in an isolated lab and capture audit-friendly JSON envelopes for
blue-team grading. Mostly a building block, not a finished product.

**Where it doesn't fit**: anything requiring breadth of TTP coverage,
multi-host orchestration, agent frameworks, or commercial reporting —
use Atomic Red Team, Caldera, or a commercial platform respectively.

## Status — what's verified vs not

`v0.1.0` — single author, ~1 day of work. ~500 LOC Zig.

What works:
- `zig build` + `zig build test` green; 2 unit tests (TTP parser + missing-id rejection).
- Reads JSON TTP descriptor, executes via `bash -c`, captures
  stdout/stderr/exit/duration, hashes each stream with SHA-256, writes
  a JSON envelope to disk.
- Two example TTPs ship, both intentionally read-only enumeration
  (T1018 `ip neigh show`, T1082 `uname -a`).

What does NOT work yet:
- **No safety gate** — see Safety section. Any TTP descriptor's `exec`
  field runs as the invoking user with no review. v0.2 plan adds a
  target-IP whitelist refuse-by-default.
- **No envelope schema validator** — the schema URI in the envelope is
  whatever the writer puts in it. There is no schema enforcement and no
  consumer-side validator beyond "is this valid JSON."
- **No Atomic Red Team compatibility** — v0.4 plan. Today the descriptor
  format is custom (close to but not identical to ART JSON).
- **No multi-host orchestration** — explicitly out of scope.
- **No detection-engineering output** — Sigma rule emission and
  Velociraptor artifact stubs are v0.4 plans.
- **No "local-LLM TTP planner"** — that's v0.3 vaporware right now;
  no design, no integration, no working code.

Roadmap in [STATUS.md](STATUS.md). Treat the version numbers as planning
labels, not promises.

## Install

```sh
git clone https://github.com/stax/sovereign-offense-harness
cd sovereign-offense-harness
zig build              # produces ./zig-out/bin/sovereign-offense-harness
```

## Usage

```sh
# Validate a TTP descriptor's structure
sovereign-offense-harness validate ttps/examples/t1018-remote-system-discovery.json

# Run a TTP — emits envelope to envelopes/<id>-<unix-ts>.json
sovereign-offense-harness run --ttp ttps/examples/t1082-system-information-discovery.json

# Custom output directory
sovereign-offense-harness run --ttp my-ttp.json --out /var/lib/sentinel-lab/envelopes
```

## ⚠️ Safety — read this before running anything

**v0.1 will execute any string in a TTP's `exec` field as the invoking
user, with no allowlist, no sandbox, no target check.** A malicious TTP
descriptor with `"exec": "rm -rf $HOME"` will do exactly that. There is
nothing in the v0.1 binary that prevents it.

Practical implications:
- **Do not run a TTP descriptor you didn't write or audit.** Read the
  `exec` line of every TTP before you run it. The example TTPs shipped
  in `ttps/examples/` are both intentionally read-only (`ip neigh show`,
  `uname -a; cat /etc/os-release`) and safe; nothing else is implicitly safe.
- **Do not run this tool on production hosts.** It is meant for
  isolated lab targets — air-gapped VMs, throwaway containers,
  dedicated sentinel-lab infrastructure.
- **Do not pipe random TTP descriptors from the internet into this**
  any more than you'd pipe a stranger's bash script into `sudo bash`.

The v0.2 release plans a refuse-by-default whitelist gate ("only run if
target IP is in `~/sentinel-lab/lab-targets.txt`"). Until v0.2 ships,
you ARE the safety gate.

If you need a battle-tested adversary-emulation tool right now, use
Atomic Red Team or MITRE Caldera. They have years of community review.
This is v0.1 of a single-author project.

## Roadmap

- **v0.2** — sentinel-lab integration: target whitelist (refuse-by-default
  unless lab IP), batch mode, `--detect-only`.
- **v0.3** — Local-LLM TTP planner: shells to Ollama / vLLM, picks TTPs
  for a target inventory, emits a replayable plan envelope.
- **v0.4** — Atomic Red Team JSON-format compatibility (drop-in their
  ~1500 TTPs), Sigma rule + Velociraptor artifact emission from gaps.
- **v1.0** — public OSS launch with full ATT&CK coverage, CI matrix,
  defense-procurement-shaped reference deployment.

## Why we built it

Adversary emulation in 2026 is a SaaS market. AttackIQ, SafeBreach, XBOW
all charge per-agent, per-month, per-environment. The actual *technique*
of running a TTP and capturing what happened is small — under 500 LOC of
Zig. The big-vendor pricing reflects packaging + orchestration + analyst
UI, not the underlying tech.

If you're a sovereignty-conscious team running a small purple-team
flywheel — defense lab, EU regulated finance, regulated medical, university
research — you don't need the SaaS. You need a tight binary that runs
deterministic, captures structured evidence, and composes with whatever
detection-engineering pipeline you already have.

That's this.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Signed commits required.

Security disclosure: [SECURITY.md](SECURITY.md).
