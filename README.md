# sovereign-offense-harness

> A small Zig CLI that runs a TTP descriptor (JSON, ATT&CK-shaped) via
> `bash -c`, captures stdout/stderr + exit + duration + per-stream
> SHA-256 + host fingerprint, and writes a structured JSON audit
> envelope. Single binary. No third-party Zig deps.
>
> **Status: v0.3.0 — early.** ~1160 LOC. Two example TTPs + one ART
> example shipped. v0.2 added the **safety gate** (refuse-by-default
> unless `--target <IP>` matches a whitelist OR `--unsafe-local`).
> **v0.3 adds an `--art` mode (EXPERIMENTAL):** a minimal in-tree YAML
> parser + Atomic Red Team adapter that translates ART atomic-test
> descriptors into the existing Ttp shape. Safety gate still applies. The
> v0.2 surface (`run --ttp …`, `validate …`) is unchanged.

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Zig 0.16](https://img.shields.io/badge/Zig-0.16-orange.svg)](https://ziglang.org/)

Part of the [Sovereign Stack](https://stax.dev/sovereign-stack). Companion
to [`sentinel-sbom`](https://github.com/SMC17/sentinel-sbom) and
[`sovereign-edge`](https://github.com/SMC17/sovereign-edge).

## Why this exists

The big-name adversary-emulation products — AttackIQ, SafeBreach, XBOW,
MITRE Caldera, Red Canary's Atomic Red Team — solve different problems
at very different scales than this project does.

- **Atomic Red Team** is a *library* of ~1,500+ atomic tests with a
  PowerShell + cross-platform runner. If you want comprehensive
  technique coverage, use Atomic Red Team. v0.3 of this project reads
  ART's YAML schema (experimental — bash/sh executors only) via the
  `--art` flag; it does not replace ART's runner.
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
| Maturity | v0.3, 1 author, ~4 days of work | mature, large community | mature, MITRE-backed | mature commercial |
| Single-binary supply chain | yes (Zig binary, no third-party runtime) | no (PowerShell or runner toolchain required) | no (Python + Go + UI) | n/a (cloud) |

**Where this fits today**: a small team that wants to run a handful of
TTPs in an isolated lab and capture audit-friendly JSON envelopes for
blue-team grading. Mostly a building block, not a finished product.

**Where it doesn't fit**: anything requiring breadth of TTP coverage,
multi-host orchestration, agent frameworks, or commercial reporting —
use Atomic Red Team, Caldera, or a commercial platform respectively.

## Status — what's verified vs not

`v0.3.0` — single author, ~4 days of work. ~1160 LOC Zig.

What works:
- `zig build` + `zig build test` green; 18 unit tests (TTP parser,
  missing-id rejection, YAML subset parser, ART adapter, plus an
  end-to-end ART adapter test).
- Reads JSON TTP descriptor, executes via `bash -c`, captures
  stdout/stderr/exit/duration, hashes each stream with SHA-256, writes
  a JSON envelope to disk.
- Two example TTPs ship in the native JSON shape, both intentionally
  read-only enumeration (T1018 `ip neigh show`, T1082 `uname -a`).
- One example ART atomic ships at `ttps/examples/art-t1082-system-info.yml`.
- **v0.2 safety gate**: `run` refuses unless `--target <IP>` matches a
  whitelist CIDR/IP in `~/sentinel-lab/lab-targets.txt` OR
  `--unsafe-local` is passed. Whitelist supports IPv4 CIDR + bare IPs,
  blank lines and `#`-comments. Refusal exits 3 with a refusal message.
  Applies to `--art` runs too — no path around it.
- **v0.3 `--art` mode (EXPERIMENTAL)**: in-tree minimal YAML subset
  parser (block mappings/sequences, plain/quoted scalars, `|` literal
  blocks, `#`-comments, indent-tracked nesting — no anchors, tags, flow
  style, multi-doc, or tabs) plus an ART → Ttp adapter. Supports
  `attack_technique`, `atomic_tests[]`, `supported_platforms`,
  `input_arguments.<var>.default` substitution into `#{var}`, and
  `executor.{command,name}` for bash/sh only. Selectors: `--art-test
  first` (default), `--art-test index:N`, `--art-test name:<exact>`.

What does NOT work yet:
- **`--art` is experimental and read-only of the YAML subset above.**
  Anchors, tags, flow-style YAML, multi-document streams, and tabs are
  rejected. PowerShell / `command_prompt` executors are rejected
  (returns `UnsupportedExecutor`) rather than silently mis-run.
  `cleanup_command`, `dependencies`, and `dependency_executor_name` are
  ignored — an atomic that depends on prereqs will fail loudly at
  shell time. v0.4 plans a `--check-deps` mode.
- **No envelope schema validator** — the schema URI in the envelope is
  whatever the writer puts in it. There is no schema enforcement and no
  consumer-side validator beyond "is this valid JSON."
- **No multi-host orchestration** — explicitly out of scope.
- **No detection-engineering output** — Sigma rule emission and
  Velociraptor artifact stubs are v0.4 plans.
- **No "local-LLM TTP planner"** — that's v0.5+ vaporware right now;
  no design, no integration, no working code.
- **IPv6 in the whitelist** — v0.3 still IPv4 only.

Roadmap in [STATUS.md](STATUS.md). Treat the version numbers as planning
labels, not promises.

## Install

```sh
git clone https://github.com/SMC17/sovereign-offense-harness
cd sovereign-offense-harness
zig build              # produces ./zig-out/bin/sovereign-offense-harness
```

## Usage

```sh
# Validate a native TTP descriptor's structure
sovereign-offense-harness validate ttps/examples/t1018-remote-system-discovery.json

# Run a native TTP — emits envelope to envelopes/<id>-<unix-ts>.json
sovereign-offense-harness run --unsafe-local \
  --ttp ttps/examples/t1082-system-information-discovery.json

# Custom output directory
sovereign-offense-harness run --unsafe-local \
  --ttp my-ttp.json --out /var/lib/sentinel-lab/envelopes

# v0.3 EXPERIMENTAL — run an Atomic Red Team atomic-test YAML.
# Mutually exclusive with --ttp. Same safety gate applies.
sovereign-offense-harness run --unsafe-local \
  --art ttps/examples/art-t1082-system-info.yml

# Select a specific atomic test inside the YAML (default is first):
sovereign-offense-harness run --unsafe-local --art file.yml \
  --art-test 'name:System Information Discovery — Linux uname / os-release'
sovereign-offense-harness run --unsafe-local --art file.yml --art-test index:1
```

## ⚠️ Safety — read this before running anything

The TTP's `exec` field runs via `bash -c` as the invoking user. There
is no sandbox. v0.2 adds a **refuse-by-default safety gate**: every
`run` must explicitly acknowledge what's being targeted.

Two acknowledgement paths:

1. **`--target <IP>`** — runs against a remote host. The IP must be in
   the lab-targets whitelist file (default
   `~/sentinel-lab/lab-targets.txt`, override with `--lab-targets
   <path>`). The whitelist supports IPv4 CIDR notation and bare IPs;
   blank lines and `#`-comments are ignored. The target IP is exposed
   to the TTP as `$TARGET` so descriptors can write `ssh "$TARGET"
   ...` patterns.

2. **`--unsafe-local`** — explicitly runs against the local host. The
   flag's name is the warning: this is the runner happily executing
   `exec` as the invoking user with no rollback. Use only for
   read-only smoke tests (the shipped examples T1018, T1082) or in
   throwaway containers.

Without one of those flags, `run` exits 3 with a refusal message.

```sh
$ sovereign-offense-harness run --ttp examples/t1082.json
error: refused by safety gate.
… (exits 3)

$ sovereign-offense-harness run --unsafe-local --ttp examples/t1082.json
[PASS] T1082: System Information Discovery
  envelope: envelopes/T1082-…json
  duration: 11ms exit=0
```

Whitelist file format:
```
# ~/sentinel-lab/lab-targets.txt
# IPv4 CIDR or bare IPs; one per line; #-comments and blank lines OK.
10.0.0.0/24
192.168.99.42
```

Other safety guidance:
- Read the `exec` line of every TTP before you run it. The shipped
  examples are intentionally read-only enumeration; nothing else is
  implicitly safe.
- Do not run this against production. Period.
- Do not pipe random TTP descriptors from the internet through this
  any more than you'd pipe a stranger's bash script into `sudo bash`.

If you need a battle-tested adversary-emulation tool right now, use
Atomic Red Team or MITRE Caldera. This is a single-author project at
v0.2; the safety story is reasonable but the TTP library is two
examples.

## Roadmap

- **v0.2** ✅ shipped — sentinel-lab integration: target whitelist
  (refuse-by-default unless lab IP), `--unsafe-local` ack flag,
  exit 3 on refusal.
- **v0.3** ✅ shipped (EXPERIMENTAL) — Atomic Red Team YAML adapter:
  in-tree minimal YAML subset parser + ART → Ttp adapter, `--art` /
  `--art-test` flags, bash/sh executors only. Batch mode and
  `--detect-only` deferred to v0.4.
- **v0.4** — Sigma rule + Velociraptor artifact emission from gaps;
  envelope schema validator and consumer-side checker; ART batch mode
  + `--check-deps`.
- **v0.5+** — Local-LLM TTP planner (shells to Ollama / vLLM, picks
  TTPs for a target inventory, emits a replayable plan envelope).
- **v1.0** — full ATT&CK coverage, CI matrix, defense-procurement-shaped
  reference deployment.

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
