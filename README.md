# sovereign-offense-harness

> Adversary emulation runner. Single Zig binary. Reads MITRE-ATT&CK-shaped
> TTP descriptors, executes them via `bash -c`, captures structured audit
> envelopes (timing, exit, stdout/stderr, SHA-256 of each, host fingerprint).
> AttackIQ minus the SaaS.

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Zig 0.16](https://img.shields.io/badge/Zig-0.16-orange.svg)](https://ziglang.org/)
[![v0.1.0](https://img.shields.io/badge/version-0.1.0-blue.svg)](STATUS.md)

Part of the [Sovereign Stack](https://stax.dev/sovereign-stack). Companion
to [`sentinel-sbom`](https://github.com/stax/sentinel-sbom) and
[`sovereign-edge`](https://github.com/stax/sovereign-edge).

## Why

Adversary emulation tools (Atomic Red Team, MITRE Caldera, AttackIQ, SafeBreach,
XBOW) are powerful but heavyweight, SaaS-shaped, or require a Python/Go
runtime that itself becomes a supply-chain dependency. For purple-team
flywheels — where the *output of red runs feeds blue's detection engineering* —
you want something tight, scriptable, and auditable.

`sovereign-offense-harness` is one Zig binary that does the narrow thing well:
read a JSON TTP descriptor, run it, write a structured envelope. No agent,
no server, no cloud. The envelope is the artifact your blue team grades
detection coverage against.

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

## Comparison

| | sovereign-offense-harness | Atomic Red Team | MITRE Caldera | AttackIQ | SafeBreach |
|---|---|---|---|---|---|
| Single binary | ✅ Zig | ❌ PowerShell + bash + ... | ❌ Python + Go + UI | ❌ SaaS | ❌ SaaS |
| No runtime / agent | ✅ | ⚠️ shell runtime | ❌ agent + server | ❌ agent | ❌ agent |
| Open source | ✅ AGPL | ✅ MIT | ✅ Apache | ❌ commercial | ❌ commercial |
| Structured audit envelope | ✅ JSON v1 | ⚠️ ad-hoc | ✅ ops/operations | ✅ proprietary | ✅ proprietary |
| Deterministic envelope shape | ✅ | ❌ | ⚠️ | ⚠️ | ⚠️ |
| TTP library size | 2 (v0.1) → ATT&CK in v0.4 | ~1500 | ~600 | proprietary | proprietary |
| Sovereign-lab integration | ✅ v0.2 (target whitelist) | ❌ | ⚠️ | ❌ | ❌ |
| Local-LLM TTP planner | ✅ v0.3 (planned) | ❌ | ❌ | ⚠️ | ❌ |

**Where this excels:** small-footprint purple-team flywheels. You want to
run TTPs against an isolated sentinel-lab, capture structured evidence, feed
gaps into Sigma rules / Velociraptor artifacts, and you want zero runtime
dependencies you didn't compile yourself.

**Where it doesn't compete (today):** comprehensive attack libraries,
multi-host orchestration, GUI-driven scenario builders. v0.4 will read
upstream Atomic Red Team JSON directly to absorb their library. Multi-host
is roadmap.

## Status

`v0.1.0` — `compiled` + `unit-tested`.

| Property | Status |
|---|---|
| `zig build` green | ✅ |
| `zig build test` green | ✅ (2 tests) |
| Reads TTP JSON descriptor | ✅ |
| Executes via bash, captures stdout/stderr | ✅ |
| Emits structured JSON envelope | ✅ |
| Verdict evaluation (PASS/FAIL) | ✅ |
| Target whitelist enforcement | ⏳ v0.2 |
| Atomic Red Team JSON compatibility | ⏳ v0.4 |
| Local-LLM planner | ⏳ v0.3 |

Detailed roadmap in [STATUS.md](STATUS.md).

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

## ⚠️ Safety

**v0.1 has no built-in target safety.** A TTP descriptor's `exec` field
runs as the invoking user. Don't run TTPs whose `exec` field you haven't
read. Don't run this tool against production hosts. v0.2 adds the
sentinel-lab whitelist gate (refuse-by-default unless target IP ∈ lab CIDR).

The v0.1 example TTPs (T1018, T1082) are both **read-only enumeration** —
they won't change system state. Safe to run for smoke tests.

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
