# sovereign-offense-harness

> Adversary emulation runner for sentinel-lab's purple-team flywheel.
> Executes canned TTP descriptors and captures structured audit envelopes.
> AGPL.

F3 build #2 (S1 cluster) per
[`COMPETITIVE_LANDSCAPE.md`](../COMPETITIVE_LANDSCAPE.md). Companion to
[sentinel-sbom](../sentinel-sbom/) (S3) and
[sovereign-edge](../sovereign-edge/) (Cloudflare-parity / E1-E8).

## What it does (v0.1)

1. Reads a TTP descriptor (JSON, Atomic-Red-Team-shaped).
2. Executes the TTP via `bash -c`.
3. Captures stdout, stderr, exit code, monotonic duration, SHA-256 of
   each stream, host hostname, wall-clock timestamp.
4. Evaluates expectations (`exit_code`, `stdout_contains`,
   `stdout_excludes`).
5. Writes a deterministic-shaped JSON envelope to
   `envelopes/<TTP>-<unix-ts>.json`.
6. Prints PASS/FAIL summary; exits 1 on FAIL.

## Why

Adversary emulation tools (Atomic Red Team, Caldera, AttackIQ, SafeBreach)
are powerful but heavyweight, SaaS-shaped, or require a Python/Go runtime
that itself becomes a supply-chain dependency. `sovereign-offense-harness`
is a single Zig binary that reads a JSON TTP, runs it, and emits a
structured envelope. No agent, no server, no cloud.

It's intentionally minimal so it composes with sentinel-lab (per
`~/SENTINEL_FLYWHEEL_PLAN.md` §4): the envelope feeds blue-team
detection-engineering work; gaps land as Sigma rules / Velociraptor
artifacts.

## Roadmap

### v0.1 (this commit) — `compiled` + `unit-tested`

- ✅ Subcommands: `run`, `validate`, `--version`, `--help`.
- ✅ TTP JSON descriptor format defined.
- ✅ Envelope schema `sovereign-offense-harness/envelope/v1`.
- ✅ Two example TTPs (T1018, T1082) — both safe-to-run.

### v0.2 — sentinel-lab integration

- Refuse-by-default unless target IP ∈ lab whitelist (read from
  `~/sentinel-lab/lab-targets.txt` or env).
- Batch mode: run a directory of TTPs sequentially, aggregate envelopes.
- `--detect-only` mode: report what WOULD execute without running.

### v0.3 — local-LLM-driven planner

- Optional `--plan` subcommand: shells to a local Ollama / vLLM endpoint
  (`OLLAMA_HOST` / `VLLM_URL`) with the lab inventory; LLM picks TTPs
  to run against the target. Plan is itself an envelope, replayable.

### v1.0 — public OSS ship

- AGPL release on GitHub as `stax/sovereign-offense-harness`.
- Sigma rule + Velociraptor artifact emission from gaps.
- Full Atomic Red Team JSON-format compatibility (so existing TTP libs
  can drop in).

## Usage

```sh
zig build

# Validate a TTP descriptor.
./zig-out/bin/sovereign-offense-harness validate ttps/examples/t1018-remote-system-discovery.json

# Run a TTP — emits envelope to envelopes/<id>-<ts>.json.
./zig-out/bin/sovereign-offense-harness run --ttp ttps/examples/t1082-system-information-discovery.json

# Custom output directory.
./zig-out/bin/sovereign-offense-harness run --ttp my-ttp.json --out /var/lib/sentinel-lab/envelopes
```

## Safety

**v0.1 has no built-in target safety.** A TTP descriptor's `exec` field
runs as the invoking user. Don't run TTPs whose exec field you haven't
read. Don't run this tool against production hosts. v0.2 adds the
sentinel-lab whitelist gate.

The v0.1 example TTPs (T1018, T1082) are both **read-only enumeration**
— they won't change system state. They're safe to run for smoke tests.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
