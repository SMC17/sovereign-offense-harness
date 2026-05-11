# sovereign-offense-harness status

Last green: 2026-05-11 (v0.3.0 — `unit-tested`, 18/18)
Last touched: 2026-05-11 (Claude, pass-3)

## Active focus

- **Claude (2026-05-11 pass-3):** v0.3.0 — Atomic Red Team adapter
  (EXPERIMENTAL).
  - New `src/yaml.zig` (~350 LOC, 9 tests): minimal YAML subset parser.
    Supports block mappings, block sequences, plain/quoted scalars, `|`
    literal blocks, `#`-comments, indent-tracked nesting, and the
    "compact mapping after dash" idiom (`- key: value` with continuation
    keys at indent+2). Explicitly does NOT support anchors, tags, flow
    style, multi-document streams, or tabs. URL-in-scalar heuristic
    prevents `http://...` from being parsed as a mapping. `#` only
    starts a comment when preceded by whitespace.
  - New `src/art.zig` (~190 LOC, 5 tests): ART → Ttp adapter. Reads
    `attack_technique`, `atomic_tests[]`, `supported_platforms`,
    `input_arguments.<var>.default` (used for `#{var}` substitution),
    and `executor.{command,name}`. Rejects non-bash/sh executors with
    `UnsupportedExecutor` rather than silently mis-running. Selectors:
    `.first`, `.{ .index = N }`, `.{ .name = "exact" }`. Unresolvable
    `#{var}` left literal so the shell fails loudly (no silent
    substitute-with-empty).
  - `src/main.zig` wiring: `VERSION = "0.3.0"`, refactor `runCmd` →
    split into `runTtp` (existing) and `runArtCmd` (new). New flags
    `--art <path>` and `--art-test <selector>`, mutually exclusive with
    `--ttp`. Same safety gate applies to ART runs — no `--art` path
    escapes refuse-by-default.
  - One example ART atomic shipped at
    `ttps/examples/art-t1082-system-info.yml` (T1082 uname /
    os-release). v0.2 surface unchanged; native JSON descriptors still
    run via `--ttp`.
  - **Latent envelope-writer bug fixed in this pass.** The pre-v0.3
    writer used raw `{s}` interpolation for string fields, which
    produced invalid JSON whenever `ttp.exec` contained a newline.
    Native JSON descriptors are typically one-liners so this stayed
    hidden; ART `|` literal blocks expose it immediately. Added a
    `writeJsonString` helper (escapes `"`, `\`, LF/CR/TAB/BS/FF, and
    control bytes via `\u00XX`) and wired it into the id / name / exec
    / hostname / verdict_reason fields. Two new tests cover the helper
    and a multi-line exec regression.
  - `zig build test --summary all` → `20/20 tests passed`. End-to-end
    smoke: both `--art` (multi-line) and `--ttp` (single-line) paths
    produce `jq`-parseable envelopes with substituted `#{var}`.

- **Claude (2026-05-07 pass-2):** v0.2.0 — refuse-by-default safety gate.
  - `run` subcommand now refuses unless one of two acknowledgements is
    explicit: `--target <IP>` (IP must match a CIDR or bare entry in the
    lab-targets whitelist file, default `~/sentinel-lab/lab-targets.txt`,
    overridable via `--lab-targets <path>`) OR `--unsafe-local`
    (explicit local-host ack, intended for shipped read-only smoke
    tests like T1018/T1082 or throwaway containers).
  - Refusal exits 3 with a single-line message naming which flag was
    expected. Tilde expansion is implemented by reading
    `/proc/self/environ` for HOME (no `std.posix.getenv` in Zig 0.16).
  - When `--target <IP>` is supplied, the IP is exposed to the TTP via
    a `TARGET=<IP>` environment variable prepended to the bash exec
    line, so descriptors can write `ssh "$TARGET" ...` patterns.
  - Whitelist parser supports IPv4 CIDR notation + bare IPs; blank
    lines and `#`-comments are ignored. IPv6 is intentionally deferred
    to a later pass (no test rig yet).

- **Claude (2026-05-06 pass-1):** v0.1.0 lands.
  - Subcommands: `run`, `validate`, `--version`, `--help`.
  - TTP descriptor JSON parser + structured envelope emitter.
  - Two safe example TTPs: T1018 (Remote System Discovery — `ip neigh
    show`), T1082 (System Information Discovery — `uname -a`).
  - Envelope shape v1 includes: schema URI, ttp metadata, execution
    timing (wall clock + monotonic duration), exit code, stdout/stderr
    byte counts + SHA-256, host hostname, verdict.
  - Verified: T1082 runs against this workstation, envelope written,
    verdict PASS, exit 0.

## Acceptance gate (per ~/COMPETITIVE_LANDSCAPE.md S1)

| Property | Status |
|---|---|
| sketch → compiled | ✅ DONE |
| `zig build` green | ✅ |
| `zig build test` green | ✅ (18 tests) |
| Reads TTP JSON descriptor | ✅ |
| Executes via bash -c, captures stdout/stderr | ✅ |
| Emits structured JSON envelope | ✅ |
| Verdict evaluation (PASS/FAIL) | ✅ |

## Open

### v0.2 — sentinel-lab integration (DONE 2026-05-07 pass-2)

- ✅ **Target whitelist enforcement.** Refuse-by-default unless target
  IP ∈ lab whitelist OR `--unsafe-local` ack. Whitelist read from
  `~/sentinel-lab/lab-targets.txt` (override via `--lab-targets`).
- ⏳ **Batch mode** (`run-all <ttp-dir>`) — moved to v0.3.
- ⏳ **`--detect-only`** — moved to v0.3.

### v0.3 — adversary-emulation parity (DONE 2026-05-11 pass-3, EXPERIMENTAL)

- ✅ **Atomic Red Team YAML compatibility** — in-tree minimal YAML
  subset parser (`src/yaml.zig`, ~350 LOC) + ART → Ttp adapter
  (`src/art.zig`, ~190 LOC). `--art <file>` / `--art-test <selector>`
  flags. bash/sh executors only; other executors rejected, not
  silently mis-run. Marked EXPERIMENTAL in README and `--help`.
- ⏳ **Batch mode** (`run-all <ttp-dir>`) — moved to v0.4 (paired with
  ART batch + `--check-deps`).
- ⏳ **`--detect-only`** — moved to v0.4.

### v0.4 — detection-engineering output

- **Sigma rule emitter**: when a TTP runs and an expected detection
  signal is absent, emit a Sigma rule stub for the operator to extend.
- **Velociraptor artifact emitter**: similar for Velociraptor.
- **Envelope schema validator** + consumer-side checker.

### v0.5+ — local-LLM planner (designed not built)

- **`--plan`** subcommand: ingest lab inventory (a JSON file
  enumerating target VMs + their fingerprints), shell out to a local
  Ollama / vLLM endpoint, produce a plan envelope of "which TTPs
  should run against which target."
- **Plan replay**: a plan envelope can be re-executed for reproducibility.

### v1.0 — public OSS ship

- **GitHub publish** as `stax/sovereign-offense-harness` (AGPL).
- **CI**: Zig build matrix on Linux x86_64 + aarch64.
- **Documentation site** under blog/ or its own subdomain.
- **Defense procurement narrative**: reference deployment as the
  red-team-emulation tool inside a sentinel-lab purple-team setup.

## Conventions

- Append-only protocol per `~/AGENT_CONVENTIONS.md`. Each pass adds a
  dated section under "Active focus" claiming what that pass did.
- Single-file source (`src/main.zig`) until it grows past ~600 LOC,
  then split: `ttp.zig` (parser), `envelope.zig` (writer), `runner.zig`
  (executor), `lab.zig` (whitelist + sentinel-lab integration).
- Stay zero-third-party-dep. Single Zig binary, AGPL.
