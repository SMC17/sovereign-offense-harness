# THREAT_MODEL — sovereign-offense-harness

This document states, in plain terms, **who this tool is for, who it is
not for, what its safeguards do and do not do, and what trust
assumptions it relies on**. Read it before publishing anything from
this repo, and before running the binary against anything you care
about.

## Who this tool is for

- **Authorized red-teamers** running emulation in their own labs or
  under written engagement authority.
- **Blue-team detection engineers** running scripted TTPs in isolated
  lab VMs to validate signatures.
- **Sovereignty-conscious organizations** (defense labs, regulated
  finance, regulated medical, university security research) running a
  small purple-team flywheel with their own infrastructure.
- **OSS consumers** who want to read, audit, and modify a ~1,180 LOC
  Zig binary instead of a multi-megabyte SaaS agent.

## Who this tool is not for

- Anyone running offensive techniques against systems they do not own
  or do not have explicit, written authorization to test. The AGPL
  does not (and cannot) restrict use case. Most jurisdictions
  criminalize unauthorized access regardless of intent (CFAA in the
  US, Computer Misuse Act in the UK, equivalents EU-wide).
- Anyone planning to take an upstream Atomic Red Team atomic and run
  it against a third party "to see what happens."
- Production environments. Period.

If you are not in a position to articulate (in writing, to a
counterparty) why your use of this tool is authorized, **stop
reading and uninstall**.

## What the safety gate does

The `v0.2` safety gate refuses every `run` invocation unless one of:

1. `--target <IP>` matches an entry in the lab-targets whitelist file
   (default `~/sentinel-lab/lab-targets.txt`).
2. `--unsafe-local` is explicitly passed.

It exits `3` with a refusal message on either condition's absence. It
prints a stderr warning on every `--unsafe-local` run (suppressible
via `SOH_QUIET=1`). It prints the selected ART atomic + the
substituted exec line to stderr before every `--art` run,
unconditionally.

**This is an operator-error gate.** It catches:

- Fat-fingered `run` against the wrong host (you meant `lab-host-3`,
  you got `localhost`).
- Muscle-memory `run` after `cd`-ing into a different lab.
- "I copied a TTP from Slack and forgot to read the `exec` line."
- ART YAMLs with multiple atomics where the default-first-atomic
  isn't what you thought it was.

## What the safety gate does not do

It is **not an adversary gate.** An operator who *wants* to fire an
unsafe TTP can:

- Set `--unsafe-local` once and forget it.
- Add `0.0.0.0/0` to the whitelist file (or a more targeted entry to
  any IP they like).
- Modify the source — it's open, AGPL, ~1,180 LOC of unobfuscated Zig.

The gate is **friction-against-accident**, not friction-against-intent.
The honest framing is the only credible one. If you are an InfoSec
reviewer reading this looking for the place the project overclaims,
this section is where it does not.

## What the audit envelope is

A forensic-correlation artifact for the team running the test:

- `schema`, `ttp.id`, `ttp.name`, `ttp.exec` (verbatim — including
  ART substitution).
- `execution.{started_at_unix, duration_ms, exit_code, stdout_bytes,
  stderr_bytes, stdout_sha256, stderr_sha256}`.
- `host.hostname` (plaintext — see "Disclosure" below).
- `verdict` (PASS/FAIL) + optional `verdict_reason`.

It is suitable for: diffing against blue-team detection events,
proving that a given technique ran on a given host at a given time,
feeding into a detection-engineering pipeline.

## What the audit envelope is not

- **It is not an authorization artifact.** Possessing an envelope is
  not proof of authorized use. Authorization records (engagement
  letter, internal change request, signed scope-of-work) are the
  operator's responsibility and live outside this tool.
- **It is not a secret store.** If you embedded credentials in the
  `exec` line, they are in the envelope. See SECURITY.md.
- **It is not anonymized.** Hostname is plaintext. A `--anonymize`
  flag is on the v0.4 roadmap.

## Trust assumptions

The tool trusts:

- Its own binary. Build from source if you need integrity
  verification; signed-commit history is the integrity story.
- The TTP descriptor / ART YAML file at face value. **You** are
  expected to have read and validated it before invoking the runner.
- The local `bash` and standard utilities.
- The whitelist file's contents (`~/sentinel-lab/lab-targets.txt` by
  default).

The tool does not trust:

- Network sources at runtime. The default invocation makes no network
  calls; only the user-supplied `exec` line does, if it chooses to.
- The shell environment beyond `$PATH` for child processes.
- Other agents on the host. There is no daemon, no IPC.

## Out of scope

- Sandboxing: there is none. The TTP runs as the invoking user.
  Sandboxing is the *lab's* job (think: an isolated VM, an
  unprivileged container, a network segment that can't reach
  production). This tool is the runner inside the sandbox, not the
  sandbox.
- Cleanup: not performed. The shipped descriptors are intentionally
  read-only enumeration. ART `cleanup_command` is ignored by the v0.3
  adapter (called out in the README's experimental note).
- Multi-host orchestration: out of scope. Use MITRE Caldera if you
  need agents + a server.

## What changes the threat model

If a future version adds:

- A scheduler / daemon: re-evaluate the agent-trust assumption.
- A schema-validator / consumer-side checker: re-evaluate the
  "envelope is forensic" assumption (consumers gain attack surface).
- An LLM-planner integration (v0.5+ roadmap): re-evaluate
  network-trust, sandbox, and authorization-record assumptions
  comprehensively before merging.
- A signed-binary distribution: re-evaluate the "build from source"
  integrity story.

Any of these would warrant a fresh threat-model document. Do not
silently extend the existing assumptions to cover them.
