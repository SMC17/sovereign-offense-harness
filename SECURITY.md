# Security

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Email: **security@stax.dev** (alias once `stax.dev` MX is configured;
fallback `fbw5wgxp59@privaterelay.appleid.com` until then).

Encrypted reports welcome — request the project's current SSH-signing
public key (`~/.ssh/id_stax_mesh.pub`-shape ED25519 key) by replying to
the initial acknowledgement email; we'll publish a stable disclosure key
in this file once one is generated.

Include in your report: project name, version (`<binary> --version`),
reproduction steps, and any flake.lock / TTP / configuration files
needed to reproduce. If practical, attach a minimal reproducer.

## Response timeline

This is a single-author project. Realistic, not aspirational:

- Acknowledgement: within **72 hours**, target 48.
- Triage: within **14 days**, target 7. Holiday and travel periods
  may extend this — communicated explicitly if so.
- Patch + coordinated disclosure: within **90 days** for confirmed
  issues. We'll communicate ETA and any extension request as soon as
  we have one.

If you need a faster timeline (active exploitation, etc.), say so in
the report and we'll prioritize accordingly.

## Scope

In-scope:
- Code execution as the running user via crafted input (TTP
  descriptor, flake.lock, SPDX, CLI args).
- Audit-envelope tampering or hash forgery in `sovereign-offense-harness`.
- Determinism violations (same input → different output) in
  `sentinel-sbom`.
- Privilege escalation via the tool's normal usage paths.
- Module misconfiguration in `sovereign-edge` that produces an
  insecure default (e.g., a CRS rule disabled by default that
  shouldn't be).

Out-of-scope:
- Vulnerabilities in upstream dependencies. Please report there
  first; we'll bump our pin once a fix lands upstream.
- Denial-of-service via resource exhaustion when handling
  obviously-malicious input (e.g., a 4 GB flake.lock, a TTP whose
  `exec` field is `:(){ :|:& };:` (fork bomb)).
- Issues with the example TTP descriptors themselves — they're
  intentionally simple read-only commands, not security boundaries.
- "Self-XSS" — running an attacker-controlled TTP descriptor /
  flake.lock that you intentionally chose to feed into the tool. The
  README explicitly says don't do this.

## Scope-of-trust

The tools in this repo trust:
- Their own binary. Build from source for an actual audit; the
  signed-commit history under `git verify-commit` is the integrity
  story. There is no signed-binary distribution yet.
- The input file at face value. The user is expected to have
  validated the source of the input *before* running the tool.
- The local Nix store (for `sentinel-sbom --strict` verify mode).
- The host's `bash` and standard utilities (for `sovereign-offense-harness`).

The tools do **not** trust:
- Network sources at runtime (none are queried in the default
  invocation; `sentinel-sbom --strict` shells to local `nix path-info`
  which only reads the local store).
- The shell environment beyond `$PATH` for child processes.
- Other agents on the host (none of these tools talk to a daemon).

### Do not embed credentials in TTP descriptors

The TTP descriptor's `exec` field — and the substituted ART exec line
after `#{var}` resolution — is captured verbatim into the audit
envelope JSON. A line like
`curl -H "Authorization: Bearer $TOKEN" …`
written into a descriptor results in the literal bearer token (after
shell expansion at run time) and the descriptor text both being
visible in `envelopes/<id>-<ts>.json`.

Use environment-variable indirection. The runner already passes
`$TARGET` through the child shell; the same pattern works for
`$API_TOKEN`, `$AWS_SECRET_ACCESS_KEY`, etc. Keep secrets out of the
descriptor file and out of any ART YAML you import — both are
captured into the envelope, which is forensic evidence designed to
be portable.

The envelope also records the host's `hostname` in plaintext. For
defense-lab / sensitive-target work, treat the envelope as a
hostname-disclosing artifact. A `--anonymize` flag is on the v0.4
roadmap.

### AGPL does not restrict use case

The license is copyleft, not responsible-use. The project relies
entirely on downstream-operator authorization. See
[`THREAT_MODEL.md`](THREAT_MODEL.md) and the
**Authorized Use Only** notice at the top of the README.

## Coordinated disclosure

[90-day clock](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure)
for confirmed unpatched issues, extendable on mutual agreement when an
upstream fix is in flight.
