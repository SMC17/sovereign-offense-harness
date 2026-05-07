# Security

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Email: **fbw5wgxp59@privaterelay.appleid.com** (PGP key on request).

Include: the project name, version (`<binary> --version`), reproduction
steps, and any relevant `flake.lock` / TTP / configuration files.

## Response timeline

- Acknowledgement within **48 hours**.
- Triage within **7 days**.
- Patch + coordinated disclosure within **30 days** for confirmed issues
  (longer if upstream fix requires it; we'll communicate ETA).

## Scope

In-scope:
- Code execution as the running user via crafted input (TTP descriptor,
  flake.lock, SPDX, CLI args).
- Audit-envelope tampering or hash forgery.
- Determinism violations (same input → different output).
- Privilege escalation via the tool's normal usage paths.

Out-of-scope:
- Vulnerabilities in upstream dependencies (please report there first;
  we'll bump our pin once a fix is published).
- Denial-of-service via resource exhaustion when handling
  obviously-malicious input (e.g., a 4 GB flake.lock).
- "Self-XSS" — running an attacker-controlled TTP descriptor /
  flake.lock that you intentionally chose to feed into the tool.

## Scope-of-trust

The tools in this repo trust:
- Their own binary (signed-commit history, build-from-source recommended).
- Their input files at face value (the user is expected to have
  validated the source of TTP / flake.lock files before piping them in).
- The local Nix store (for `--strict` verify mode).

The tools do **not** trust:
- Network sources (none are queried at runtime in normal operation).
- The shell environment beyond `$PATH` for child processes.

## Coordinated disclosure

We follow [a 90-day disclosure clock](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure)
for confirmed unpatched issues, extendable on mutual agreement when an
upstream fix is in flight.
