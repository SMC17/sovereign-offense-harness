# PUBLISH_AUDIT — sovereign-offense-harness

**Audit lane:** WS 12 (Claude, codebase audit).
**Date:** 2026-05-11.
**Verdict:** PASS-WITH-FIXES → ready to push as `github.com/SMC17/sovereign-offense-harness`.

**Adjacent lanes:** WS 3 (Codex, README/STATUS audit), WS 6
(Claude, dual-use security review → `SECURITY_REVIEW.md`).
WS 12 owns the publishing-readiness layer only — license, secret
scan, namespace, public-OSS housekeeping. **The dual-use ethics
+ legal disclaimer + responsible-use review is WS 6's
authoritative output.** If WS 6 flags BLOCKING, this push must be
deferred regardless of WS 12's PASS verdict.

## Findings

### 1. Secret scan — CLEAN

Dispatch regex
(`BEGIN .+ PRIVATE KEY|aws_secret|sk-ant-|ghp_|gho_|sk-[a-zA-Z0-9]{20,}|api[_-]key`)
plus broader sweep (`AKIA*`, `password=`, `bearer …`, `xoxb-`,
`xoxp-`, `secret_key=`, `ssh-rsa AAAA`) across every git-tracked
file. **No matches.**

### 2. Hardcoded targets / production IPs — CLEAN

The dispatch flagged this as extra-care because the tool is
offensive. Scanned every tracked file for RFC1918 IP literals,
real ATT&CK targets, production-shaped hostnames.

Hits found:
- `README.md` line 238–239: `10.0.0.0/24`, `192.168.99.42` —
  documentation examples for the CIDR whitelist format. Both
  RFC1918 (private), neither connectable from outside a target's
  own LAN. **OK.**
- `src/main.zig` line 254: doc-comment example `10.0.0.5` for
  whitelist-parser unit explanation. **OK.**

No real ATT&CK targets, no production hostnames, no embedded
credentials in any TTP descriptor. The three shipped TTPs
(`t1018`, `t1082`, `art-t1082`) are intentionally read-only
enumeration — verified by reading each `exec` line.

### 3. EXPERIMENTAL marker consistency — DEFER

Per WS 3's lane: "Cross-check that the EXPERIMENTAL marker on
Atomic Red Team adapter is consistent everywhere."

Spot-check from WS 12 lens:
- `README.md` mentions Atomic Red Team adapter (line numbers
  vary by section). Marker present in v0.3.0 release notes
  (commit `b5f1bd6`).
- `STATUS.md` carries the v0.3.0 changelog.
- WS 3 owns the authoritative cross-check. Deferring.

### 4. LICENSE — fixed

Same fix as the rest of the WS 12 batch: per-project AGPL
notice moved to `NOTICE`, full SPDX
`AGPL-3.0-or-later.txt` (235 lines) installed as `LICENSE`.

### 5. GitHub namespace — fixed

`github.com/stax/<repo>` and `github.com/stax` maintainer link
rewritten to `github.com/SMC17` in `README.md` and
`CONTRIBUTING.md`. Verified zero residual `github.com/stax`
references post-rewrite.

### 6. CODE_OF_CONDUCT.md — added

Same canonical 50-line CoC as the rest of the batch (Contributor
Covenant *spirit*, not formal adoption).

### 7. .gitignore — hardened

**Before:** `/zig-out/`, `/.zig-cache/`, `/envelopes/*.json`
(audit-envelope outputs are local-only).

**Fix applied:** Added `.env*`, `*.key`, `*.pem`, `*.p12`,
`*.crt`, `.idea/`, `.vscode/`, `*.swp`, `.DS_Store`. The
existing `envelopes/*.json` ignore is correct as-is — audit
envelopes can contain hostnames + command output and should
stay local.

### 8. Open-but-not-blocking (flagged for adjacent lanes)

- **WS 6's SECURITY_REVIEW.md is in flight** (untracked).
  This commit deliberately leaves it untracked so WS 6 can
  commit when their review finalizes.
- **WS 3 owns the README/STATUS claim audit** — defer to its
  `PUBLISH_AUDIT.md` for that layer.
- **`AGENTS.md` untracked** — WS 4 lane.
- **`stax.dev` references** in README — same launch-arc
  aspiration as the rest of the batch; not blocking the push.

## Push-blocker dependency

This repo's push is **gated on WS 6's
SECURITY_REVIEW.md** clearing the dual-use ethics + legal
disclaimers + responsible-use review. WS 12 has cleared the
mechanical pre-push layer; the *ethical* publish decision is
WS 6 + Stax's call.

If WS 6 clears: proceed with the push plan below.
If WS 6 flags: write `BLOCKING.md` and stop.

## Evidence

```
$ git ls-files | xargs grep -lE "BEGIN .+ PRIVATE KEY|aws_secret|sk-ant-|ghp_|gho_|sk-[a-zA-Z0-9]{20,}|api[_-]key"
(no matches)

$ wc -l LICENSE NOTICE CODE_OF_CONDUCT.md
   235 LICENSE
    17 NOTICE
    50 CODE_OF_CONDUCT.md

$ grep -rn "github\.com/stax/" .
(no matches after fix)

$ git tag --list
v0.1.0
v0.2.0
v0.3.0
```

## Push plan (gated on WS 6 clearance)

```
gh repo create SMC17/sovereign-offense-harness --public --source=. \
  --description "Adversary-emulation runner: safety-gated, allow-listed targets, signed audit envelopes. v0.3 ships an EXPERIMENTAL Atomic Red Team adapter."
git push -u origin main
git push --tags  # v0.1.0, v0.2.0, v0.3.0
```
