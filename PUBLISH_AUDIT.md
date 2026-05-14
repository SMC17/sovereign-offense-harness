# PUBLISH_AUDIT — sovereign-offense-harness

**Audit lane:** WS 3 (Codex, README/STATUS vs shipped-binary parity).
**Date:** 2026-05-12.
**Verdict:** **PASS-WITH-DOC-VERSION-FIXES**.

This repo is public and has already received WS 6's security review
remediation plus WS 12's mechanical publishing pass. My lane audited
whether the README / STATUS / tags / source / shipped binary tell the
same story, with extra attention to the Atomic Red Team adapter and
dual-use posture.

## Scope

- `README.md`, `STATUS.md`, `SECURITY.md`, `THREAT_MODEL.md`,
  `SECURITY_REVIEW.md`.
- `src/main.zig`, `src/art.zig`, `src/yaml.zig`, `build.zig`,
  `build.zig.zon`.
- TTP descriptors under `ttps/examples/`.
- License files: `LICENSE`, `NOTICE`.
- Current Git state, tags, binary output, help text, unit tests, and
  smoke runs.

## Findings

### 1. Build and test parity — PASS

`zig build --summary all` succeeds.

`zig build test --summary all` succeeds with `20/20 tests passed`.

Native descriptor validation succeeds for:

- `ttps/examples/t1082-system-information-discovery.json`
- `ttps/examples/t1018-remote-system-discovery.json`

Native smoke run succeeds and emits parseable JSON:

```sh
tmpdir=$(mktemp -d /tmp/soh-audit.XXXXXX)
./zig-out/bin/sovereign-offense-harness run --unsafe-local \
  --ttp ttps/examples/t1082-system-information-discovery.json \
  --out "$tmpdir"
jq empty "$tmpdir"/*.json
rm -rf "$tmpdir"
```

ART smoke run succeeds and emits parseable JSON:

```sh
tmpdir=$(mktemp -d /tmp/soh-art-audit.XXXXXX)
./zig-out/bin/sovereign-offense-harness run --unsafe-local \
  --art ttps/examples/art-t1082-system-info.yml \
  --out "$tmpdir"
jq empty "$tmpdir"/*.json
rm -rf "$tmpdir"
```

The ART run prints the selected atomic and substituted exec before
execution, and `--unsafe-local` prints the no-sandbox warning.

### 2. Version and tag parity — NEEDS FIX BEFORE NEXT AMPLIFICATION

Current repository state:

- `HEAD` is tagged `v0.3.2` at commit `21ee752`.
- `origin/main` also points at `21ee752`.
- Tags present: `v0.3.2`, `v0.3.1`, `v0.3.0`, `v0.2.0`, `v0.1.0`.
- `v0.3.2` changed `SECURITY.md` only: reports now route through
  GitHub private advisory.

Stale or ambiguous surfaces:

- `./zig-out/bin/sovereign-offense-harness --version` reports
  `0.3.1`.
- `src/main.zig` top comment still says `sovereign-offense-harness
  v0.3.0`; `const VERSION = "0.3.1"`.
- `build.zig.zon` says `.version = "0.3.1"`.
- README top status says `v0.3.1 — early`.
- README "Status — what's verified vs not" starts with `v0.3.0`.
- README comparison table says maturity is `v0.3`.
- STATUS.md "Last green" says `v0.3.1`, and the top active-focus
  section does not mention `v0.3.2`.
- STATUS.md roadmap still says "GitHub publish as
  `stax/sovereign-offense-harness`"; the actual public namespace is
  `SMC17/sovereign-offense-harness`.

This is not a code correctness blocker. It is a publication hygiene
problem: a reader landing from GitHub sees `v0.3.2` tags, a `0.3.1`
binary, and mixed `v0.3.0` / `v0.3.1` prose. Fix by either:

1. bumping source/package/README/STATUS to `0.3.2`, or
2. explicitly documenting `v0.3.2` as a docs/security-routing tag
   whose CLI remains `0.3.1`.

Option 1 is cleaner.

### 3. Atomic Red Team EXPERIMENTAL marker — PASS

The experimental marker is present and consistent enough for public
reading:

- README top status: `--art` mode is marked `EXPERIMENTAL`.
- README usage block: `# v0.3 EXPERIMENTAL`.
- README "what does NOT work yet" explicitly lists YAML subset limits,
  rejected executors, ignored cleanup/dependencies, and future
  `--check-deps`.
- Help text marks `--art` as `EXPERIMENTAL` and lists bash/sh-only
  executor support, minimal YAML parser, default substitution, ignored
  dependencies and cleanup.
- `src/art.zig` and `src/yaml.zig` comments state the adapter/parser
  limitations directly.
- STATUS.md v0.3 section marks ART compatibility `EXPERIMENTAL`.

Remaining improvement: in launch copy and examples, prefer explicit
`--art-test name:...` even for one-atomic files. The current CLI
default is honest, but explicit selector examples are safer for
copy-paste public materials.

### 4. TTP descriptor safety — PASS

Tracked TTP descriptors are intentionally low-risk enumeration:

- `t1082-system-information-discovery.json`: `uname -a; cat
  /etc/os-release`.
- `t1018-remote-system-discovery.json`: `ip neigh show`.
- `art-t1082-system-info.yml`: `uname -a | tee
  /tmp/sovereign-offense-art-t1082.out` and `cat /etc/os-release`.

No descriptor contains production targets, real external target IPs,
tokens, bearer strings, private keys, or production credentials. The
ART example writes to `/tmp`; that is acceptable for a smoke demo, but
launch docs should name that side effect if they include the command.

Regex scan findings:

- `README.md`: private RFC1918 whitelist examples `10.0.0.0/24` and
  `192.168.99.42`; OK as documentation examples.
- `src/main.zig`: private RFC1918 examples in whitelist parser docs;
  OK.
- `SECURITY.md`: `Authorization: Bearer $TOKEN` appears as a warning
  example; OK.
- `THREAT_MODEL.md`: `0.0.0.0/0` appears as an example of bypassing
  the whitelist; OK.
- `LICENSE`: generic AGPL text includes "password or key"; OK.

### 5. Dual-use public-safety posture — PASS

WS 6's remediation is present:

- Top-of-README "Authorized Use Only" block.
- README distinguishes operator-error gate from adversary/malice gate.
- `THREAT_MODEL.md` exists and is explicit about who the tool is and
  is not for.
- `SECURITY.md` warns against embedding credentials in descriptors and
  notes hostname disclosure in envelopes.
- Runtime `--unsafe-local` warning is present.
- Runtime ART selection + substituted exec preview is present.

The posture is not magic. It does not prevent malicious use. It is
honest about that, which is the correct standard for a public
dual-use tool.

### 6. AGPL sanity — PASS

- `LICENSE` is the full GNU Affero General Public License v3 text
  (`235` lines).
- `NOTICE` carries the project-specific copyright and
  `SPDX-License-Identifier: AGPL-3.0-or-later`.
- README license section says `AGPL-3.0-or-later`.
- `src/main.zig` comments say `AGPL-3.0-or-later`.

No AGPL use-case restriction is implied; README and SECURITY.md
correctly say AGPL is copyleft, not responsible-use licensing.

## Required fixes

Before the next public amplification or patch tag:

1. Reconcile version surfaces to `v0.3.2`, or explicitly document
   `v0.3.2` as a docs/security-routing tag over a `0.3.1` binary.
2. Update STATUS.md "Last green" after the 2026-05-12 test run.
3. Replace the stale roadmap namespace `stax/sovereign-offense-harness`
   with `SMC17/sovereign-offense-harness`.
4. Prefer explicit `--art-test name:...` examples in launch copy.

## Evidence

```text
git status --short --branch --untracked-files=all
git tag --sort=-creatordate
git log --oneline --decorate -n 8
zig build --summary all
zig build test --summary all
./zig-out/bin/sovereign-offense-harness --version
./zig-out/bin/sovereign-offense-harness --help
./zig-out/bin/sovereign-offense-harness validate ttps/examples/t1082-system-information-discovery.json
./zig-out/bin/sovereign-offense-harness validate ttps/examples/t1018-remote-system-discovery.json
./zig-out/bin/sovereign-offense-harness run --unsafe-local --ttp ttps/examples/t1082-system-information-discovery.json --out "$tmpdir"
./zig-out/bin/sovereign-offense-harness run --unsafe-local --art ttps/examples/art-t1082-system-info.yml --out "$tmpdir"
git grep -n -E "BEGIN .+ PRIVATE KEY|aws_secret|sk-ant-|ghp_|gho_|sk-[A-Za-z0-9]{20,}|api[_-]key|password|Authorization:|Bearer|AKIA|[0-9]{1,3}(\\.[0-9]{1,3}){3}"
wc -l README.md STATUS.md SECURITY.md THREAT_MODEL.md LICENSE NOTICE src/main.zig src/art.zig src/yaml.zig
```

## Claim template

Claim: `sovereign-offense-harness` is publishable from the WS 3
README/STATUS-vs-binary lane after small version-surface cleanup.

Proof level: `audited` plus `unit-tested` for the current Zig test
suite.

Command/source: commands listed above.

False-positive risk: smoke runs covered only the shipped examples, not
arbitrary ART files or malicious descriptors.

False-negative risk: grep-based scans can miss encoded secrets or
unsafe semantics hidden in future descriptors.

Not measured: runtime behavior against remote allowlisted targets,
multi-host orchestration, detection-engineering integration, or
malicious ART YAMLs.

Confidence: 0.82.
