# SECURITY REVIEW — public-publish readiness

**Reviewer:** Claude (Sonnet/Opus session, WS 6 of DISPATCH 2026-05-11)
**Repo state reviewed:** `v0.3.0` (commit `b5f1bd6`, signed) — *the same v0.3 I just shipped in this session. This review therefore audits my own work; treat it as such and weight independent corroboration accordingly.*
**Scope:** dual-use disclosure ethics, legal/authorized-use posture, default-deny configuration, weaponization-as-shipped risk, README / SECURITY.md / LICENSE adequacy, comparison against Atomic Red Team and MITRE Caldera publishing practices.
**Out of scope (handled by WS 3 / WS 12):** secret scanning, license-file presence, README ↔ shipped-binary parity, push readiness.

---

## TL;DR — go/no-go

**Updated 2026-05-11, pass-4: HOLD → CLEAR.** All five P0 items, plus
P1-1 / P1-2 / P1-3 / P1-5, have been applied in this session (commit
to follow as `v0.3.1`). Remaining P1 items (P1-4 `set -o pipefail` —
*deferred* because it's a behavior change that could mask shipped
example TTPs; P1-6 privaterelay-email — *operator decision*, not
mine) and all P2 items are non-blocking for the initial public push.

**WS 12 push-gate posture:** WS 12's PUBLISH_AUDIT.md explicitly gates
on this file's verdict. With CLEAR posted here, WS 12 may proceed with
the offense-harness public push once stax / WS 1 coordinator
acknowledges. See §"Resolved by pass-4" below for the per-item evidence.

---

**Original verdict (kept for the record):** Hold. Do not push public until P0 items below are addressed. They are small, mostly README-text changes — collectively a 30-minute fix — but they substantially affect how this lands when it surfaces in front of hostile or unsophisticated downstream actors. Two specific items (P0-1, P0-3) are the ones that, if absent, will be the first thing a hostile-press reviewer or a sceptical InfoSec Twitter account will pick on.

**Type 1 (overclaim) lens:** the README's "refuse-by-default safety gate" language consistently overstates what the gate actually does. It is a *usability* gate against accident, not a *security* gate against malice. The fix is wording, not code.

**Type 2 (missed risk) lens:** missing standard disclaimers/legal-context that every comparable offensive-tooling OSS project ships with. There is no "authorized testing only" notice; no statement that downstream operators are responsible for their own authorization; no acknowledgement that the AGPL does not (and cannot) restrict use case; no warning against embedding credentials in descriptors; no `--art-test` selection-safety note. None of these are show-stoppers individually; together they are a posture problem.

---

## Baseline: how mature offensive-OSS projects publish

I am citing these from training; verify the exact text in the linked README files before mirroring quotes.

| Project | License | Top-of-README posture |
|---|---|---|
| **Atomic Red Team** (redcanaryco/atomic-red-team) | MIT | Prominent **Warning** block before anything else: "Tests within this repository should not be ran on any system or network in which you do not have permission to do so." + disclaimer of Red Canary liability. |
| **MITRE Caldera** (mitre/caldera) | Apache 2.0 | "For authorized red-team operations only" notice; explicit "intended for use by cybersecurity professionals in legally-authorized engagements." |
| **Metasploit Framework** (rapid7/metasploit-framework) | BSD-3-Clause | LICENSE includes use disclaimer; README links to TOS-style usage warning. |
| **Nmap** | NPSL (custom) | LICENSE itself encodes use disclaimer; the README is comparatively terse but the license is loud. |

The pattern is consistent: **license stays permissive, README/LICENSE pair carries the responsible-use language**. AGPL doesn't restrict use case (and cannot, by FSF doctrine), so the README has to carry that weight.

`sovereign-offense-harness` currently carries roughly zero of it. The Safety section is excellent for operator-error prevention but says nothing about authorization.

---

## Findings, prioritized

### P0 — block public push until fixed

**P0-1 — Missing "Authorized Use Only" notice at top of README.** (Type 2)
The README opens with technical framing ("A small Zig CLI that runs a TTP descriptor..."). There is no statement that this tool is intended for authorized testing only and that running it against systems you do not own or are not contractually authorized to test is a crime in most jurisdictions (CFAA in the US, Computer Misuse Act in the UK, equivalent statutes EU-wide). Every comparable project leads with this. Its absence will be the first thing a hostile reviewer flags.

*Fix:* add a clearly-bordered notice block immediately after the H1, before the v0.3 status callout. Proposed wording below in §"Concrete diffs". 5-minute change.

**P0-2 — README claims "refuse-by-default safety gate" without distinguishing accident-prevention from malice-prevention.** (Type 1)
The safety gate is bypassed by a single CLI flag (`--unsafe-local`) with no prompt, no env-var ack, no log entry beyond the envelope. Against a malicious operator the gate provides ~zero resistance — they set the flag once and forget it. Against accident (the actual threat the gate addresses) it works fine. The README presently does not draw this distinction. A sceptic will (correctly) say "your 'safety gate' is one flag."

*Fix:* re-word the Safety section to say "operator-error gate, not adversary gate." Operators who *want* to weaponize this will not be slowed down. The honest framing is the only credible one. Proposed wording below. ~5-minute change.

**P0-3 — No statement that AGPL does not restrict use case.** (Type 2)
A reader assumes "AGPL + safety gate = controlled distribution." It is not. AGPL is a *copyleft* license, not a *responsible-use* license. The project relies entirely on downstream-operator authorization, period. README should say so explicitly.

*Fix:* one paragraph in README or new `AUTHORIZED_USE.md` (one file is fine). ~10-minute change.

**P0-4 — `--unsafe-local` does not log a stderr warning when used.** (Type 2)
Operator runs `sovereign-offense-harness run --unsafe-local --ttp foo.json`. Binary prints `[PASS] ...` and exits 0. There is no `WARNING: --unsafe-local was passed; this ran as your user with no sandbox` line printed to stderr. The flag's *name* is the warning, per the existing README, but that's a one-time read; muscle memory will erase it within a week of regular use. Compare: `sudo`, `rm -rf`, `git push --force` all loudly announce what they're doing.

*Fix:* add a single `std.debug.print("warning: --unsafe-local: running TTP as {s} with no sandbox\n", .{user})` to stderr at the top of `runCmd` when the flag is set. ~10-minute change. Could also gate behind `SOH_QUIET=1` env var for batch users.

**P0-5 — `--art-test` defaults to first atomic silently.** (Type 1 + Type 2)
ART atomic-test files routinely contain multiple variants with very different risk profiles (e.g., `T1059.004` ranges from `echo hello` to `wget … | sh`). The harness silently runs the first one by default. The README says "default: first test in the file" but does not warn that this can be substantially more dangerous than the operator thinks. An ART YAML downloaded from an untrusted source is exactly the case where defaulting to "the first one" is wrong.

*Fix (minimum):* before executing an ART test, print `running atomic_tests[N]: <name> (of M total)` to stderr unconditionally. ~10-minute change.
*Fix (better):* require `--art-test` to be explicit (`first`, `index:N`, or `name:…`) when the file contains >1 atomic. ~20-minute change.
*Fix (best):* both of the above, plus a `--art-dry-run` that prints the substituted command without running it. ~30-minute change.

### P1 — must ship before v0.4

**P1-1 — TTP descriptor `exec` is written to the envelope in plaintext.** (Type 2)
If an operator embeds a credential in a TTP — e.g. `curl -H "Authorization: Bearer $TOKEN" …` — the literal `Bearer …` line is written to `envelopes/T….json`. Operators will absolutely do this. README/SECURITY.md should warn explicitly and recommend env-var indirection (the runner already exposes `$TARGET`; same pattern can carry credentials).

*Fix:* add to SECURITY.md "Scope-of-trust" section: descriptor `exec` is captured verbatim into the envelope; do not embed credentials inline; use env-var indirection. ~5-minute change.

**P1-2 — ART `#{var}` substitution uses defaults uncritically.** (Type 2)
ART atomic descriptors often have `default:` values intended as demonstration values (e.g. URLs pointing to redcanaryco-hosted test payloads). Operators who do not pre-read the YAML get those defaults baked into their `exec`. Worse: if the upstream ART repo is mirrored maliciously, the `default:` field is a clean injection vector. README/`--help` should flag this.

*Fix:* `--art` runs should print the *substituted* exec line to stderr before executing, so the operator sees what's about to run. ~10-minute change. (This pairs cleanly with P0-5.)

**P1-3 — No `THREAT_MODEL.md`.** (Type 2)
Caldera ships one; ART implicitly ships one in README; this project has no explicit model. A `THREAT_MODEL.md` (300–500 words) should articulate: who the tool is for (authorized red-teamers running an isolated lab); who it is not for (anyone testing against systems they don't own/aren't authorized for); what threats the safety gate addresses (operator error) and what it does not (malice); what the envelope is/isn't (correlation artifact, *not* authorization artifact).

*Fix:* write `THREAT_MODEL.md`. ~30-minute change.

**P1-4 — `bash -c` invocation has no shell-safety pragmas.** (Type 2, mostly correctness)
The harness spawns `bash -c '<exec>'` with no `set -euo pipefail` prepend. A failing pipeline mid-exec yields exit 0 if the last command succeeded. This is a *correctness* issue (envelope verdict will overclaim success) not a security one, but it touches both — a "PASS" envelope on a partial-failure run is type-1 overclaim. v0.4 candidate.

*Fix:* prepend `set -o pipefail` to the bash invocation by default; document as a flag if anyone needs the current behavior. ~10-minute change.

**P1-5 — Hostname in envelope is technically PII.** (Type 2)
Envelopes are designed to be portable evidence artifacts (that's their whole point). `host.hostname` is in every envelope, plaintext. For a hobbyist this is fine; for a defense-procurement reference deployment (the v1.0 ambition) it's a deployment-secrecy leak. Document this and offer `--no-hostname` or a `--anonymize` flag.

*Fix (now):* document in README. (~5 min.)
*Fix (v0.4):* `--anonymize` flag that zeroes hostname. (~20 min.)

**P1-6 — `SECURITY.md` discloses a privaterelay alias that ties the GitHub identity to a Apple-Relay email.** (Type 2, opsec)
Current line:
> `fallback fbw5wgxp59@privaterelay.appleid.com until then`
This is the maintainer's anonymizing alias for `seancollins2027@u.northwestern.edu` — fine to publish as a contact, but pinning it next to the GH `@stax` handle and the `.dev` domain makes correlation trivial. Decide deliberately whether this is intended. If yes, leave; if no, set up the `security@stax.dev` alias before push.

*Fix:* operator decision — confirm intent before push.

### P2 — v0.4+ / nice-to-have

**P2-1 — Export-control acknowledgement.** Adversary-emulation tooling has been argued (Wassenaar Arrangement debates around "intrusion software") to be export-controlled in some jurisdictions. The consensus has been that pure-research OSS is exempt under TSU/published-research exceptions, but the conservative move is to publish a brief `EXPORT.md` saying "this is published as basic research under TSU/published-research exemptions; consult counsel before redistributing in commercial form." 10 lines max. Not blocking.

**P2-2 — `--art-test` could fuzzy-match a name; today it's exact-match only.** Quality-of-life; not security.

**P2-3 — Envelope schema should be versioned + documented as a separate file.** Today the schema URI is `sovereign-offense-harness/envelope/v1` but there is no published v1 spec. v0.4 plans a schema validator; ship a JSON Schema doc alongside.

**P2-4 — CI matrix.** Roadmap mentions v1.0; add a GitHub Actions workflow that runs `zig build test` on push. This is signal-of-life for OSS reviewers; absence is a downvote.

**P2-5 — `CODE_OF_CONDUCT.md`.** Currently mentioned in CONTRIBUTING.md spirit-not-letter. For a security-adjacent project that will receive vuln reports from unfamiliar parties, a formal CoC is cheap insurance. ~10 min using Contributor Covenant verbatim.

---

## Concrete recommended diffs

### 1. README.md — add an "Authorized Use Only" block immediately after the H1 / before the v0.3 status line

```markdown
> ## ⚠️ Authorized Use Only
>
> **`sovereign-offense-harness` is adversary-emulation tooling intended
> for use against systems you own or are explicitly authorized to test.**
> Running offensive techniques against systems you do not own, or
> against which you do not have written authorization, is a crime in
> most jurisdictions (Computer Fraud and Abuse Act in the US, Computer
> Misuse Act in the UK, equivalent statutes EU-wide). The AGPL license
> does not (and cannot) restrict use case — responsibility for legal,
> ethical, and authorized operation rests entirely with the operator.
>
> The built-in safety gate (refuse-by-default unless `--target <IP>` ∈
> whitelist OR `--unsafe-local`) prevents *operator error*. It does not
> and cannot prevent operator *malice*. If you are not in a position to
> articulate (in writing, to a counterparty) why your use of this tool
> is authorized, **do not use it**.
>
> See `THREAT_MODEL.md` for who this tool is for and who it is not for.
```

### 2. README.md — re-word the Safety section opener

Current:
> The TTP's `exec` field runs via `bash -c` as the invoking user. There is no sandbox. v0.2 adds a **refuse-by-default safety gate**: every `run` must explicitly acknowledge what's being targeted.

Proposed:
> The TTP's `exec` field runs via `bash -c` as the invoking user. There
> is no sandbox. v0.2 added a **refuse-by-default operator-error gate**:
> every `run` must explicitly acknowledge what's being targeted via
> either `--target <IP>` (with an entry in the lab-targets whitelist)
> or `--unsafe-local`. This protects against accidents — a fat-fingered
> `run` is not enough to fire a TTP. It does not protect against a
> deliberate operator; the flags are trivially settable and the gate
> is honest framing only.

### 3. New file: `THREAT_MODEL.md` (~300 words)

Outline:
- **Who this is for:** authorized red-teamers, blue-team detection engineers, defense-lab researchers, sovereignty-conscious teams with their own isolated test environment.
- **Who this is not for:** anyone targeting systems they do not own / are not authorized to test. The tool is intentionally easy to read and modify; that lowers the bar to misuse. Caveat operator.
- **What the safety gate addresses:** operator-error (running against `localhost` when meaning `lab-host-3`; pasting a TTP from chat without re-reading the `exec` line).
- **What the safety gate does not address:** an operator who *wants* to run an unsafe TTP. The `--unsafe-local` flag exists. The gate is a friction-against-accident, not a friction-against-intent.
- **What the audit envelope is:** a forensic-correlation artifact for the team running the test, suitable for diffing against blue-team detections. Includes `exec`, hostname, hashes, timing.
- **What the audit envelope is not:** an authorization artifact. Possessing an envelope is not proof of authorized use. Operators are responsible for their own authorization records.
- **Trust assumptions:** local bash, the user-supplied descriptor file, the local lab-targets whitelist file. Nothing else. No network calls in the default invocation.

### 4. SECURITY.md — add a paragraph under "Scope-of-trust"

```markdown
**Do not embed credentials in TTP descriptors.** The `exec` field is
captured verbatim into the envelope JSON. A `curl -H "Authorization:
Bearer $TOKEN" …` line in a descriptor results in the literal bearer
token written to `envelopes/<id>-<ts>.json`. Use env-var indirection
(the runner already passes `$TARGET` through; the same pattern works
for `$API_TOKEN`) and keep secrets out of the descriptor file. The
envelope is forensic evidence, not a secret store.
```

### 5. `src/main.zig` — add a one-line `--unsafe-local` stderr warning (P0-4)

At the top of `runCmd` (or equivalent), when `unsafe_local` is true:
```zig
std.debug.print(
    "warning: --unsafe-local is set; TTP will run as your user, no sandbox.\n",
    .{},
);
```
Suppress under `SOH_QUIET=1` if batch users complain.

### 6. `src/main.zig` — add a one-line ART selection stderr line (P0-5)

When `--art` is used, before executing:
```zig
std.debug.print(
    "art: running atomic_tests[{d}]: {s} (of {d} total) — exec preview:\n{s}\n",
    .{ idx, adapted.name, total, adapted.exec },
);
```
This single line covers P0-5, P1-2, and provides a free dry-run-by-eyeball.

---

## Resolved by pass-4 (2026-05-11 evening)

The five P0 items + four P1 items have been addressed in-tree. Evidence:

| ID | Status | Where |
|---|---|---|
| P0-1 Authorized-Use notice | ✅ Resolved | `README.md` top-of-file blockquote, links to `THREAT_MODEL.md` |
| P0-2 Safety-gate wording (operator-error gate, not adversary gate) | ✅ Resolved | `README.md` Safety section opener, re-worded |
| P0-3 AGPL doesn't restrict use case | ✅ Resolved | Stated in `README.md` Authorized-Use block + `SECURITY.md` final section + `THREAT_MODEL.md` |
| P0-4 `--unsafe-local` stderr warning | ✅ Resolved | `src/main.zig` runTtp emits stderr line every run; `SOH_QUIET=1` suppresses; verified by smoke test |
| P0-5 `--art` selection + exec preview | ✅ Resolved | `src/main.zig` runArtCmd echoes selected atomic name + selector + total-count + substituted exec to stderr; unconditional; verified by smoke test |
| P1-1 Credential-in-descriptor warning | ✅ Resolved | `SECURITY.md` new "Do not embed credentials in TTP descriptors" subsection |
| P1-2 ART substitution preview | ✅ Resolved | Folded into P0-5 |
| P1-3 `THREAT_MODEL.md` | ✅ Resolved | ~140-line new file shipping in pass-4 |
| P1-5 Hostname disclosure note | ✅ Resolved | `README.md` Safety section + `SECURITY.md` Scope-of-trust + `THREAT_MODEL.md` |
| P1-4 `set -o pipefail` prepend | ⏸ Deferred to v0.4 | Behavior change; could mask exit codes in shipped examples; needs a separate review pass with all shipped descriptors |
| P1-6 Privaterelay email in SECURITY.md | ⏸ Operator decision | Stax confirms intent before push; not mine to silently change |
| P2-1 Export-control note | ⏸ v0.4 | Not blocking |
| P2-2 Fuzzy `--art-test` matching | ⏸ v0.4 | Quality-of-life |
| P2-3 Envelope schema spec file | ⏸ v0.4 | Pairs with planned validator |
| P2-4 CI matrix | ⏸ v0.4 | GitHub Actions workflow; absence is a quiet downvote signal but not blocking |
| P2-5 `CODE_OF_CONDUCT.md` | ✅ Already shipped by WS 12 | `cbd8955` |

**Final WS 6 posture: CLEAR for public push.**

---

## Final recommendation

**Updated pass-4: CLEAR for public push.** With P0-1 through P0-5
applied and P1-1/P1-2/P1-3/P1-5 also folded in, the offense-harness
publish posture is *better* than median offensive-OSS for a v0.x
project. The safety-gate work was genuinely good; the missing piece
was owning the framing of what the gate is and is not, plus the
missing top-of-README authorized-use notice. Both are now in.

**Operator action required before push:**

1. Decide on P1-6 (privaterelay email in SECURITY.md). Either ship
   `security@stax.dev` first, or accept the correlation.
2. Read `THREAT_MODEL.md` end-to-end and confirm it captures stax's
   intended posture (this is the document that will get quoted at
   stax in adversarial Twitter / Hacker News threads, so it has to
   be the *intended* framing, not just my approximation).

After those two checkpoints, WS 12 may push.

**Deferred to v0.3.2 / v0.4:** P1-4 (`set -o pipefail`), P2-1 (export-
control note), P2-2 (fuzzy `--art-test`), P2-3 (envelope schema spec),
P2-4 (CI matrix).

---

## What was not measured

- I did not cross-fetch the live Atomic Red Team / Caldera / Metasploit README text. The baseline table above is from training data; verify the exact quoted text before mirroring it verbatim in this repo.
- I did not run the binary against a malicious-input TTP descriptor (e.g. one with shell-injection in `id` / `name`). The envelope writer was just hardened against newline injection (this session, v0.3.0) — but adversarial descriptor fuzzing is a separate review (suggest a future WS).
- I did not audit the Zig source for memory-safety properties beyond compile-time correctness (the test suite covers happy paths; no fuzzing).
- I did not evaluate the cryptographic strength of the SHA-256 envelope hashes (they're stdlib; presumably correct, but unaudited).
- I did not assess whether the GitHub repo settings (branch protection, secrets, Actions permissions) are correctly configured — that's WS 12's lane.
- I am auditing my own v0.3 work; an independent reviewer might catch things I'm blind to. Treat this review as one signal, not the only one.

---

*— Claude, WS 6, 2026-05-11 evening*
