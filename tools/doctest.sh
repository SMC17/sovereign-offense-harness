#!/usr/bin/env bash
# sovereign-offense-harness / tools / doctest.sh
#
# Documentation tests — verify the README's executable claims actually
# hold against the installed binary. A passing run means:
#
#   1. The README documents `run` + `validate` subcommands — both appear
#      in `--help`.
#   2. The README documents `--ttp <path>`, `--art <path>`, `--art-test`,
#      `--target <IP>`, `--unsafe-local`, `--lab-targets <path>` flags —
#      all appear in `--help`.
#   3. The README quotes a "refused by safety gate" refusal message in
#      the Safety section — the binary's stderr on a refused `run`
#      contains that exact substring.
#   4. The README demo block shows a JSON envelope with specific top-level
#      keys (`schema`, `ttp`, `execution`, `host`, `verdict`) — a benign
#      `--unsafe-local` run of the shipped T1082 descriptor produces an
#      envelope with those keys and the documented schema URI
#      `sovereign-offense-harness/envelope/v1`.
#
# WHY: Adversary-emulation tooling lives or dies on operator trust.
# README drift (documented flag missing, refusal message changed, schema
# URI moved) is exactly the class of bug an operator can't audit without
# reading source. This script makes the README a load-bearing artifact
# that `zig build doctest` gates.
#
# This is a documentation harness, NOT a substitute for
# `tests/safety_gate_integration.sh`. The integration test verifies
# gate *behavior* (exits, mutex pairs, /32 CIDR boundary). Doctest
# verifies the README *describes* that behavior accurately. Both are
# wired into `zig build test` via `build.zig`.

set -uo pipefail
cd "$(dirname "$0")/.."

BIN="zig-out/bin/sovereign-offense-harness"
TTP="ttps/examples/t1082-system-information-discovery.json"

# Build first (no-op when artifacts are current).
if ! zig build >/dev/null 2>&1; then
  echo "FAIL: zig build failed"
  exit 1
fi

if [ ! -x "$BIN" ]; then
  echo "FAIL: $BIN not found after build"
  exit 1
fi

n_pass=0
n_fail=0
declare -a FAILURES=()

HELP_OUT=$("$BIN" --help 2>&1 || true)

assert_help_contains() {
  local name="$1"
  local needle="$2"
  if echo "$HELP_OUT" | grep -qF -- "$needle"; then
    n_pass=$((n_pass + 1))
    echo "  PASS  $name"
  else
    n_fail=$((n_fail + 1))
    FAILURES+=("$name: --help did not contain '$needle'")
    echo "  FAIL  $name (--help missing '$needle')"
  fi
}

assert_readme_contains() {
  local name="$1"
  local needle="$2"
  if grep -qF -- "$needle" README.md; then
    n_pass=$((n_pass + 1))
    echo "  PASS  $name"
  else
    n_fail=$((n_fail + 1))
    FAILURES+=("$name: README.md did not contain '$needle'")
    echo "  FAIL  $name (README missing '$needle')"
  fi
}

echo "=== sovereign-offense-harness doctest ==="

# ─── Check 1: README documents `run` + `validate`; --help reflects both ────
assert_readme_contains "README documents 'run' subcommand"      "run --ttp"
assert_readme_contains "README documents 'validate' subcommand" "validate ttps/examples"
assert_help_contains   "--help advertises 'run'"                "run ("
assert_help_contains   "--help advertises 'validate'"           "validate <ttp.json>"

# ─── Check 2: documented CLI flags appear in --help ───────────────────────
# README's Usage + Safety sections name each of these; --help must too.
assert_help_contains "--help advertises '--ttp <path>'"     "--ttp <path>"
assert_help_contains "--help advertises '--art <path>'"     "--art <path>"
assert_help_contains "--help advertises '--art-test'"       "--art-test"
assert_help_contains "--help advertises '--target <IP>'"    "--target <IP>"
assert_help_contains "--help advertises '--unsafe-local'"   "--unsafe-local"
assert_help_contains "--help advertises '--lab-targets'"    "--lab-targets <path>"

# ─── Check 3: README quotes 'refused by safety gate'; binary prints it ────
#
# README quotes the literal string in the Safety section's `$ sovereign-...`
# pre block. Verify both that the README contains it AND that the binary
# prints it on a no-auth `run` invocation (exit 3).
assert_readme_contains "README quotes 'refused by safety gate' message" "refused by safety gate"

REFUSAL_OUT=$("$BIN" run --ttp "$TTP" 2>&1 || true)
REFUSAL_EXIT=$?
# bash quirk: command-substitution loses the exit code captured above,
# re-derive it from a separate invocation to be safe.
"$BIN" run --ttp "$TTP" >/dev/null 2>&1
REFUSAL_EXIT=$?

if echo "$REFUSAL_OUT" | grep -qF "refused by safety gate"; then
  if [ "$REFUSAL_EXIT" -eq 3 ]; then
    n_pass=$((n_pass + 1))
    echo "  PASS  binary refuses with 'refused by safety gate' on no-auth run (exit 3)"
  else
    n_fail=$((n_fail + 1))
    FAILURES+=("binary printed refusal but exited $REFUSAL_EXIT (expected 3)")
    echo "  FAIL  binary printed refusal but exited $REFUSAL_EXIT (expected 3)"
  fi
else
  n_fail=$((n_fail + 1))
  FAILURES+=("binary did not print 'refused by safety gate' on no-auth run")
  echo "  FAIL  binary did not print 'refused by safety gate' on no-auth run"
fi

# ─── Check 4: --unsafe-local run produces a documented-shape envelope ─────
#
# README's Demo block shows the envelope has top-level keys:
#   schema, ttp, execution, host, verdict
# and a schema URI of "sovereign-offense-harness/envelope/v1".
# Run a benign T1082 enumeration TTP under --unsafe-local against a
# scratch envelope dir and assert all of those.
ENV_DIR=$(mktemp -d)
SOH_QUIET=1 "$BIN" run --unsafe-local --ttp "$TTP" --out "$ENV_DIR" >/dev/null 2>&1 || true

ENV_FILE=$(ls "$ENV_DIR"/T1082-*.json 2>/dev/null | head -n 1 || true)
if [ -z "$ENV_FILE" ] || [ ! -f "$ENV_FILE" ]; then
  n_fail=$((n_fail + 1))
  FAILURES+=("--unsafe-local run did not produce an envelope file in $ENV_DIR")
  echo "  FAIL  --unsafe-local run produced no envelope"
else
  # Use jq if present; fall back to grep on the raw JSON otherwise.
  if command -v jq >/dev/null 2>&1; then
    schema=$(jq -r '.schema // empty' "$ENV_FILE" 2>/dev/null)
    ttp_id=$(jq -r '.ttp.id // empty' "$ENV_FILE" 2>/dev/null)
    has_exec=$(jq -r '.execution.exit_code // empty' "$ENV_FILE" 2>/dev/null)
    has_host=$(jq -r '.host.hostname // empty' "$ENV_FILE" 2>/dev/null)
    verdict=$(jq -r '.verdict // empty' "$ENV_FILE" 2>/dev/null)

    if [ "$schema" = "sovereign-offense-harness/envelope/v1" ]; then
      n_pass=$((n_pass + 1)); echo "  PASS  envelope.schema = 'sovereign-offense-harness/envelope/v1'"
    else
      n_fail=$((n_fail + 1)); FAILURES+=("envelope.schema='$schema' (expected sovereign-offense-harness/envelope/v1)")
      echo "  FAIL  envelope.schema='$schema'"
    fi
    if [ "$ttp_id" = "T1082" ];      then n_pass=$((n_pass + 1)); echo "  PASS  envelope.ttp.id = 'T1082'"; else
      n_fail=$((n_fail + 1)); FAILURES+=("envelope.ttp.id='$ttp_id'"); echo "  FAIL  envelope.ttp.id='$ttp_id'"; fi
    if [ -n "$has_exec" ];           then n_pass=$((n_pass + 1)); echo "  PASS  envelope.execution.exit_code present"; else
      n_fail=$((n_fail + 1)); FAILURES+=("envelope.execution.exit_code missing"); echo "  FAIL  envelope.execution.exit_code missing"; fi
    if [ -n "$has_host" ];           then n_pass=$((n_pass + 1)); echo "  PASS  envelope.host.hostname present"; else
      n_fail=$((n_fail + 1)); FAILURES+=("envelope.host.hostname missing"); echo "  FAIL  envelope.host.hostname missing"; fi
    if [ "$verdict" = "PASS" ];      then n_pass=$((n_pass + 1)); echo "  PASS  envelope.verdict = 'PASS'"; else
      n_fail=$((n_fail + 1)); FAILURES+=("envelope.verdict='$verdict' (expected PASS)"); echo "  FAIL  envelope.verdict='$verdict'"; fi
  else
    # jq missing — fall back to substring grep on the raw JSON.
    for key in '"schema": "sovereign-offense-harness/envelope/v1"' '"id": "T1082"' '"exit_code"' '"hostname"' '"verdict": "PASS"'; do
      if grep -qF -- "$key" "$ENV_FILE"; then
        n_pass=$((n_pass + 1)); echo "  PASS  envelope contains $key (jq-less)"
      else
        n_fail=$((n_fail + 1)); FAILURES+=("envelope missing $key"); echo "  FAIL  envelope missing $key"
      fi
    done
  fi
fi
rm -rf "$ENV_DIR"

# ─── Check 5: README's documented schema URI matches the binary output ────
# Already verified in Check 4 against the running binary; this check
# pins the README side so README-only edits also fail loudly.
assert_readme_contains "README documents envelope schema URI" \
  "sovereign-offense-harness/envelope/v1"

# ─── Check 6: README authorized-use notice is non-negotiable + present ────
# The threat model claims this notice is load-bearing; doctest treats it
# as such. If a contributor deletes the notice, this fails.
assert_readme_contains "README contains Authorized Use Only notice" \
  "Authorized Use Only"
assert_readme_contains "README references THREAT_MODEL.md"          \
  "THREAT_MODEL.md"

echo
echo "=== summary ==="
echo "  pass: $n_pass"
echo "  fail: $n_fail"
if [ "$n_fail" -gt 0 ]; then
  echo
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
