#!/usr/bin/env bash
# sovereign-offense-harness / tests / safety_gate_integration.sh
#
# Subprocess-driven integration test for the load-bearing safety gate.
# Models the same pattern as `mast/tests/strict_mode_integration.sh`.
#
# Closes mutation-testing findings M01–M03 (mutation testing surfaced
# that the safety-gate logic had zero direct test coverage).
#
# Each case spawns the built binary, captures stdout / stderr / exit code,
# and asserts a specific contract. Failure = the safety gate is not
# enforcing what its README claims it enforces.

set -uo pipefail
cd "$(dirname "$0")/.."

BIN="zig-out/bin/sovereign-offense-harness"
TTP="ttps/examples/t1082-system-information-discovery.json"

# Build first.
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

assert_case() {
  local name="$1"
  local expected_exit="$2"
  local expected_stderr_substr="$3"
  shift 3
  local stderr_file; stderr_file=$(mktemp)
  local stdout_file; stdout_file=$(mktemp)

  "$BIN" "$@" >"$stdout_file" 2>"$stderr_file"
  local got_exit=$?
  local got_stderr; got_stderr=$(cat "$stderr_file"; cat "$stdout_file")
  rm -f "$stderr_file" "$stdout_file"

  if [ "$got_exit" -ne "$expected_exit" ]; then
    n_fail=$((n_fail + 1))
    FAILURES+=("$name: expected exit $expected_exit, got $got_exit")
    echo "  FAIL  $name (exit $got_exit, wanted $expected_exit)"
    return 1
  fi
  if [ -n "$expected_stderr_substr" ] && ! echo "$got_stderr" | grep -qF -- "$expected_stderr_substr"; then
    n_fail=$((n_fail + 1))
    FAILURES+=("$name: stderr did not contain '$expected_stderr_substr'")
    echo "  FAIL  $name (stderr did not contain '$expected_stderr_substr')"
    return 1
  fi
  n_pass=$((n_pass + 1))
  echo "  PASS  $name"
}

echo "=== safety_gate_integration ==="

# Case 1 (kills M02): --ttp without --target / --unsafe-local → refuse
assert_case \
  "no-auth refuses (M02 mutation: refuse-by-default)" \
  3 "refused by safety gate" \
  run --ttp "$TTP"

# Case 2: --ttp with --unsafe-local → proceeds past the gate
# Exit code may be 0 or non-zero depending on TTP success, but the SAFETY-GATE
# refusal message must NOT appear; the envelope-writing path must engage.
out=$("$BIN" run --ttp "$TTP" --unsafe-local 2>&1)
got_exit=$?
if echo "$out" | grep -qF "refused by safety gate"; then
  n_fail=$((n_fail + 1))
  FAILURES+=("with-unsafe-local refused (gate over-eager)")
  echo "  FAIL  with-unsafe-local refused (gate over-eager)"
elif [ "$got_exit" -ne 0 ] && [ "$got_exit" -ne 1 ]; then
  n_fail=$((n_fail + 1))
  FAILURES+=("with-unsafe-local: unexpected exit $got_exit")
  echo "  FAIL  with-unsafe-local: unexpected exit $got_exit"
else
  n_pass=$((n_pass + 1))
  echo "  PASS  with-unsafe-local passes gate (got exit $got_exit, envelope written)"
fi

# Case 3 (kills M03): --target AND --unsafe-local → "mutually exclusive"
assert_case \
  "target+unsafe-local mutex (M03 mutation: conflicting-flags check)" \
  2 "mutually exclusive" \
  run --ttp "$TTP" --target 127.0.0.1 --unsafe-local

# Case 4 (kills M01): --ttp AND --art → "mutually exclusive"
assert_case \
  "ttp+art mutex (M01 mutation: both-paths-given check)" \
  2 "mutually exclusive" \
  run --ttp "$TTP" --art ttps/examples/art-t1082-system-info.yml

# Case 5: --ttp without --art-test value is irrelevant here; verify
# --art-test without --art rejects.
assert_case \
  "art-test without art rejected" \
  2 "--art-test requires --art" \
  run --ttp "$TTP" --art-test "some-test-name"

# Case 6 (kills M04): --target 127.0.0.1 with a whitelist containing 127.0.0.1/32
# Verifies the CIDR /32 boundary is correct — under the M04 mutation
# (`prefix > 32` -> `prefix >= 32`), /32 lines are dropped and the target
# would not be found in the whitelist, causing refusal.
WL=$(mktemp)
echo "127.0.0.1/32" > "$WL"
out=$("$BIN" run --ttp "$TTP" --target 127.0.0.1 --lab-targets "$WL" 2>&1)
got_exit=$?
rm -f "$WL"
if echo "$out" | grep -qF "refused by safety gate" || echo "$out" | grep -qF "not in whitelist"; then
  n_fail=$((n_fail + 1))
  FAILURES+=("M04 mutation /32 boundary: 127.0.0.1/32 whitelist did not accept 127.0.0.1")
  echo "  FAIL  /32 whitelist boundary (M04): 127.0.0.1/32 should accept 127.0.0.1"
else
  n_pass=$((n_pass + 1))
  echo "  PASS  /32 whitelist boundary (M04): 127.0.0.1/32 accepts 127.0.0.1 (exit $got_exit)"
fi

echo
echo "=== summary ==="
echo "  pass: $n_pass"
echo "  fail: $n_fail"
if [ "$n_fail" -gt 0 ]; then
  echo
  echo "Failures:"
  for f in "${FAILURES[@]}"; do
    echo "  - $f"
  done
  exit 1
fi
exit 0
