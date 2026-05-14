#!/usr/bin/env bash
# sovereign-offense-harness / tools / mutation-test.sh
#
# Stylized mutation-testing harness. Targets the safety-gate logic (the
# part that REFUSES to fire absent --target whitelist / --unsafe-local),
# the IPv4 + CIDR parser, parseTtp strict-type checks (added in this
# session's commit `856e575`), and the ART executor allowlist.
#
# A SURVIVOR on a safety-gate mutation = a real correctness gap in the
# refuse-by-default posture. That's the load-bearing security claim of
# this tool — any mutation that slips through is a finding.

set -euo pipefail
cd "$(dirname "$0")/.."

declare -a SRC_FILES=("src/main.zig" "src/art.zig")
declare -A BACKUPS=()
for f in "${SRC_FILES[@]}"; do
  BACKUPS["$f"]=$(mktemp)
  cp "$f" "${BACKUPS[$f]}"
done
trap 'for f in "${SRC_FILES[@]}"; do cp "${BACKUPS[$f]}" "$f"; rm -f "${BACKUPS[$f]}"; done' EXIT

declare -a MUTATIONS=(
  # ─── Safety gate ──────────────────────────────────────────────────────────
  "M01 (gate): both-paths-given check sense flip (accept ambiguity)|src/main.zig|s|if (ttp_path != null and art_path != null) {|if (ttp_path == null and art_path == null) {|"
  "M02 (gate): refuse-by-default sense flip (target null AND not unsafe = ALLOWED)|src/main.zig|s|if (target == null and !unsafe_local) {|if (target != null and !unsafe_local) {|"
  "M03 (gate): target+unsafe both-given check (allow conflicting flags)|src/main.zig|s|if (target != null and unsafe_local) {|if (target == null and unsafe_local) {|"

  # ─── CIDR / IPv4 parser ───────────────────────────────────────────────────
  "M04 (cidr): prefix-range bound > -> >= (off-by-one at /32)|src/main.zig|s|if (prefix > 32) continue|if (prefix >= 32) continue|"
  "M05 (cidr): IPv4 octet-count != -> == (accept wrong number of octets)|src/main.zig|s|if (idx != 4) return error.InvalidIpv4|if (idx == 4) return error.InvalidIpv4|"
  "M06 (cidr): IPv4 octet-overflow >= -> > (accept 4th octet then more)|src/main.zig|s|if (idx >= 4) return error.InvalidIpv4|if (idx > 4) return error.InvalidIpv4|"

  # ─── parseTtp strict-type checks (added 856e575) ─────────────────────────
  "M07 (ttp): id strict-type check sense flip (accept non-string id)|src/main.zig|s|if (id_val != .string) return error.TtpIdNotString|if (id_val == .string) return error.TtpIdNotString|"
  "M08 (ttp): exec strict-type check sense flip (accept non-string exec)|src/main.zig|s|if (exec_val != .string) return error.TtpExecNotString|if (exec_val == .string) return error.TtpExecNotString|"

  # ─── ART executor allowlist ───────────────────────────────────────────────
  "M09 (art): bash executor check sense flip (reject bash)|src/art.zig|s|std.mem.eql(u8, exec_name, \"bash\")|std.mem.eql(u8, exec_name, \"BASH\")|"
)

n_total=${#MUTATIONS[@]}
n_killed=0
n_survived=0
declare -a SURVIVORS=()

echo "=== sovereign-offense-harness mutation testing ==="
echo "operators: $n_total"

for mutation in "${MUTATIONS[@]}"; do
  desc="${mutation%%|*}"
  rest="${mutation#*|}"
  target_file="${rest%%|*}"
  sed_expr="${rest#*|}"

  for f in "${SRC_FILES[@]}"; do cp "${BACKUPS[$f]}" "$f"; done
  sed -i "$sed_expr" "$target_file"

  if cmp -s "${BACKUPS[$target_file]}" "$target_file"; then
    echo "  SKIPPED   $desc (sed no-op)"
    n_total=$((n_total - 1))
    continue
  fi

  if zig build test >/dev/null 2>&1; then
    n_survived=$((n_survived + 1))
    SURVIVORS+=("$desc")
    echo "  SURVIVED  $desc"
  else
    n_killed=$((n_killed + 1))
    echo "  KILLED    $desc"
  fi
done

for f in "${SRC_FILES[@]}"; do cp "${BACKUPS[$f]}" "$f"; done

echo
echo "=== summary ==="
echo "  total effective: $n_total"
echo "  killed:          $n_killed"
echo "  survived:        $n_survived"
if [ "$n_total" -gt 0 ]; then
  score=$(awk -v k="$n_killed" -v t="$n_total" 'BEGIN{printf "%.1f", k/t*100}')
  echo "  mutation score:  $score%"
fi
if [ "$n_survived" -gt 0 ]; then
  echo
  echo "Survivors:"
  for s in "${SURVIVORS[@]}"; do echo "  - $s"; done
  exit 1
fi
exit 0
