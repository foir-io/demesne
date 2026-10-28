#!/usr/bin/env bash
set -euo pipefail

GO="$1"
RUST="$2"
ROOT="$(git rev-parse --show-toplevel)"
CASES="$ROOT/testdata/gaps/cases.tsv"

pass=0
fail=0
while IFS=$'\t' read -r gap spec args old new; do
  [[ -z "$gap" || "$gap" == \#* ]] && continue
  args="${args//\{gaps\}/$ROOT/testdata/gaps}"
  read -r -a argv <<< "${args//\{spec\}/$ROOT/testdata/gaps/$spec}"
  go_out="$("$GO" "${argv[@]}" 2>&1 || true)"
  rust_out="$("$RUST" "${argv[@]}" 2>&1 || true)"
  if grep -Eq -- "$old" <<< "$go_out" && ! grep -Eq -- "$new" <<< "$go_out" && grep -Eq -- "$new" <<< "$rust_out"; then
    printf 'ok    %-6s %s\n' "$gap" "$spec"
    pass=$((pass + 1))
  else
    printf 'FAIL  %-6s %s\n' "$gap" "$spec"
    printf '  v0.93.1: %s\n' "$(head -c 400 <<< "$go_out")"
    printf '  now:     %s\n' "$(head -c 400 <<< "$rust_out")"
    fail=$((fail + 1))
  fi
done < "$CASES"
echo "gaps: $pass reproduce on v0.93.1 and are fixed now, $fail do not"
[[ "$fail" -eq 0 ]]
