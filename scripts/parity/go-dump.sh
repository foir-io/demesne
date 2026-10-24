#!/usr/bin/env bash
set -euo pipefail

TAG="$1"
LIST="$2"
OUT="$3"
ROOT="$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/demesne-godump.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

git -C "$ROOT" archive "$TAG" | tar -x -C "$WORK"
cp "$ROOT/testdata/parity/go/zz_parity_dump_test.go" "$WORK/"
mkdir -p "$OUT"
(cd "$WORK" && GOWORK="$WORK/go.work" DEMESNE_PARITY_LIST="$LIST" DEMESNE_PARITY_OUT="$OUT" \
  go test -count=1 -run '^TestZZParityDump$' . >"$WORK/dump.log" 2>&1) || { cat "$WORK/dump.log" >&2; exit 1; }
grep -q '^ok' "$WORK/dump.log" || { cat "$WORK/dump.log" >&2; exit 1; }
