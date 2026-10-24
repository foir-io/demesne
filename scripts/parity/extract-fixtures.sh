#!/usr/bin/env bash
set -euo pipefail

TAG="${1:-v0.93.1}"
ROOT="$(git rev-parse --show-toplevel)"
OUT="${2:-$ROOT/testdata/corpus/fixtures}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/demesne-extract.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

git -C "$ROOT" archive "$TAG" | tar -x -C "$WORK"
CAP="$WORK/.capture"
mkdir -p "$CAP"

cat >"$WORK/zz_parity_capture.go" <<'EOF'
package demesne

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func parityCapture(src string) {
	dir := os.Getenv("DEMESNE_PARITY_CAPTURE")
	if dir == "" {
		return
	}
	sum := sha256.Sum256([]byte(src))
	h := hex.EncodeToString(sum[:])[:16]
	_ = os.WriteFile(filepath.Join(dir, h+".demesne"), []byte(src), 0o644)
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	test := "?"
	for {
		f, more := frames.Next()
		name := f.Function[strings.LastIndex(f.Function, "/")+1:]
		for _, part := range strings.Split(name, ".") {
			if strings.HasPrefix(part, "Test") || strings.HasPrefix(part, "Example") {
				test = strings.TrimPrefix(f.Function, "github.com/foir-io/")
			}
		}
		if !more {
			break
		}
	}
	idx, err := os.OpenFile(filepath.Join(dir, "index.tsv"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		_, _ = idx.WriteString(h + "\t" + test + "\n")
		_ = idx.Close()
	}
}
EOF

perl -0pi -e 's/func Parse\(src string\) \(\*Spec, error\) \{\n/func Parse(src string) (*Spec, error) {\n\tparityCapture(src)\n/' "$WORK/parser.go"
grep -q 'parityCapture(src)' "$WORK/parser.go" || { echo "extract: Parse hook did not apply" >&2; exit 1; }

export DEMESNE_PARITY_CAPTURE="$CAP"
export GOWORK="$WORK/go.work"
status=0
(cd "$WORK" && go test -count=1 ./... >"$WORK/engine.log" 2>&1) || status=1
(cd "$WORK/cmd/demesne" && go test -count=1 ./... >"$WORK/cmd.log" 2>&1) || status=1
(cd "$WORK/pgx" && go test -count=1 ./... >"$WORK/pgx.log" 2>&1) || status=1
if [ "$status" -ne 0 ]; then
  echo "extract: a Go suite failed under capture; see below" >&2
  tail -30 "$WORK"/*.log >&2
  exit 1
fi

mkdir -p "$OUT"
rm -f "$OUT"/*.demesne "$OUT/index.tsv"
cp "$CAP"/*.demesne "$OUT/"
sort -u "$CAP/index.tsv" | sort -k1,1 -k2,2 >"$OUT/index.tsv"
printf '%s\n' "$TAG" >"$OUT/TAG"
echo "extract: $(ls "$OUT"/*.demesne | wc -l | tr -d ' ') unique specs from $(cut -f2 "$OUT/index.tsv" | sort -u | wc -l | tr -d ' ') tests at $TAG"
