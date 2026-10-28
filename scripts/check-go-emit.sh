#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cli="${1:-$root/target/debug/demesne}"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

printf 'module example.test/emitted\n\ngo 1.25.0\n\nrequire github.com/foir-io/demesne/go v0.0.0\n\nreplace github.com/foir-io/demesne/go => %s/go\n' "$root" > "$out/go.mod"
cp "$root/go/go.sum" "$out/go.sum"

specs=0
emitted=0
while IFS= read -r spec; do
  specs=$((specs + 1))
  for kind in framework projections claims pdp; do
    dir="$out/s$specs/$kind"
    mkdir -p "$dir"
    if "$cli" emit "$spec" --target go "$kind" "$kind" > "$dir/emitted.go" 2>/dev/null; then
      emitted=$((emitted + 1))
    elif "$cli" emit "$spec" --target ts "$kind" > /dev/null 2>&1; then
      echo "$spec: --target go $kind is refused, but --target ts $kind emits" >&2
      exit 1
    else
      rm -r "$dir"
    fi
  done
done < <(find "$root/testdata/corpus" "$root/examples" "$root/testdata/go" -name '*.demesne' | sort)

cd "$out"
go mod tidy
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
  echo "emitted Go that gofmt would change:" >&2
  echo "$unformatted" >&2
  exit 1
fi
go vet ./...
echo "$emitted Go files emitted from $specs specs are gofmt-clean and pass go vet"
