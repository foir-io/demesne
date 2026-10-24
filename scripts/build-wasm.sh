#!/usr/bin/env bash
set -euo pipefail

OUT="${1:?usage: scripts/build-wasm.sh <out-dir> [nodejs|web|bundler]}"
TARGET="${2:-nodejs}"
ROOT="$(git rev-parse --show-toplevel)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
WANT="$(grep -A2 'name = "wasm-bindgen"' "$ROOT/Cargo.lock" | sed -n 's/^version = "\(.*\)"/\1/p' | head -1)"
HAVE="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}')"
if [ "$WANT" != "$HAVE" ]; then
  echo "wasm-bindgen $WANT is required (found ${HAVE:-none}): cargo install wasm-bindgen-cli --version $WANT --locked" >&2
  exit 1
fi
(cd "$ROOT" && cargo build -p demesne-wasm --target wasm32-unknown-unknown --release)
wasm-bindgen --target "$TARGET" --out-dir "$OUT" "$TARGET_DIR/wasm32-unknown-unknown/release/demesne_wasm.wasm"
