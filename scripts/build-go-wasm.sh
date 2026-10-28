#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
(cd "$ROOT" && cargo build -p demesne-runtime-abi --target wasm32-unknown-unknown --profile wasm)
cp "$TARGET_DIR/wasm32-unknown-unknown/wasm/demesne_runtime_abi.wasm" "$ROOT/go/runtime.wasm"
