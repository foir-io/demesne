import { cpSync, existsSync } from "node:fs";

const from = new URL("../src/wasm/", import.meta.url);
if (!existsSync(new URL("demesne_runtime_wasm_bg.wasm", from))) {
  throw new Error("src/wasm is missing: run `pnpm build:wasm` (scripts/build-runtime-wasm.sh) first");
}
cpSync(from, new URL("../dist/wasm/", import.meta.url), { recursive: true });
