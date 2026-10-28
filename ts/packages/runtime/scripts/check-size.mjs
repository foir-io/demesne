import { readdirSync, readFileSync, statSync } from "node:fs";
import { gzipSync } from "node:zlib";

const WASM_BUDGET = 200_000;
const ENTRY_GZIP_BUDGET = 105_000;

const dist = new URL("../dist/", import.meta.url);
const wasm = statSync(new URL("wasm/demesne_runtime_wasm_bg.wasm", dist)).size;
const js = [
  ...readdirSync(dist).filter((f) => f.endsWith(".js") && !f.includes("workerd")).map((f) => new URL(f, dist)),
  ...readdirSync(new URL("wasm/", dist)).filter((f) => f.endsWith(".js")).map((f) => new URL(`wasm/${f}`, dist)),
];
const entry = gzipSync(Buffer.concat(js.map((f) => readFileSync(f))), { level: 9 }).length;

console.log(`wasm ${wasm} bytes (budget ${WASM_BUDGET}); default entry ${entry} bytes gzipped (budget ${ENTRY_GZIP_BUDGET})`);
if (wasm > WASM_BUDGET || entry > ENTRY_GZIP_BUDGET) {
  console.error("over the size budget");
  process.exit(1);
}
