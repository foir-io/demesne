import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';

const [pkgDir, runDir, tablePath] = process.argv.slice(2);
if (!pkgDir || !runDir || !tablePath) {
  console.error('usage: node wasm.mjs <wasm-pkg-dir> <parity-run-dir> <cli-table.json>');
  process.exit(2);
}
const wasm = createRequire(import.meta.url)(join(pkgDir, 'demesne_wasm.js'));
const table = JSON.parse(readFileSync(tablePath, 'utf8'));
const specs = readFileSync(join(runDir, 'list.tsv'), 'utf8').trim().split('\n').map((l) => l.split('\t'));

let total = 0;
let sameGo = 0;
let sameRustOnly = 0;
const diffs = [];
for (const [id, path] of specs) {
  const src = readFileSync(path);
  for (const c of table) {
    const goFile = join(runDir, 'go', id, `cli-${c.name}.txt`);
    const rustFile = join(runDir, 'rust', id, `cli-${c.name}.txt`);
    if (!existsSync(goFile)) continue;
    const args = c.args.map((a) => (a === '{spec}' ? path : a));
    const r = wasm.run(args, [path], src, new Uint32Array([src.length]));
    const rec = Buffer.concat([
      Buffer.from(`exit: ${r.code}\n--- stdout ---\n`),
      Buffer.from(r.stdout),
      Buffer.from('\n--- stderr ---\n'),
      Buffer.from(r.stderr),
    ]);
    total++;
    if (rec.equals(readFileSync(goFile))) {
      sameGo++;
    } else if (existsSync(rustFile) && rec.equals(readFileSync(rustFile))) {
      sameRustOnly++;
    } else {
      diffs.push(`${id} ${c.name}`);
    }
  }
}
for (const d of diffs.slice(0, 20)) console.log(`DIFF ${d}`);
console.log(`wasm: specs ${specs.length}  outputs ${total}  identical-to-go ${sameGo}  identical-to-native-rust-only ${sameRustOnly}  differ ${diffs.length}`);
process.exit(diffs.length === 0 ? 0 : 1);
