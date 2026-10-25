import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { chromium } from "playwright";

const pkgDir = fileURLToPath(new URL("..", import.meta.url));
const work = mkdtempSync(join(tmpdir(), "demesne-packed-"));

const PROBE = `import { composeCan, Decision, mintClaimsValuesWithExtra, resolve, levelGrants } from "@foir/demesne";
const vocab = { name: "v", permissions: ["a:read"], presets: [{ name: "viewer", star: false, set: ["a:read"] }], rank: ["viewer"] };
const resolver = { assignments: "ra", kindCol: "", kindVal: "", subjectCol: "s", scopeCols: ["t"], revokedCol: "", roleCol: "r", rolesTable: "roles", rolesId: "id", keyCol: "key", permsCol: "", vocab };
const held = resolve(resolver, [{ scope: ["t1"], roleKey: "viewer", permissions: [] }], ["t1"]);
const surface = { name: "g", level: "tenant", table: "grants", granteeCol: "grantee", levelCol: "tenant_id", activeCol: "", expiresCol: "expires_at", pk: "id", grantedByCol: "granted_by", revokedByCol: "", createdAtCol: "", extraCols: [] };
const when = new Date(0);
const stmt = levelGrants.grantInsert(surface, "g1", "u1", "t1", "admin", when);
export const result = [composeCan(true, true, Decision.NotGoverned), mintClaimsValuesWithExtra(["a"], { a: "<x>" }), held.permissions().join(","), stmt.args[4] === when].join(" ");
`;
const WANT = 'allow {"a":"\\u003cx\\u003e"} a:read true';

function node() {
  return execFileSync("node", ["--input-type=module", "-e", 'import { result } from "./probe.mjs"; process.stdout.write(result);'], { cwd: work }).toString();
}

async function workerd() {
  writeFileSync(join(work, "worker.mjs"), 'import { result } from "./probe.mjs";\nexport default { fetch: () => new Response(result) };\n');
  writeFileSync(join(work, "wrangler.toml"), 'name = "demesne-packed"\nmain = "worker.mjs"\ncompatibility_date = "2026-01-01"\n');
  execFileSync(join(pkgDir, "node_modules/.bin/wrangler"), ["deploy", "--dry-run", "--outdir", "out"], { cwd: work, stdio: "ignore" });
  const out = join(work, "out");
  const mf = new Miniflare({
    modules: true,
    modulesRoot: out,
    modulesRules: [{ type: "CompiledWasm", include: ["**/*.wasm"] }],
    scriptPath: join(out, "worker.js"),
    compatibilityDate: "2026-01-01",
  });
  try {
    return await (await mf.dispatchFetch("http://probe/")).text();
  } finally {
    await mf.dispose();
  }
}

async function browser() {
  const bundled = await build({ stdin: { contents: 'import { result } from "./probe.mjs";\nglobalThis.__demesne = result;\n', resolveDir: work }, bundle: true, write: false, format: "iife", platform: "browser", minify: true });
  const chrome = await chromium.launch({ channel: "chrome", headless: true });
  try {
    const page = await chrome.newPage();
    await page.evaluate(bundled.outputFiles[0].text);
    return await page.evaluate(() => globalThis.__demesne);
  } finally {
    await chrome.close();
  }
}

try {
  execFileSync("npm", ["pack", "--pack-destination", work], { cwd: pkgDir, stdio: "ignore" });
  const tarball = join(work, readdirSync(work).find((f) => f.endsWith(".tgz")));
  writeFileSync(join(work, "package.json"), JSON.stringify({ name: "consumer", private: true, type: "module" }));
  execFileSync("npm", ["install", "--no-audit", "--no-fund", tarball], { cwd: work, stdio: "ignore" });
  writeFileSync(join(work, "probe.mjs"), PROBE);
  let failed = 0;
  for (const [name, run] of [["node", node], ["workerd", workerd], ["browser", browser]]) {
    let got;
    try {
      got = await run();
    } catch (e) {
      got = `threw ${e instanceof Error ? e.message.split("\n")[0] : String(e)}`;
    }
    const ok = got === WANT;
    failed += ok ? 0 : 1;
    console.log(`${ok ? "ok  " : "FAIL"} ${name}: ${got}`);
  }
  console.log(`packed @foir/demesne (${readFileSync(tarball).length} bytes): ${3 - failed} of 3 environments`);
  process.exitCode = failed === 0 ? 0 : 1;
} finally {
  rmSync(work, { recursive: true, force: true });
}
