import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import {
  cpSync,
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const distDir = path.resolve(repoRoot, process.env.DIST ?? "target/distrib");
const outDir = path.resolve(repoRoot, "npm", "dist");
const cliSrc = path.resolve(repoRoot, "npm", "cli");
const licenseSrc = path.resolve(repoRoot, "LICENSE");

const rawVersion = process.argv[2] ?? process.env.VERSION;
if (!rawVersion) {
  console.error("usage: node npm/scripts/build-npm.mjs <version>  (or set VERSION)");
  process.exit(2);
}
const version = rawVersion.replace(/^v/, "");

const TRIPLE_TO_NODE = {
  "aarch64-apple-darwin": "darwin-arm64",
  "x86_64-apple-darwin": "darwin-x64",
  "aarch64-unknown-linux-musl": "linux-arm64",
  "x86_64-unknown-linux-musl": "linux-x64",
  "x86_64-pc-windows-msvc": "win32-x64",
};

const PLATFORM_PACKAGES = {
  "darwin-arm64": "@foir/demesne-cli-darwin-arm64",
  "darwin-x64": "@foir/demesne-cli-darwin-x64",
  "linux-arm64": "@foir/demesne-cli-linux-arm64",
  "linux-x64": "@foir/demesne-cli-linux-x64",
  "win32-x64": "@foir/demesne-cli-win32-x64",
};

const manifestPath = path.join(distDir, "dist-manifest.json");
if (!existsSync(manifestPath)) {
  console.error(`no dist-manifest.json at ${manifestPath} — run dist build first`);
  process.exit(1);
}
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

function findFile(dir, name) {
  for (const entry of readdirSync(dir)) {
    const p = path.join(dir, entry);
    if (statSync(p).isDirectory()) {
      const found = findFile(p, name);
      if (found) return found;
    } else if (entry === name) {
      return p;
    }
  }
  return null;
}

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

const built = new Set();
for (const [name, artifact] of Object.entries(manifest.artifacts ?? {})) {
  if (artifact.kind !== "executable-zip") continue;
  const triple = (artifact.target_triples ?? [])[0];
  const key = TRIPLE_TO_NODE[triple];
  if (!key) continue;
  const archive = path.join(distDir, name);
  if (!existsSync(archive)) {
    console.error(`dist-manifest.json lists ${name} but it is not in ${distDir}`);
    process.exit(1);
  }
  const nodeOs = key.split("-")[0];
  const binName = nodeOs === "win32" ? "demesne.exe" : "demesne";
  const work = mkdtempSync(path.join(os.tmpdir(), "demesne-npm-"));
  if (name.endsWith(".zip")) {
    execFileSync("unzip", ["-q", archive, "-d", work]);
  } else {
    execFileSync("tar", ["-xzf", archive, "-C", work]);
  }
  const bin = findFile(work, binName);
  if (!bin) {
    console.error(`${name} has no ${binName}`);
    process.exit(1);
  }
  const pkgDir = path.join(outDir, `cli-${key}`);
  mkdirSync(path.join(pkgDir, "bin"), { recursive: true });
  const dest = path.join(pkgDir, "bin", binName);
  cpSync(bin, dest);
  if (nodeOs !== "win32") chmodSync(dest, 0o755);
  rmSync(work, { recursive: true, force: true });
  cpSync(licenseSrc, path.join(pkgDir, "LICENSE"));
  writeFileSync(
    path.join(pkgDir, "package.json"),
    JSON.stringify(
      {
        name: PLATFORM_PACKAGES[key],
        version,
        description: `Demesne CLI binary for ${key}.`,
        license: "Apache-2.0",
        repository: { type: "git", url: "git+https://github.com/foir-io/demesne.git" },
        homepage: "https://github.com/foir-io/demesne#readme",
        os: [nodeOs],
        cpu: [key.split("-")[1]],
        files: ["bin"],
      },
      null,
      2
    ) + "\n"
  );
  built.add(key);
  console.log(`staged ${PLATFORM_PACKAGES[key]}@${version} (${name})`);
}

const expected = Object.keys(PLATFORM_PACKAGES);
const missing = expected.filter((k) => !built.has(k));
if (missing.length) {
  if (process.env.DEMESNE_NPM_ALLOW_PARTIAL !== "1") {
    console.error(`missing binaries for: ${missing.join(", ")} — aborting incomplete release`);
    process.exit(1);
  }
  console.error(`DEMESNE_NPM_ALLOW_PARTIAL=1: staging without ${missing.join(", ")} (local testing only)`);
}

const mainPkg = JSON.parse(readFileSync(path.join(cliSrc, "package.json"), "utf8"));
mainPkg.version = version;
for (const dep of Object.keys(mainPkg.optionalDependencies)) {
  mainPkg.optionalDependencies[dep] = version;
}
const mainDir = path.join(outDir, "cli");
cpSync(cliSrc, mainDir, { recursive: true });
cpSync(licenseSrc, path.join(mainDir, "LICENSE"));
writeFileSync(path.join(mainDir, "package.json"), JSON.stringify(mainPkg, null, 2) + "\n");
console.log(`staged @foir/demesne-cli@${version} (+${built.size} platform packages)`);
