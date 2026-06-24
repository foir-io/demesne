import { fileURLToPath } from "node:url";
import {
  cpSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const distDir = path.resolve(repoRoot, process.env.DIST ?? "dist");
const outDir = path.resolve(repoRoot, "npm", "dist");
const cliSrc = path.resolve(repoRoot, "npm", "cli");
const licenseSrc = path.resolve(repoRoot, "LICENSE");

const rawVersion = process.argv[2] ?? process.env.VERSION;
if (!rawVersion) {
  console.error("usage: node npm/scripts/build-npm.mjs <version>  (or set VERSION)");
  process.exit(2);
}
const version = rawVersion.replace(/^v/, "");

const GOOS_TO_NODE = { darwin: "darwin", linux: "linux", windows: "win32" };
const GOARCH_TO_NODE = { amd64: "x64", arm64: "arm64" };

const PLATFORM_PACKAGES = {
  "darwin-arm64": "@foir/demesne-cli-darwin-arm64",
  "darwin-x64": "@foir/demesne-cli-darwin-x64",
  "linux-arm64": "@foir/demesne-cli-linux-arm64",
  "linux-x64": "@foir/demesne-cli-linux-x64",
  "win32-x64": "@foir/demesne-cli-win32-x64",
};

const artifactsPath = path.join(distDir, "artifacts.json");
if (!existsSync(artifactsPath)) {
  console.error(`no artifacts.json at ${artifactsPath} — run goreleaser first`);
  process.exit(1);
}
const artifacts = JSON.parse(readFileSync(artifactsPath, "utf8"));
const binaries = artifacts.filter((a) => a.type === "Binary");

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

const built = new Set();
for (const bin of binaries) {
  const nodeOs = GOOS_TO_NODE[bin.goos];
  const nodeArch = GOARCH_TO_NODE[bin.goarch];
  if (!nodeOs || !nodeArch) continue;
  const key = `${nodeOs}-${nodeArch}`;
  const pkgName = PLATFORM_PACKAGES[key];
  if (!pkgName) continue;

  const pkgDir = path.join(outDir, `cli-${key}`);
  const binName = nodeOs === "win32" ? "demesne.exe" : "demesne";
  mkdirSync(path.join(pkgDir, "bin"), { recursive: true });
  const dest = path.join(pkgDir, "bin", binName);
  cpSync(path.resolve(repoRoot, bin.path), dest);
  if (nodeOs !== "win32") chmodSync(dest, 0o755);
  cpSync(licenseSrc, path.join(pkgDir, "LICENSE"));

  writeFileSync(
    path.join(pkgDir, "package.json"),
    JSON.stringify(
      {
        name: pkgName,
        version,
        description: `Demesne CLI binary for ${key}.`,
        license: "Apache-2.0",
        repository: { type: "git", url: "git+https://github.com/foir-io/demesne.git" },
        homepage: "https://github.com/foir-io/demesne#readme",
        os: [nodeOs],
        cpu: [nodeArch],
        files: ["bin"],
      },
      null,
      2
    ) + "\n"
  );
  built.add(key);
  console.log(`staged ${pkgName}@${version} (${bin.path})`);
}

const expected = Object.keys(PLATFORM_PACKAGES);
const missing = expected.filter((k) => !built.has(k));
if (missing.length) {
  console.error(`missing binaries for: ${missing.join(", ")} — aborting incomplete release`);
  process.exit(1);
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
console.log(`staged @foir/demesne-cli@${version} (+${expected.length} platform packages)`);
