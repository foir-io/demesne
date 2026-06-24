#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");

const PLATFORM_PACKAGES = {
  "darwin-arm64": "@foir/demesne-cli-darwin-arm64",
  "darwin-x64": "@foir/demesne-cli-darwin-x64",
  "linux-arm64": "@foir/demesne-cli-linux-arm64",
  "linux-x64": "@foir/demesne-cli-linux-x64",
  "win32-x64": "@foir/demesne-cli-win32-x64",
};

function fail(message) {
  process.stderr.write(`demesne: ${message}\n`);
  process.exit(1);
}

function resolveBinary() {
  const key = `${process.platform}-${process.arch}`;
  const pkg = PLATFORM_PACKAGES[key];
  if (!pkg) {
    fail(
      `no prebuilt binary for ${key}. Build from source: clone ` +
        "github.com/eidestudio/demesne and run 'go build ./cmd/demesne'"
    );
  }
  const binName = process.platform === "win32" ? "demesne.exe" : "demesne";
  let manifest;
  try {
    manifest = require.resolve(`${pkg}/package.json`);
  } catch {
    fail(
      `the platform package ${pkg} is not installed. ` +
        "Reinstall @foir/demesne-cli without --no-optional / --omit=optional."
    );
  }
  return path.join(path.dirname(manifest), "bin", binName);
}

const result = spawnSync(resolveBinary(), process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  fail(result.error.message);
}
process.exit(result.status === null ? 1 : result.status);
