const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { findings } = require("../lint.js");

const repo = join(__dirname, "../../..");
const gap = readFileSync(join(repo, "testdata/gaps/d37-wider-write.demesne"), "utf8");

test("a valid spec has no findings", () => {
  assert.deepEqual(findings(readFileSync(join(repo, "examples/example.demesne"), "utf8")), []);
});

test("each validation error carries the line it names", () => {
  const got = findings(gap);
  assert.deepEqual(
    got.map((f) => [f.severity, f.line]),
    [
      ["error", 24],
      ["error", 25],
    ],
  );
  assert.match(got[0].message, /^permission note\.remove maps delete, and its term `grantee:write` admits callers/);
});

test("a blind write is a warning, not an error", () => {
  const blind = gap.replace("@rls maps delete", "@rls maps delete blind").replace("@rls maps update", "@rls maps update blind");
  assert.deepEqual(
    findings(blind).map((f) => [f.severity, f.line]),
    [
      ["warning", 24],
      ["warning", 25],
    ],
  );
});

test("a parse error is an error on its line", () => {
  assert.deepEqual(findings("topology {"), [{ severity: "error", line: 1, message: 'expected }, got EOF ""' }]);
});
