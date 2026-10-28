const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { findings, findingsInFiles } = require("../lint.js");

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

const nestedSpec = (expr) =>
  `topology {\n  level tenant\n  level workspace parent tenant\n}\nsubject member { anchor workspace; reach self; identifies sub; roles none }\nobject doc {\n  table docs\n  scoped tenant > workspace\n  relation owner: member via owner_id\n  permission view = ${expr} @rls maps select\n}\n`;
const parens = (depth) => "(".repeat(depth) + "owner" + ")".repeat(depth);

test("a spec nested to the limit validates", () => {
  let deepest = "owner";
  for (let i = 0; i < 32; i++) deepest = i % 2 ? `(owner and (${deepest} + @kind("k${i}")))` : `(@kind("k${i}") + (${deepest} and owner))`;
  assert.deepEqual(findings(nestedSpec(deepest)), []);
});

test("a spec nested past the limit is an error on its line, and the compiler keeps answering", () => {
  const refused = [{ severity: "error", line: 10, message: "parentheses nest more than 64 deep" }];
  assert.deepEqual(findings(nestedSpec(parens(65))), refused);
  assert.deepEqual(findings(nestedSpec(parens(100000))), refused);
  assert.deepEqual(findings(nestedSpec(parens(1))), []);
});

test("the files of a spec are checked as one, and a finding names its file", () => {
  const files = ["base.demesne", "extra.demesne"].map((f) => join(repo, "testdata/multi", f));
  assert.deepEqual(findingsInFiles(files, files.map((f) => readFileSync(f, "utf8"))), []);
  const got = findingsInFiles([files[1]], [readFileSync(files[1], "utf8")]);
  assert.deepEqual(
    got.map((f) => [f.severity, f.file, f.line]),
    [["error", files[1], 11]],
  );
});
