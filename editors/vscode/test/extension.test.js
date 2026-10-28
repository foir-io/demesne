const { test, mock } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { activateWith } = require("../extension.js");

const gap = readFileSync(join(__dirname, "../../../testdata/gaps/d37-wider-write.demesne"), "utf8");

function fake(docs, specs = []) {
  const sets = [];
  const deleted = [];
  const handlers = {};
  const config = { specs };
  let cleared = 0;
  const on = (name) => (f) => {
    handlers[name] = f;
    return { dispose() {} };
  };
  class Diagnostic {
    constructor(range, message, severity) {
      Object.assign(this, { range, message, severity });
    }
  }
  class Range {
    constructor(line) {
      this.line = line;
    }
  }
  const uri = (p) => ({ toString: () => `file://${p}`, fsPath: p });
  const vscode = {
    DiagnosticSeverity: { Error: 0, Warning: 1 },
    Diagnostic,
    Range,
    Uri: { file: uri },
    languages: {
      createDiagnosticCollection: () => ({
        set: (u, diagnostics) => sets.push([u.toString(), diagnostics]),
        delete: (u) => deleted.push(u.toString()),
        clear: () => cleared++,
        dispose() {},
      }),
    },
    workspace: {
      onDidOpenTextDocument: on("open"),
      onDidChangeTextDocument: on("change"),
      onDidCloseTextDocument: on("close"),
      onDidChangeConfiguration: on("config"),
      getConfiguration: (section) => ({ get: (key) => (section === "demesne" ? config[key] : undefined) }),
      workspaceFolders: [{ uri: uri("/") }],
      textDocuments: docs,
    },
  };
  return { vscode, sets, deleted, handlers, config, cleared: () => cleared };
}

function doc(uri, text, languageId = "demesne") {
  const lines = text.split("\n");
  return { uri: { toString: () => uri, fsPath: uri.replace("file://", "") }, languageId, getText: () => text, lineCount: lines.length, lineAt: (n) => ({ range: { line: n } }) };
}

test("open documents are checked on activation, one diagnostic per finding on its line", () => {
  const f = fake([doc("file:///a.demesne", gap), doc("file:///b.txt", gap, "plaintext")]);
  activateWith(f.vscode, { subscriptions: [] });
  assert.equal(f.sets.length, 1, "only the demesne document is checked");
  const [uri, diagnostics] = f.sets[0];
  assert.equal(uri, "file:///a.demesne");
  assert.deepEqual(
    diagnostics.map((d) => [d.range.line, d.severity, d.source]),
    [
      [23, 0, "demesne"],
      [24, 0, "demesne"],
    ],
  );
});

test("an edit is checked once its typing pauses, and a closed document loses its diagnostics", () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const f = fake([]);
    activateWith(f.vscode, { subscriptions: [] });
    const d = doc("file:///c.demesne", "topology {");
    f.handlers.change({ document: d });
    f.handlers.change({ document: d });
    mock.timers.tick(199);
    assert.equal(f.sets.length, 0, "nothing runs while typing continues");
    mock.timers.tick(1);
    assert.equal(f.sets.length, 1, "two quick edits run one check");
    assert.deepEqual(
      f.sets[0][1].map((x) => [x.range.line, x.message]),
      [[0, 'expected }, got EOF ""']],
    );
    f.handlers.close(d);
    assert.deepEqual(f.deleted, ["file:///c.demesne"]);
  } finally {
    mock.timers.reset();
  }
});

test("a finding without a line sits on the first, and one past the end sits on the last", () => {
  const src = readFileSync(join(__dirname, "../../../testdata/gaps/quirk-accessors-schema.demesne"), "utf8");
  const f = fake([doc("file:///d.demesne", src)]);
  activateWith(f.vscode, { subscriptions: [] });
  const lines = f.sets[0][1].map((d) => d.range.line);
  assert.ok(lines.includes(0), `an unplaced finding sits on line 0: ${lines}`);
  const short = doc("file:///e.demesne", gap.split("\n").slice(0, 3).join("\n"));
  short.getText = () => gap;
  const g = fake([short]);
  activateWith(g.vscode, { subscriptions: [] });
  assert.deepEqual(
    g.sets[0][1].map((d) => d.range.line),
    [2, 2],
  );
});

test("a warning stays a warning", () => {
  const blind = gap.replace("@rls maps delete", "@rls maps delete blind").replace("@rls maps update", "@rls maps update blind");
  const f = fake([doc("file:///f.demesne", blind)]);
  activateWith(f.vscode, { subscriptions: [] });
  assert.deepEqual(
    f.sets[0][1].map((d) => [d.range.line, d.severity]),
    [
      [23, 1],
      [24, 1],
    ],
  );
});

const multi = join(__dirname, "../../../testdata/multi");
const spec = ["base.demesne", "extra.demesne", "last.demesne"].map((f) => join(multi, f));
const read = (p) => readFileSync(p, "utf8");

test("a file in a configured spec is checked with the files before it, and each file gets its own diagnostics", () => {
  const extra = doc(`file://${spec[1]}`, read(spec[1]));
  const alone = fake([extra]);
  activateWith(alone.vscode, { subscriptions: [] });
  assert.deepEqual(
    alone.sets[0][1].map((d) => [d.range.line, d.message]),
    [[10, "`replace` swaps in a declaration for one an earlier file made, and a spec in one file has no earlier file"]],
  );
  const f = fake([extra], [spec]);
  activateWith(f.vscode, { subscriptions: [] }, read);
  assert.deepEqual(
    f.sets.map(([u, d]) => [u, d.length]),
    spec.map((p) => [`file://${p}`, 0]),
  );
});

test("a finding shows in the file it names, from the editor's text of an open file", () => {
  const stray = "\nobject stray {\n  table strays\n  scoped tenant > workspace\n  relation owner: member via owner_id\n  permission view = nobody @rls maps select\n}\n";
  const bad = join(multi, "stray.demesne");
  const f = fake([doc(`file://${bad}`, stray)], [[spec[0], bad]]);
  activateWith(f.vscode, { subscriptions: [] }, read);
  const byFile = Object.fromEntries(f.sets.map(([u, d]) => [u, d.map((x) => [x.range.line, x.message.split(" (")[0]])]));
  assert.deepEqual(byFile[`file://${spec[0]}`], []);
  assert.deepEqual(byFile[`file://${bad}`], [
    [5, 'permission stray.view references unknown relation "nobody"'],
    [0, "uncompilable @rls permission"],
  ]);
});

test("a spec file that can't be read is reported on the document being checked", () => {
  const missing = join(multi, "missing.demesne");
  const f = fake([doc(`file://${spec[0]}`, read(spec[0]))], [[spec[0], missing]]);
  activateWith(f.vscode, { subscriptions: [] }, read);
  assert.equal(f.sets.length, 1);
  assert.deepEqual(
    f.sets[0][1].map((d) => [d.range.line, d.severity]),
    [[0, 0]],
  );
  assert.match(f.sets[0][1][0].message, /^the spec's files can't all be read: ENOENT/);
});

test("changing the configured specs checks the open documents again", () => {
  const extra = doc(`file://${spec[1]}`, read(spec[1]));
  const f = fake([extra]);
  activateWith(f.vscode, { subscriptions: [] }, read);
  assert.equal(f.sets.at(-1)[1].length, 1);
  f.config.specs = [spec];
  f.handlers.config({ affectsConfiguration: (k) => k === "demesne.other" });
  assert.equal(f.cleared(), 0, "another setting changes nothing");
  f.handlers.config({ affectsConfiguration: (k) => k === "demesne.specs" });
  assert.equal(f.cleared(), 1);
  assert.deepEqual(
    f.sets.slice(-3).map(([u, d]) => [u, d.length]),
    spec.map((p) => [`file://${p}`, 0]),
  );
});
