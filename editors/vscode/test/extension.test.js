const { test, mock } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { activateWith } = require("../extension.js");

const gap = readFileSync(join(__dirname, "../../../testdata/gaps/d37-wider-write.demesne"), "utf8");

function fake(docs) {
  const sets = [];
  const deleted = [];
  const handlers = {};
  const on = (name) => (f) => {
    handlers[name] = f;
    return { dispose() {} };
  };
  class Diagnostic {
    constructor(range, message, severity) {
      Object.assign(this, { range, message, severity });
    }
  }
  const vscode = {
    DiagnosticSeverity: { Error: 0, Warning: 1 },
    Diagnostic,
    languages: {
      createDiagnosticCollection: () => ({
        set: (uri, diagnostics) => sets.push([uri.toString(), diagnostics]),
        delete: (uri) => deleted.push(uri.toString()),
        dispose() {},
      }),
    },
    workspace: { onDidOpenTextDocument: on("open"), onDidChangeTextDocument: on("change"), onDidCloseTextDocument: on("close"), textDocuments: docs },
  };
  return { vscode, sets, deleted, handlers };
}

function doc(uri, text, languageId = "demesne") {
  const lines = text.split("\n");
  return { uri: { toString: () => uri }, languageId, getText: () => text, lineCount: lines.length, lineAt: (n) => ({ range: { line: n } }) };
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
