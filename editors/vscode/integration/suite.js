const vscode = require("vscode");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");

const repo = join(__dirname, "../../..");

async function until(probe, what) {
  for (let i = 0; i < 100; i++) {
    const got = probe();
    if (got) return got;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${what}`);
}

exports.run = async () => {
  const bad = readFileSync(join(repo, "testdata/gaps/d37-wider-write.demesne"), "utf8");
  const doc = await vscode.workspace.openTextDocument({ language: "demesne", content: bad });
  await vscode.window.showTextDocument(doc);
  const found = await until(() => {
    const d = vscode.languages.getDiagnostics(doc.uri);
    return d.length > 0 && d;
  }, "diagnostics on the invalid spec");
  assert.deepEqual(
    found.map((d) => [d.range.start.line, d.severity, d.source]),
    [
      [23, vscode.DiagnosticSeverity.Error, "demesne"],
      [24, vscode.DiagnosticSeverity.Error, "demesne"],
    ],
  );

  const fixed = bad.replace("@rls maps delete", "@rls maps delete blind").replace("@rls maps update", "@rls maps update blind");
  const edit = new vscode.WorkspaceEdit();
  edit.replace(doc.uri, new vscode.Range(0, 0, doc.lineCount, 0), fixed);
  await vscode.workspace.applyEdit(edit);
  await until(
    () => vscode.languages.getDiagnostics(doc.uri).every((d) => d.severity === vscode.DiagnosticSeverity.Warning) && vscode.languages.getDiagnostics(doc.uri).length === 2,
    "the edit to turn the errors into warnings",
  );
  console.log(`demesne live validation: ${found.length} errors on lines ${found.map((d) => d.range.start.line + 1).join(", ")}, then ${vscode.languages.getDiagnostics(doc.uri).length} warnings after the edit`);

  const files = ["base.demesne", "extra.demesne", "last.demesne"].map((f) => join(repo, "testdata/multi", f));
  const extra = await vscode.workspace.openTextDocument(vscode.Uri.file(files[1]));
  await vscode.window.showTextDocument(extra);
  await until(() => vscode.languages.getDiagnostics(extra.uri).length === 1, "the second file, checked alone, refusing its replace");
  await vscode.workspace.getConfiguration("demesne").update("specs", [files], vscode.ConfigurationTarget.Global);
  await until(() => vscode.languages.getDiagnostics(extra.uri).length === 0, "the second file checked with the files of its spec");
  console.log("demesne spec in several files: the second file is clean once the setting names the files before it");
};
