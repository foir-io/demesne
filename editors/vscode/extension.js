const fs = require("node:fs");
const path = require("node:path");
const { findings, findingsInFiles } = require("./lint.js");

const DELAY_MS = 200;

function activateWith(vscode, context, readFile = (p) => fs.readFileSync(p, "utf8")) {
  const collection = vscode.languages.createDiagnosticCollection("demesne");
  const timers = new Map();

  const diagnostics = (found, text, doc) => {
    const lines = text.split("\n");
    return found.map((f) => {
      const line = f.line === null ? 0 : Math.min(Math.max(f.line - 1, 0), lines.length - 1);
      const range = doc ? doc.lineAt(Math.min(line, doc.lineCount - 1)).range : new vscode.Range(line, 0, line, lines[line].length);
      const severity = f.severity === "warning" ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Error;
      const d = new vscode.Diagnostic(range, f.message, severity);
      d.source = "demesne";
      return d;
    });
  };

  const specs = () => {
    const lists = vscode.workspace.getConfiguration("demesne").get("specs") || [];
    const roots = (vscode.workspace.workspaceFolders || []).map((f) => f.uri.fsPath);
    return lists.flatMap((files) => (roots.length ? roots : [""]).map((root) => files.map((f) => path.resolve(root, f))));
  };

  const checkSpec = (doc, files) => {
    const open = new Map(vscode.workspace.textDocuments.map((d) => [d.uri.fsPath, d]));
    let texts;
    try {
      texts = files.map((p) => (open.has(p) ? open.get(p).getText() : readFile(p)));
    } catch (e) {
      const unread = { severity: "error", line: null, message: `the spec's files can't all be read: ${e.message}` };
      collection.set(doc.uri, diagnostics([unread], doc.getText(), doc));
      return;
    }
    const found = findingsInFiles(files, texts);
    files.forEach((p, i) => {
      const mine = found.filter((f) => f.file === p || (f.file === null && p === doc.uri.fsPath));
      const uri = open.has(p) ? open.get(p).uri : vscode.Uri.file(p);
      collection.set(uri, diagnostics(mine, texts[i], open.get(p)));
    });
  };

  const check = (doc) => {
    if (doc.languageId !== "demesne") return;
    const files = specs().find((list) => list.includes(doc.uri.fsPath));
    if (files) return checkSpec(doc, files);
    collection.set(doc.uri, diagnostics(findings(doc.getText()), doc.getText(), doc));
  };

  const schedule = (doc) => {
    const key = doc.uri.toString();
    clearTimeout(timers.get(key));
    timers.set(
      key,
      setTimeout(() => {
        timers.delete(key);
        check(doc);
      }, DELAY_MS),
    );
  };

  context.subscriptions.push(
    collection,
    vscode.workspace.onDidOpenTextDocument(check),
    vscode.workspace.onDidChangeTextDocument((e) => schedule(e.document)),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      clearTimeout(timers.get(doc.uri.toString()));
      collection.delete(doc.uri);
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (!e.affectsConfiguration("demesne.specs")) return;
      collection.clear();
      vscode.workspace.textDocuments.forEach(check);
    }),
  );
  vscode.workspace.textDocuments.forEach(check);
  return { check };
}

function activate(context) {
  return activateWith(require("vscode"), context);
}

function deactivate() {}

module.exports = { activate, activateWith, deactivate };
