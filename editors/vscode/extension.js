const { findings } = require("./lint.js");

const DELAY_MS = 200;

function activateWith(vscode, context) {
  const collection = vscode.languages.createDiagnosticCollection("demesne");
  const timers = new Map();

  const check = (doc) => {
    if (doc.languageId !== "demesne") return;
    const found = findings(doc.getText()).map((f) => {
      const line = f.line === null ? 0 : Math.min(Math.max(f.line - 1, 0), doc.lineCount - 1);
      const severity = f.severity === "warning" ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Error;
      const d = new vscode.Diagnostic(doc.lineAt(line).range, f.message, severity);
      d.source = "demesne";
      return d;
    });
    collection.set(doc.uri, found);
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
  );
  vscode.workspace.textDocuments.forEach(check);
  return { check };
}

function activate(context) {
  return activateWith(require("vscode"), context);
}

function deactivate() {}

module.exports = { activate, activateWith, deactivate };
