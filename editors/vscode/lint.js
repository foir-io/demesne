const { diagnostics, diagnostics_files } = require("./wasm/demesne_wasm.js");

function findings(source) {
  return JSON.parse(diagnostics(source));
}

function findingsInFiles(names, sources) {
  return JSON.parse(diagnostics_files(names, sources));
}

module.exports = { findings, findingsInFiles };
