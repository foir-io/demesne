const { diagnostics } = require("./wasm/demesne_wasm.js");

function findings(source) {
  return JSON.parse(diagnostics(source));
}

module.exports = { findings };
