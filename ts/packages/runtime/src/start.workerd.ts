import { initSync } from "./wasm/demesne_runtime_wasm.js";
import wasm from "./wasm/demesne_runtime_wasm_bg.wasm";

initSync({ module: wasm });
