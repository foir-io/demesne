import { initSync } from "./wasm/demesne_runtime_wasm.js";
import { BYTES } from "./wasm/bytes.js";

initSync({ module: Uint8Array.from(atob(BYTES), (c) => c.charCodeAt(0)) });
