#![doc = "demesne's runtime as WebAssembly, for `@foir/demesne`. `call` runs one runtime operation: its projection and inputs arrive as a JSON object, and the result returns as `{\"ok\": value}` or `{\"error\": message}`. `authorize` runs the PDP against a JavaScript `holds` callback."]
#![forbid(unsafe_code)]

use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

/// Runs the runtime operation `op` on `args`, a JSON object, and returns `{"ok": value}` or `{"error": message}` as JSON.
#[wasm_bindgen]
#[must_use]
pub fn call(op: &str, args: &str) -> String {
    demesne_runtime_call::call(op, args)
}

#[wasm_bindgen]
extern "C" {
    pub type HoldsFn;

    #[wasm_bindgen(method, js_name = call)]
    fn invoke(this: &HoldsFn, ctx: &JsValue, perm: &str) -> JsValue;
}

/// Returns the PDP's decision for `procedure` under `pdp`, a JSON projection, asking `holds` whether the caller holds the permission that governs it; the result is the same envelope as [`call`].
#[wasm_bindgen]
#[must_use]
pub fn authorize(pdp: &str, procedure: &str, holds: &HoldsFn) -> String {
    demesne_runtime_call::authorize(pdp, procedure, |perm| holds.invoke(&JsValue::UNDEFINED, perm).is_truthy())
}
