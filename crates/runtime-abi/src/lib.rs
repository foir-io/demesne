#![doc = "demesne's runtime as WebAssembly with plain exports, for the Go module, which runs it on wazero."]
#![doc = ""]
#![doc = "A host reserves memory for each argument with `demesne_alloc` and writes the argument's bytes there. It then runs `demesne_call` or `demesne_authorize`, which take those blocks back, and reads the JSON result at the returned `(pointer << 32) | length`, giving it back with `demesne_free`. `demesne_authorize` asks the host whether the caller holds a permission through the imported `demesne.demesne_holds(pointer, length)`, which answers 1 or 0. The exports exist only on wasm32."]

#[cfg(target_arch = "wasm32")]
pub mod exports;
