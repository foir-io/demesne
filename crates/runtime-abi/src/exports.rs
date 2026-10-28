use std::ptr::{slice_from_raw_parts_mut, with_exposed_provenance_mut};
use std::str;

#[expect(unsafe_code, reason = "a host's question to its Go caller is a WebAssembly import, declared in an extern block")]
#[link(wasm_import_module = "demesne")]
unsafe extern "C" {
    safe fn demesne_holds(perm: u32, perm_len: u32) -> u32;
}

fn word(n: usize) -> u32 {
    u32::try_from(n).expect("a wasm32 address or length fits in 32 bits")
}

fn give(bytes: Box<[u8]>) -> (u32, u32) {
    let len = word(bytes.len());
    (word(Box::into_raw(bytes).cast::<u8>().expose_provenance()), len)
}

#[expect(unsafe_code, reason = "it rebuilds a block this module reserved or returned from the address the host hands back")]
fn take(ptr: u32, len: u32) -> Box<[u8]> {
    let raw = slice_from_raw_parts_mut(with_exposed_provenance_mut::<u8>(ptr as usize), len as usize);
    // SAFETY: the host hands back, once, a block `demesne_alloc` reserved or a result this module returned, at the
    // address and length it was given, so `raw` is a live boxed slice this module allocated and nothing else owns.
    unsafe { Box::from_raw(raw) }
}

fn result(out: String) -> u64 {
    let (ptr, len) = give(out.into_bytes().into_boxed_slice());
    (u64::from(ptr) << 32) | u64::from(len)
}

fn texts(a: &[u8], b: &[u8], run: impl FnOnce(&str, &str) -> String) -> u64 {
    result(match (str::from_utf8(a), str::from_utf8(b)) {
        (Ok(a), Ok(b)) => run(a, b),
        _ => demesne_runtime_call::refusal("demesne runtime: an argument is not UTF-8"),
    })
}

/// Reserves `len` zeroed bytes for the host to write an argument into, and returns their address.
#[expect(unsafe_code, reason = "a plain WebAssembly export needs an unmangled symbol")]
#[unsafe(no_mangle)]
pub extern "C" fn demesne_alloc(len: u32) -> u32 {
    give(vec![0; len as usize].into_boxed_slice()).0
}

/// Gives back the `len` bytes at `ptr` that a call returned.
#[expect(unsafe_code, reason = "a plain WebAssembly export needs an unmangled symbol")]
#[unsafe(no_mangle)]
pub extern "C" fn demesne_free(ptr: u32, len: u32) {
    drop(take(ptr, len));
}

/// Runs the runtime operation named at `op` on the JSON arguments at `args`.
///
/// It takes both blocks back and returns the result envelope as `(pointer << 32) | length`.
#[expect(unsafe_code, reason = "a plain WebAssembly export needs an unmangled symbol")]
#[unsafe(no_mangle)]
pub extern "C" fn demesne_call(op: u32, op_len: u32, args: u32, args_len: u32) -> u64 {
    let (op, args) = (take(op, op_len), take(args, args_len));
    texts(&op, &args, demesne_runtime_call::call)
}

/// Decides the procedure at `procedure` under the JSON PDP projection at `pdp`.
///
/// It takes both blocks back, asks the host through `demesne_holds` whether each permission is held, and returns the
/// result envelope as `(pointer << 32) | length`.
#[expect(unsafe_code, reason = "a plain WebAssembly export needs an unmangled symbol")]
#[unsafe(no_mangle)]
pub extern "C" fn demesne_authorize(pdp: u32, pdp_len: u32, procedure: u32, procedure_len: u32) -> u64 {
    let (pdp, procedure) = (take(pdp, pdp_len), take(procedure, procedure_len));
    texts(&pdp, &procedure, |pdp, procedure| {
        demesne_runtime_call::authorize(pdp, procedure, |perm| demesne_holds(word(perm.as_ptr().expose_provenance()), word(perm.len())) != 0)
    })
}
