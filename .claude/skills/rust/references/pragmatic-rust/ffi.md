<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT license (see LICENSE.md). -->
<!-- From the Pragmatic Rust Guidelines, https://microsoft.github.io/rust-guidelines/agents/all.txt -->

# FFI Guidelines



## FFI crates follow established naming conventions (M-FFI-NAMING) { #M-FFI-NAMING }

<why>immediately recognizable crate roles across projects.</why>

Crates used for FFI should follow established naming practices:

- `-sys` for crates defining items to call into existing (C-style) libraries
- `-ffi` for crates defining (C-style) items when called from existing applications

There are slight variations of this scheme (e.g., `-sys2` when a previous `-sys` crate was abandoned and using `-` vs `_`), but overall `-ffi` clearly defines 'export' libraries, and `-sys` 'import' ones.



## Business logic belongs in core crates, FFI only translates (M-FFI-TRANSLATES) { #M-FFI-TRANSLATES }

<why>maximal safe code and a clean separation of concerns.</why>

When Rust is used to create FFI libraries, there should be a clear separation of concerns between the core _business logic_ crate `foo` and the glue crate `foo-ffi`.

Any operational functionality belongs in the core crate and should be expressed as idiomatic, safe, testable Rust. The FFI crate exists only to translate between native Rust and C constructs, and the core crate must not be infected with interop concerns, even if this means repeating, and slightly adjusting, type and function signatures. For example, given the following type in the core crate `foo`:

```rust,ignore
pub struct Message {
    destination: [u8; 8],
    data: Vec<u8>,
}

impl Message {
    pub fn new(destination: [u8; 8], data: Vec<u8>) -> Self { /* ... */ }
    pub fn transmit(&self) -> Result<(), TransmitError> { /* ... */ }
}
```

A proper separation of concerns might collapse construction and transmission into a single FFI entry point in `foo-ffi`:

```rust,ignore
#[no_mangle]
pub unsafe extern "C" fn transmit_message(
    destination: *const [u8; 8],
    data: *const u8,
    data_len: usize,
) -> u8 {
    let data = std::slice::from_raw_parts(data, data_len).to_vec();
    match Message::new(*destination, data).transmit() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}
```

However, it would be improper to leak FFI requirements into `foo` itself: ownership, data models and signatures do not translate seamlessly between the two worlds. Any time _saved_ by skipping a clean split will have to be paid back many times over during refactorings down the line.

```rust
#[repr(C)]
pub struct Message {
    pub destination: [u8; 8],
    pub data_ptr: *mut u8,
    pub data_len: usize,
    pub data_cap: usize,
}
```



## Isolate DLL state between FFI libraries (M-ISOLATE-DLL-STATE) { #M-ISOLATE-DLL-STATE }

<why>data integrity and defined behavior across DLL boundaries.</why>

When loading multiple Rust-based dynamic libraries (DLLs) within one application, you may only share 'portable' state between these libraries.
Likewise, when authoring such libraries, you must only accept or provide 'portable' data from foreign DLLs.

Portable here means data that is safe and consistent to process regardless of its origin. By definition, this is a subset of FFI-safe types.
A type is portable if it is `#[repr(C)]` (or similarly well-defined), and _all_ of the following:

- It must not have any interaction with any `static` or thread local.
- It must not have any interaction with any `TypeId`.
- It must not contain any value, pointer or reference to any non-portable data (it is valid to point into portable data within non-portable data, such as
  sharing a reference to an ASCII string held in a `Box`).

_Interaction_ means any computational relationship, and therefore also relates to how the type is used. Sending a `u128` between DLLs is OK, using it to
exchange a transmuted `TypeId` isn't.

The underlying issue stems from the Rust compiler treating each DLL as an entirely new compilation artifact, akin to a standalone application. This means each DLL:

- has its own set of `static` and thread-local variables,
- the type layout of any `#[repr(Rust)]` type (the default) can differ between compilations,
- has its own set of unique type IDs, differing from any other DLL.

Notably, this affects:

- ⚠️ any allocated instance, e.g., `String`, `Vec<u8>`, `Box<Foo>`, ...
- ⚠️ any library relying on other statics, e.g., `tokio`, `log`,
- ⚠️ any struct not `#[repr(C)]`,
- ⚠️ any data structure relying on consistent `TypeId`.

In practice, transferring any of the above between libraries leads to data loss, state corruption, and usually undefined behavior.

Take particular note that this may also apply to types and methods that are invisible at the FFI boundary:

```rust,ignore
/// A method in DLL1 that wants to use a common service from DLL2
#[ffi_function]
fn use_common_service(common: &CommonService) {
    // This has at least two issues:
    // - `CommonService`, or ANY type nested deep within might have
    //   a different type layout in DLL2, leading to immediate
    //   undefined behavior (UB) ⚠️
    // - `do_work()` here looks like it will be invoked in DLL2, but
    //   the code executed will actually come from DLL1. This means that
    //   `do_work()` invoked here will see a data structure coming from
    //   DLL2, but will use statics from DLL1 ⚠️
    common.do_work();
}
```
