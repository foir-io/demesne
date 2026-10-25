# Pragmatic Rust Guidelines (vendored)

Microsoft's [Pragmatic Rust Guidelines](https://microsoft.github.io/rust-guidelines/), MIT licensed (`LICENSE.md`).

- Source: `https://microsoft.github.io/rust-guidelines/agents/all.txt`, fetched 2026-10-24.
- Book version 2026.6, built 2026-09-25.
- sha256 of the fetched `all.txt`: `e69533b0541a5d185ad9d8304f5eb5cf4b033135b7046f89c499b6126dced3b6`.
- Split by section into the files below. The text is unchanged apart from a two-line header on each file. All 90 guideline IDs are present.

The text contains relative links such as `../libs/ux/#M-ERRORS-CANONICAL-STRUCTS`. Those links point at the online book. To follow one here, open the file that holds that ID.

| File | Read it when | Guidelines |
|---|---|---|
| `universal.md` | Any Rust work: naming, lints, logging, Debug and Display, crate splits | M-UPSTREAM-GUIDELINES, M-STATIC-VERIFICATION, M-LINT-OVERRIDE-EXPECT, M-PUBLIC-DEBUG, M-PUBLIC-DISPLAY, M-SMALLER-CRATES, M-WEASEL-WORDS, M-SHORT-NAMES, M-REGULAR-FN, M-DOCUMENTED-MAGIC, M-LOG-STRUCTURED |
| `correctness.md` | Panics, invariants, unsafe | M-PANIC-IS-STOP, M-PANIC-ON-BUG, M-PANIC-CONTINUATION, M-PANIC-MESSAGE, M-UNSAFE, M-UNSAFE-IMPLIES-UB, M-UNSOUND |
| `libraries-ux.md` | Public API shape: error types, builders, traits versus generics, modules | M-ERRORS-CANONICAL-STRUCTS, M-FROM-ERROR, M-INIT-BUILDER, M-INIT-CASCADED, M-DI-HIERARCHY, M-SIMPLE-ABSTRACTIONS, M-AVOID-WRAPPERS, M-SERVICES-CLONE, M-ESSENTIAL-FN-INHERENT, M-BALANCED-MODULES, M-NO-PRELUDE, M-PARAMETER-CONSISTENCY, M-COLLECTION-TRAITS, M-ASYNC-FN |
| `libraries-resilience.md` | Testability, statics, newtypes, test utilities, logging versus print | M-MOCKABLE-SYSCALLS, M-TEST-UTIL, M-INTEGRATION-TESTS, M-STRONG-TYPES, M-STRONG-TYPES-GUARD, M-BUILD-RESULT, M-NO-GLOB-REEXPORTS, M-AVOID-STATICS, M-LOG-NOT-PRINT |
| `libraries-interoperability.md` | Types that cross crate boundaries; Send; I/O traits | M-TYPES-SEND, M-ESCAPE-HATCHES, M-DONT-LEAK-TYPES, M-FOREIGN-REEXPORTS, M-IMPL-ASREF, M-IMPL-RANGEBOUNDS, M-IMPL-IO |
| `libraries-building.md` | Cargo features; building on every platform | M-OOBE, M-SYS-CRATES, M-FEATURES-ADDITIVE |
| `application.md` | Binaries: app-level errors, allocator, target-cpu | M-APP-ERROR, M-MIMALLOC-APPS, M-TARGET-CPU |
| `performance.md` | Hot paths, allocation, async future size, yielding | M-THROUGHPUT, M-HOTPATH, M-YIELD-POINTS, M-MEM-REUSE, M-LOG-OVERHEAD, M-AVOID-INDIRECTION, M-BOX-DST, M-SHRINK-TO-FIT, M-FAST-HASHER, M-INITIAL-CAPACITY, M-ASYNC-STACK-SIZE |
| `project.md` | Workspace layout, editions, MSRV | M-CARGO-WORKSPACE, M-CRATES-IN-WORKSPACE, M-CRATES-FLAT-FOLDER, M-LATEST-EDITION, M-MSRV |
| `documentation.md` | Doc comments and module docs | M-FIRST-DOC-SENTENCE, M-MODULE-DOCS, M-CANONICAL-DOCS, M-DOC-INLINE |
| `ai.md` | How agents tend to go wrong in Rust: ports, tests, re-exports, docs | M-DESIGN-FOR-AI, M-SINGLE-ITEM-PATH, M-NO-META-DESIGN-DOCUMENTATION, M-TAUTOLOGICAL-TESTS, M-RUST-SHAPED |
| `macros.md` | Writing a macro (a last resort) | M-MACRO-LAST-RESORT, M-EXAMPLE-OVER-PROC, M-MACROS-DONT-LIE, M-MACRO-MAIN-CRATE, M-MACRO-VERSION-PIN, M-MACRO-HELPERS, M-PROC-IMPL, M-PROC-IMPLIED-ITEMS |
| `ffi.md` | FFI or WASM boundary crates | M-ISOLATE-DLL-STATE, M-FFI-TRANSLATES, M-FFI-NAMING |

## Updating

1. Fetch `all.txt` again into an empty directory.
2. Diff it against the sha above.
3. Re-split it with the same section boundaries (each top-level `# … Guidelines` heading that follows a `---`).
4. Check that every `M-` ID appears exactly once.
5. Update the version, date and sha here.
