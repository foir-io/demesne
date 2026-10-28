# AGENTS.md

Guide for an agent (or a human) working in this repository.

## What this is

Demesne is a compiler that turns one authorization spec (`.demesne`) into Postgres Row-Level
Security (the enforcement floor) plus a typed application surface in TypeScript and Rust.
There is no running authorization service; enforcement lives in the database. The compiler,
CLI and runtime are Rust. The Go engine is frozen at v0.93.1 on the `release/v0.93` branch and
is not on `main`.

## Repository layout

- `crates/` — the Rust workspace: `syntax` (lexer, parser), `model` (analysis and
  validation), `emit-sql`, `emit-ts`, `emit-rust` (static tables from `build.rs`), `runtime`
  (no parser), `runtime-wasm` (the runtime as WebAssembly, for `@foir/demesne`), `postgres`
  (live-database support), `cli` (the `demesne` binary, and a library of its pure commands),
  `wasm` (the compiler as WebAssembly, for editors), `gocompat` (the quoting, JSON escaping and
  sort order the output keeps from the Go engine), and the test-only `parity` and
  `static-parity`.
- `scripts/parity/`, `testdata/` — the differential harness against the frozen Go engine,
  built from a tag's archive, and the spec corpus every suite reads.
- `npm/` — the `@foir/demesne-cli` launcher and the script that stages its platform packages
  from dist's archives.
- `examples/` — worked `.demesne` specs, each pinned in full by the snapshots.
- `ts/` — a pnpm workspace: `@foir/demesne` (the Rust runtime compiled to WebAssembly by
  `crates/runtime-wasm`, behind a thin TypeScript API; build it with
  `scripts/build-runtime-wasm.sh` before the TS tests) and an example app whose generated
  files are goldens.
- `editors/vscode/` — the VS Code extension, which validates specs with `crates/wasm`.
- `go.mod` — no Go code. It retracts v0.94.0 and v1.0.0 through v1.999.999, so Go's tooling
  keeps Go users on v0.93.1 even though every `vX.Y.Z` tag on `main` is also a Go module
  version.

## Build, test, lint

- Rust: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`; the
  live-Postgres suites run with `cargo test -p demesne-postgres -- --ignored` and
  `$DEMESNE_PG_URL` set. The Supabase round-trip also needs `$SUPABASE_DB_URL`.
- TypeScript: `scripts/build-runtime-wasm.sh`, then `cd ts && pnpm install && pnpm -r test`.
- VS Code: `cd editors/vscode && npm run build:wasm && npm test`.
- Goldens (the example app's generated files and `oracle.json`) are regenerated with
  `UPDATE_ORACLE=1 cargo test -p demesne-parity --test goldens --test oracle_manifest`.
- Every CLI output of the examples, the corpus fixtures and the gap specs is pinned by insta
  snapshots in `crates/parity/tests/snapshots/`: the examples in full, the rest as a checksum
  manifest. After an intended output change, run
  `INSTA_UPDATE=always cargo test -p demesne-parity --test pinned_output` and read the whole
  diff before committing it.
- Mutation tests run only in CI (`.github/workflows/mutants.yml`), on pull requests that touch the
  `emit-sql`, `model` or `runtime` sources. Never run `cargo mutants` on a developer machine: a
  runaway mutant can exhaust its memory.

## The workflow: spec to enforcement

1. Write a `.demesne` spec: topology levels, vocabularies, rolestores, subjects, and objects
   with their relations and permissions.
2. `demesne validate <spec>` and `demesne emit <spec> <kind>`, where `<kind>` is one of
   `rls | definers | enablement | triggers | pdp | all | manifest | migrate`. `--target ts`
   emits TypeScript (`claims | pdp | projections | framework | all`); `--profile supabase`
   emits the Supabase deployment profile.
3. Apply the emitted SQL (RLS policies, the SECURITY DEFINER kernel, FORCE RLS) as a
   migration. Keep `emit <spec> manifest` beside it, and write the next migration with
   `emit <spec> migrate <manifest>`, which also drops what the spec stopped emitting.
4. In a TypeScript application, generate the typed surface with
   `demesne emit <spec> --target ts framework` and run its checks with `@foir/demesne`. A Rust
   application builds its surface from the crates, with `demesne-emit-rust` in `build.rs`.

## Conventions

- **Rust:** load the `rust` skill (`.claude/skills/rust/SKILL.md`) before writing or reviewing Rust.
  It holds the house rules on lints, panics, errors, determinism and tests, built on Microsoft's
  Pragmatic Rust Guidelines.
- **This repository is public.** Never commit an adopter's spec, schema, generated output or
  data, not even as a test fixture. Write fixtures from scratch; an adopter's spec stays in the
  adopter's own repository.
- **No comments.** Code carries no explanatory comments. The only comments are functional
  directives and the `// Code generated … DO NOT EDIT.` marker on generated files. If a
  comment seems necessary, make the code clearer instead; keep one only for a firm, concrete
  reason. Rustdoc on a published crate's public items is API documentation, not a comment.
- **A spec value reaches SQL only as a quoted literal**, through `demesne_runtime::quote_literal`.
- The compiler and runtime crates use only the standard library. A database driver lives in
  `demesne-postgres`.
- Emitters are deterministic, and the generated TypeScript byte-matches the committed goldens,
  which tests verify.
- The RLS floor is the source of truth. The application surface is equal-by-delegation: it
  runs the same compiled predicate the database enforces. Do not add a second evaluator.
- Keep every suite green before a change is done.

## Where to look

- Spec language: `crates/syntax`
- Analysis and validation: `crates/model`
- Enforcement: `crates/emit-sql` (`rls.rs`, `definers.rs`, `app_surface.rs`, `write_reach.rs`)
- Codegen: `crates/emit-ts` (TypeScript), `crates/emit-rust` (Rust)
- Runtime: `crates/runtime`, and `crates/runtime-wasm` for `@foir/demesne`
- Deployment profiles: `crates/emit-sql/src/supabase.rs`
- Adopter guide: `GUIDE.md`
