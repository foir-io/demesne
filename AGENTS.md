# AGENTS.md

Guide for an agent (or a human) working in this repository.

## What this is

Demesne is a compiler that turns one authorization spec (`.demesne`) into Postgres Row-Level
Security (the enforcement floor) plus a typed application surface in Go, TypeScript and Rust.
There is no running authorization service; enforcement lives in the database. The compiler,
CLI and runtime are Rust; the Go engine is frozen at v0.93.x as the full Go library.

## Repository layout

- `crates/` — the Rust workspace: `syntax` (lexer, parser), `model` (analysis and
  validation), `emit-sql`, `emit-go`, `emit-ts`, `emit-rust` (static tables from `build.rs`),
  `runtime` (no parser), `postgres` (live-database support), `cli` (the `demesne` binary, and a
  library of its pure commands), `wasm` (the compiler as WebAssembly), `gocompat` (Go's
  quoting, JSON escaping and sort order, for byte parity), and the test-only `parity` and
  `static-parity`.
- `scripts/parity/`, `testdata/` — the differential harness against the Go engine and its
  corpus.
- `npm/` — the `@foir/demesne-cli` launcher and the script that stages its platform packages
  from dist's archives.
- `/` — the Go engine, module `github.com/foir-io/demesne`. Standard library only. The
  lexer, parser, AST, validator, every `Emit*` target (RLS, definers, triggers, PDP, claims,
  app surface, framework codegen, changelog, TypeScript, Supabase profile), and the runtime
  helpers.
- `cmd/demesne/` — the CLI, a separate module that links pgx for the live-database
  subcommands. Has `replace github.com/foir-io/demesne => ../..`.
- `pgx/` — module `github.com/foir-io/demesne/pgx`, the pgx adapter (`FromPgx`). A separate
  module so the engine stays standard-library only.
- `examples/` — worked `.demesne` specs plus committed generated packages (`examples/authz`,
  `examples/supabaseauthz`) that serve as compile proofs and golden references.
- `ts/` — a pnpm workspace: `@foir/demesne` (a hand-written zero-dependency TypeScript
  runtime), the TypeScript emit target, and an example app.

## Build, test, lint

- Rust: `cargo test --workspace`, `cargo clippy --workspace --all-targets`; the live-Postgres
  suites run with `cargo test -p demesne-postgres -- --ignored` and `$DEMESNE_PG_URL` set.
- Engine: `go build ./...`, `go test ./...`, `go vet ./...`, `golangci-lint run ./...`
- CLI: `cd cmd/demesne && go test ./...`
- pgx: `cd pgx && go test ./...`
- TypeScript: `cd ts && pnpm install && pnpm -r test`
- Golden examples are regenerated with `UPDATE_ORACLE=1 go test -run <ArtifactTest> .`
- The live-Postgres round-trip is gated on `$SUPABASE_DB_URL` and skips without it.

## The workflow: spec to enforcement

1. Write a `.demesne` spec: topology levels, vocabularies, rolestores, subjects, and objects
   with their relations and permissions.
2. `demesne validate <spec>` and `demesne emit <spec> <kind>`, where `<kind>` is one of
   `rls | definers | triggers | claims | pdp | framework | all | manifest | migrate`. `--target ts` selects the
   TypeScript projection; `--profile supabase` emits the Supabase deployment profile.
3. Apply the emitted SQL (RLS policies, the SECURITY DEFINER kernel, FORCE RLS) as a
   migration. Keep `emit <spec> manifest` beside it, and write the next migration with
   `emit <spec> migrate <manifest>`, which also drops what the spec stopped emitting.
4. In the application, generate the typed framework by calling `Spec.EmitFramework(pkg)` from
   your own generator, then run its `Can<Verb>` inside a transaction that has run
   `SessionSetupSQL` and installed `Claims.Mint()`. Adapt your connection with
   `demesne.FromSQL` (database/sql) or `demesne/pgx.FromPgx` (pgx).

## Conventions

- **Rust:** load the `rust` skill (`.claude/skills/rust/SKILL.md`) before writing or reviewing Rust.
  It holds the house rules on lints, panics, errors, determinism and tests, built on Microsoft's
  Pragmatic Rust Guidelines (vendored under `references/`).
- **No comments.** Code carries no explanatory comments. The only comments are functional
  directives and the `// Code generated … DO NOT EDIT.` marker on generated files. If a
  comment seems necessary, make the code clearer instead; keep one only for a firm, concrete
  reason. Rustdoc on a published crate's public items is API documentation, not a comment.
- The engine is standard-library only. Anything that needs a third-party dependency (a
  database driver) lives in a separate module.
- Emitters are deterministic and `go/format`-clean. The framework and TypeScript emitters
  byte-match the committed golden examples, which tests verify.
- The RLS floor is the source of truth. The application surface is equal-by-delegation: it
  runs the same compiled predicate the database enforces. Do not add a second evaluator.
- Keep every suite green and `golangci-lint` clean (gocognit ≤ 30) before a change is done.

## Where to look

- Spec language: `lexer.go`, `parser.go`, `ast.go`
- Enforcement: `emit_rls.go`, `emit_definers.go`, `emit_pdp.go`, `app_surface.go`
- Codegen: `emit_framework.go` (Go), `emit_ts.go` (TypeScript)
- Runtime helpers: `runtime.go`, `holds.go`, `querier.go`
- Deployment profiles: `emit_supabase.go`
- Adopter guide: `GUIDE.md`
