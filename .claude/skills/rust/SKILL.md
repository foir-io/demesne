---
name: rust
description: House rules for writing, testing and reviewing Rust with a coding agent, covering lints, panics, errors, determinism, types, async and tests, built on Microsoft's Pragmatic Rust Guidelines. Use this skill whenever you write, change, review, refactor or port Rust code, or touch Cargo.toml, lint config, error types, tests or CI for a Rust crate. That includes small edits and fixes that look mechanical, because most of the rules here are about the details that make a change correct.
---

# Rust house rules

Rust written with a coding agent follows two layers of guidance:
- **The house rules below.** They cover the judgement calls the compiler and clippy can't check.
- **Microsoft's Pragmatic Rust Guidelines** (MIT). Each guideline has a stable ID such as `M-PANIC-ON-BUG`. `references/guidelines.md` links every ID, pinned to the commit these rules were checked against.

Workspace lints and CI enforce everything that can be enforced mechanically. So this skill is mostly about what a lint can't see:
- whether an error is the right kind;
- whether an order is deterministic;
- whether a test can actually fail;
- whether a port carries the old language's habits forward.

**Precedence:**
1. The repo's `CLAUDE.md` / `AGENTS.md`, which hold repo-specific rules (release process, parity constraints, crate boundaries).
2. These house rules.
3. The Pragmatic Rust Guidelines.
4. The upstream [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html).

When a house rule departs from a guideline, it says why.

## Find the guideline you need

Don't read the whole book. Open only the guidelines for the area you're working in, from its section of `references/guidelines.md`.

| Working on | Section |
|---|---|
| Panics, invariants, `unsafe` | correctness |
| A public API, error types, builders, traits versus generics | libs/ux |
| Testability, statics, newtypes, printing versus logging | libs/resilience |
| Types crossing crates, `Send`, I/O parameters | libs/interop |
| Cargo features, building on every platform | libs/building |
| A binary's `main`, its allocator, target-cpu | apps |
| Hot paths, allocation, async future size | performance |
| Workspace layout, editions, MSRV | project |
| Doc comments | docs |
| Naming, lint overrides, logging, Debug and Display | universal |
| Porting code, writing tests, re-exports, crate docs | ai: it lists the mistakes agents make most often in Rust |
| Macros, FFI, WASM boundaries | macros, ffi |

## House rules

### 1. Lints are the floor, not the target

- **One lint config.** Lint config lives in `[workspace.lints]` in the root `Cargo.toml`, and every crate sets `[lints] workspace = true`. Don't add lint tables to a single crate's `Cargo.toml`.
  - **A crate exported to JavaScript is no exception.** `wasm-bindgen`'s generated glue builds under `forbid(unsafe_code)`. A claim that a crate can't build under a lint is a hypothesis: build it before writing the exception down.
- **Fix the warning, don't silence it.** Lints stay at warn while you work, and CI turns every warning into a failure with `-D warnings`.
- **Overrides are narrow, and each one gives a reason.** When a lint is wrong for a specific item, put `#[expect(clippy::lint_name, reason = "…")]` on the smallest item that needs it (M-LINT-OVERRIDE-EXPECT).
  - `#[expect]` warns as soon as the lint stops firing, so a stale override shows up by itself.
  - `#[allow]` hides that, so keep `#[allow]` for generated code.
  - Never add a workspace-wide `allow` to get a change through.
- **Crates whose job is printing** (a CLI, a test harness) take one crate-level `#![expect(clippy::print_stdout, reason = "…")]`. Library code logs instead (M-LOG-NOT-PRINT).
- **No complexity score.** Clippy's own docs say `cognitive_complexity` doesn't measure how hard code is to understand. The structural limits are `too_many_lines`, `excessive_nesting` and `too_many_arguments`.
  - When one fires, restructure along a real seam: a type, a phase, or a helper with a name a reader would search for.
  - Cutting a function at an arbitrary line to get under the threshold makes the code worse and only hides the warning.
  - If there's no honest seam, use `#[expect]` and say why.

### 2. Panics and errors

- **Pick the failure mode by its cause.** Input, I/O, the network and the environment fail with a `Result`. A detected programming bug, meaning an invariant your own code should have upheld, panics (M-PANIC-ON-BUG). Don't invent an error variant for a bug no caller could act on.
- **No `unwrap()` outside tests.**
  - Use `expect` with a message that names the invariant: `expect("a validated order always has a customer")`, not `expect("failed to get customer")`.
  - A poisoned lock is the one routine case: `expect("<lock name> poisoned")`.
  - The message is what the next person reads in a crash report (M-PANIC-MESSAGE).
- **Library errors.** A published library's public errors follow M-ERRORS-CANONICAL-STRUCTS: a struct, a private kind, `is_xxx()` helpers, `Display` and `std::error::Error`. `thiserror` is a fine way to implement them.
- **Size an API change from rustdoc, not a grep.** Trait methods, signatures behind a type alias such as `type R<T> = Result<T, String>`, and re-exports don't match a search for `pub fn`. Count the surface with `cargo public-api` or the rustdoc JSON before saying how big a change is.
- **Binaries.** A binary may use `anyhow` at the top level (M-APP-ERROR). Anything a caller has to branch on must still be a typed error.
- **Never branch on an error's message text.** Match the type or kind. Messages get reworded, and a string match silently stops matching. It looks like it still handles the case, but it doesn't.
- **Convert errors with `From` and `?`** (M-FROM-ERROR). Use `map_err` only to add context.
- **Don't drop a `Result` silently.** `let _ = …` and `.ok()` on a `Result` need a comment saying why dropping it is correct.
- **Decode a boundary strictly.** At a boundary where JSON, a projection or a caller's arguments come in, a field that is missing or of the wrong type is an error naming the field. Never read it as empty, `false` or zero: a lenient default chooses without saying so, and in authorization code it can choose to allow.
- **Recursion over input takes a depth limit.** A parser or walker that recurses once per level of input refuses past a named limit. Natively a stack overflow aborts the process. In WebAssembly there is no stack guard, so the module fails every later call until it is reloaded. Test both sides of the limit, and that the module still answers afterwards.

### 3. Determinism

- **Everything that reaches output has a defined order.** Output includes generated files, SQL, JSON, error lists and CLI stdout.
  - Don't produce output by iterating a `HashMap` or `HashSet`. Use `BTreeMap` or `IndexMap`, or sort with a total order that breaks ties on a unique key.
  - Hash order changes between runs and versions, so goldens flap, diffs grow noisy, and two identical inputs produce different bytes.
  - When real input can make two entries tie, check whether they collide. Two objects that write the same name are usually a bug to refuse, not an order to pick.
- **Fast hashers only for trusted keys.** M-FAST-HASHER is fine for keys you control. Keep the default DoS-resistant hasher for anything an outside caller supplies.
- **A hand-written `Ord` agrees with `PartialEq` and `Hash`.** `a.cmp(&b) == Equal` exactly when `a == b`, and equal values hash alike. Otherwise a `BTreeSet` and a `HashSet` disagree about which entries are duplicates, and output depends on which one built it. Derive the three together when you can.
- **Pass the outside world in.** Time, randomness, environment variables, the filesystem and the network go through a handle the caller passes in (M-MOCKABLE-SYSCALLS), so tests control them.
  - If the repo has disallowed `std::env::var` or the clock calls in `clippy.toml`, that's the reason; use the project's wrapper.
- **No global mutable state** (M-AVOID-STATICS). A `static` is fine as a cache whose value can't change correctness, such as a compiled regex. A process-wide registry that callers add to at startup is not fine: it's hidden coupling, and tests can't isolate it.

### 4. Make the compiler carry the rule

- **Make invalid states unrepresentable.**
  - Use enums instead of string tags and boolean flags.
  - Give each newtype a constructor that checks its invariant (M-STRONG-TYPES-GUARD).
  - Use typestate when an operation is only valid in some states.
- **"Everything" is a variant, not a sentinel.** An empty list, a `"*"` string or a `None` that means "everything" is one refactor away from meaning "nothing", and a reader can't tell which. Give "everything" its own enum variant that only one constructor builds.
- **Privilege is a value only the gate can make.** Code that may bypass a check, such as row-level security or a tenant filter, takes a token or a distinct type (a privileged transaction, say) that only the gate that decided can construct. The compiler then lists every bypass, and no grep script or allowlist has to.
- **What a type requires belongs to the type.** When every write must also audit, or record an idempotency key, make the transaction type require it: `commit` takes it, or the builder can't finish without it. A registry each write path has to remember to join can't tell when one forgets.
- **No `bool` parameter in a public signature.** `session_setup_sql(true)` says nothing at the call site, and two swapped bools still compile. Take an enum (`Scope::Transaction`), split the function in two (`to_string` and `to_string_pretty`), or take a struct with named fields. Settle it before 1.0: changing a public signature later is a major version.
- **Match exhaustively on your own enums.** A `_ =>` arm on an enum you own hides the next variant someone adds. Security-relevant crates deny `clippy::wildcard_enum_match_arm` for exactly this reason.
- **Mark public types that will grow `#[non_exhaustive]`** before the first stable release, so adding an enum variant or a struct field isn't a breaking change. Inside your own crate, matches on them stay exhaustive.
- **Don't clone to quiet the borrow checker.** A `.clone()` added only to end a borrow error usually hides a shape problem: borrow for a shorter scope, move the value to where it's consumed, or pass a reference. Clone when two owners really need the value.
- **Prefer a check the compiler runs.** A crate boundary, a private constructor or a type the compiler checks beats a grep guard, a code-review convention, or a comment saying "don't call this from X". If you find yourself writing such a comment, look for the type that would make it unnecessary.

### 5. Porting from another language

- **Keep the domain, drop the old language's habits** (M-RUST-SHAPED). Port the logic, not the old language's idioms:
  - error strings, nil checks and sentinel values;
  - an interface for everything;
  - registries populated at init;
  - stringly typed options;
  - goroutine-per-thing concurrency.
- **Contain byte-identical compatibility.** When output has to match the old implementation exactly, put the shims in one clearly named compat module or crate, and keep everything else idiomatic. Then the shims can be deleted in one place once parity is no longer required.
  - **Known traps when matching Go byte for byte:**
    - `sort.Slice` isn't stable, so ties come out in whatever order it leaves them. Give both sides a total order first.
    - Go's `%q` and Rust's `{:?}` escape differently. Port quoting as its own function, with golden tests.
    - `encoding/json` escapes `<`, `>`, `&`, U+2028 and U+2029 by default; `serde_json` escapes none of them.
    - protojson varies its whitespace on purpose. Compare it by meaning, never byte for byte.
    - A hash over Go's "deterministic" protobuf encoding isn't canonical across implementations. Export golden vectors from Go for every stored format before switching.
- **Flag old bugs; don't silently copy or fix them.** When the old code has a bug or a non-best-practice pattern, record it where the repo records debt (its debt register or ticket).
  - A silent fix breaks parity without anyone noticing.
  - A silent copy carries the debt forward.
  - Either way, the reviewer loses the decision.

### 6. Tests that can fail

- **Write the failing test before the fix.** For a bug, first write the test that reproduces it and watch it fail on the unfixed code, then fix it. A test written after the fix can pass for a reason that has nothing to do with the bug.
- **Break the code before claiming coverage.** Before saying a test covers a behaviour:
  1. break the code it guards (a plant);
  2. run the test and watch it fail;
  3. revert.

  A plant that doesn't compile proves nothing; count it as unviable, not caught. If a plant isn't caught, there are two possible causes: the test is blind, or the code is dead. Find out which.
- **Count what ran.**
  - Run nextest with `--no-tests=fail`.
  - Report how many tests actually ran.
  - Check that suites behind `#[ignore]`, a feature or an env var really ran. A skipped database suite looks exactly like a passing one.
- **A database test fails when its database is missing.** It panics, naming the variable to set. It never skips, because a skipped suite reads as a pass.
- **Test two paths against each other over a grid.** When two paths must agree, such as a point check and the policy it mirrors, a cache and its source, or a port and its original, generate a grid of inputs and compare every answer, not a handful of examples. Check that the grid produced both outcomes for every case, or the paths may agree only because the grid never tried.
- **When a test fails, check its expectation first.** An expected value an agent wrote is a hypothesis about the system. Confirm it against the system before changing code to match it.
- **Assertion messages carry the input.** Pass the values under test to the message (`assert!(errs[0].contains(…), "{errs:#?}")`), so a failure in CI can be read without running it again.
- **No tautological tests** (M-TAUTOLOGICAL-TESTS). Don't re-assert a constant or mirror the implementation's branches. Assert a property or a behaviour someone can observe.
- **Snapshot goldens.** Golden outputs are snapshot files, reviewed as diffs (insta). Never regenerate goldens to make a failing test pass without reading the diff and saying why it's right.
  - **Pin before you refactor.** When a change shouldn't alter output, snapshot the output first, then let the snapshots prove it didn't.
- **A plant counts only if tests ran.**
  - Run with `--no-fail-fast`, so every test binary runs, not just the first one that fails.
  - Treat a run that shows no test results as invalid, not missed.
  - In zsh an unquoted `$var` is not split into words, so pass argument lists as arrays.
- **Cover every operator.** In a parser or compiler, each operator the language accepts (`and`, `or`, `not`, nesting, precedence) has a test that fails if the operator is ignored. A pass that flattens a tree can drop an operator and still produce plausible output.
- **Isolate live tests.** nextest runs each test in its own process, in parallel, so live tests that share a database schema race each other. Give each test its own schema or database.
- **Test the shipped artifact where it runs.** Package it as users get it (`npm pack`, `cargo package`), install that in a clean project, and run it in every environment it targets. Assert where each run happened, and include a control that must fail, so a harness that silently ran nowhere can't pass.
- **Where tests live.** Tests of the public surface go under `tests/` (M-INTEGRATION-TESTS). Use `mod tests` for private internals.
- **Mutation-test correctness-critical code, in CI only, on a throwaway runner or under a memory cap.** For authorization, data-integrity or security code, run `cargo mutants --in-diff` on your change in a CI job, never on a developer's machine. Treat each missed mutant like an uncaught plant.
  - A mutant can turn a loop into one that allocates without bound: `i += 1` becomes `i *= 1` next to a `push`. A few of those running at once exhaust a laptop's memory in seconds, and macOS then panics the kernel. A local run crashed a laptop twice this way.
  - macOS can't cap a process's memory, so a shorter `--timeout` or fewer jobs doesn't make a local run safe.
  - **Where it may run:**
    - A runner that is thrown away after the job, such as a GitHub-hosted one, where a runaway kills only that job.
    - A shared self-hosted runner, only under a hard memory cap on the mutants step: systemd's `MemoryMax` with `MemorySwapMax=0`, or a container's `--memory` equal to its `--memory-swap`. Without a cap, Linux's out-of-memory killer may thrash the host and kill other jobs before it reaches the runaway.
  - Keep `-j` at 1 or 2 and set a short `--timeout`, so a stuck mutant ends quickly.
  - `--in-diff` mutates every line the diff adds, and a moved file is all added lines. Moving a module mutates code that may never have been mutated, so expect misses in it that have nothing to do with the move.
  - `--timeout` bounds only the tests. If a build script runs the code being mutated, a looping mutant hangs the build instead, and builds have no timeout by default, so set `--build-timeout` too: a few times the slowest cold build.
  - Locally, prove tests with plants instead. If the repo has no mutants job in CI, say so and ask before adding one; don't fall back to running it locally.

### 7. Async

- **No std lock guard across `.await`.** Never hold a `std::sync::Mutex` or `RwLock` guard across an `.await`. Restructure, or use an async-aware lock if one is genuinely needed.
- **Spawn through the project.** Spawn through the project's helper if it has one, so the task keeps its tracing span and shutdown waits for it. Don't drop a `JoinHandle` without deciding what happens when the task fails.
- **Long CPU-bound work yields.** It calls `yield_now().await` at intervals or moves to `spawn_blocking` (M-YIELD-POINTS).
- **Futures and public types are `Send`** (M-TYPES-SEND), and `Sync` unless they need interior mutability. Assert it at compile time: a test calls `const fn send_sync<T: Send + Sync>() {}` for each public type, so a field that loses it fails this crate's build, not an adopter's.
- **Every network call has a timeout.**
- **A function holding a transaction takes the transaction.** It takes `&mut Transaction`, and its state holds no pool, so it can't acquire a second connection while the first is open. With a small pool, that nested acquire deadlocks under load.

### 8. Dependencies, features, unsafe

- **Publish from an empty target directory.** `cargo publish --workspace` verifies each crate against the others through a local registry, and Cargo never rebuilds a registry crate whose name and version it has already compiled. A target directory that holds an earlier dry run at the same version verifies against that stale build: `CARGO_TARGET_DIR="$(mktemp -d)" cargo publish --workspace`.
- **Declare dependencies once.** Put each dependency in `[workspace.dependencies]` and reference it with `.workspace = true` (M-CARGO-WORKSPACE). Before adding one, check its licence, maintenance and footprint; cargo-deny checks licences and advisories in CI.
- **Features are additive** (M-FEATURES-ADDITIVE). CI checks each feature on its own.
  - When features select editions or tiers of a product, check every combination with `cargo hack --feature-powerset`, and give each tier its own schema and migration set from the first migration. Tools such as sqlx record a checksum for each applied migration, so splitting a set later means rewriting history on every database.
- **Don't leak dependency types.** A published crate keeps third-party types out of its public API unless they earn their place (M-DONT-LEAK-TYPES).
- **`unsafe` is forbidden in every crate but `runtime-abi`.** Its plain WebAssembly exports need `#[unsafe(no_mangle)]`, and handing a buffer back to the host needs one `Box::from_raw`. Each such item carries `#[expect(unsafe_code, reason = "…")]` and each unsafe block a `SAFETY` comment, and every other crate root has `#![forbid(unsafe_code)]`. If you think another crate needs it, stop and ask rather than adding an exception.

### 9. Docs, comments and logs

- **Public items are documented with the canonical sections:** `# Errors`, `# Panics`, `# Examples` (M-CANONICAL-DOCS). The first sentence is one line, about 15 words (M-FIRST-DOC-SENTENCE).
- **Doc examples use `?`.** An example returns a `Result` and propagates errors with `?`, so readers copy error handling rather than `unwrap()` (C-QUESTION-MARK in the Rust API Guidelines).
- **Comments explain the invariant or the reason, not the history.** Leave out ticket numbers and the story of how the design was reached, in both code and crate docs (M-NO-META-DESIGN-DOCUMENTATION). That history belongs in the commit message and the ticket.
- **Name magic values.** A magic value becomes a named constant, with a comment on why it has that value and what breaks if it changes (M-DOCUMENTED-MAGIC).
- **Log structured events.** Logs are `tracing` events with named fields (M-LOG-STRUCTURED). Never log secrets, tokens or personal data, and redact before the event, not after.

## Before you say it's done

1. Run these after your last edit, and report what each printed. A formatter run followed by one more file fails CI on formatting.
   - `cargo fmt --check`;
   - `cargo clippy --workspace --all-targets -- -D warnings`;
   - `cargo nextest run --workspace --no-tests=fail`, plus the repo's ignored or live suites if you touched their area;
   - `cargo deny check` if dependencies changed.

   The gate is rustc: `cargo check`, clippy and the tests decide. A faster checker can shorten the loop, but one without a borrow checker passes code rustc rejects.
2. Report test counts and which suites ran. Name anything you skipped and why.
3. Check that each new `#[expect]` has a reason a reviewer would accept.
4. Record any quirk you reproduced on purpose, and any debt you found, where the repo records debt.

## Reviewing Rust

- **Cite each finding.** Give the guideline ID (`M-…`) or the house rule number, so the author can read the reasoning instead of arguing with a paraphrase.
- **Rank by consequence.** A wrong order in emitted output or a test that can't fail matters more than a naming nit.
- **No compliance tables.** Don't add a table of the rules you followed to docs, PRs or crate READMEs (M-NO-META-DESIGN-DOCUMENTATION).
