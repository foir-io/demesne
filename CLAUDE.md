# CLAUDE.md

Guidance for Claude Code in this repository. Read `AGENTS.md` for the full layout, commands,
and the spec-to-enforcement workflow; this file is the short version of what matters most.

## Hard rules

- **No comments in code.** Strip them. Only `// Code generated … DO NOT EDIT.` and functional
  directives survive. A comment belongs only when there is a firm, concrete reason; if it is a
  maybe, remove it and make the code clearer.
- The engine (`/`) is standard-library only. Third-party dependencies (a database driver)
  live in the separate `cmd/demesne` and `pgx` modules.
- Keep every suite green and `golangci-lint` clean. Regenerate golden examples with
  `UPDATE_ORACLE=1`; never hand-edit a generated file.

## Fast commands

- Engine: `go test ./... && go vet ./... && golangci-lint run ./...`
- CLI: `cd cmd/demesne && go test ./...`
- pgx: `cd pgx && go test ./...`
- TypeScript: `cd ts && pnpm -r test`
- Regenerate examples: `UPDATE_ORACLE=1 go test -run TestEmitFramework_ExampleArtifact .`

## Cutting a release

**This repo has THREE Go modules, and Go resolves a submodule only from a path-prefixed tag.**
Tagging `vX.Y.Z` alone publishes the engine and leaves `pgx` unresolvable, so an adopter pinning
both gets `unknown revision pgx/vX.Y.Z` on every Go job — a red CI that looks like a code failure
and is not. That has happened.

1. Promote the CHANGELOG's `## Unreleased` heading to `## vX.Y.Z`.
2. Merge to `main`.
3. Tag **both**: `vX.Y.Z` (engine) and `pgx/vX.Y.Z`. Check what the previous release tagged —
   `git ls-remote --tags origin | grep -oE '(pgx|cmd/demesne)/v[0-9.]+$'` — and match it.
4. Bump `cmd/demesne/go.mod` and `pgx/go.mod` to require the new engine version, `go mod tidy`
   each with `GOWORK=off`, test, and push.
5. Verify **each** module resolves before telling an adopter it is ready:
   `GOWORK=off GOPROXY=proxy.golang.org go list -m github.com/foir-io/demesne@vX.Y.Z`
   and the same for `.../demesne/pgx@vX.Y.Z`.

The proxy caches a negative result, so a module fetched *before* its tag existed keeps 404ing for
a few minutes afterwards. Confirm the tag itself with `GOPROXY=direct` and wait the cache out
rather than assuming the tag is wrong.

**Order matters across repos:** release here first, then bump the adopter's pin. Pushing an
adopter PR that pins an untagged version reddens its CI on work that is fine.

## Mental model

One `.demesne` spec compiles to two things: a Postgres RLS enforcement floor (the moat) and an
equivalence-checked, typed application surface (Go and TypeScript). The database decides; the
generated `Can<Verb>` delegates to the same compiled predicate the RLS policy enforces. Do not
introduce a parallel evaluator, and do not let the application surface diverge from the floor.
