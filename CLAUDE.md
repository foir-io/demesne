# CLAUDE.md

Guidance for Claude Code in this repository. Read `AGENTS.md` for the full layout, commands,
and the spec-to-enforcement workflow; this file is the short version of what matters most.

## Hard rules

- **No comments in code.** Strip them. Only `// Code generated … DO NOT EDIT.` and functional
  directives survive. A comment belongs only when there is a firm, concrete reason; if it is a
  maybe, remove it and make the code clearer.
- The engine (`/`) is **standard-library only.** Third-party dependencies (a database driver)
  live in the separate `cmd/demesne` and `pgx` modules.
- Keep every suite green and `golangci-lint` clean. Regenerate golden examples with
  `UPDATE_ORACLE=1`; never hand-edit a generated file.

## Fast commands

- Engine: `go test ./... && go vet ./... && golangci-lint run ./...`
- CLI: `cd cmd/demesne && go test ./...`
- pgx: `cd pgx && go test ./...`
- TypeScript: `cd ts && pnpm -r test`
- Regenerate examples: `UPDATE_ORACLE=1 go test -run TestEmitFramework_ExampleArtifact .`

## Mental model

One `.demesne` spec compiles to two things: a Postgres RLS enforcement floor (the moat) and an
equivalence-checked, typed application surface (Go and TypeScript). The database decides; the
generated `Can<Verb>` delegates to the same compiled predicate the RLS policy enforces. Do not
introduce a parallel evaluator, and do not let the application surface diverge from the floor.
