# @foir/demesne-cli

The Demesne CLI, distributed as a prebuilt binary for the JavaScript toolchain. Compile one
`.demesne` spec into a Postgres RLS enforcement floor and a typed, equivalence-checked app surface.

```sh
npx @foir/demesne-cli emit app.demesne all
# or install it
npm i -D @foir/demesne-cli
```

This package is a thin launcher: on install, npm pulls the one
`@foir/demesne-cli-<platform>` optional dependency that matches your OS and CPU, and the `demesne`
bin execs that binary. No Go toolchain required.

Prefer a standalone binary? Grab one from the [GitHub releases](https://github.com/foir-io/demesne/releases), or build from source — clone the repo and run `go build ./cmd/demesne`.

See the [project README](https://github.com/foir-io/demesne#readme) for the spec grammar and
the full command reference (`demesne help`). Licensed under Apache-2.0.
