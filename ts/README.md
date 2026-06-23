# Demesne — TypeScript emit target

Demesne compiles one spec into a Postgres enforcement floor and a typed application surface. This module is the TypeScript half of that surface. From a spec you get a generated, typed authorization API — `canView`, `holds`, `check` — that mirrors the Go one and runs the same compiled predicate the RLS policy enforces. The two are proven equivalent, not assumed to be.

The surface has two parts: read glue, which checks access on the way out, and control-plane writes, which assign roles, grants, and per-record sharing. Each piece lines up with its Go counterpart:

| Go (engine) | TypeScript |
|---|---|
| hand-written runtime helpers in the `demesne` lib (`MintClaims`, `AssignInsert`, `Resolve`, …) | hand-written `@demesne/runtime` (`packages/runtime`) |
| `Render*Go` — render per-spec data as Go source | `emit_ts.go` `EmitTS` — render the per-spec projection as a TS module |
| `EmitFramework` — typed Go package over the engine (`Can<Verb>`, `Holds`, `Check`) | `EmitFrameworkTS` — typed TS module over `@demesne/runtime` (`canView`, `holds`, `check`) |

## What the emitter produces

A spec's projection is the interface between the two sides. It is the per-spec data the runtime needs: the claims contract, app surface, policy decision point, holds-resolver, role-assignment, level grants, and resource ACL.

`demesne emit <spec> --target ts` serializes that projection as typed TS literals that import `@demesne/runtime`. The runtime reproduces every Go builder over the projection, byte for byte.

`demesne emit <spec> framework --target ts` goes one step further and renders a typed, ready-to-call module:

- `mint` and `sessionSetupSQL` for claims and session setup;
- per-object `canView` / `canEdit`, plus `listResources` and `checkMany`;
- `can<Verb>(held)` for verb permissions;
- the `holds` resolver and a reusable `check`;
- `checkHandler`, a framework-agnostic `Request` → `Response` entry point.

The framework module bakes the same per-spec SQL the Go `EmitFramework` bakes. Both come from `EmitAppSurface`. It delegates the shared logic to `@demesne/runtime`, so the generated `canView` runs the very predicate the RLS policy enforces — there is no second evaluator to drift.

`packages/example-app/generated/framework.ts` is the committed worked example. `test/framework.test.ts` round-trips it against a live Postgres.

## Packages

- `packages/runtime`: `@demesne/runtime`, with zero runtime dependencies. It holds the algorithms: claims and session minting, the verb policy decision point and `composeCan`, the holds-resolver (`scopeContains` / `resolve`) and vocabulary expansion, the delegation cap, the app-level read builders, and the write builders for role assignment, level grants, and resource ACLs. These are faithful ports of the Go runtime, and the Go golden tables from `*_test.go` are ported into Vitest.
- `packages/example-app`: a worked example. It stands up a real Postgres with `pg_ctl` and no Docker, applies the emitted RLS over a hand-written schema, and round-trips the runtime builders against it under the `authenticated` role. This proves the TypeScript path agrees with the database end to end. It skips cleanly where Postgres is absent.

## Equivalence is proven, not asserted

The Go and TypeScript surfaces are checked against a shared oracle.

`generated/oracle.json`, written by the Go test `TestOracle_Manifest`, carries — for a battery of specs — the emitted projections and the expected output of every Go builder. `packages/runtime/test/oracle.test.ts` replays each case through the TypeScript runtime and asserts byte-identity. A field-name drift in the emitter or a logic drift in the runtime fails immediately. Nothing is hand-transcribed.

## Commands

```sh
pnpm install
pnpm -r test         # runtime unit + oracle + example-app round-trip
pnpm -r typecheck

# regenerate the engine-emitted fixtures after an intentional engine change:
UPDATE_ORACLE=1 go test -run 'TestOracle_Manifest|TestRoundtrip_Fixtures'
```
