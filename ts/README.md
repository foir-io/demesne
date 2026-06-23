# Demesne — TypeScript emit target

The TypeScript half of Demesne's generated Layer-2 (read glue) + Layer-3 (control-plane
write) surface. It mirrors the Go split exactly:

| Go (engine) | TypeScript |
|---|---|
| hand-written runtime helpers in the `demesne` lib (`MintClaims`, `AssignInsert`, `Resolve`, …) | hand-written **`@demesne/runtime`** (`packages/runtime`) |
| `Render*Go` — render per-spec **data** as Go source | `emit_ts.go` `EmitTS` — render the per-spec **projection** as a TS module |
| `EmitFramework` — typed Go package over the engine (`Can<Verb>`, `Holds`, `Check`) | `EmitFrameworkTS` — typed TS module over `@demesne/runtime` (`canView`, `holds`, `check`) |

The projection IS the interface: `demesne emit <spec> --target ts` serializes a spec's
projections (claims contract, app surface, PDP, holds-resolver, role-assignment, level
grants, resource ACL) as typed TS literals that import `@demesne/runtime`. The runtime
reproduces every Go builder over that projection — **byte-for-byte**.

`demesne emit <spec> framework --target ts` goes one step further: it renders a typed,
ready-to-call module — `mint`/`sessionSetupSQL`, a per-object `canView`/`canEdit` +
`listResources`/`checkMany`, `@pdp` `can<Verb>(held)`, the `holds` resolver, a reusable
`check`, and a framework-agnostic `checkHandler` (`Request` → `Response`). It bakes the
same per-spec SQL the Go `EmitFramework` bakes (both from `EmitAppSurface`) and delegates
the shared logic to `@demesne/runtime`, so the generated `canView` runs the very predicate
the RLS policy enforces. `packages/example-app/generated/framework.ts` is the committed
worked example; `test/framework.test.ts` round-trips it against a live Postgres.

## Packages

- **`packages/runtime`** — `@demesne/runtime`, zero runtime dependencies. The algorithms:
  claims/session minting, the verb PDP + `composeCan`, the holds-resolver
  (`scopeContains` / `resolve`) + vocabulary expansion, the delegation cap, the
  app-level read builders, and the Layer-3 write builders (role-assignment, level-grant,
  resource-ACL). Faithful ports of the Go runtime; the Go `*_test.go` golden tables are
  ported into Vitest.
- **`packages/example-app`** — a worked example. Stands up a real Postgres
  (`pg_ctl`, no Docker), applies the **emitted** RLS over a hand-written schema, and
  round-trips the runtime builders against it under the `authenticated` role — proving
  equal-by-delegation end-to-end (skips cleanly where Postgres is absent).

## Equivalence is proven, not asserted

`generated/oracle.json` (written by the Go test `TestOracle_Manifest`) carries, for a
battery of specs, the emitted projections **and** the expected output of every Go
builder. `packages/runtime/test/oracle.test.ts` replays each case through the runtime and
asserts byte-identity — so a field-name drift in the emitter or a logic drift in the
runtime fails immediately. Nothing is hand-transcribed.

## Commands

```sh
pnpm install
pnpm -r test         # runtime unit + oracle + example-app round-trip
pnpm -r typecheck

# regenerate the engine-emitted fixtures after an intentional engine change:
UPDATE_ORACLE=1 go test -run 'TestOracle_Manifest|TestRoundtrip_Fixtures'
```
