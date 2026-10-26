# Demesne — TypeScript emit target

Demesne compiles one spec into a Postgres enforcement floor and a typed application surface. This module is the TypeScript half of that surface. From a spec you get a generated, typed authorization API — `canView`, `holds`, `check` — that runs the same compiled predicate the RLS policy enforces.

The surface has two parts: read glue, which checks access on the way out, and control-plane writes, which assign roles, grants, and per-record sharing. It has three pieces:

- `@foir/demesne` (`packages/runtime`): demesne's Rust runtime, `crates/runtime`, compiled to WebAssembly, behind a thin TypeScript API (`mintClaims`, `assignInsert`, `resolve`, …);
- `demesne emit <spec> --target ts`: the per-spec projection as a TS module;
- `demesne emit <spec> --target ts framework`: a typed module over `@foir/demesne` (`canView`, `holds`, `check`).

## What the emitter produces

A spec's projection is the interface between the two sides. It is the per-spec data the runtime needs: the claims contract, app surface, policy decision point, holds-resolver, role-assignment, level grants, and resource ACL.

`demesne emit <spec> --target ts` serializes that projection as typed TS literals that import `@foir/demesne`. The runtime runs every builder over the projection.

`demesne emit <spec> framework --target ts` goes one step further and renders a typed, ready-to-call module:

- `mint` and `sessionSetupSQL` for claims and session setup;
- per-object `canView` / `canEdit`, plus `listResources` and `checkMany`;
- `can<Verb>(held)` for verb permissions, and `caps(held)` — a typed, synchronous boolean per verb for UI affordance gating;
- `roleTiers(held)` — a typed, synchronous boolean per role tier (platform plane + scoped roles) for UI affordance gating;
- the `holds` and `holdsRoles` resolvers and a reusable `check`;
- `checkHandler`, a framework-agnostic `Request` → `Response` entry point.

The framework module bakes the per-spec SQL of the app surface (`Sql::emit_app_surface`). It delegates the shared logic to `@foir/demesne`, so the generated `canView` runs the very predicate the RLS policy enforces — there is no second evaluator to drift.

`packages/example-app/generated/framework.ts` is the committed worked example. `test/framework.test.ts` round-trips it against a live Postgres.

## Gating UI affordances

`caps(held)` projects the rolestore vocabulary's `domain:verb` permissions into a typed, synchronous boolean tree (`caps(held).docs.publish` from `docs:publish`) — no magic strings, no `Decision` unwrapping. Resolve `held` once, then read a boolean per permission. It is a UI hint only: enforcement stays the RLS floor and the verb gate, so removing a `caps` check never grants access — the database still says no.

```ts
const c = caps(held);

{c.docs.publish && <PublishButton />}       // React
{#if c.docs.publish}<PublishButton />{/if}  // Svelte
<PublishButton v-if="c.docs.publish" />     // Vue
```

Parameterized permissions (a `*` model segment, e.g. `records:write:*`) get no static field — a banner lists them; check those with raw `held.holds(...)`. `check(object, verb, id)` covers the row verbs; a verb-gate verb passed to `check` throws and points you to `can<Verb>(held)` rather than silently answering "ungoverned".

## Gating on role tier

`caps(held)` answers the verb axis ("can this principal *publish*?"). `roleTiers(held)` answers the orthogonal role-tier axis ("is this principal a *platform admin*? a *tenant owner*?"). A wildcard role (`tenant_owner = *`) or a global plane membership can't be read off the verb set, so this is a separate accessor over a separate held set. It projects the spec's role presets into a typed, synchronous boolean: the platform-plane roles first, then the rolestore's scoped roles. Like `caps`, it is a UI hint only. Enforcement stays the RLS floor and the generated SQL definers, so dropping a `roleTiers` check never grants access. The bare name `roles` is left for a governed object accessor (an app that manages a `roles` table), so the role-tier projection is `roleTiers`.

The input is a held-_roles_ set (`EffectiveRoles`), the role-key counterpart of `caps`'s held-_verbs_ set. Build it server-side from assignments with `holdsRoles(q, principalId, scope)` or `resolveHeldRoles(assignments, scope)`, or build it straight from a session with `newEffectiveRoles([...])`. The session path takes the scoped role keys effective at the current scope, plus `"platform_admin"` when the session carries the platform-admin flag.

```ts
const r = roleTiers(held);

{r.platformAdmin && <CrossTenantConsole />}    // React — staff operator surface
{#if r.tenantOwner}<TenantSettings />{/if}     // Svelte — own-tenant self-service
<InviteButton v-if="r.tenantOwner" />          // Vue
```

Scope semantics match the floor. A scoped role is held only at or below the scope it was granted at (root-strict). A role granted with an empty scope is a global plane role, held in every scope, which is how a platform admin reaches across tenants.

## Packages

- `packages/runtime`: `@foir/demesne`, with zero runtime dependencies. Its TypeScript is a thin layer over demesne's Rust runtime (`crates/runtime`) compiled to WebAssembly by `crates/runtime-wasm`. Rust adopters link that runtime natively, so there is one implementation of the algorithms: claims and session minting, the verb policy decision point and `composeCan`, the holds-resolver (`scopeContains` / `resolve`) and vocabulary expansion, the delegation cap, the app-level read builders, and the write builders for role assignment, level grants, and resource ACLs.
  - The API is synchronous. The default entry carries the module's bytes and compiles them on import, which Node and browsers allow. Cloudflare Workers forbid compiling bytes at runtime, so the package's `workerd` export condition imports the `.wasm` file as a module instead.
  - A size budget is checked on every build: at most 180 KB for the module, and 96 KB gzipped for everything the default entry loads.
- `packages/example-app`: a worked example. It stands up a real Postgres with `pg_ctl` and no Docker, applies the emitted RLS over a hand-written schema, and round-trips the runtime builders against it under the `authenticated` role. This proves the TypeScript path agrees with the database end to end. It skips cleanly where Postgres is absent.

## Equivalence is proven, not asserted

The native Rust runtime and its WebAssembly build are checked against a shared oracle.

`generated/oracle.json`, written by `UPDATE_ORACLE=1 cargo test -p demesne-parity --test oracle_manifest`, carries — for a battery of specs — the emitted projections and the expected output of every runtime builder. `crates/runtime/tests/oracle.rs` replays each case natively, and `packages/runtime/test/oracle.test.ts` replays it through the WebAssembly build behind the TypeScript API; both assert byte-identity. A field-name drift in the emitter or a logic drift in the runtime fails immediately. Nothing is hand-transcribed.

## Commands

```sh
pnpm --filter @foir/demesne build:wasm   # build the runtime's WebAssembly first: needs the Rust toolchain and wasm-bindgen
pnpm install
pnpm -r build        # also checks the size budget
pnpm -r test         # runtime unit + oracle + example-app round-trip, in Node
pnpm -r typecheck
pnpm --filter @foir/demesne test:workerd   # the same suite inside workerd, through the workerd export
pnpm --filter @foir/demesne test:browser   # the same suite in headless Chrome
pnpm --filter @foir/demesne test:packed    # the packed tarball, bundled and run in Node, workerd and Chrome

# regenerate the generated fixtures after an intentional change, from the repository root:
UPDATE_ORACLE=1 cargo test -p demesne-parity --test goldens --test oracle_manifest
```
