# Demesne

Write your authorization rules once, in a single spec file. Demesne compiles them into Postgres Row-Level Security, so the database enforces access on every query — a forgotten `WHERE` clause, a background job, or an ad-hoc `psql` session can't reach data the rules forbid.

It takes the idea behind Google's Zanzibar — a declarative schema of who-relates-to-what — but skips the separate authorization service. There's no `Check` API to call, no second datastore to keep in sync, no consistency tokens. The policy lives in the one place it can't be bypassed: the data path.

## The problem

Authorization usually lives in application code — a service you call, or `if` checks spread across handlers. Both only protect the paths that remember to ask. Miss one and the rule isn't there.

Demesne moves the decision into Postgres, so access is a property of the data rather than a step in the request. One `.demesne` file compiles to two layers:

- **Row-Level Security — the enforcement floor.** Demesne generates the policies and the trusted `SECURITY DEFINER` functions they call. Every query is filtered by the same rules, whether it comes from your app, a cron job, or a database console.
- **A verb gate — for actions RLS can't see.** Some permissions aren't about rows ("can this user *publish*?"). For those, Demesne generates a Go and TypeScript capability map you check at the request boundary.

The same spec also produces the JWT claims your sessions carry. Change the spec, regenerate, and the database floor and the application code move together — nothing to hand-write and keep in sync.

## How it works

A spec describes four things:

- a **topology** — your tenancy shape, e.g. `tenant → project`;
- the **subjects** that act — users, customers, staff;
- the **objects** they act on — your tables;
- the **relations and permissions** that connect them — ownership, roles, sharing, group membership.

From those, Demesne emits the RLS policies, the `SECURITY DEFINER` kernel, the verb-gate map, and the claims contract. Every trusted function is generated, so there's no opaque hand-written SQL to audit — and the test suite applies the generated SQL to a real Postgres and checks the live policies match what it emitted, byte for byte.

```go
import "github.com/eidestudio/demesne"

spec, _ := demesne.Parse(src)      // text → AST
demesne.Validate(spec)             // static checks

rls, _    := spec.EmitRLS()        // Postgres RLS policies
pdp, _    := spec.EmitPDP()        // Go capability map
defs, _   := spec.EmitDefiners()   // the SECURITY DEFINER kernel
claims, _ := spec.ClaimsContract() // the JWT claims the policies read
```

Adopting Demesne on an existing database is a short loop: introspect the schema, scaffold a starter spec, edit it, emit the SQL, apply it as a migration. [GUIDE.md](GUIDE.md) walks through it end to end.

## The spec language

[`examples/example.demesne`](examples/example.demesne) is a complete worked spec — a small document app. The building blocks:

| Block | Declares |
| --- | --- |
| `topology` | the tenancy hierarchy; a `virtual` root sits above tenancy |
| `vocabulary` | permissions, presets, and a rank ladder |
| `rolestore` | where role assignments live, so the role checks can be generated |
| `subject` | who acts: where they sit in the hierarchy, how far they reach, how they're identified |
| `object` | a governed table — its relations, permissions, and optional per-record sharing |
| `grant` | a scoped, revocable, expiring grant of reach into part of the hierarchy |

Permissions are a small boolean algebra over those terms — union, intersection, and fail-closed negation — so `viewer and not banned` or `(owner or shared) and not banned` compile straight to an RLS predicate.

## Worked examples

The patterns that are easy to get subtly wrong by hand are each a few lines of spec, and each ships with a test that asserts the generated policy actually enforces the intended reach:

| Pattern | Spec |
| --- | --- |
| Folder → document inheritance, unbounded nesting | [`inheritance.demesne`](examples/canonical/inheritance.demesne) |
| Groups within groups (transitive membership) | [`groups.demesne`](examples/canonical/groups.demesne) |
| Role-based access control | [`rbac.demesne`](examples/canonical/rbac.demesne) |
| `viewer ∩ member − banned` | [`boolean.demesne`](examples/canonical/boolean.demesne) |

Run them with `go test . -run TestCanonical`.

## How it compares

Demesne is a Zanzibar-class relationship model, but it compiles into Postgres instead of running as a separate `Check` service. [CAPABILITIES.md](CAPABILITIES.md) has the full matrix and an honest comparison with Zanzibar, Ory Keto, OpenFGA, Cerbos, and Oso — including where each of those is the better fit.

## What to expect

- **Postgres only.** Compiling to RLS is the whole idea; a Supabase deployment profile ships ([SUPABASE.md](SUPABASE.md)).
- **A library and CLI, not a service** — nothing extra to run or scale next to your database.
- **Every rule must be expressible as a SQL predicate.** Reverse "who can see this?" queries are supported but deliberately conservative (fail-closed), not exhaustive.
- **No dependencies in the core.** The engine module is standard-library only and never opens a connection; the CLI is a separate module that links a Postgres driver for its live-database commands.

## Development

```sh
go build ./...
go vet ./...
go test ./...
```

## License

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
