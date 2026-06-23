# How Demesne compares

Demesne is a Zanzibar-class relationship model, the same declarative who-relates-to-what idea behind systems like Ory Keto, OpenFGA, Cerbos, and Oso. What sets it apart is where the decision runs. Demesne compiles your rules into Postgres Row-Level Security, so access is enforced on every query rather than in an API the application has to remember to call.

This page lays out the differences side by side, explains the one structural choice that drives them, and is honest about when another system is the better fit.

## Capability matrix

| | **Demesne** | **Zanzibar** | **Ory Keto** | **OpenFGA** | **Cerbos** | **Oso** |
|---|---|---|---|---|---|---|
| **Enforcement locus** | Inside Postgres, on the query's own plan (RLS) | External ACL service | External service | External service | External sidecar PDP | External (Oso Cloud) or in-proc lib |
| **Authorization model** | ReBAC relations + verb-gate PDP | ReBAC (relation tuples + userset rewrites) | ReBAC (Zanzibar tuples) | ReBAC + ABAC (CEL conditions) | RBAC + ABAC + derived roles | RBAC / ReBAC / ABAC (Polar) |
| **Decision point** | The SQL query itself (predicates + `SECURITY DEFINER EXISTS`) | Out-of-band `Check` RPC vs Spanner snapshot | Out-of-process gRPC/REST `Check` | Out-of-process `Check` / `ListObjects` | In-process CEL eval over request payload | SDK call to Edge, or returned SQL filter |
| **Consistency** | Same rows, same transaction — no lag, no token | Strong via TrueTime + zookies | Eventually consistent | Eventually consistent | Stateless; freshness = caller's attrs | Eventually consistent facts |
| **Reverse queries (who-can-access)** | Coverage-gated, fail-closed — not provably complete | `Expand` (tree) | Partial, depth-bounded | First-class `ListObjects` / `ListUsers` | `PlanResources` partial eval + ORM adapters | First-class list / SQL `WHERE` filter |
| **Separate datastore** | None — reads existing domain tables | Yes (Spanner + Leopard) | Yes (own DB) | Yes (own store) | None (stateless) | Yes for Oso Cloud; none for the lib |
| **Spec / policy language** | One `.demesne` spec → SQL + Go/TS | Per-namespace config + rewrites | OPL DSL + tuples | Model DSL → JSON + CEL | YAML/JSON + CEL | Polar |
| **Bypass-resistance** | High — ambient; raw SQL as the app role is still filtered | Advisory — must call and obey | Advisory | Advisory | Advisory | Advisory — depends on call-site coverage |
| **Runtime footprint** | Library + CLI, no service | Large (Spanner, aclservers, Leopard) | Service + its own DB | Service + its own datastore | Stateless sidecar | Managed service (or in-proc lib) |

## Where Demesne is different

The one structural choice is where authorization runs: inside the database, on the data path, rather than in a service alongside it. Demesne compiles one spec into a fail-closed Postgres Row-Level Security floor — the layer queries can't get under. That floor is a trusted `SECURITY DEFINER` role-resolution kernel, the `USING` and `WITH CHECK` policies that call it, and `FORCE RLS` to apply them to everyone.

A few things follow from that:

- Access rides every query. A forgotten check or an ad-hoc raw query is still filtered, because the rule is part of the data path, not a step the caller chooses to take.
- There is no second datastore. Authorization reads the same domain tables in the same transaction, so there is no dual-write to keep in sync and no consistency token reconciling two timelines.
- The application layer is checked against the floor. The same spec generates a typed Go and TypeScript surface (`Check`, `ListResources`, `CheckMany`), and that surface is equivalence-checked against the policies the database enforces. The in-app code is a convenience, not the only gate.

Every other system in the matrix lives outside the data path, so it can only protect the calls that remember to ask.

That trade has costs, and they are real:

- Demesne is Postgres-only. Compiling to RLS is the whole point; a Supabase deployment profile ships.
- It is a library, compiler, and CLI, not a globally replicated service. There is nothing extra to run or scale next to your database, but also no planet-scale standalone `Check` service to call.
- Every rule must be expressible as a SQL predicate.
- Reverse "who can access this?" answers are coverage-gated and fail-closed. They are deliberately conservative, not provably complete. OpenFGA's native `ListObjects`, Cerbos's `PlanResources`, and Oso's same-policy list filtering are stronger here.

## Pick another system instead when…

- **Zanzibar** — you operate at Google scale (trillions of tuples, millions of checks/sec)
  across many polyglot services and need one datastore-agnostic ACL system with Spanner-backed
  strong consistency.
- **Ory Keto** — you want a mature, language-agnostic centralized ReBAC service decoupled from
  any single app or database.
- **OpenFGA** — you need first-class native reverse queries (`ListObjects` / `ListUsers`) and a
  vendor-neutral CNCF ecosystem across a non-Postgres or polyglot stack.
- **Cerbos** — you want zero authz state and a stateless sidecar deployable anywhere
  (edge / Lambda / air-gapped), over per-request attributes, with sound `PlanResources` filters
  across multiple ORMs.
- **Oso** — you want one expressive policy language spanning RBAC/ReBAC/ABAC across services
  with a managed, globally-distributed service, and you're not on Postgres or don't want
  DB-resident enforcement.
