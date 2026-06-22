# How Demesne compares

Demesne sits in the Zanzibar-class / policy-as-code landscape but makes one structural choice
the others don't: it compiles authorization **into Postgres** as Row-Level Security, so the
decision rides every query instead of being an API the application must remember to call.

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

The moat is the enforcement locus: Demesne compiles one spec into a fail-closed Postgres RLS
floor (a `SECURITY DEFINER` role-resolution kernel, `USING`/`WITH CHECK` policies, `FORCE
RLS`), so authorization rides every query inside the database rather than being an API the
application has to remember to call — a forgotten check or an ad-hoc raw query is still
filtered, which is exactly the property every system here trades away by living outside the
data path. Because authz reads the *same* domain rows in the *same* transaction, there is no
second datastore, no dual-write, and no consistency token to reconcile two timelines. The same
spec also generates an equivalence-checked app layer (`Check` / `ListResources` / `CheckMany`
plus typed Go and TypeScript codegen), so the in-app surface is verified against the floor
rather than being the sole gate.

Honestly, this is **not** a planet-scale, datastore-agnostic standalone `Check` service:
Demesne is Postgres-only (a Supabase profile ships), it is a library/compiler + CLI rather than
a globally replicated service, and every rule must be SQL-expressible. Its reverse
"who-can-access" answers are coverage-gated and fail-closed, **not provably complete** — the
dimension where OpenFGA's native `ListObjects`, Cerbos's `PlanResources`, and Oso's
same-policy list filtering are stronger.

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
