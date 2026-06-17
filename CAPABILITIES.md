# Demesne capability matrix — every access pattern, and how it compiles

Demesne's claim is to be a general, Zanzibar-class authorization model whose
*enforcement compiles into Postgres RLS* (the moat) rather than a runtime Check
service. This matrix is the honest accounting of which access patterns it
expresses, how each one compiles, and what it costs. Every row is now general;
the platform/global plane (row 14) closed in v3 WS6.

The compiled mechanisms fall into three cost classes:

- **Inline** — a sargable predicate on the row's own columns (`x = claim`). No
  function call; the planner uses the table's indexes. Cheapest.
- **Definer** — a `SECURITY DEFINER` `EXISTS(...)` over an edge/role table. One
  indexed subquery per row-batch. Moderate.
- **Closure** — a trigger-maintained transitive-closure table + an indexed
  reachability lookup. Read-cheap, **write-amplified** (the trigger recomputes on
  writes to the base graph). Opt-in, and always banner-marked in the emitted SQL.

| # | Access pattern | Zanzibar analogue | Demesne spec construct | Compiles to (RLS) | Cost | Status |
|---|---|---|---|---|---|---|
| **Containment — "you're inside its container"** |
| 1 | Single-level tenancy scope | hierarchy (1 level) | `object … scoped tenant` | `tenant_id = claim` | Inline | ✅ |
| 2 | Multi-level chain / tree | folder hierarchy | `scoped tenant > project` | AND-chain of scope cols | Inline | ✅ |
| 3 | Multi-parent DAG | object in many parents | `level x parents a, b` | OR of per-lineage AND-chains | Inline | ✅ |
| 4 | Unbounded-depth hierarchy | recursive `tuple_to_userset` | `relation … via closure C(anc,desc) base B(id,parent) on col` | reachability definer (read) + maintenance trigger (write) | Closure | ✅ |
| **Ownership & per-record ACL — "it's yours / shared with you"** |
| 5 | Owner principal | direct tuple (`owner`) | `descriptor { owner customer via owner_id }` | `owner_id = claim` | Inline | ✅ |
| 6 | Per-record mode (public/private) | — (sentinel) | `descriptor { mode via access_mode; modes private + read "public_project" }` | mode-column check | Inline | ✅ |
| 7 | Per-record ACL grant list | direct tuples on an object | `descriptor { grants via edge record_acl(record_id, kind, principal, access) }` | definer `EXISTS` over the ACL edge | Definer | ✅ |
| 8 | Level-scoped grant / impersonation | tuple with a scope | `grant g at tenant via edge … ; subject operator reach via grant g` | grant-reach definer `EXISTS`, top OR-branch + role disjunct | Definer | ✅ |
| **Roles & usersets — "because of who you are"** |
| 9 | Role (computed userset) | `computed_userset` rewrite | `rolestore … ; subject admin roles configurable admin` + `vocabulary/preset/rank` | role definer `is_<level>_<role>` `EXISTS` (+ verb PDP) | Definer | ✅ |
| 10 | Nested groups (userset-of-usersets) | group-in-group `this#member` | `relation … via group C(group,member) edge E(member,group) on col` | membership-closure + transitive term | Closure | ✅ |
| 11 | Cross-object reference | `tuple_to_userset` (this#rel → that#rel) | `relation … via object Other->verb on col` | borrow the other object's predicate via definer at the related row | Definer | ✅ |
| **Composition & verbs** |
| 12 | Union / intersection / exclusion | `userset_rewrite` (∪ / ∩ / ∖) | `permission p = a + b` / `a and b` / `a and not b` | boolean predicate composition; negation fail-closed | (max of operands) | ✅ |
| 13 | Verb-level capability | — (RLS can't see verbs) | `permission publish = content:publish @pdp` | app-layer `PDP.Authorize` | (PDP) | ✅ |
| **Platform / global plane — "you're staff, on a table above tenancy"** |
| 14 | Global object governed by a **platform-level role** | a tenant at the schema root | `level platform virtual` + `subject staff anchor platform roles configurable platform` + `platform <table>` (global object) | a **generated** `has_platform_role` definer (`role_assignments` with NULL tenant/project scope) | Definer | ✅ |

## The platform plane (row 14) — closed (v3 WS6)

A handful of Foir tables live *above* the tenancy hierarchy — `admin_users`, the
`admin_*` satellites, `tenants`, `billing_events`, `customer_credentials`. They
have no `tenant_id`/`project_id`; they are global. They *were* governed by the
`is_platform_admin` **god-flag** — a standing boolean column on `admin_users`,
read by `auth.is_platform_admin(sub)`. That is precisely the legacy pattern this
generalisation surfaces and retires, not preserves.

Two engine capabilities close it, and they are the SAME primitives the rest of
the matrix already uses, lifted to the schema root:

1. **Platform-anchored roles** — `roleDefiner` pins a role's scope columns over
   its anchor's root→level path; a role anchored at the **virtual root** has no
   non-virtual ancestor, so every scope column is NULL and the signature is just
   `(user_id)`. It emits `has_platform_role(user_id)` =
   `EXISTS role_assignment WHERE tenant_id IS NULL AND project_id IS NULL AND
   role = '<role>' AND NOT revoked` — a revocable, audited platform role, the same
   role-resolution EXISTS as `is_tenant_admin` / `is_project_admin`.
2. **Global objects** — an object scoped at the **virtual root** (no containment
   columns; e.g. `object admin_users { table admin_users; scoped platform; use
   contained }`). A virtual-anchored *role* subject
   (`isPlatformRoleSubject`) contributes the platform-role definer as the policy's
   whole top branch; there is no containment to AND against, and `rlsPredicate`
   emits exactly that branch (never a bare `OR ()`).

So `is_platform_admin` retires the **general** way (the generated definer is named `has_platform_role`, not the legacy flag): the god-flag column and its
hand-written function are dropped, the global tables become objects scoped at the
virtual root, and their staff-access definer is *generated* — a revocable
`platform_admin` role in `role_assignments`, identical in shape to every other
role in the system. No bespoke hand-written one-off; the generated
`has_platform_role` is the same role primitive that governs tenant and project
roles, lifted to the platform root. The blunt
virtual-anchored **membership** operator stays in the engine as a valid option
for other adopters, but it is the pattern Foir is leaving.

Proof: `platform_plane_test.go` (a global object scoped at the virtual root compiles
to the generated `has_platform_role` role branch; the grant operator and the platform
role do not bleed across the tenancy boundary — forward isolation).
