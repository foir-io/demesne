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
| 11b | Composition-parent cascade (1-hop) | `tuple_to_userset` over a structural EDGE table, same object, calling verb | `relation … via composition Edge(child, parent) [where kind = "v"]` | a definer over the edge runs the PARENT row's own predicate at the CALLING verb (read/write/delete), with composition **pruned** from that predicate → strictly 1-hop, no recursion / cycle hang; the accessor enumerator splits `<t>_direct_accessors` + the 1-hop reverse cascade | Definer | ✅ |
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

## Layer 2 — the holds-resolver (closing the compiler→framework gap, EID-334)

Rows 1–14 are **enforcement** (Layer 1): generated RLS + the SECURITY DEFINER
kernel, where the database is both the source of truth and the runtime check. But
`PDP.Authorize(proc, holds)` and the emitted verb map take a `holds(perm) → bool`
callback the engine never computed — so every adopter hand-wrote "given a principal
+ scope, what permission set do they hold?" from the same rolestore + vocabulary the
engine already compiles the role definers from. That is now generated
(`holds.go`):

- **Read** — `HoldsResolver.AssignmentsSQL()` builds the GENERIC active-assignment
  query for a principal across all scopes (`$1` = principal id, filtered by
  kind + subject + not-revoked); the **caller** executes it (under the principal's
  claims, or as a trusted read for another subject). Same read/compute split, and the
  same moat, as the `access_runtime.go` grant template — the engine shapes the
  statement, the database returns the rows. It deliberately omits adopter-specific
  *admission* policy (a disabled role, an RP/client-scoped grant, a role-key
  allowlist): those are the adopter's policy, not the rolestore grammar, so a caller
  that needs them composes them itself (the engine bakes in no policy).
- **Compute** — `HoldsResolver.Resolve(rows, scope)` keeps each assignment whose
  scope **contains** the query scope (the containment match derived from the
  rolestore's scope columns: the **root** column is a strict tenancy boundary — an
  unpinned root never matches a real query — while a grant pinned at a deeper level
  covers that level's whole subtree, so a higher-level grant answers a lower-level
  query but never the reverse) and unions their permissions into an `EffectivePerms`
  whose `Holds(perm)` method **is** the `PDP.Authorize` callback. This compute
  reproduces the hand-written effective-permission resolver exactly.
- **Expand** — `Vocabulary.PresetPermissions` turns a preset into its flat
  permission set (`*`, nested refs, fail-closed on cycles) + rank helpers. A role's
  permissions come from a materialized `permissions` column when the rolestore
  declares one (so operator-configured **custom** roles resolve verbatim, not only
  vocabulary presets), else from this expansion.

Pure stdlib and target-neutral: `AssignmentsSQL` is a plain statement and the
materialized-column compute is a small transform over the resolver's plain-data
projection, so a TypeScript target reproduces it from the same projection (a non-Go
target reproducing the *expand* path must also project the vocabulary). Nothing is
Foir-specific — the rolestore, scope columns and vocabulary are all spec-declared
(EID-267 / EID-315). The **compute** replaces the effective-permission logic the
**two** hand-written resolvers a real adopter (Foir) carried share
(`session.AdminEffectivePermissions` + `AdminEffectivePermissionsForUser`); their
read-time *admission* filters stay adopter policy (the documented read-filter delta).

Proof: `holds_test.go` (preset/rank expansion incl. star, nested refs, cycle
fail-close; the scope-containment matrix; materialized vs key-expansion union). The
no-drift proof — the generated resolver reproducing Foir's two hand-written ones over
the real `foir.demesne` spec — lives consumer-side (`demesne_holds_test.go`), where
the database and Foir's code are.

## Layer 2 — the session/claims wrapper (closing the compiler→framework gap, EID-334)

The other Layer-2 glue every adopter re-writes: going from a principal to an
in-force RLS session. The engine emits the claims *contract* and ships `MintClaims`/
`ClaimsSetSQL`, but never the principal→claims mapping nor the session envelope — so
Foir hand-maps the blob (`db.BuildRLSClaims`: `UserID→sub`, `TenantID→tenant_id`, …)
and hand-writes the `SET LOCAL ROLE authenticated` + `set_config` sequence
(`db.WithRLS`). Both are now derived from the spec (`session.go`):

- **Contract (structured)** — `ClaimsContractEntries()` enriches the flat
  `ClaimsContract()` into `[{Key, Level, Subjects}]`: each key plus its source — the
  topology level whose scope id feeds it, and/or the subjects whose `identifies`
  feeds it. `ClaimsContract()` now delegates to it, so the flat key list is
  byte-identical (the generated artifact is unchanged).
- **Build** — `BuildClaims(Principal{Subject, ID, Scopes})` maps a principal onto the
  contract: the subject id → its `identifies` key, each presented scope id → that
  level's claim key (the override or the `<level>_id` convention). Fail-closed: an
  unknown subject, a subject with no identity key, or a scope for an unknown/virtual
  level is rejected (never mint a claim no policy reads). `MintClaimsFor` pairs it
  with `MintClaims`; a session with non-contract keys adds them to the map first.
- **Envelope** — `SetRoleSQL(local)` + `SessionSetupSQL(local)` build the
  WithRLS-shaped statement sequence (`SET [LOCAL] ROLE <role>` then the claims
  `set_config`); the caller runs them in its tx (no driver in the engine — the moat).
  The RLS connection role is spec-declared (`claims … role <r>`), defaulting to
  `authenticated` exactly as the GUC defaults to `request.jwt.claims` and the definer
  schema to `auth` — so the engine bakes in no role name and Foir renders identically.

Pure stdlib and target-neutral: `ClaimEntry`/`Principal` are plain data, `BuildClaims`
is a pure transform over the spec's levels + subjects, the SQL builders return strings.
Nothing is Foir-specific (EID-267 / EID-315). Parity is scoped precisely: `BuildClaims`
reproduces `BuildRLSClaims` for every key it emits (the scope keys + the subject
identity); the keys `BuildRLSClaims` adds — `role` (vestigial), `kind` (the
principal-kind discriminator, read by `@kind` but outside the topology+subject
contract), `owner_kind`/`owner_id` (secrets-DB only), and `sub` for a customer (Foir
mirrors the id; the spec attributes a customer's identity to `customer_id`) — are
documented deltas an adopter layers on, not spec-contract keys.

Proof: `session_test.go` (structured contract; BuildClaims mapping + claim-key
overrides + fail-closed rejections; the envelope shape, default and spec-declared
role). The no-drift proof — `BuildClaims`/`SessionSetupSQL` reproducing
`BuildRLSClaims`/`db.WithRLS` over the real `foir.demesne` spec, the deltas pinned,
and a dev-DB forward proof that the derived blob yields the same RLS row visibility as
the hand-mapped one — lives consumer-side (`demesne_session_test.go`).

## Layer 3 — role-assignment management (closing the compiler→framework gap, EID-334)

The control-plane WRITE side of the rolestore — the dual of the holds-resolver's read.
The engine compiles the role-resolution READ definers from the rolestore but never the
writes that MAINTAIN it, so every adopter hand-writes assign / revoke / list (Foir:
`AssignRole`/`RevokeRoleAssignment`/`ListRoleAssignments*` over hand-authored sqlc).
They are derivable from the same rolestore declaration, exactly as the per-object ACL
writes are in `access_runtime.go` (the template this mirrors). `RoleAssignmentSurface`
(`role_assignment_runtime.go`) projects the store and builds:

- **AssignInsert** — the `INSERT … RETURNING` that confers a role at a scope (kind
  inlined as the compile-time constant; the supplied id, subject, role, scope and — when
  declared — grantor bound; `granted_at` left to the table default).
- **RevokeSQL** — the idempotent soft-revoke (`UPDATE <revoked> = now()[, <revoked_by> =
  $2] WHERE <pk> = $1 AND <revoked> IS NULL`).
- **ListForRoleSQL / ListForPrincipalSQL** — the by-role audit view (active + revoked)
  and the by-principal active view joined to the role's key + materialized permissions.

Same read/compute boundary and moat as the rest: these BUILD SQL + ordered args; the
caller executes them under `WithRLS`, and the **`role_assignments` object's own RLS is
the write moat** (an out-of-scope `INSERT`/`UPDATE` is denied — the engine never
re-checks). The write surface's columns are optional, additive rolestore declarations
(`pk`, `granted <at> [by <by>]`, `revoked <col> [by <by>]`) — no read emitter references
them, so declaring them leaves all generated authz byte-identical. GENERIC by
construction: it bakes in no RP/client secondary scope, no reactivate-on-reassign upsert
over an adopter unique index, and no disabled-role admission filter — those are adopter
policy composed around the statements (the management delta, the write-side analogue of
the holds-resolver's read-filter delta). The intersection-cap delegation guard ("can't
grant a role you don't hold") is a separate primitive (EID-334 #4).

Target-neutral: `RoleAssignmentSurface` is plain data and the builders return strings +
ordered args. Proof: `role_assignment_runtime_test.go` (full + minimal surface, pk
override, short-scope, no-rolestore). The no-drift proof — the generated builders
reproducing Foir's hand-written queries over the real `foir.demesne` rolestore (Revoke
byte-identical; Assign/List column tuples minus the pinned `client_id` + `ON CONFLICT`
deltas) plus a dev-DB assign→list→revoke round-trip under RLS with an out-of-scope DENY —
lives consumer-side (`demesne_role_assignment_test.go`).

## Layer 3 — the delegation cap (closing the compiler→framework gap, EID-334)

The generic ReBAC guard on conferring authority: **"you cannot grant a permission you
do not hold."** Without it an in-scope grantor could author/assign a role carrying more
than the grantor holds (privilege escalation). The RFC calls this out as *generic ReBAC
policy, not adopter policy* — yet Foir hand-wrote it (`AuthorizeAdminRoleGrant`:
`adminperm.Unknown` for vocabulary validity + `adminperm.Subset` for the intersection).
It is derivable from the vocabulary + the grantor's held set, so the engine computes it
(`delegation.go`): `Vocabulary.CapGrant(held, requested) → DelegationCap{Allowed,
Unknown, Excess}` — `Unknown` = requested perms outside the vocabulary (fail-closed),
`Excess` = valid perms the grantor doesn't hold (the cap). The two failure classes are
disjoint, each carrying its own denial reason.

Pure compute, no SQL, no policy re-evaluation — it folds two sets the caller already
has: the vocabulary's permission list (the engine owns it) and the grantor's effective
held set, which is exactly the `EffectivePerms` the holds-resolver (Layer 2) resolves,
so the two compose directly. GENERIC by construction: it owns *only* the intersection
cap + validity — the rank **floor** ("must be ≥ project_admin to author at all", via the
shipped `RankOf`/`PresetsAtOrAbove`), a higher-plane **bypass** (platform staff skip the
cap), and the principal-kind check are adopter policy a caller wraps around it. Nothing
is Foir-specific — the vocabulary is spec-declared (EID-267 / EID-315).

Proof: `delegation_test.go` (allowed / excess / unknown / dedup / rank-floor
composition). The no-drift proof — `CapGrant.Unknown` reproducing `adminperm.Unknown`
and `CapGrant.Excess`-empty reproducing `adminperm.Subset` over the real `foir.demesne`
admin vocabulary, plus a **full reconstruction of `AuthorizeAdminRoleGrant`** (CapGrant
+ the rank ladder + the kind/bypass glue) matching the live function's allow/deny + error
code across its own matrix — lives consumer-side (`demesne_delegation_test.go`),
demonstrating the Foir swap is mechanical.

## Layer 3 — level-grant management (closing the compiler→framework gap, EID-334)

The control-plane WRITE side of a `grant … via edge` store (operator / impersonation
reach) — the dual of the reach definer. The engine compiles the READ
(`auth.<table>_reach`, a SECURITY DEFINER EXISTS over the edge with the active/expiry
predicate) but never the writes that MAINTAIN the edge — issue / revoke / list — so
every adopter hand-writes them (Foir: `GrantImpersonation` / `RevokeImpersonation` /
`ListImpersonationGrants`). They are derivable from the same grant declaration, exactly
as the role-assignment writes are (the sibling this mirrors). `GrantSurface`
(`grant_runtime.go`) projects the grant and builds:

- **GrantInsert** — issue a grant (the grantee reaches the level node): writes pk /
  grantee / level / grantor / expiry, leaves created-at to the table default and the
  active/revoker columns NULL. Adopter edge columns the grammar doesn't model
  semantically (e.g. an audited justification) are declared `column <col>` and are both
  WRITTEN (value from GrantInsert's `extra`) and PROJECTED in every RETURNING/SELECT —
  so a response that echoes them is not silently emptied (the drop-in requirement).
- **RevokeSQL** — a SOFT-revoke (stamp the active column + revoker, idempotent) when the
  grant declares an active column, else a hard `DELETE`.
- **ListSQL** — three optional filters ($1 grantee, $2 level, $3 active-only). The
  active predicate is built from the grant's own `ActiveCol`/`ExpiresCol` — **byte-for-
  byte the conjuncts the reach definer uses** (`<active> IS NULL`, `<expires> > now()`)
  — so management and enforcement agree on "active" by construction.

The level-grant moat differs from the role-assignment one: the edge is the
root-of-trust and deliberately exposes NO app-role write policy (a self-grant must be
impossible), so its writes run on the privileged pool behind an **eligibility gate the
adopter owns** (Foir: "is staff"). This layer shapes the statements and never decides
who may call them. The write-surface columns (`pk`, `granted by`, `revoked by`,
`created`, `column <col>`) are optional, additive grant declarations — read by no
emitter, so byte-identical for Foir. Target-neutral; nothing names a tenant/operator
(the table, columns and level are spec-declared, EID-267 / EID-315).

Proof: `grant_runtime_test.go` (full + minimal surface, multi-`column` projection in
declaration order, the active-predicate degradations, hard-DELETE fallback, no-grant
error). The no-drift proof — the generated builders reproducing Foir's hand-written
`impersonation_grants` queries (full column-set parity incl. the declared `reason`
extra; the list filter/predicate/order byte-identical; the only revoke delta a
placeholder-order swap) **plus a dev-DB round-trip where the generated issue makes
`auth.impersonation_grants_reach` TRUE and the generated revoke makes it FALSE** (writes
maintain exactly what the reach definer reads, and the projected `reason` is echoed
back) — lives consumer-side (`demesne_grant_test.go`).
