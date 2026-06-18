# Demesne — a guide for adopting it on your Postgres app

Demesne compiles **one declarative authorization spec** into a Postgres
**Row-Level-Security** policy set, the **SECURITY DEFINER kernel** those policies
call, a **verb-level PDP** (the capability map RLS can't express), and the **JWT
claims contract** your sessions must present. Enforcement lives in the database —
not in a runtime authorization service — so a row is provably invisible to the
wrong tenant at the storage layer, not merely in your app code.

It borrows Zanzibar's *declarative schema* and rejects its *runtime*: there is no
Check service, no parallel reachability evaluator. The trade is deliberate and is
the moat. The honest niche: **multi-tenant Postgres apps with a hierarchical
tenancy + an ACL grant tail.**

This guide is for an engineer adopting Demesne on their own database — no
knowledge of any particular deployment assumed.

---

## The workflow

```
introspect → scaffold → edit the spec → validate → check → emit → apply → verify
```

1. **Introspect** your database and **scaffold** a starter spec:

   ```
   demesne scaffold "$DATABASE_URL" > authz.demesne
   ```

   The starter infers your tenancy hierarchy from the foreign-key graph and emits
   one containment-only object per scoped table. It is a **draft** — the schema
   cannot tell a tenancy *level* (a container every row lives in) from an owner
   *principal* (a customer/user a row belongs to); both look like "a table many
   rows reference." Review every line.

2. **Edit** `authz.demesne` to express your real policy: mark which inferred
   "levels" are actually owner principals, add owner axes, roles, descriptors
   (per-record ACLs), and subjects. See the language reference below.

3. **Validate** the spec, and **check** it binds to your live schema:

   ```
   demesne validate authz.demesne
   demesne check    authz.demesne "$DATABASE_URL"
   ```

   `check` fails loudly if the spec references a table or column your database
   doesn't have (a typo, a missing migration, drift).

4. **Emit** the generated SQL and apply it as a normal migration:

   ```
   demesne emit authz.demesne all > 0001_authz.sql   # definers + policies + triggers
   # review it, then run it in your migration tool
   ```

   Demesne owns the idempotent **policy + definer + closure-trigger + RLS
   enablement** layer (`emit … all` includes `ENABLE`/`FORCE ROW LEVEL SECURITY`
   per governed table — a policy is *inert* on a table where RLS isn't enabled,
   and a non-`FORCE`d table lets the owner read past it, so the moat requires
   both). Tables, columns, indexes, and `GRANT`s stay your own migrations.

5. **Verify** drift any time:

   ```
   demesne diff authz.demesne "$DATABASE_URL"
   ```

   Reports any generated policy missing live, or any **orphan** policy live on a
   governed table but not generated (RLS policies are permissive — an orphan is an
   open path).

---

## The CLI

| command | needs a DB | what it does |
|---|---|---|
| `demesne validate <spec>` | no | parse + validate the spec |
| `demesne emit <spec> [rls\|definers\|triggers\|claims\|pdp\|all]` | no | print the generated SQL/Go |
| `demesne introspect <dsn>` | yes | summarise the live schema |
| `demesne scaffold <dsn>` | yes | generate a starter spec from the schema |
| `demesne check <spec> <dsn>` | yes | validate, then bind the spec to the live schema |
| `demesne diff <spec> <dsn>` | yes | generated-vs-live policy drift |

`<dsn>` defaults to `$DATABASE_URL`. The engine package never touches a database;
only the CLI links a Postgres driver, for the live-database subcommands.

---

## The spec language, briefly

```demesne
// How a claim is read from the session, and the RLS connection role a session
// assumes (defaults shown; omit the block to use them). `role` is optional.
claims via "request.jwt.claims" json role authenticated

// The tenancy shape: a DAG of levels. One parent = a chain/tree; `parents A, B`
// = a multi-parent DAG; `virtual` = a synthetic root with no scope column.
topology {
  level tenant
  level project parent tenant
}

// A verb grammar → the capability PDP. Presets bind at a @level; rank delegates.
vocabulary admin {
  permission content:read   permission content:write
  preset viewer @ project = content:read
  preset owner  @ tenant  = *
  rank owner > viewer
}

// Where role assignments live, so the compiler GENERATES the role definers.
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
}

// Actors. `binds owner|admin` declares a subject's plane explicitly.
subject admin    { anchor tenant  reach descendants identifies sub          roles configurable admin    binds admin }
subject customer { anchor project reach self        identifies customer_id  roles configurable customer binds owner }

// A named, reusable permission set the APP defines and applies with `use` — the
// generic way to name an access pattern (containment-only here) and reuse it.
template contained {
  permission view   = @scoped @rls maps select
  permission create = @scoped @rls maps insert
  permission edit   = @scoped @rls maps update
  permission delete = @scoped @rls maps delete
}

// A containment-only config table: inherits the template; supplies its own scope.
object configs { table configs; scoped tenant > project; use contained }

// A governed content table — composed from plain relations + terms (owner-
// origination, a per-record visibility mode, an app-managed grant store / ACL).
// owner is the unified (owner_id, owner_kind) principal reference.
object record {
  table  records
  scoped tenant > project
  relation owner:   customer via owner_id where owner_kind = "customer"
  relation grantee: customer via grant record_acl(record_id, principal_kind, principal_id, access)
  permission view = @app_scope + owner + mode access_mode = "public" + grantee:read   @rls maps select
  permission edit = @app_scope + owner + grantee:write                                @rls maps update
}
```

Permission expressions are a boolean algebra over the grant terms: **union**
(`a + b` / `a or b`), **intersection** (`a and b`), **exclusion / negation**
(`a and not b`), and parentheses, with precedence union < intersection < `not`.
So `viewer and member`, `viewer and not banned`, and `(owner + shared) and not
banned` all compile to RLS. Negation is **fail-closed**: an exclusion whose
condition can't be determined (a NULL claim) denies. A union-only expression is
unchanged.

Beyond this: **permission templates** (`template <name> { … }` + `object … use
<name>` — a named, reusable permission set the app composes from the generic terms
and applies uniformly; a using object may `omit` a verb or override one with its
own permission line), **level-scoped grants** (`grant … at <level> via edge …` — a
scoped, revocable operator/impersonation reach; a subject reaches via it
(`reach via grant <name>`), and a **permission** may be conferred by it directly
(`permission create = via grant <name>` — granted only to the grant's holders, with
the containment branch suppressed, e.g. an operator-only write that excludes a
tenant's own admins)), **unbounded-depth hierarchies**
(`relation … via closure <C>(anc,desc) base <B>(id,parent) on <col>` — the
compiler generates a trigger-maintained transitive-closure table + an indexed
reachability lookup, an explicit write-amplification cost), **nested groups**
(`relation … via group <C>(group,member) edge <E>(member,group) on <col>` —
group-in-group membership over a many-to-many edge, a userset-of-usersets; the
compiler maintains the membership closure and the RLS term tests transitive
membership), **cross-object references** (`relation … via object <Other>-><verb>
on <col>` — the general *tuple-to-userset*: this object's grant is "the caller
passes the related object's `<verb>` permission," borrowing whatever that object's
policy expresses, evaluated at the related row), and a spec-declared
**definer schema** (`definers schema "<name>"`). A level grant and a descriptor's
ACL edge are the *same* reachability-grant concept at different granularities
(level subtree vs one row) — unified declaratively, kept as separate physical
stores (never one generic tuple table).

---

## The runtime glue

Enforcement is in the DB; a little runtime still mints claims, enforces verbs, and
answers point-checks. The engine ships it as pure helpers (it never re-evaluates
policy in app code):

- **The session/claims wrapper** — go from a principal to an in-force RLS session
  without hand-mapping field names:
  - `Spec.ClaimsContractEntries()` — the **structured** claims contract: each key +
    its source (the topology level whose scope id feeds it, and/or the subjects whose
    `identifies` feeds it). `ClaimsContract()` is the flat key list (its keys).
  - `Spec.BuildClaims(Principal{Subject, ID, Scopes})` — maps a principal's typed
    inputs (which subject it is, that subject's id, the scope id per topology level)
    onto the contract: the subject id → its `identifies` key, each scope id → that
    level's claim key. The spec-derived replacement for a hand-written field map; a
    contract key added to the spec flows through with no code change. A session that
    also carries non-contract keys adds them to the returned map before minting.
  - `Spec.MintClaims(values)` / `Spec.MintClaimsFor(principal)` + `Spec.ClaimsSetSQL(local)`
    — render the validated `request.jwt.claims` blob (MintClaimsFor = BuildClaims then
    MintClaims) and the `set_config` statement that installs it.
  - `Spec.SetRoleSQL(local)` + `Spec.SessionSetupSQL(local)` — the WithRLS-shaped
    statement sequence: `SET [LOCAL] ROLE <role>` then the claims `set_config`, run in
    order in your tx (the second binds the minted blob to `$1`). The RLS role is
    spec-declared (`claims … role <r>`), defaulting to `authenticated`.
- `PDP.Authorize(procedure, holds) → Allow | Deny | NotGoverned` — the verb gate
  at your request boundary (RLS can't see verbs).
- `Spec.HoldsResolver(rolestore)` — the **holds-resolver**: it produces the `holds`
  callback `PDP.Authorize` takes, so you never hand-write "given a principal + scope,
  what permissions do they hold?".
  - `HoldsResolver.AssignmentsSQL()` builds the GENERIC active-assignment read —
    every role a principal holds across all scopes (`$1` = principal id; kind +
    subject + not-revoked) — that **you** execute (under the principal's claims, or
    as a trusted read for another subject); the engine never runs it. Adopter-
    specific admission rules (a disabled role, a client/RP-scoped grant) stay your
    policy: compose them around this read; the engine bakes in none.
  - `HoldsResolver.Resolve(rows, scope) → EffectivePerms` folds those rows into the
    effective permission set at a query scope: it keeps each assignment whose scope
    *contains* the query (the root column is a strict tenancy boundary; a grant
    pinned deeper covers that subtree, so a higher-level grant answers a lower-level
    query but never the reverse — derived from the rolestore's scope columns) and
    unions their permissions. `EffectivePerms.Holds` is the `PDP.Authorize` callback.
    A role's permissions come from a materialized `permissions` column when the
    rolestore declares one (so operator-configured *custom* roles resolve verbatim),
    otherwise from expanding its key through the vocabulary.
  - `Vocabulary.PresetPermissions(name)` — the preset → flat permission set
    expansion (`*`, nested preset refs, fail-closed on cycles); the same logic seeds
    or validates a materialized `permissions` column. `RankOf` / `PresetsAtOrAbove`
    expose the rank ladder for delegation.
- `Spec.RoleAssignmentSurface(rolestore)` — the control-plane **write** side of the
  rolestore (the dual of the holds-resolver's read), so you never hand-write the
  assign/revoke/list statements either:
  - `AssignInsert(id, subject, role, scope, grantedBy)` — the `INSERT … RETURNING`
    that confers a role at a scope (kind inlined; scope + grantor bound).
  - `RevokeSQL()` — the soft-revoke (`UPDATE <revoked> = now()[, <revoked_by>] WHERE
    <pk> = $1 AND <revoked> IS NULL`), idempotent.
  - `ListForRoleSQL()` / `ListForPrincipalSQL()` — the by-role audit view and the
    by-principal active view (joined to the role's key + permissions).
  These **build** SQL + ordered args you execute under `WithRLS`; the
  `role_assignments` table's own RLS is the write moat (an out-of-scope write is
  denied), so the engine never re-checks. The audit columns (`pk`, `granted … by`,
  `revoked … by`) are optional rolestore declarations; the intersection-cap
  delegation guard ("can't grant a role you don't hold") is a separate primitive.
- `Vocabulary.CapGrant(held, requested) → DelegationCap{Allowed, Unknown, Excess}` —
  the **delegation cap**, the generic "you can't grant a permission you don't hold"
  guard on authoring/assigning a role. `Unknown` is the requested perms outside the
  vocabulary (fail-closed); `Excess` is the valid perms the grantor doesn't hold (the
  cap). It composes directly with the holds-resolver — `held` is the grantor's
  `EffectivePerms.Permissions()` — and owns *only* the intersection + validity; a rank
  **floor** (via `RankOf`/`PresetsAtOrAbove`), a higher-plane **bypass**, and the
  principal-kind check are the adopter glue you wrap around it.
- `Spec.GrantSurface(name)` — the control-plane **write** side of a `grant … via edge`
  store (operator/impersonation reach), the dual of the reach definer:
  - `GrantInsert(id, grantee, level, grantedBy, expiresAt, extra)` — issue a grant (the
    grantee reaches that level node); declared extra columns (`column <col>`) are
    written from `extra` **and projected**, so a response echoing them isn't emptied.
  - `RevokeSQL()` — soft-revoke (stamp the active column) when the grant is revocable,
    else a hard `DELETE`; idempotent.
  - `ListSQL()` — grants with three optional filters ($1 grantee, $2 level, $3
    active-only), the **active predicate built from the grant's own active/expiry
    columns — the same conjuncts the reach definer uses**, so writes and reads agree.
  Build SQL + args; the caller runs them behind its own eligibility gate (the
  level-grant moat — the edge exposes no app-role write policy, so a self-grant is
  impossible). The audit/extra columns (`pk`, `granted by`, `revoked by`, `created`,
  `column <col>`) are optional grant declarations.
- `Spec.PointCheckSQL(object)` — a read-check **query** you run *under* the
  principal's claims; the **database** answers "can this principal see this row?"
  via the real policy. For UI affordances, never as a substitute for enforcement.

---

## What it is not

Not arbitrary general ReBAC, and not a Zanzibar/Permify-style Check service. The
graph reachability you express compiles to inline sargable predicates + SECURITY
DEFINER `EXISTS` + (opt-in) a closure index — all in Postgres, all on the query's
own plan. If you need a standalone authorization service evaluating relations at
request time across heterogeneous stores, that is a different tool. Demesne's bet
is that *enforcement compiled into your database* is worth the constraint.
