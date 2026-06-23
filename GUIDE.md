# Adopting Demesne on your Postgres app

This guide walks you through putting Demesne on an existing Postgres database, from a starter spec to enforced policies. It assumes you know your own schema and nothing about any particular deployment.

Demesne compiles one authorization spec into four things:

- a Postgres Row-Level Security policy set;
- the SECURITY DEFINER kernel those policies call;
- a verb-level PDP, the capability map RLS can't express;
- the JWT claims contract your sessions present.

Enforcement lives in the database, not in a separate authorization service. A row is provably invisible to the wrong tenant at the storage layer, not just in your app code.

It borrows Zanzibar's declarative schema but drops its runtime: there is no Check service and no parallel reachability evaluator. The trade is deliberate. Demesne fits multi-tenant Postgres apps that have a hierarchical tenancy plus an ACL grant tail.

---

## The workflow

```
introspect → scaffold → edit the spec → validate → check → emit → apply → verify
```

1. Introspect your database and scaffold a starter spec:

   ```
   demesne scaffold "$DATABASE_URL" > authz.demesne
   ```

   The starter infers your tenancy hierarchy from the foreign-key graph and emits
   one containment-only object per scoped table. Treat it as a draft and review
   every line. The schema can't tell a tenancy level from an owner principal:

   - A tenancy level is a container every row lives in.
   - An owner principal is a customer or user a row belongs to.

   Both look the same in the schema: a table that many rows reference.

2. Edit `authz.demesne` to express your real policy. Mark which inferred "levels"
   are actually owner principals, then add owner axes, roles, descriptors
   (per-record ACLs), and subjects. See the language reference below.

3. Validate the spec, and check it binds to your live schema:

   ```
   demesne validate authz.demesne
   demesne check    authz.demesne "$DATABASE_URL"
   ```

   `check` fails loudly if the spec references a table or column your database
   doesn't have — a typo, a missing migration, or drift.

4. Emit the generated SQL and apply it as a normal migration:

   ```
   demesne emit authz.demesne all > 0001_authz.sql   # definers + policies + triggers
   # review it, then run it in your migration tool
   ```

   Demesne owns one layer: the idempotent policies, definers, closure triggers,
   and RLS enablement. `emit … all` includes `ENABLE`/`FORCE ROW LEVEL SECURITY`
   for each governed table. Both are required:

   - A policy is inert on a table where RLS isn't enabled.
   - A non-`FORCE`d table lets the table owner read past the policy.

   Tables, columns, indexes, and `GRANT`s stay in your own migrations.

5. Verify drift any time:

   ```
   demesne diff authz.demesne "$DATABASE_URL"
   ```

   `diff` reports two kinds of drift: a generated policy that's missing from the
   live database, and an orphan policy that's live on a governed table but not
   generated. RLS policies are permissive, so an orphan is an open path.

---

## The CLI

| command | needs a DB | what it does |
|---|---|---|
| `demesne validate <spec>` | no | parse + validate the spec |
| `demesne emit <spec> [rls\|definers\|triggers\|claims\|pdp\|all]` | no | print the generated SQL/Go |
| `demesne introspect <dsn>` | yes | summarise the live schema |
| `demesne scaffold [-i] <dsn>` | yes | generate a starter spec from the schema (`-i`: interactive — asks for the RLS role + definer/table schemas, lists ungoverned tables as TODO stubs) |
| `demesne check <spec> <dsn>` | yes | validate, bind to the live schema, AND verify the RLS role is not `BYPASSRLS` |
| `demesne diff <spec> <dsn>` | yes | generated-vs-live policy drift (on governed tables) |
| `demesne coverage <spec> <dsn>` | yes | list live tables with NO governing object (ungoverned → no RLS) — the drift/gap check |

`<dsn>` defaults to `$DATABASE_URL`. The engine package never touches a database;
only the CLI links a Postgres driver, for the live-database subcommands.

Editor support: a VS Code syntax-highlighting extension for `.demesne` lives in
`editors/vscode/` (a TextMate grammar, no build step).

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

Permission expressions are a boolean algebra over the grant terms: union (`a + b`
/ `a or b`), intersection (`a and b`), exclusion/negation (`a and not b`), and
parentheses, with precedence union < intersection < `not`. So `viewer and member`,
`viewer and not banned`, and `(owner + shared) and not banned` all compile to RLS.
Negation is fail-closed: an exclusion whose condition can't be determined (a NULL
claim) denies. A union-only expression is unchanged.

The language adds five more constructs on top of that:

- **Permission templates.** A named, reusable permission set. Declare it with
  `template <name> { … }` and apply it with `object … use <name>`. A using object
  can `omit` a verb or override one with its own permission line.
- **Level-scoped grants.** Scoped, revocable operator or impersonation reach,
  declared with `grant … at <level> via edge …`. A subject reaches through it with
  `reach via grant <name>`. A permission can also be conferred by it directly:
  `permission create = via grant <name>` grants only the grant's holders and
  suppresses the containment branch. That gives, for example, an operator-only
  write that excludes a tenant's own admins.
- **Unbounded-depth hierarchies.** `relation … via closure <C>(anc,desc) base
  <B>(id,parent) on <col>`. The compiler generates a trigger-maintained
  transitive-closure table plus an indexed reachability lookup. The cost is write
  amplification.
- **Nested groups.** `relation … via group <C>(group,member) edge <E>(member,group)
  on <col>`. Group-in-group membership over a many-to-many edge — a userset of
  usersets. The compiler maintains the membership closure, and the RLS term tests
  transitive membership.
- **Cross-object references.** `relation … via object <Other>-><verb> on <col>`.
  The general tuple-to-userset. This object's grant is "the caller passes the
  related object's `<verb>` permission," borrowing whatever that object's policy
  expresses, evaluated at the related row.

It also lets the spec name two deployment schemas. `definers schema "<name>"` is
where the generated SECURITY DEFINER kernel lives; `tables schema "<name>"` is
where your governed tables live. The table schema qualifies the emitted
ENABLE/FORCE, policy, and trigger DDL. Both default to `auth`/`public`, so a spec
that omits them emits byte-identically.

A level grant and a descriptor's ACL edge are the same reachability-grant concept
at different granularities — a level subtree versus a single row. They're unified
in the spec but kept as separate physical stores, never one generic tuple table.

---

## The runtime glue

Enforcement lives in the database, but your app still needs a little runtime: to
mint claims, enforce verbs, and answer point-checks. The engine ships these as
pure helpers, and none of them re-evaluate policy in app code.

- **The session and claims wrapper** takes a principal to an in-force RLS session
  without hand-mapping field names.
  - `Spec.ClaimsContractEntries()` — the structured claims contract. Each key
    comes with its source: the topology level whose scope id feeds it, and/or the
    subjects whose `identifies` feeds it. `ClaimsContract()` returns the flat list
    of keys.
  - `Spec.BuildClaims(Principal{Subject, ID, Scopes})` — maps a principal's typed
    inputs onto the contract. The inputs are which subject it is, that subject's
    id, and the scope id per topology level. The subject id maps to its
    `identifies` key, and each scope id to that level's claim key. Add a contract
    key to the spec and it flows through with no code change. A principal that also
    carries non-contract keys adds them to the returned map before minting.
  - `Spec.MintClaims(values)` / `Spec.MintClaimsFor(principal)` plus
    `Spec.ClaimsSetSQL(local)` — render the validated `request.jwt.claims` blob and
    the `set_config` statement that installs it. `MintClaimsFor` is `BuildClaims`
    then `MintClaims`.
  - `Spec.SetRoleSQL(local)` / `Spec.SessionSetupSQL(local)` — the statement
    sequence that opens an RLS session: `SET [LOCAL] ROLE <role>`, then the claims
    `set_config`. Run them in order in your transaction; the second binds the
    minted blob to `$1`. The RLS role is spec-declared via `claims … role <r>` and
    defaults to `authenticated`.
- `PDP.Authorize(procedure, holds) → Allow | Deny | NotGoverned` — the verb gate at
  your request boundary, for the verb permissions RLS can't see.
- `Spec.HoldsResolver(rolestore)` — the holds resolver. It produces the `holds`
  callback `PDP.Authorize` takes, so you never hand-write "given a principal and
  scope, what permissions do they hold?".
  - `HoldsResolver.AssignmentsSQL()` builds the active-assignment read: every role
    a principal holds across all scopes (`$1` is the principal id; filters on kind,
    subject, and not-revoked). You execute it — under the principal's claims, or as
    a trusted read for another subject. The engine never runs it. Adopter-specific
    admission rules stay your policy: a disabled role, or a client- or RP-scoped
    grant. Compose them around this read; the engine bakes in none.
  - `HoldsResolver.Resolve(rows, scope) → EffectivePerms` folds those rows into the
    effective permission set at a query scope. It keeps each assignment whose scope
    contains the query and unions their permissions. The root column is a strict
    tenancy boundary: a grant pinned deeper covers that subtree, so a higher-level
    grant answers a lower-level query but never the reverse. This boundary is
    derived from the rolestore's scope columns. `EffectivePerms.Holds` is the
    `PDP.Authorize` callback. A role's permissions come from a materialized
    `permissions` column when the rolestore declares one, so operator-configured
    custom roles resolve verbatim; otherwise they come from expanding the role key
    through the vocabulary.
  - `Vocabulary.PresetPermissions(name)` — expands a preset into a flat permission
    set, handling `*`, nested preset refs, and fail-closed on cycles. The same logic
    seeds or validates a materialized `permissions` column. `RankOf` and
    `PresetsAtOrAbove` expose the rank ladder for delegation.
- `Spec.RoleAssignmentSurface(rolestore)` — the control-plane write side of the
  rolestore, the dual of the holds resolver's read. It generates the assign,
  revoke, and list statements so you never hand-write them.
  - `AssignInsert(id, subject, role, scope, grantedBy)` — the `INSERT … RETURNING`
    that confers a role at a scope (kind inlined; scope and grantor bound).
  - `RevokeSQL()` — the idempotent soft-revoke: `UPDATE <revoked> = now()[,
    <revoked_by>] WHERE <pk> = $1 AND <revoked> IS NULL`.
  - `ListForRoleSQL()` / `ListForPrincipalSQL()` — the by-role audit view and the
    by-principal active view, joined to the role's key and permissions.

  Each builds SQL plus ordered args you execute under `WithRLS`. The
  `role_assignments` table's own RLS denies an out-of-scope write, so the engine
  never re-checks it. The audit columns (`pk`, `granted … by`, `revoked … by`) are
  optional rolestore declarations. The intersection-cap delegation guard — "can't
  grant a role you don't hold" — is a separate primitive.
- `Vocabulary.CapGrant(held, requested) → DelegationCap{Allowed, Unknown, Excess}`
  — the delegation cap, the "you can't grant a permission you don't hold" guard
  when authoring or assigning a role. `Unknown` is the requested perms outside the
  vocabulary (fail-closed); `Excess` is the valid perms the grantor doesn't hold.
  It composes with the holds resolver: pass the grantor's
  `EffectivePerms.Permissions()` as `held`. It owns only the intersection and
  validity. The rest is adopter glue you wrap around it: a rank floor (via `RankOf`
  / `PresetsAtOrAbove`), a higher-plane bypass, and the principal-kind check.
- `Spec.GrantSurface(name)` — the control-plane write side of a `grant … via edge`
  store (operator or impersonation reach), the dual of the reach definer.
  - `GrantInsert(id, grantee, level, grantedBy, expiresAt, extra)` — issue a grant,
    so the grantee reaches that level node. Declared extra columns (`column <col>`)
    are written from `extra` and projected back, so a response echoing them isn't
    emptied.
  - `RevokeSQL()` — soft-revoke (stamp the active column) when the grant is
    revocable, otherwise a hard `DELETE`. Idempotent.
  - `ListSQL()` — grants with three optional filters: `$1` grantee, `$2` level,
    `$3` active-only. The active predicate is built from the grant's own active and
    expiry columns — the same conjuncts the reach definer uses — so reads and writes
    agree.

  Build SQL plus args; the caller runs them behind its own eligibility gate. The
  edge exposes no app-role write policy, so a self-grant is impossible. The audit
  and extra columns (`pk`, `granted by`, `revoked by`, `created`, `column <col>`)
  are optional grant declarations.
- `Spec.PointCheckSQL(object)` — a read-check query you run under the principal's
  claims. The database answers "can this principal see this row?" through the real
  policy. Use it for UI affordances, never as a substitute for enforcement.

---

## The typed app framework (`emit … framework`)

Above the runtime glue, Demesne can generate the typed Go your app is built on.
The generated package gives you:

- a `Claims` struct and the session envelope;
- per-object `Can<Verb>(ctx, q, id)` methods;
- `Caps(held)` — a typed boolean per verb-gate permission, for UI affordances;
- scoped query builders, `ListResources` and `CheckMany`;
- a per-rolestore holds resolver;
- a reusable `Check(ctx, q, object, verb, id)`;
- an HTTP `CheckHandler`.

The generated package imports the engine and references `demesne.Querier`
directly. The engine owns the composition rules, so the typed surface stays a thin
wrapper. Everything runs under the caller's claims, and the database decides: the
generated check delegates to the same compiled predicate the RLS policy enforces.

Generate it from your own code, not the CLI. Call `Spec.EmitFramework(pkg)` from
your generator behind a `//go:generate` directive. Don't depend on the CLI binary:
`cmd/demesne` is a separate nested module with a local `replace`, so
`go run …/cmd/demesne@v0.59.0` won't resolve for a consumer. The engine API is the
right seam:

```go
//go:generate go run ./internal/gen
// internal/gen/main.go:
src, _ := spec.EmitFramework("authz")   // gofmt'd, deterministic
os.WriteFile("internal/authz/authz.go", []byte(src), 0o644)
```

**Wiring a connection.** Adapt your driver to `demesne.Querier`. Use
`demesne.FromSQL(db)` for `database/sql`, or
`github.com/eidestudio/demesne/pgx`.`FromPgx(pool)` for pgx — a separate module, so
the engine stays stdlib-pure. Run the generated `Can<Verb>` inside a transaction
that has already run `SessionSetupSQL` and the `Claims.Mint()` result.

**A few sharp edges.**

- *Composite primary keys.* An object with `pk (a, b, …)` has no single-column row
  identity, so it gets no `Can`, `ListResources`, or `CheckMany`. The generated
  code lists it in a banner. Check those rows through a related object or your own
  predicate.
- *Admission filters.* `Holds` bakes in the generic active-assignment read. When
  you need adopter filters such as disabled roles or scoped grants, use the
  `AssignmentsSQL` + `ResolveHeld` seam instead: run your own filtered read, then
  resolve.
- *Extra claims.* `Claims.Extra` carries deployment claims the spec's contract
  doesn't model.
- *Which verbs get a row check.* Only `select` (read) and `update` (edit) get one,
  and the reusable `Check` covers those. `@pdp` verbs decide on held permissions —
  call `Can<Verb>(held)`, or read `Caps(held)` for a boolean; passing one to `Check`
  returns a capability-gate error, never a silent `NotGoverned`. Insert and delete
  have no pre-flight check.
- *Multiple rolestores.* The holds surface is suffixed per rolestore (`HoldsStaff`,
  `HoldsOps`, …). A `@pdp` verb whose permission no rolestore vocabulary covers is
  flagged in a banner: nothing can produce its `held`, so resolve it yourself or
  add a rolestore.

---

## What it is not

Demesne is not general-purpose ReBAC, and not a Zanzibar- or Permify-style Check
service. The graph reachability you express compiles to inline sargable
predicates, SECURITY DEFINER `EXISTS` checks, and an opt-in closure index — all in
Postgres, all on the query's own plan. If you need a standalone authorization
service that evaluates relations at request time across heterogeneous stores,
that's a different tool. Demesne's bet is that enforcement compiled into your
database is worth the constraint.
