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
   generated. A permissive orphan is an open path; a missing `_require` policy is
   a floor that has quietly stopped being enforced.

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

### `require` — the clause that narrows

Every term in a `permission` line is a **disjunct**, and Postgres ORs permissive
policies together, so a `permission` can only ever say "you may *also*…". A
`require` clause says "…but only if":

```demesne
object invitation {
  table  invitations
  scoped tenant
  relation sender: admin via invited_by

  permission create = @holds(invitations:write)          @rls maps insert
  permission edit   = @holds(invitations:write) + sender @rls maps update

  require create = @external(invitation_projects_in_tenant, tenant_id, project_ids)
  require edit   = @self(invited_by)
}
```

`require <verb> = <expr>` compiles to a second policy on the same table and the
same command, emitted `AS RESTRICTIVE` and named `<table>_<op>_require`. Postgres
**ANDs** the restrictive set with the permissive one, so the require is a floor
under the permission rather than another branch beside it. Above, a tenant-wide
`invitations:write` holder is still admitted by `invitations_insert` — which
never reads `project_ids` — and is still refused by `invitations_insert_require`
if the row names a project outside its tenant.

Four properties are worth knowing before you reach for it:

- **It is per-verb.** `require create` restricts INSERT and nothing else. That
  matters: a containment rule applied to SELECT would *hide* rows that violate
  it, and a row you cannot see is a row you cannot revoke.
- **It only narrows.** The widening terms — `@scoped`, `@public`, `@open`, and
  `via grant` — are rejected in a `require`. The rest of the term vocabulary
  (relations, `@holds`, `@within`, `@kind`, `@self`, `@session`, `mode`, and the
  boolean algebra above) composes as usual.
- **It reaches every surface.** The narrowing is ANDed into the same compiled
  predicate the app surface runs, so `CanEdit` / `canEdit`, `@check`
  point-checks, and a verb borrowed through `via object <Other>-><verb>` all
  carry it. There is no second evaluator to keep in step.
- **A `require` with no matching `permission` is a compile error.** A restrictive
  policy with no permissive policy beside it denies everyone, so the compiler
  refuses rather than emitting a silent lockout.

#### `external predicate` — the one thing the compiler does not own

Every demesne term relates one row to one principal. Some constraints are not of
that shape — "every element of this array column satisfies P" is the common one —
and rather than invent a quantifier syntax, a `require` may call a predicate you
supply:

```demesne
external predicate invitation_projects_in_tenant(text, text[])
```

The declaration is the whole surface: name and argument types, returning
`boolean`, living in the definer schema. `@external(<name>, <arg>, …)` calls it
with row columns, `@claim` keys, or `"string"` literals, and the compiler checks
arity, emits the call, and counts the name as satisfying the definer-closure
check (V11). You write the function body — as `SECURITY DEFINER` with a pinned
`search_path`, like every generated definer — and ship it in your own migration.

An `@external` term is legal **only inside a `require`**. That is the point of
the restriction: an adopter-supplied predicate can subtract authority and can
never add it, so the worst a wrong one can do is lock people out. A declared
external that no `require` calls is a compile error too — an unused escape hatch
is an unaudited one.

`examples/require.demesne` is the worked spec, with its live-Postgres proof in
`ts/packages/example-app/test/require.test.ts`.

#### `require` does not replace a trigger

**`BYPASSRLS` skips policies. It does not skip triggers.** If any lane in your
system writes on a pooled connection whose role carries `BYPASSRLS` — an
operator console, an MCP or agent lane, a migration job, a psql session — then
no policy demesne emits is consulted on that lane at all, permissive or
restrictive. "The moat holds even when application code is wrong" is only true
of lanes that go through policies.

So the durable arrangement for an invariant you actually depend on is both:

- **`require`** for the RLS floor — declared in the spec, compiled into every
  surface, drift-checked by `demesne diff`.
- **a trigger** for the bypass lanes — the same invariant, enforced where
  policies are not.

A trigger also reaches two things a policy cannot. RLS `WITH CHECK` sees only the
NEW row, so any rule about **OLD versus NEW** — "this column is immutable after
insert" — has to be a trigger. And a trigger can be conditioned on `TG_OP`, so an
invariant can be enforced on INSERT without also being enforced on the UPDATE
path that cleans up rows which predate it.

Claim-side builtins (`@kind`, `@session`, `@app_scope`, `@within`, `@scoped`,
`@holds`) compose inside intersections: `(@kind("admin") and grantee:read)`
enforces both in the emitted policy. The reverse accessor enumeration treats a
claim-side conjunct as neutral — it drops the conjunct and may over-report,
never under-report, because the forward RLS still enforces it — and refuses,
fail-closed, when a conjunction leaves no relational term to enumerate. A
`@public`, `@open`, or `@self` conjunct still refuses: the first two would mean
"everyone", and `@self` binds a row column to the caller's claim, which the
enumerator cannot reverse.

A permission can also gate on what the caller *holds*: `@holds(docs:publish)`
means "the caller's admin role confers `docs:publish` at this row's scope" and
compiles to a generated `<admin>_has_perm` definer matching the verb against the
rolestore's materialized `permissions` array (`p_perm = ANY(...)`). It scopes
like the Go `HoldsResolver`: an assignment left NULL at a scope level is a
wildcard at that level, so a tenant-wide assignment reaches every project and an
assignment left NULL at the *root* level is global — it reaches every tenant.
That root NULL is how a platform-wide scope is expressed; there is no separate
level for it.

### `wildcard` — a NULL scope column on the *row* side

The rule above is about a role assignment: NULL at a scope level means "every
value at that level". A row can want to say the same thing. A role definition
that belongs to the whole workspace rather than to one project stores
`project_id = NULL` and means *all* projects, not *no* project.

Containment does not read it that way by default, and it must not: `scoped
tenant > project` emits

```sql
tenant_id = <tenant claim> AND project_id = <project claim>
```

and `NULL = anything` is NULL, so a workspace-wide row is invisible to every
session — including the one that owns it. Mark the level to opt that column into
the assignment-side reading:

```demesne
object role {
  table  roles
  scoped tenant > project wildcard
  permission view = @holds(members:read) @rls maps select
}
```

The marked level's conjunct becomes

```sql
tenant_id = <tenant claim> AND (project_id IS NULL OR project_id = <project claim>)
```

Three things to know before using it:

- **It is additive on the marked level and nothing else.** The emitted predicate
  gains exactly one disjunct, `<col> IS NULL`. Every row that was visible before
  is still visible, on the same terms; the only rows whose visibility changes are
  the NULL ones, which no session could reach at all. Unmarked levels — including
  the parent, and including the same level on a different object — keep the bare
  equality, so a project-scoped row stays invisible to another project's session.
- **It says "everywhere below the parent", not "nowhere".** A row with a NULL
  project is reachable from any session in its tenant, which is what a
  tenant-wide row means. If you want a partition instead — workspace sessions see
  only workspace rows — do not mark the level; store a real value.
- **It is containment, not permission.** The authority conjunct is untouched, and
  it is what decides who may write such a row. `@holds` passes the *row's* scope
  columns to the definer, so a NULL project is checked at tenant scope: an
  assignment pinned to one project does not satisfy it. On a containment-only
  object (`@scoped` alone) there is no such check, and any session in the tenant
  can write a wildcard row — mark the level there only if that is what you mean.

The marker is rejected where it could not bind: on a virtual level, which emits
no containment conjunct at all, and on a level entity's own level, whose scope
column is the primary key. Both would be silent no-ops otherwise.

Because the check keys on the permission verb at query time,
editing a role's permissions array changes the floor immediately, with no
re-emit — unlike preset-key grants, whose key sets are baked into definer
bodies. `@holds` needs a rolestore with a `permissions` column and a verb from
its vocabulary, and rides the @rls and @check layers; in a @pdp permission,
write the permission key as a bare term.

A vocabulary permission can **imply** others, so one held verb confers a set:

```
vocabulary admin {
  permission platform:manage implies *
  permission tenant:manage   implies project:manage, billing:*, invitations:*
  permission project:manage  implies records:*, content:*
  permission records:read
  permission records:write
  …
}
```

An implication item is a permission of the same vocabulary, a `<domain>:*`
wildcard standing for every permission in that domain, or a bare `*` for the
whole vocabulary. Implication is transitive (`tenant:manage` reaches
`records:read` through `project:manage`) and cycles are a compile error. The two
axes are independent and both bind: the **key** is the ceiling — what level of
authority the role carries, fixed by the vocabulary, not by where it is
assigned — and the **scope** is the subtree it carries that authority over. A
`project:manage` role assigned at tenant scope therefore reaches every project
in that tenant but still confers no `billing:*`.

The closure is compiled into all three surfaces from the one declaration: the
Go and TypeScript `Resolve` expand a held permission into its closure, and the
SQL definer tests the role's array against a generated
`<admin>_perm_implied_by(p_perm)` reverse closure with an array overlap. A NULL
`permissions` column fails closed.

### A rolestore's role relation may be a view

`rolejoin <fk> <relation> <id> <key>` names a **relation**, not specifically a
table. It is interpolated verbatim as a bare relation into every read that joins
it — the emitted definers, `AssignmentsSQL`, `ListForPrincipalSQL` — so a view
serves exactly as a table does, and `ValidateAgainst` binds it from whatever
`information_schema` reports, which does not distinguish the two.

That is the supported way to apply an admission rule the **database** must also
honour. The `AssignmentsSQL` + `ResolveHeld` seam is a Go read path; the emitted
definers run inside Postgres, where no Go filter reaches. A rule applied only in
Go therefore holds in the session and the PDP while every RLS branch ignores it —
the two planes disagree, and nothing in the generated artefacts says so. Naming a
filtered relation here applies the rule to both at once, and to any definer a
later spec change adds:

```
rolejoin role_id roles_active id key
```

with `roles_active` a view over the role table carrying whatever the adopter's
policy is — a `disabled_at IS NULL`, a tenant partition, an RP scope. The engine
still bakes in none of it; it just stops being a Go-only choice where to put it.

**If the underlying table has RLS, create the view `WITH (security_invoker =
true)`.** A view otherwise runs with its *owner's* rights, and a migration role is
usually a superuser or carries `BYPASSRLS` — so a default view reads the base
table with RLS switched off, and anything granted `SELECT` on it reads across
every tenant. Under `security_invoker` the view is exactly as reachable as the
table it wraps, and a SECURITY DEFINER function still sees every row, because
inside one the querying role is the function's owner.

A spec can declare more than one rolestore, and `@holds` resolves to **the
rolestore whose vocabulary declares the permission** — not to whichever
rolestore was declared first. With exactly one rolestore nothing changes. With
several, a permission declared in two vocabularies, or a vocabulary backing two
rolestores, is a compile error rather than a silent pick; there is no `via`
selector, because a selector could disagree with the vocabulary and the
vocabulary is what the delegation guard already enforces. The default (first)
rolestore keeps the `<admin>_has_perm` / `<admin>_perm_implied_by` definer
names; every other rolestore gets `<rolestore>_has_perm` /
`<rolestore>_perm_implied_by`.

That is what lets a **plane** exist alongside the tenant hierarchy. A rolestore
whose assignments live at a level *above* the ones its scope columns name
declares `plane <level>`:

```
rolestore platform {
  assignments role_assignments
  kind        principal_kind = "admin"
  subject     principal_id
  scope       tenant_id project_id
  plane       platform
  rolejoin    role_id roles id key
  revoked     revoked_at
  permissions permissions
}
```

`plane` names the deepest level an assignment in this rolestore may carry.
Levels at or above it keep the wildcard-on-NULL matching described above; every
scope column *below* it is **pinned `IS NULL`**, in the emitted definer, in the
assignment fetch, and in the Go and TypeScript `Resolve`. Pinning is not the
same as omitting the columns: with `plane platform` (the virtual root) the
generated check takes no scope argument at all and reads

```
EXISTS (SELECT 1 FROM role_assignments ra JOIN roles r ON r.id = ra.role_id
  WHERE ra.principal_kind = 'admin' AND ra.principal_id = user_id
    AND ra.tenant_id IS NULL AND ra.project_id IS NULL
    AND ra.revoked_at IS NULL AND p_perm = ANY(r.permissions))
```

so a `platform:manage` row written at a tenant scope satisfies nothing. Because
the plane is a rolestore and not a vocabulary entry, `preset tenant_owner @
tenant = *` still star-expands only its own vocabulary and can never reach a
permission that lives on another plane. A `plane` that leaves a level below it
unnamed in `scope` is rejected: an unnamed level cannot be pinned, and the check
would accept an assignment scoped there. `examples/planes.demesne` is the
worked two-plane spec.

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

A word on `virtual`, because it is the one keyword whose name undersells what it
does. A virtual level is the operator plane *above* tenancy: the place platform
staff live. It carries no scope column, so a subject anchored there is not
scoped to anything and reaches every row of every object beneath it. That reach
is disjoined into each policy, which is what makes platform staff platform
staff.

The consequence is that a virtual level cannot host graded access. An `@holds`
gate on a global object compiles correctly and is then never consulted, because
the plane-wide reach beside it is already true for anyone holding any preset. It
is rejected at validate rather than compiled into a policy that looks graded and
is not.

So `virtual` does not mean "I have no tenancy." A single-tenant deployment still
wants a real level with a scope column, even if exactly one row ever occupies
it; that column is what `@holds` keys on. Reach for `virtual` only when you
genuinely want a plane whose members outrank the whole tree.

Row-layer gating is by capability, not by role identity. `via role` asks "does
this principal hold any role here", and `@holds(<domain>:<verb>)` asks "does the
role it holds grant this verb". There is deliberately no way to gate a policy on
which preset someone holds: matching role keys as string literals cannot see
what a role actually grants, so two roles with identical permissions would get
different row access. `rank` still orders presets for delegation and for the
generated surfaces, never for enforcement.

Identifiers are `text` by default, because they arrive as JWT claims. If your
keys are another SQL type, declare it once — `identifiers uuid` — and the emitter
types every generated definer parameter with it and casts identifier claims to it
(`(claims ->> 'sub')::uuid`). Columns are still passed natively, so indexes stay
usable. Any SQL type works (`uuid`, `bigint`, `citext`, a domain); nothing in the
emitter special-cases a particular one. Value claims like `@kind` stay `text` —
they are compared against string literals, not keys. A spec that omits the
declaration emits byte-identically to one written before it existed.

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

    This seam governs the **Go** plane only. The same spec also emits SECURITY
    DEFINER bodies that join the rolestore's role relation, and no Go filter
    reaches inside those, so an admission rule applied only here holds in the PDP
    and is ignored by every RLS branch. A rule that must hold on **both** planes
    belongs in the relation the spec names — see *A rolestore's role relation may
    be a view* below.
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
- `demesne.ResolveRoles(assignments, scope) → EffectiveRoles` — the role-tier read,
  the sibling of the holds resolver. `Resolve` answers "what permissions does this
  principal hold here?"; `ResolveRoles` answers "what role tiers does it hold here?",
  which a wildcard role (`owner = *`) or a global plane role can't be read off the
  permission set. It reads the same assignment rows, keeping each role key whose scope
  contains the query. A role granted at an empty scope is a global plane role, held in
  every scope: the same boundary the generated `has_<plane>_role` definer enforces.
  `EffectiveRoles.Holds` reports membership of one role key. `NewEffectiveRoles(keys...)`
  builds the set straight from a session when you already know the held keys and don't
  need a database read.
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
- `Spec.Vocabularies()` and `Spec.ExpandedPresets(rolestore)` — the introspection
  read for a role-management or permission-admin UI built from the compiled spec, the
  single source of the vocabulary, with nothing re-declared. `Vocabularies()` returns
  every declared vocabulary and its permissions in declaration order, and marks each
  parameterized permission: one that carries the open `*` model segment (`docs:read:*`)
  rather than a concrete one (`docs:read`), so a picker can split the model segment
  itself. `ExpandedPresets(rolestore)` resolves each preset of that rolestore's bound
  vocabulary to a flat permission set. It expands both `+` preset references and the
  `= *` wildcard to the full vocabulary, reusing the `PresetPermissions` logic and the
  same rolestore-to-vocabulary binding the generated `Holds` surface uses. Each
  permission list is sorted. The map is unordered, so sort its keys for a stable
  display. A vocabulary with no presets yields an empty map. It returns generic data
  only: which permissions exist, which are parameterized, and what each preset resolves
  to. It never decides what any of that means; the bucketing, labeling, and layout are
  your UI's job, not the engine's.
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
- `RoleTiers(held)` — a typed boolean per role tier, plane and scoped, for UI affordances;
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
`github.com/foir-io/demesne/pgx`.`FromPgx(pool)` for pgx — a separate module, so
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
  resolve. That covers the Go plane. If the same rule must also hold under RLS,
  put it in the relation `rolejoin` names rather than in the read — the emitted
  definers join that relation and cannot see a Go filter.
- *Extra claims.* `Claims.Extra` carries deployment claims the spec's contract
  doesn't model.
- *Which verbs get a row check.* Only `select` (read) and `update` (edit) get one,
  and the reusable `Check` covers those. `@pdp` verbs decide on held permissions —
  call `Can<Verb>(held)`, or read `Caps(held)` for a boolean; passing one to `Check`
  returns a capability-gate error, never a silent `NotGoverned`. Insert and delete
  have no pre-flight check.
- *Two affordance axes.* `Caps(held)` answers the verb axis: can this principal
  publish? `RoleTiers(held)` answers the role-tier axis: is this principal a platform
  admin, or a tenant owner? A wildcard role or a global plane membership can't be read
  off the verb set, so the two stay separate accessors over separate held sets. Both
  are UI hints; the floor still decides. `RoleTiers` reads a held-roles set
  (`EffectiveRoles`), resolved by the generated `HoldsRoles` / `ResolveHeldRoles`, or
  built from a session with `demesne.NewEffectiveRoles`. A preset at a `virtual` level
  is a plane role and lists first; the rolestore's scoped presets follow.
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
