# Changelog

## Unreleased

### Added — `require`, a clause that compiles to `AS RESTRICTIVE`

Until now every emitted policy was `PERMISSIVE`. Postgres ORs those together, so
every term in a `permission` line was a disjunct and the compiler could only ever
widen: once a generated policy admitted a principal, no further demesne construct
could take that back. An authorization compiler that can only add permission
cannot express a constraint.

`require <verb> = <expr>` closes that. It emits a second policy on the same table
and command, `AS RESTRICTIVE`, named `<table>_<op>_require`. Postgres ANDs the
restrictive set with the permissive one, which is exactly the missing primitive:

```demesne
permission create = @holds(invitations:write)          @rls maps insert
require    create = @external(invitation_projects_in_tenant, tenant_id, project_ids)
```

The tenant-wide `invitations:write` holder is still admitted by the permissive
`invitations_insert`, which never reads `project_ids`; the restrictive policy is
what refuses a row naming a project outside the tenant.

It is per-verb, so a containment rule on INSERT does not also filter SELECT and
hide the rows an administrator most needs to revoke. It only narrows: the
widening terms (`@scoped`, `@public`, `@open`, `via grant`) are rejected inside a
`require`. And the narrowing is ANDed into the same compiled predicate the app
surface runs, so `CanEdit`/`canEdit`, `@check` point-checks, and a verb borrowed
through `via object` all carry it — there is no second evaluator.

A `require` naming a verb the object does not declare as a `permission` is a
compile error (V13). A restrictive policy with no permissive policy beside it
denies every caller, so the compiler refuses rather than emitting a silent
lockout.

### Added — `external predicate`, a declared, narrowing-only escape hatch

Every term in the language relates one row to one principal. "Every element of
this array column satisfies P" is not of that shape. Rather than invent quantifier
syntax, a `require` may call a predicate the adopter supplies:

```demesne
external predicate invitation_projects_in_tenant(text, text[])
```

The compiler checks arity, emits the call against the definer schema, and counts
the declared name as satisfying the definer-closure check (V11); the body is
yours to write and ship. `@external` is legal **only** inside a `require`, so an
adopter-supplied predicate can subtract authority and never add it. A declared
external that nothing requires is a compile error (V14), because an unused escape
hatch is an unaudited one.

`require` does not replace a trigger. `BYPASSRLS` skips policies but not
triggers, and any rule about OLD versus NEW is outside what `WITH CHECK` can see.
`GUIDE.md` states the split: `require` for the RLS floor, a trigger for the
bypass lanes.

Additive. Every existing spec emits byte-identically — the `Policy` struct gains
a `Restrictive` field that is false everywhere a spec declares no `require`, and
`PolicySQL` writes `AS RESTRICTIVE` only when it is set.

## v0.77.1

### Fixed — a vocabulary that backs no rolestore no longer makes `@holds` ambiguous

v0.77.0 resolves `@holds(<perm>)` to the rolestore whose vocabulary declares the
permission, and rejects a permission declared by more than one vocabulary. The
rejection counted *every* vocabulary, including ones that back no rolestore at
all. Such a vocabulary can never be the answer — it names no candidate — so it
could only ever turn a well-defined resolution into a compile error.

This bit the first real two-rolestore spec. Foir declares `vocabulary admin`
(backed by `rolestore admin`) and `vocabulary customer` (an API-key scope set,
backed by nothing), and the two share five permission names — `files:read`,
`files:write`, `files:delete`, `operations:read`, `operations:execute` — because
they name the same actions on the same data at different planes. Adding a second
rolestore made `@holds(operations:read)` fail to compile at three existing sites
that were correct and unchanged.

Ambiguity between two *rolestore-backed* vocabularies is still a compile error,
and so is a vocabulary backing two rolestores. Single-rolestore specs are
unaffected, as are all v0.77.0 outputs.

## v0.77.0

### Known limitation — the generated `Holds` helper cannot read a NULL scope column

Pre-existing, and made significant by v0.76.0. The generated `Holds`/`HoldsRoles`
scan every scope column into a `string`, so a SQL NULL fails the scan outright in
Go (`database/sql` cannot convert NULL to string) and becomes the literal
`"null"` in TypeScript. v0.76.0 made a NULL root scope *meaningful* — it is how a
global assignment is expressed — so these helpers cannot read the very rows the
new semantics are about.

Plane rolestores are unaffected: their pinned columns are neither selected nor
scanned. `HoldsResolver.Resolve` is also unaffected — a consumer that reads its
own rows (for example through pgx/pgtype) and calls `Resolve` directly gets the
correct semantics. Only the generated fetch helpers are affected. Fixing it
rewrites every committed golden and so lands separately.

### Added — rolestore planes, and `@holds` resolving to the owning rolestore

`@holds(<perm>)` used to compile against `RoleStores[0]` whatever the permission
was. It now resolves to the rolestore whose vocabulary declares the permission.
With exactly one rolestore nothing changes and every existing spec emits
byte-identical SQL, Go, and TypeScript. With several, a permission declared in
two vocabularies — or a vocabulary backing two rolestores — is a compile error
instead of a silent pick. There is deliberately no `@holds(x via y)` selector:
the vocabulary already decides, and a second source of truth could disagree with
it. The first rolestore keeps the `<admin>_has_perm` and
`<admin>_perm_implied_by` definer names; the rest get `<rolestore>_has_perm` and
`<rolestore>_perm_implied_by`, and a name collision between two rolestores is a
compile error.

A rolestore may now declare `plane <level>` — the deepest topology level an
assignment in that rolestore may carry. Levels at or above the plane keep the
wildcard-on-NULL matching; every scope column **below** it is pinned `IS NULL`
in all three surfaces: the emitted definer, the assignment fetch, and the
Go/TypeScript `Resolve`. This is what lets a platform plane share one
`role_assignments` table with the tenant hierarchy:

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

emits a check that takes no scope argument and requires
`ra.tenant_id IS NULL AND ra.project_id IS NULL`, so platform authority is
unreachable from a tenant- or project-scoped row. A `plane` that leaves a level
below it unnamed in `scope` is rejected — an unnamed level cannot be pinned.
`@holds` on a global object, previously always rejected, is now allowed exactly
when the resolved rolestore's plane is at or above the object's level.

`HoldsResolver` gains `Plane` and `PlaneDepth` (`plane`/`planeDepth` in the
TypeScript projection), both omitted when no plane is declared; `PlaneDepth` is
read only when `Plane` is set, so a zero value keeps the previous behaviour and
a partially constructed resolver fails closed. `examples/planes.demesne` is the
worked two-plane spec.

## v0.76.0

### Breaking — the root scope level is now a wildcard when NULL

`@holds` scope matching treated the **root** scope level as an exact match: an
assignment whose root scope column was NULL matched nothing, at any query scope.
Every level below the root already treated NULL as "all". That asymmetry is
gone. NULL now means "all" at every level, including the root, in all three
surfaces: the generated `<admin>_has_perm` SQL definer, the Go
`HoldsResolver.Resolve`, and the TypeScript `resolve`. `ResolveRoles` already
treated an all-empty scope as global, so roles and permissions now agree.

This is what makes a platform-wide scope expressible — an assignment with every
scope column NULL confers its permissions everywhere — and it is a
**privilege-escalation change for existing data**. Any active role assignment
that already has a NULL root scope column silently becomes cross-tenant on
upgrade. Assignments with a non-NULL root scope are unaffected: they gain no
reach, and they still do not answer a global (all-NULL) query.

**Before upgrading, find the at-risk rows.** For a rolestore declared as

```
rolestore admin {
  assignments role_assignments
  kind        principal_kind = "user"
  subject     user_id
  scope       tenant_id project_id
  rolejoin    role_id roles id key
  revoked     revoked_at
  permissions permissions
}
```

run:

```sql
SELECT ra.user_id, r.key, ra.tenant_id, ra.project_id
FROM role_assignments ra
JOIN roles r ON r.id = ra.role_id
WHERE ra.principal_kind = 'user'
  AND ra.revoked_at IS NULL
  AND ra.tenant_id IS NULL
ORDER BY 1, 2;
```

Every row it returns becomes a cross-tenant grant. Scope them to a tenant, or
revoke them, before deploying. `HoldsResolver.GlobalAssignmentsSQL()` emits this
query for your own rolestore, and `demesne check <spec> <dsn>` now runs it and
reports `DANGER: N active role assignment(s) leave …` when any row exists.

### Added — permission implication in a vocabulary

A vocabulary permission may declare what else it confers:

```
vocabulary admin {
  permission platform:manage implies *
  permission tenant:manage   implies project:manage, billing:*, invitations:*
  permission project:manage  implies records:*, content:*
  …
}
```

An item is a permission of the same vocabulary, a `<domain>:*` wildcard for
every permission in that domain, or a bare `*` for the whole vocabulary.
Expansion is transitive; a cycle or an item matching no permission is a compile
error, reported by `Validate`.

The key is the ceiling and the assignment scope is the subtree, independently: a
`project:manage` role assigned at tenant scope reaches every project in that
tenant and still confers no `billing:*`.

All three surfaces are compiled from the one declaration. Go and TypeScript
expand a held permission into its closure inside `Resolve` (so `Holds` stays a
map lookup, and `Permissions()` now reports the **effective** set, not the
literally assigned one). A vocabulary with implications additionally emits
`auth.<admin>_perm_implied_by(p_perm text) RETURNS text[]` — the compile-time
reverse closure — and `<admin>_has_perm` tests
`r.<permissions>::text[] && <admin>_perm_implied_by(p_perm)`. A NULL permissions
column yields NULL and fails closed; an empty array is false. A vocabulary
without implications emits the previous `p_perm = ANY(r.<permissions>)`
unchanged and no new function, so specs that do not use the feature emit
byte-identical SQL.
