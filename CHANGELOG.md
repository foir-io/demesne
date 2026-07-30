# Changelog

## Unreleased

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
