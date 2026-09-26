# Changelog

## v0.90.0

### A definer body probes a relation's first hop before calling its definer

A SQL definer called from another definer's body is planned again on every
outer call. A composition or via-object arm inside a definer body therefore
cost a full plan of the callee's body per row, even for a caller the arm could
never admit: a record with no composition edge still paid for planning the
parent's whole predicate, once per access branch, on every call.

Inside a definer body, a composition arm is now preceded by its first hop (an
edge row naming the record, of the relation's kind, with a parent), or by the
parent column itself when the edge is the object's own column. A via-object arm
is preceded by the existence of the row it names. Each probe is implied by the
definer it guards, so the conjunction admits exactly what the call admits, and
a caller the hop rules out never plans the callee.

Where it is not emitted, on purpose:

- **Policies.** A policy reads with the caller's privileges, where a probe could
  see less than the definer it guards and refuse what the definer would admit.
  Policies call the definers exactly as before.
- **Composition definer bodies.** They repeat the parent's predicate once per
  access, so a probe there is planned three times on every call, and a policy
  calls them per row. Measured, probing inside them slowed ordinary list reads
  for callers who can read the rows.
- **Grant arms.** A grant definer is a single index lookup. Inlining it would
  grow every call's plan to save a call only a refused caller reaches.

Measured on an adopter's spec and a seeded Postgres 17 database, per call of a
record's view definer: a caller who reads half the rows went from 2.2ms to
0.07ms, and one who reads none from 4.3ms to 0.11ms. On records that are
composed children, where the probe passes, both got faster (0.84ms to 0.75ms and
4.6ms to 1.9ms). A caller an earlier arm admits pays only for planning the longer
body, about 0.006ms per call. Emitted SQL changes only for definer bodies that
call a composition or via-object definer; every admit decision is unchanged.

## v0.89.0

Two adopter-reported engine defects, both narrowing and both previously carried
as compensation in the adopter's own code.

### A grant row's principal kind now binds the caller's plane

A grant relation naming several kinds emits one RLS fragment per kind, each
keyed on that kind's subject claim. That is only as strong as the claims being
disjoint, and they are not symmetrical. The owner-plane claim is minted for
owner-plane callers and nobody else, so a fragment keyed on it already answers
false for everyone else. The other plane's claim is the generic subject, which
an adopter may also populate for an owner-plane caller — and then a grant row
naming the OTHER kind becomes reachable by an id collision between two id spaces
that were never meant to meet.

Nothing in the generated layer objected to that, so the defence had to live in
whatever the adopter happened to put in a claim, and its removal would have been
silent. A fragment for a kind on the non-owner plane is now conjoined with "the
owner claim is absent".

Emitted where it is load-bearing and not where it is implied: the mirror test on
an owner-plane kind is deliberately left out, because that fragment's own first
argument is the claim in question and emitting the test would restate the call
as a condition on itself. A single-kind owner-plane grant — the common shape —
emits byte-identical SQL.

Narrowing only. It removes no principal from any enumeration: the accessor
definers list grant ROWS and every row still lists, because the plane test is a
condition on the request, not on the grant.

### `GrantInsert` can express an absent wildcard level

A `wildcard` level is nullable by definition — `(col IS NULL OR col = claim)` is
what the marker emits — so an adopter that declares one has a containment column
whose commonest legitimate value is SQL NULL. `GrantInsert` takes `[]string`, so
the only absence a caller could express was `""`, and `''` satisfies neither
disjunct: the insert's own `WITH CHECK` refuses it with `42501` on a grant the
caller plainly owns, naming a column they never mentioned.

The surface knows which of its levels carry the marker, so it binds `""` as NULL
for those and leaves every other column alone — a genuinely missing value still
fails loudly against `NOT NULL`. No signature change, and a call site cannot get
it wrong by forgetting.

## v0.88.0

One structural change, and a defect it closes that has been latent for a long
time. A spec emits byte-identical output unless its read contains `and` or
`not`: re-emitting a 340-policy, 49-definer spec on v0.87.0 and on this gives
the same bytes.

### The accessor enumerator had two shapes and, wrongly, two paths

A permission carrying `and`/`not` composes into one SQL expression;
intersections and subtractions cannot be a union of independent branches. A pure
`+` chain is such a union. That difference is irreducible.

What was not irreducible is what used to follow it. The tree shape produced its
expression and **returned**, skipping everything the flat shape did afterwards.
Two things live in that tail, and neither is a property of a permission's shape:

* the **role branch**, gated on the object's rolestore and its use of
  `@app_scope`, and
* **composition**, which needs the `<table>_direct_accessors` split to stay free
  of recursion — a property of the relation.

So an object with one `and` anywhere in its read **silently lost its role
branch**, and could not carry a composition relation at all. The first is the
under-reporting direction this enumerator exists to prevent: the listing simply
stopped naming role holders, with nothing said.

Both now live in the tail both shapes share, so the shapes differ only in how
relational terms compose and in nothing else. A composition on a DISJUNCT is
skipped by the walk and added by the tail, exactly as the flat shape does; one
nested inside an `and` still refuses, because the tail can only add a union arm
and a union arm is not an intersection.

### Why this, rather than another targeted fix

v0.84.0 through v0.87.0 each taught one of the two paths something the other
already knew — conditional terms dropped silently on one, refused on the other;
a negated claim refused on one; an all-conditional conjunction refused on one.
Every one was a real fix and every one was a symptom. The shared tail is the
cause, and with it in place the remaining divergence is the one the grammar
actually requires.

## v0.87.0

One fix, to a gap v0.85.0 left. A spec only meets it if it writes a shape that
previously failed validation, so emission is unchanged for everything else:
re-emitting a 340-policy, 49-definer spec on v0.86.0 and on this gives
byte-identical output.

### A conjunction of only conditional terms is one admission, not a refusal

v0.85.0 taught the accessor enumerator about a term that admits readers it
cannot name — a claim, the app plane, a public mode — when that term stands
alone on a disjunct. A conjunction of ONLY such terms fell through to the
conjunction path, which looks for a relational term to enumerate from, found
none, and refused:

```
cannot soundly enumerate accessors — a conjunction of only narrowing terms
(@app_scope, not @claim) leaves no relational term to enumerate
```

The refusal was wrong. The conjunction admits readers perfectly well; it simply
names no subject, which is the case the conditional enumerator exists for. Both
shapes it blocked are ordinary:

```demesne
(@app_scope(exclude admin_owner) and @kind("service"))          // a plane confined to one caller kind
(@app_scope(exclude admin_owner) and not @claim("credential", "public"))  // a plane with a credential subtracted
```

The fold: the `source` comes from the term that ADMITS, since the others only
qualify it, and every row-side condition is ANDed into the anchor so the row
appears exactly where the conjunction does. A negated kid contributes no anchor
— it subtracts on the request side, which is the part no query can express, and
that is precisely why the row is conditional rather than enumerated.

**A conjunction carrying a relational term is untouched.** It is enumerable, and
folding it into a nameless row would lose the subjects it can actually name.
That guard has a test, and the test was rewritten after a mutation went unkilled
against its first version: it paired the relation with `@kind`, which admits
nothing on its own, so the fold never triggered and the assertion passed whether
or not the guard was there.

## v0.86.0

Two additions to the grammar, both of which a spec only meets if it asks for
them. Emission is unchanged for every spec that does not: re-emitting a
340-policy, 49-definer spec on v0.85.0 and on this gives byte-identical output.

One breaking change to the Go AST, for anyone building `Term` values
programmatically rather than parsing a spec: `Term.ExcludeRel string` is now
`Term.ExcludeRels []string`.

### `@app_scope(exclude a, b)` takes more than one owner plane

`@app_scope` admits a caller presenting no subject claim; `exclude` subtracts a
plane it should not reach. It took exactly one relation, and a table can be
owned on more than one — an admin-owned row and a customer-owned row are both
somebody's private data, and a trusted caller with no subject of its own has no
business reading either.

One exclusion could only ever name one of them, so the adopter that needed both
filtered the second in application code: a second gate for one read, on a rule
the row layer was already half-expressing. Each exclusion is now ANDed on, in
spec order, and the conditional accessor's app_scope row is anchored on all of
them — anchoring on the first alone would put a row in the listing for a row the
plane does not admit at all.

### A negated `@claim` is dropped from the enumeration rather than refused

`(… ) and not @claim("k", "v")` previously failed validation: the reverse
enumeration reached the negated leaf and refused, because a claim names no
subject to reverse.

Refusing was too strong. Dropping ANY conjunct from the enumeration can only add
names, never remove one, so the listing over-reports and stays sound — and the
forward policy still enforces the term. Reversing this one is not merely hard
but meaningless: "everyone who does NOT carry the claim" is no more enumerable
than everyone who does.

**Only a claim, deliberately.** The same argument would cover every narrowing
leaf, and it is not applied to them, for two reasons. The others are coupled to
branch generation in a way a claim is not — the role branch exists only because
`@app_scope` is present, so negating that is not a conjunct that lifts out
cleanly — and widening this would turn an existing refusal into an emission for
specs that rely on it. `not @app_scope` still fails closed, and a test drives
that case so the distinction cannot quietly erode.

## v0.85.0

One change, and it is a **breaking emission change** for any spec whose read
carries `@app_scope` or a `mode` disjunct: those objects now emit
`auth.<table>_accessors_conditional` and stop emitting
`auth.<table>_accessors`. Re-emit and diff before upgrading; the section below
says how to tell which objects are affected.

Nothing else changes. A spec with no such disjunct emits what it emitted at
v0.84.0.

### The accessor rule now covers every disjunct that names nobody

v0.84.0 introduced the conditional enumerator for `@claim` and said the rule was
about POSITION rather than about which term was special. It was, and `@claim`
was not the only term on the wrong side of it.

`@app_scope` and a `mode` disjunct admit readers no query can name, exactly as a
claim does, and both were being dropped from the enumeration **in silence** —
the accessor builder reverses relation leaves only, and on a flat `+` chain a
non-relation term was skipped with no error. An object reading

```demesne
permission view = @app_scope + owner + mode access_mode = "public" + grantee:read  @rls maps select
```

emitted a `<table>_accessors` listing its owners and grantees, saying nothing
about "any caller presenting no subject claim" or "anyone, because this row is
public". That is the under-reporting direction this engine refuses everywhere
else.

Both are now conditional admissions, carried as their own rows:

| disjunct | `source` | `principal_kind` | row anchor |
| -- | -- | -- | -- |
| `@claim("k", "v")` | `claim` | NULL | — (plus `via_claim_key`/`via_claim_value`) |
| `@app_scope` | `app_scope` | NULL | the `exclude` relation's column test, when present |
| `mode <col> = "<v>"` | `mode` | the `for <subject>`, when present | `<col> = '<v>'` |

**Row-anchored where the term tests the row.** A `mode` row appears on a public
row and not on a private one; `@app_scope(exclude admin_owner)` contributes
nothing to an admin-owned row. The listing is accurate per row rather than a
blanket statement about the table.

**`principal_kind` is filled where the term narrows to one plane.**
`mode … for admin` yields `('mode', 'admin', NULL, …)` — only the id was ever
unknowable.

`@app_scope` deserves a note: part of it IS nameable. Where a rolestore exists,
`roleAccessorBranch` enumerates the assignments and that branch still stands.
The conditional row is the remainder — a trusted caller holding no assignment
anywhere satisfies the term and appears in no table.

### A narrowing `mode` conjunct is now dropped rather than refused

The mirror image. A `mode` on a conjunct narrows, so dropping it from the
enumeration can only over-report, which is the safe direction — the same
argument that has always applied to the claim-side builtins. It joins them, and
the refusal for a conjunction with no relational term left now reads "a
conjunction of only narrowing terms".

This unblocks a shape that was previously impossible: a `mode` disjunct used to
make the entire SELECT tree un-enumerable the moment any `and` appeared anywhere
in it, because the tree path refused the mode leaf instead of skipping it. A
permission like

```demesne
permission view = admin_owner + owner + mode access_mode = "public" + (@kind("admin") and grantee:read)
```

now emits: the mode becomes a conditional row and the conjunction enumerates
from its relational term.

### Upgrading

Emit before and after and diff the function names. An object is affected if and
only if its `@rls maps select` permission carries `@app_scope` or a `mode`
disjunct. In the Go runtime, `ResourceAccessSurface` refuses such an object and
names `ConditionalResourceAccessSurface`; `IsConditional()` and
`ConditionalBy()` say which admissions were responsible. In the TypeScript
descriptor, `accessorsConditional` flips to `true` and `accessorFn` names the
conditional function.

## v0.84.0

One engine addition: `@claim`, a permission term that tests a claim on the
request. It comes with the accessor rule that makes it safe, which is the larger
half of the change.

A spec that does not name `@claim` emits the same SQL it emitted at v0.83.0 —
verified by re-emitting a 340-policy, 49-definer spec on both and diffing: byte
for byte identical. The one visible change for every spec is in the **TypeScript
descriptor**, which gains `accessorsConditional: false` on each resource-access
entry. Re-emit and diff; expect only that.

### `@claim("key", "value")` — a condition on the request, in a permission

```demesne
permission view = owner + grantee:read + @claim("view_all", "true")   @rls maps select
```

Compiles to the obvious test against the claims accessor: no edge, no subject,
no definer. Two arguments rather than an infix `=`, because a permission
expression has no comparison operator and adding one would raise a precedence
question against `and`/`or` that every existing expression would inherit. Legal
only in an `@rls` permission — a claim is read at the row layer, so a permission
that compiles to no policy would silently ignore it, and that is now a refusal.

### An object whose read admits a claim enumerates conditionally

This is the part worth reading before adopting the term.

Every other leaf in the language names a subject that can be read back off a
row. A claim names a condition on the request, and nothing in the database
records who satisfies it. On a **conjunct** that costs nothing: the existing
rule already drops claim-side conjuncts from the reverse enumeration, which can
only over-report, and `@claim` joins `@kind`, `@session`, `@app_scope`,
`@within`, `@scoped` and `@holds` in that set.

On a **disjunct** it is the opposite, and this was previously emitted wrongly
rather than refused. A builtin term on a `+` chain was silently skipped by the
accessor builder, so an object admitting readers by a claim still got a plain
`auth.<table>_accessors` that listed its owners and grantees and left out every
reader the claim admits — the under-reporting direction the engine refuses
everywhere else.

Such an object now emits

```
auth.<table>_accessors_conditional(p_id)
  → (source, principal_kind, principal_id, access, via_claim_key, via_claim_value)
```

— the identity rows it always had, widened with two null columns, plus one row
per admitting claim with `source = 'claim'`, a NULL principal, and the key and
value. **`auth.<table>_accessors` is not emitted for that object**, so a caller
that has not been updated asks for a function that is not there instead of
receiving a confident, incomplete list. A sentinel principal was rejected because
it renders as a person in exactly the caller this protects; a flag beside the
function was rejected because it can be ignored without writing a line of code.

Two consequences. A `via object` borrow of such an object is refused at
validation, because the borrow compiles to a call to the plain enumerator and
taking the identity half while losing the claim is the failure being prevented.
And `ResourceAccessSurface` refuses a conditional object, naming
`ConditionalResourceAccessSurface` — same surface over the conditional function,
with `IsConditional()` and an `AccessorsSQL()` that selects the claim columns. A
caller written against the conditional constructor stays correct if a claim is
added to the spec later.

## v0.83.0

Six engine additions, one accessor fix and one validation that turns a silent
wrong emission into a refusal. A spec that names none of the new grammar emits
what it emitted at v0.82.0 with two exceptions, both below: accessor definers for
an object scoped deeper than its rolestore, and a spec with two grants over one
edge table that emit different predicates. Re-emit and diff; expect only those.

### An accessor's role join widens at the deepest level the store covers

`roleAccessorBranch` widened the role assignment's scope match at the object's
last level. For an object scoped deeper than the rolestore that level has no
assignment column, so the widening was dropped and every level the store did
cover was matched strictly: an assignment left NULL at its deepest column, which
reaches everything below it, vanished from the `<table>_accessors` listing while
the policy kept admitting it. The widening now lands at
`min(len(scoped), len(scope columns)) - 1`. Objects no deeper than their store
emit byte for byte what they did.

### A claim can lift one level's containment

`grant <name> at <level> via claim <key> = "<value>" confers <ops>` ORs
`<claim> = '<value>'` into the containment term at that level, beside any edge
reach there, on the named operations only. It needs no subject and emits no
definer. It is refused on a virtual level, without `confers`, with edge options,
as a subject's reach, as a `via grant` term and in an object's `reach` clause.
Its key is not added to the claims contract; like a `@kind` value it is minted by
the adopter.

### A grant edge can carry scope levels, and an object chooses which reach it uses

`scope <level> on <column> missing allow|deny`, repeated down the tree, narrows a
grant row to a subtree. `<table>_reach` and `_reach_set` admit a row whose deeper
columns are NULL or equal the session's claim at that level, reading the claims
through `NULLIF` so a direct call outside a request answers rather than raises.
A ladder also emits `_reach_unscoped`, `_reach_unscoped_set` and one
`_reach_in_<level>` probe per scope level, which takes the selection as
parameters.

In an object, `reach <grant> unscoped [for <ops>]` uses the unscoped set and
`reach <grant> bound <level> [for <ops>]` uses the unscoped set or the scoped set
confined to rows whose column at that level equals the session's claim. The level
must be one of the grant's scope levels; the object need not be scoped at it, only
carry its column, which `ValidateAgainst` binds. A grant with no scope levels
emits exactly what it did.

### Grants over one edge table are told apart, and an object can reach through another

A grant's definers are named after its edge table, and a second grant over the
same table was skipped at emission, so its policies silently called the first
grant's functions. Two grants over one table that emit different predicates are
now refused until one declares `named <base>`; grants that emit the same
predicate still share. `reach <grant> via <other> [for <ops>]` takes a subject's
reach through another edge grant at the same level, which is how one closure
serves downward administration on some objects and upward inheritance on others.
The structural accessor enumerator follows the selection.

### A borrowed predicate can be compiled for an operation

`via object <other>-><verb> on <col> for <op>` emits `<other>_can_<verb>_for_<op>`,
the predicate-only permission compiled with that operation's containment: a
bounded wildcard, grants that confer only that operation and claim reach all
apply. The unsuffixed borrow is unchanged. `for` on a permission that already
maps an operation is refused.

### Admit arms, claim-keyed closures and exported permissions

`admit <ops> = <expression>` ORs a contained arm into the object's policy for
those operations. Borrows of the object's permissions and its accessor
enumeration do not see the arm; `Can<Verb>` point checks and exports do. An arm
for an operation no permission maps is refused.

`via closure <C>(anc, desc) on <col> from claim <key> missing allow|deny` keys a
closure relation on a claim rather than the owner. `base` becomes optional for
this form, and a closure with no base emits no maintenance trigger. The accessor
enumerators refuse to reverse it.

`export <verb> as <name>(<column> <type> [as <parameter>], ...)` emits the
operation's predicate, admit arms and `require` included, as a boolean function
over parameters bound in place of the row's columns. Validation refuses an
unbound column, an unsupported type, a repeated binding and a verb that maps no
operation; emission refuses a name a generated function already uses.

## v0.82.0

One engine change, additive in surface and a plan change in effect. A spec is
unchanged: no new grammar, no marker to name, nothing to opt into. The emitted
DEFINER set grows by one function per grant and the emitted POLICIES change
shape, so the property to check on adoption is behaviour rather than bytes —
re-emit, diff, and expect every grant reach to have moved from a call to a
membership test.

### A grant's reach is spliced into a policy as a set, not called per row

`defEmitGrantReach` emitted one function per grant, a scalar boolean
`<table>_reach(grantee, value)` wrapping an `EXISTS`, and the RLS emitter
spliced that call directly into the predicate. A SECURITY DEFINER carrying a
SET clause cannot be inlined — each blocks it independently — so spliced into a
policy it is re-entered once per candidate row.

That cost is linear in the TABLE, not in the grant, and a predicate is evaluated
on every row a sort or an aggregate has to consider. `LIMIT` does not bound it:
an ordered page has to filter everything before it can sort anything.

A second function is now emitted beside the first — `<table>_reach_set(grantee)`
returning `SETOF`, selecting the level column keyed by the grantee column under
the same active and expiry bounds — and the policies splice
`<col> IN (SELECT <schema>.<table>_reach_set(<claim>))`. The planner resolves
that once, as a hashed subplan.

The two forms are the same predicate:

    EXISTS (SELECT 1 FROM T WHERE grantee = $1 AND level = row)
      =  row IN (SELECT level FROM T WHERE grantee = $1)

They differ only in three-valued logic, where `IN` yields NULL against EXISTS's
false, and a policy admits on TRUE — so NULL and false are the same admission. A
reach is only ever OR'd into a predicate and is never negated. If that ever
changes, this equivalence is the thing to re-derive rather than assume.

Measured on a 200k-row table behind a 425-node closure four levels deep, an
ordered page of 50: 683ms under the per-row scalar, 58ms under the set form.
The filter ran on 180k rows either way; only the number of definer entries
changed.

### The scalar is still emitted, and is still what a definer's body calls

Not a replacement. Inside another definer the value under test is a parameter
and the call happens once, so the scalar answers it in one comparison and a
membership test against a set would be strictly more work for the same answer.
Any caller holding a direct reference to `<table>_reach` is unaffected.

## v0.81.0

Five engine changes, all additive. A spec that names none of the new markers
emits byte-for-byte what it emitted at v0.80.3, which is the property to check
first on adoption: bump, re-emit, diff, and expect nothing.

### A grant's reach is placed by the reaching subject, not by the grant alone

`defEmitGrantReach` routed a grant's reach to the top-level branch whenever the
grant named the object's own leaf level. That is right when the subject reaching
through the grant is anchored above the leaf, and wrong when it is anchored at
it: the reach then escapes the containment conjunct entirely and admits rows the
enclosing scopes exclude.

Placement now asks where the reaching subject is anchored. A subject anchored at
the grant's own level gets the reach spliced INSIDE containment, so the enclosing
conjuncts still bind; one anchored above keeps the top-level branch it has always
had. Objects that are level entities, and objects whose leaf is global, are
unaffected.

### A doubly-named grant emits its reach once

An object naming the same grant in both a permission term and its level chain
emitted the reach twice: once inside the containment conjunct and once as a
top-level disjunct. The second copy reopened exactly the escape the first was
placed to close. `rlsExprTopBranches` dedupes across both lists now rather than
only within its own.

### A grant may confer named verbs rather than all of them

`grant ... confers select, insert` restricts what the reach admits. Previously a
grant's reach was identical across every command, so a subject reaching through
one gained write and delete wherever it gained read. The option is parsed,
validated against the object's declared ops, and emitted per command; a grant
that names no verbs behaves exactly as before.

### A grant's accessor enumeration reports the access it confers

The accessor enumerator hardcoded `write` for every grant-derived row. It now
reports what the grant actually confers, so an enumeration cannot claim an
authority the policy layer does not grant.

### A wildcard may admit NULL on named ops rather than on all of them

`scoped ... > level wildcard confers select` keeps the NULL-admitting form on the
named commands and emits `IS NOT DISTINCT FROM` on the rest. The unnamed form is
unchanged.

The distinction matters wherever a NULL column means "belongs to the enclosing
scope rather than to any leaf". Admitting NULL on a read lets a subject standing
at a leaf SEE the enclosing scope's rows, which is usually wanted. Admitting it
on a write lets the same subject MODIFY them, which usually is not. `IS NOT
DISTINCT FROM` is the pair: true when both are absent, true when they match,
false when the subject stands somewhere and the row does not. It is a strict
narrowing of the unbounded form, differing only in the cell where a
claim-carrying subject met a NULL row.

## v0.80.3

### Documented — a rolestore's role relation may be a view, and the Go admission seam covers one plane of two

No behaviour change. `rolejoin` has always named a relation rather than a table:
it is interpolated verbatim as a bare name into the emitted definers,
`AssignmentsSQL` and `ListForPrincipalSQL`, and `ValidateAgainst` binds it from
`information_schema`, which reports a view's columns the same as a table's. So a
view has always worked there. Nothing said so, and no test held it, which made it
an accident an adopter could rely on and a refactor could remove.

That matters because of a gap the GUIDE had. Its two "admission filters"
passages point an adopter at the `AssignmentsSQL` + `ResolveHeld` seam for rules
the engine deliberately does not bake in — a disabled role, a client- or
RP-scoped grant. That seam is Go. The same spec also emits SECURITY DEFINER
bodies that join the role relation inside Postgres, where no Go filter reaches,
so a rule applied only through the seam holds in the session and the PDP while
every RLS branch ignores it. The two planes disagree and nothing in the generated
artefacts says so. An adopter hit exactly this: disabling a role removed it from
the permission union and left its holders' row-level reach intact.

Both passages now say which plane the seam governs, and a new GUIDE section —
*A rolestore's role relation may be a view* — documents naming a filtered
relation as the way to apply a rule on both planes at once, including any definer
a later spec change adds. It carries the `security_invoker` caveat: a view over
an RLS-protected table must be created `WITH (security_invoker = true)`, or it
runs with its owner's rights — usually a superuser or `BYPASSRLS` role — and
reads the base table with RLS switched off for every grantee.

Three tests in `rolestore_hardening_test.go` pin the affordance: that the
declared relation reaches the definer JOINs undecorated (neither quoted nor
schema-qualified, either of which stops a view being substitutable), that it
reaches `AssignmentsSQL` and `ListForPrincipalSQL`, and that `ValidateAgainst`
binds a spec naming one without requiring it to be a table.

## v0.80.2

### Fixed — the generated `Holds` helper can read a NULL scope column

v0.76.0 made a NULL scope column meaningful: it is how an assignment says "every
value at this level", and at the root it is how a global assignment is expressed.
The generated `Holds`/`HoldsRoles` fetch helpers could not read one. They scanned
every scope column straight into a `string`, so a SQL NULL failed the scan
outright in Go — `database/sql` cannot convert NULL to string, and the whole call
returned an error instead of a permission set — and became the literal `"null"`
in TypeScript, a scope value matching no level, so the assignment silently
reached nothing. The helpers could not read the very rows the v0.76.0 semantics
are about.

The Go fetch now scans each scope column through a `*string` and copies it only
when non-NULL, leaving the zero value `""` — which is what `Resolve` already
reads as the wildcard. The TypeScript fetch coerces `null` to `""` rather than
stringifying it. Both surfaces now agree with `HoldsResolver.Resolve`, which was
correct throughout, and with the emitted `<admin>_has_perm` definer.

Only the generated fetch changes. `Resolve` is untouched, so a consumer that
reads its own rows — through pgx/pgtype, say — and calls it directly is
unaffected and always was. A plane rolestore's below-plane columns are still
neither selected nor scanned; the levels it does select get the same NULL-safe
read as any other. No policy SQL changes: the committed golden artifacts differ
only in the fetch helpers (`examples/authz`, the TypeScript projection).

`pgx/nullscan_test.go` pins the driver half of the contract — that a NULL text
column scans into a `*string` as nil rather than erroring — because the emitted
code now depends on it.

## v0.80.1

### Fixed — the closure rebuild no longer deadlocks concurrent edge cascades

The emitted `<closure>_rebuild` statement trigger fired even for zero-row
statements, and its `LOCK TABLE ... SHARE ROW EXCLUSIVE` was an upgrade of the
lock a cascading delete already held on the closure table, so two concurrent
deletes of member-able principals deadlocked each other with completely empty
group tables. Reproduced live: 1-3 deadlocks per 400 concurrent single-row
delete pairs. The function now exits before any locking when both the edge and
the closure are empty, and serializes real rebuilds with
`pg_advisory_xact_lock` instead of a table lock: the second rebuild still waits
for the first commit, so the lost-revocation guarantee is unchanged, and no
lock upgrade exists to deadlock. A narrow deadlock remains reachable with
populated tables (a concurrent member cascade against a running rebuild); it is
retryable, and deferred closure maintenance is the eventual shape.

## v0.80.0

### Added — a grant row may name a group, admitting its members through the closure

`via grant` gains an optional tail:

```
relation grantee: operator via grant resource_acl(resource_id, principal_kind, principal_id, access) where resource_type = "note" group "group" closure group_closure(grp, mem) edge group_members(admin_user_id, group_id)
```

A grant row whose kind column carries the group kind value names a GROUP in the
principal column, and admits every principal the closure lists as that group's
member. The hop lives INSIDE the emitted definer (an OR branch joining the grant
table to the closure), so the policy surface is untouched and every existing spec
emits byte-identical SQL. The closure/edge pair is the same machinery `via group`
uses: trigger emission now collects hops from grants too (deduped by closure), so
a grant-side hop alone gets the transitive rebuild, and a spec may share one
closure between an audience column and group grants. Membership itself is the
restriction — a principal population absent from the edge table gains nothing.
The accessor enumerators are deliberately unchanged: they report the group grant
row verbatim; expanding to members is a consumer choice, not an enumeration duty.

### Fixed — duplicate `maps` on one object is now a compile error (V15)

Two permission lines on one object could both map the same table op (`@rls maps select`
twice). Both emitted a policy named `<table>_select`, and because emission writes
`DROP POLICY IF EXISTS` before `CREATE POLICY`, the second silently replaced the
first — a silent authority rewrite, and for a `require` twin a silently dropped
restriction. Validation now refuses the spec and names both verbs.

## v0.79.0

### Added — `wildcard`, a scope level whose NULL means "every value"

Demesne already reads a NULL scope column as a wildcard on the assignment side:
`<admin>_has_perm` emits `(ra.project_id IS NULL OR ra.project_id = <check>)`, so
a role assignment left NULL at a level reaches every value at that level, and one
left NULL at the root is global. The Go and TypeScript `HoldsResolver` agree.

A *row* could not say the same thing. `scoped tenant > project` emits

```sql
tenant_id = <tenant claim> AND project_id = <project claim>
```

and `NULL = anything` is NULL, so a row storing `project_id = NULL` to mean "this
belongs to the whole tenant" was visible to nobody — not even to the session that
owns it, which names no project and so cannot match it either. The only way to
ship such a table was an empty-string sentinel, which is not a project id and so
cannot take a foreign key to one.

Marking the level opts that column into the assignment-side reading:

```demesne
object role {
  table  roles
  scoped tenant > project wildcard
  permission view = @holds(members:read) @rls maps select
}
```

```sql
tenant_id = <tenant claim> AND (project_id IS NULL OR project_id = <project claim>)
```

The change lands **in the containment conjunct**, which is the only place it can
be correct. `@within(<level> nullable)` looks like it does this and does not: it
appends a disjunct *inside the permission disjunction*, where containment has
already pinned the column, so the added term is unconditionally true and
dissolves the authority check beside it. That construct is unchanged and still
means what it meant; this is a different thing in a different position.

**It only ever adds `<col> IS NULL`, and only on the level you mark.** Every row
that was visible before is visible on the same terms; the rows whose visibility
changes are exactly the NULL ones, which no session could reach. Unmarked levels
keep the bare equality, so a project-scoped row stays invisible to another
project's session, and a wildcard project cannot escape its tenant.

It is containment, not permission: the authority conjunct is untouched, and
`@holds` passes the *row's* scope columns to the definer, so a NULL project is
checked at tenant scope and an assignment pinned to one project does not satisfy
it. On a containment-only object (`@scoped` alone) there is no such check and any
session in the tenant can write a wildcard row — which is what the declaration
asks for, and worth being sure of before writing it.

The marker is a compile error where it could not bind: on a virtual level, which
emits no containment conjunct, and on a level entity's own level, whose scope
column is the primary key and is never NULL (V6). A silent no-op in an
authorization spec is worse than a rejection.

One declaration, every surface: the compiled predicate is what the RLS policy,
the `Can<Verb>` point-check, `@check` accessors and a verb borrowed through `via
object` all run, so there is no second place to keep in step.

Additive. Every existing spec emits byte-identically — `wildcard` appears in no
spec until it is written, and the committed golden artifacts (`examples/authz`,
`examples/supabaseauthz`, the TypeScript projection) are unchanged.

## v0.78.0

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

Resolved in v0.80.2; the text below describes v0.77.0 as it shipped.

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
