# Changelog

## v6.0.1

### A reader listing names through a `some`, and lists a union of conditions alone

- A select permission whose every arm is conditional no longer fails with
  "empty union in the SELECT permission tree": its listing,
  `<table>_accessors_conditional`, is its conditional rows alone.
- A `some` whose brackets name principals (a column, a grant, a group or an
  unconfined closure, alone or beside conditions on the request, the row or its
  mode, or such a condition alone) lists those principals on the rows whose
  column holds an element the term binds by its prefix, with its conditions as
  conditional rows on those rows, in place of one conditional row admitting
  every caller. `held` is left to `<table>_admits`, as a claim conjunct is. Any
  other `some` lists as before.

A spec with neither emits the same SQL, definers, manifest and application
surface as v6.0.0.

## v6.0.0

The crates are 6.0.0 because public types of `demesne-syntax` change:
`Object` gains `beneath`, and `Marker`'s `closure` becomes a `MarkerClosure`,
which says which marked containers above a row's own confine it. A spec that
uses neither construct below emits the same SQL, definers, manifest and
application surface as v5.0.1. The Go module's API doesn't change, so it stays
`go/v1.6.0`.

### `beneath`: an object scoped above a level takes its containers' markers

```demesne
object space {
  table spaces
  level space
  scoped estate
  marker made_by from claim job_id confines insert, update, delete
}

object ledger {
  table ledgers
  scoped estate
  beneath space
}
```

A marker confined the rows of every object scoped at its level and no other.
An object scoped only above the level, whose rows still name one of the
level's containers by the level's column, took none of its markers, so a row
placed in a marked container was written by whoever the object's own rules
admit. `beneath <level>` says the object's rows sit beneath the level's
containers. Each marker on the level then joins the object's
`<table>_<operation>_require`, its point checks and any predicate another
object borrows from it, as `(<column> IS NULL OR
<table>_<column>_marker_admits(<column>, <claim>))`, exactly as it does for an
object scoped at the level. The object's other rules don't change, and the
clause emits no function of its own.

It is refused on a level the topology lacks, a virtual level, a level the
object is scoped at, an object not scoped at exactly the levels above it, a
level no object declares, and a second `beneath` on one object.

### `through nearest closure`: the nearest marked container decides

```demesne
closure paths(anc, des)
  base spaces(id, parent_id)
  depth hops

object space {
  table spaces
  level space
  scoped estate
  marker made_by from claim job_id confines insert, update, delete through nearest closure paths
  marker kept_by from claim kind_id confines insert, update, delete through nearest closure paths
}
```

`through closure` confines a row by every marked container above its own, so
a container marked inside another marked one is written under neither claim
alone. `through nearest closure <table>` lets the nearest container at or
above the row's own that carries any of the object's nearest markers decide:
each of that container's markers applies, an unset one passing, and the marked
containers above it don't confine. A container that carries none of them
belongs to the nearest one above it that does. The closure must declare
`depth`, and every nearest marker of an object reads the same closure.

`demesne_syntax::Object` gains `beneath`, an `Option` of the new `Beneath`.
`demesne_syntax::Marker`'s `closure` is an `Option` of the new
`MarkerClosure`, `Every` or `Nearest` with the closure's table, in place of
the table's name.

## v5.0.1

A spec that compiled under v5.0.0 emits the same SQL, definers, manifest and
application surface. The public API doesn't change, and neither does the Go
module's, so it stays `go/v1.6.0`.

### A marker on a level whose object is scoped only above it

```demesne
object space {
  table spaces
  level space
  scoped estate
  marker made_by from claim job_id confines insert, update, delete
}
```

The object that declares a level may now be scoped at exactly the levels above
it, for a container that callers stand above rather than in. v5.0.0 refused
such an object (`level space must be its deepest scoped level`), so a marker
could go only on a container scoped at its own level, which made each confined
operation holder-only: a caller whose claims did not name the container was
refused beneath it.

Its own rows keep the rules they would have if it declared no level: the same
policies and the same definers, with no accessor listing of its own. Its
markers confine the rows beneath it as before, but its containers are held by
the levels above them. The caller's containment holds a container when the
caller's claims name each level above it, whether or not they name the
container; a reach holds it when one of the caller's grants reaches a level
above it; a claim-only branch holds every container. `<table>_<column>_marker_admits`
asks the same, and is false for a container the caller does not hold.

The level is refused on an object scoped neither at it nor at exactly the
levels above it, with `object "…" level "…" must be its deepest scoped level,
or the object must be scoped at exactly the levels above "…"`.

## v5.0.0

The crates are 5.0.0 because public types of `demesne-syntax`,
`demesne-model` and `demesne-emit-sql` gain fields and variants, named under
each change, and `demesne_emit_sql::Sql` gains private fields, so it is built
with `Sql::new`. A spec that uses none of the constructs below emits the
policies v4.0.0 did, with seven exceptions: the first two under "Fixed"; a
`via memberin` relation that takes both its principal and its scope from the
row, which is refused (the first "Breaking" entry); a permission whose terms a
grant's holder used to pass (the second "Breaking" entry); a call to a
generated function whose arguments are the same for every row, which now runs
once per statement; a group or closure relation of a
subject other than the owner, or an `@session` over a relation judged by
several calls, which is refused until the spec says what it admits (the third
"Breaking" entry); and a rule that asks about the admin in a spec where no
subject binds admin and none is identified by `sub`, which is refused (the
fourth "Breaking" entry). Its generated functions change: see "Breaking"
first. The Go module's API doesn't change, so it is `go/v1.6.0`.

### Security: a temporary table could stand in for a table a generated function reads

Every generated function runs as its owner and names the tables it reads
without a schema, relying on the search path it sets. Postgres searches a
session's temporary schema before that path unless the path names `pg_temp`.
A caller who may create temporary tables, as PUBLIC may in a new database,
could create one named like a table a function reads (a subject's membership
table, a role store's assignments or roles, a grant table, a group's
closure) and the function read the caller's rows instead: a check answered
from rows the caller wrote. A trigger that keeps a closure in step could
likewise write the caller's table and leave the real one stale.

Every generated function now sets its search path with `pg_temp` last. Every
release from v1.0.0 has this, and so does the Go engine's v0.93.x, which gets
no fix: upgrade to v5. Upgrading fixes it: `emit migrate` from a v4.0.0
manifest writes the whole SQL, so every function is created again, and `diff`
names any live function whose definition still lacks `pg_temp`. A live test
shadows every table a spec reads with forged rows in a session that may create
temporary tables, and every check, and both triggers, still use the real
tables.

### Breaking: a generated function answers only about the caller, or PUBLIC cannot run it

Every generated function is `SECURITY DEFINER`, and Postgres lets PUBLIC
execute a new function. Many took an identity or a node as an argument and
answered for any value. A caller could run one directly and ask about someone
else: list another node's subtree, read which levels another principal is
granted, or learn whether another principal holds a role.

From this release one rule holds for every generated function but
`<table>_declared_by_<key>` (below). **It answers only about the caller's own
claims, or `EXECUTE` is revoked from PUBLIC.**

- **Bound to the caller.** A function that takes a principal (`user_id`,
  `p_principal`, `p_member`, the first argument of
  `<principal>_can_access_<object>`), a closure node (`<closure>_descendants`,
  `_ancestors`, `_reachable`), a marker's claim value or a stored condition's
  claim values now answers only when that argument is the caller's own claim.
  For any other value it answers false, the empty set, or NULL where the
  function can already say "undecided". The binding changes no signature;
  ids retyped to the spec's identifiers and a store copy's renamed parameter
  are the `<object>_can_<verb>` entry's (below).
  `<admin>_memberin_<level>(principal, scope)` is bound on its principal. Where
  a rule passes a row's column as the principal and a claim as the scope
  (`via memberin tenant(id, @tenant_id)`), it also answers for the scope that
  claim names, and for no other scope: such a rule already shows the caller
  which principals are members of the scope the caller stands in. A grant
  relation's check (`<relation>_grants`, `<acl>_grants_<object>`) is bound on
  the principal it is asked about. The async tier's
  `<index>_affordance(p_resource, p_kind, p_principal)` answers only where
  `p_principal` is the caller's own claim for the subject `p_kind` names. The
  async check now asks it once for each subject the relation names, each with
  that subject's claim, and, as the policy does, takes a grant to a subject
  other than the owner only from a caller who carries no owner claim. It
  passed the owner's claim under the first subject's kind, so a caller of
  another subject was never asked about, and where the first subject was not
  the owner, a grant to a principal of that subject whose id equalled the
  caller's claim answered for the caller.
  `demesne_emit_sql::AsyncIndex` gains `callers`, each principal kind with the
  claim that identifies a caller of that kind. Which argument is the principal
  is decided where the function is generated, not by its name, so a parameter
  of an `export` or a `probe` is never taken for one. A function is bound to
  the identity claims of the subjects whose principal it takes, never another
  subject's, so where ids collide across subjects (two integer sequences, say)
  a caller of one subject is never taken for a principal of another.
- **Revoked from PUBLIC, or not emitted.** A generated function stays PUBLIC
  only where something must run it as the caller: a policy calls it, a
  generated application check calls it (a `@check` point check, the edit
  check, the async check), or a spec line makes it yours to call (an `export`,
  a `probe`, a `projection`, a `check` (below), `<principal>_can_access_<object>`
  for a `@kernel` permission, and the `<flat>_resources()` list the application
  surface reads). A grant's `_reach_in_<level>` is yours to call too: it answers
  only about the caller, at the node you name. A function meant for a role you
  grant is revoked and listed `grantable` (below): `<table>_accessors`,
  `<table>_accessors_conditional`, `<table>_direct_accessors` and
  `<table>_<verb>_accessors`, which name the principals that reach any row id,
  `<closure>_path`, which returns any node's ancestors, `<table>_admits`, a
  `nearest` lookup for any node, the async tier's maintenance and a
  materialized group's `<flat>_reconcile()`. Any other function that only
  generated functions call is revoked, since they run as its owner, and keeps
  its binding. A function nothing calls is no longer emitted: a grant's
  `_reach`, `_reach_unscoped` and a `_reach_set` no policy calls, a declared
  closure's functions no relation reads, and a role check, a membership, a
  borrowed `<object>_can_<perm>`, an `<acl>_grants_<object>` or a group lookup
  that no permission uses. Neither is a composition's lower bound where only
  its upper bound is called, `<flat>_resources()` where the surface doesn't
  list through it, or `<object>_<operation>_holds_at` (below). A migration
  drops each one. `Sql::unused_definers()` names the functions a spec's
  generators make and this rule leaves out.
- **Left as it was.** `<table>_declared_by_<key>` returns the rows a table
  declares for a key, with the columns permissions read. A policy calls it with
  a row's value, so it answers any caller for any key: keep nothing in a table
  a permission declares that a caller of any tenant should not learn. A `path`
  reads its rows through `<table>_along_<key>`, with the columns paths read.
  Only the chain calls it, so it is revoked, even where a permission reads the
  same table by the same key.

Every policy passed the caller's claim but one shape's:
`via memberin <level>(<column>, <column>)` takes both the principal and the
scope from the row, so bound to the caller it would admit only a caller who is
the row's own principal. Validation now refuses that shape (below). The binding
changes no other policy, and no rule that still compiles admits or refuses
anyone it did not before because of it. Other entries do change what some
specs admit or whether they compile: the grant and relation Breaking entries
below, and the first two under "Fixed".

The binding assumes only your API sets the claims. A caller who can run
arbitrary SQL as the caller role can set them with `set_config`, as it always
could; the guide now says so in as many words.

Every function the SQL creates is now followed by `GRANT EXECUTE … TO PUBLIC`
or `REVOKE EXECUTE … FROM PUBLIC, authenticated`. `CREATE OR REPLACE FUNCTION`
keeps a function's privileges, so without the grant a function that one
release revoked and a later one made PUBLIC again would have stayed revoked.
A revoke also names `authenticated`, the role every policy is written for, so
a grant made to it by name, by a grant over the whole schema or by default
privileges does not outlast applying the SQL. Applying the SQL now leaves
PUBLIC and `authenticated` exactly the right it states. A grant to any other
role stays.

`demesne diff` reports a function PUBLIC may not run that the SQL grants, as
well as one PUBLIC may run that the SQL revokes. For a function the SQL
revokes, it also reports, as `GRANTED`, each role other than the owner that
may run it live, and each default privilege that grants new functions in a
definers schema, or in every schema, to a role other than its own. Each
finding ends with the statement that takes the grant back. A role you grant the
manifest's `grantable` functions to holds them by design: name it with
`demesne diff --grantee <role>`, once for each such role, and its grants of
those functions are not reported. Its grant of a revoked function and every
default privilege still are. `--grantee PUBLIC` is refused, since PUBLIC holds
exactly what the SQL grants it, and so is `--grantee authenticated`, the role
every policy is written for, since a grantable function answers for any id.
`demesne_postgres::drift` takes a fourth argument, `&Grantees`, built by
`Grantees::new` from the manifest and the role names; `Grantees::default()`
names none and reports what it did before. `demesne_postgres::Error` gains
`is_grantee`. `demesne_emit_sql::granted_to_public` reads the grants as
`revoked_from_public` reads the revokes; `demesne_emit_sql::POLICY_ROLE` names
`authenticated`, and `demesne_postgres::DriftKind` gains `Granted`. Every
spec's SQL gains these lines.

What breaks for an adopter:

- **SQL of your own that calls a bound function with another principal's id,
  or another node, now gets false or nothing.** So does a call made with no
  claims set. Read the tables in that statement instead, under a role that may.
- **A `via memberin <level>(<column>, <column>)` rule no longer compiles.**
  Validation refuses a `memberin` that takes both its principal and its scope
  from the row, with `reachedby` or without: its function answers only about
  the caller, so the rule would admit no one but the row's own principal. A
  `memberin` with a claim on either side, such as
  `memberin tenant(id, @tenant_id)`, compiles as before.
- **SQL of your own that runs as the caller role and calls a generated
  function no policy calls now gets `permission denied`.** That includes a role
  helper, a grant's reach function and a closure function you called directly.
  A generated function is the policies' tool: read the tables that statement
  needs instead, under a role that may. Granting `EXECUTE` on a revoked
  function that keeps its binding gives back only what the caller could ask
  about itself. An `<function>_inside` copy has no check of its own, so it
  runs with its caller's rights (`SECURITY INVOKER`): called from a generated
  function it runs as that function's owner, and run directly it reads only
  what the caller may. A function the `grantable` list names answers for any
  id or claims it is given, so grant it only to a server-side role you trust,
  such as a worker's, never to a role your API's callers run as.
- **A grant of every function in the definers schema, or default privileges
  that grant new functions there, outlive the upgrade for any role but
  `authenticated`.** Earlier versions of the Supabase guide said to run `grant
  execute on all functions in schema demesne to authenticated`. After
  upgrading, revoke such a grant from each role you made it to, with the
  matching default privileges (`alter default privileges in schema demesne
  revoke execute on functions from anon, authenticated`), grant what
  `callable` lists, and run `demesne diff`, naming with `--grantee` each role
  you grant the `grantable` functions to: it names each grant still left on a
  revoked function, or on a grantable one to a role you did not name, and each
  default privilege that would make one, with the statement that takes it
  back.
- **SQL of your own that called a generated function nothing else calls gets
  `function does not exist`**, since that function is no longer emitted. Read
  the tables in that statement instead, under a role that may.
- **A role that lists accessors or reads `<closure>_path` needs
  `GRANT EXECUTE`** on those functions. So does the role your async worker
  runs as, on `<index>_apply()`, `_rebuild()` and `_watermark()`, and the role
  that reconciles a materialized group, on `<flat>_reconcile()`: PUBLIC could
  run those four before. The manifest's `grantable` list names every function
  meant for a role you grant (below). Each answers for any id, so grant it
  only to a server-side role you trust, never to a role your API's callers
  run as.
- **A revoke from PUBLIC that you made by hand on a function the SQL grants is
  undone** when you apply the SQL. So is one made by default privileges
  (`ALTER DEFAULT PRIVILEGES … REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`). The
  manifest's `callable` and `internal` lists name every function the SQL
  grants.

**Upgrade with `emit migrate`, never by applying the new SQL alone.** v5.0.0
no longer emits functions v4.0.0 did (above). Applying v5's SQL over a v4
database leaves each of them as v4 made it: PUBLIC, unbound, and answering for
any argument. `auth.has_org_role(user_id)`, for one, would go on telling any
caller whether any user holds the role. Keep v4's manifest, or write it with
v4's CLI (`npx @foir/demesne-cli@4.0.0 emit <spec> manifest > v4.json`), and
apply `demesne emit <spec> migrate v4.json`: v5's SQL, then exact drops of
what v4 created and v5 does not, then a check that nothing dropped is still
there. If v4's manifest is lost, apply v5's SQL and run `demesne diff`: it
reports each function v4 left behind as an orphan, and you drop each one. A
spec that declares `changelog checked` has no v4 manifest to give, since
v4.0.0 refuses to write one for it (see "Fixed" below), so it upgrades by
`diff`.

### The manifest says who may run each function

`demesne emit <spec> manifest`, and its `--file` form, puts every function the
SQL creates in exactly one of four lists beside `functions`. `callable` holds
the functions a spec line makes yours to call. `grantable` holds those PUBLIC
may not run that are yours to grant to a role of your own: the listings of
accessors, `<table>_admits`, `<closure>_path`, a `nearest` lookup for any
node, the async tier's `<index>_apply()`, `_rebuild()` and `_watermark()`, and
a materialized group's `<flat>_reconcile()`. Each answers for any id it is
given, so grant it only to a server-side role you trust, never to a role your
API's callers run as. `internal` holds those PUBLIC may run that no spec line
makes yours, and `revoked` those PUBLIC may not run that only the generated
functions call. Code of your own calls what `callable` lists, and what
`grantable` lists from a role you granted it to. Every
manifest gains the four lists, empty ones included. A policy or a generated
check that would call a `grantable` function is refused when the SQL is
emitted, naming both, since the caller's role may not run it; a function is
never made PUBLIC because something calls it.

Reading a manifest refuses one whose lists hold a function twice, leave one out
or name one `functions` does not, and one with some of the lists and not the
others. A manifest written before this release has none of them. It still
reads, as one that does not record who may run its functions, and `migrate`
uses it as before.

`demesne_emit_sql::Manifest` gains `execute: Option<ExecuteLists>`.
`Sql::manifest` always fills it, and `Manifest::from_sql` leaves it `None`,
since SQL alone does not say which functions a spec line makes yours.

### `emit migrate` writes only what changed, in one transaction

The manifest now records a digest of the statements that create each object,
under `digests`. `emit migrate` writes only the objects whose statements
changed or are new since the manifest it is given, with the policies a renamed
function's drop takes (below). An unchanged policy is not dropped and created
again, so its table is not locked and the policy keeps its oid. A manifest
without digests gives the whole SQL, with a comment line saying so. Since an
unchanged object is not written, a migration no longer undoes a hand edit to
one, such as a revoke from PUBLIC: `demesne diff` reports it, and applying the
whole SQL restores it.

`emit migrate` and `emit --file … migrate` now wrap what they write in
`BEGIN` and `COMMIT`. A migration that drops a policy and creates it again
must be one transaction: between the two, a reader saw the table without that
policy, and without a restrictive `_require` policy that means rows it bars.
`--no-transaction` leaves the wrapping out, for a runner that wraps each
migration itself (sqlx does, and a `COMMIT` inside would end its transaction
early).

### `emit migrate` drops first a function whose parameters changed

Some generated parameters are named after a subject or a level, such as
`<acl>_grants(p_<subject>_id, …)` or a role check's `check_<level>_id`, so
renaming one renames the parameter, and `CREATE OR REPLACE` cannot rename a
parameter. The manifest now records each function's parameters, its return
type and the policies that call it, under `heads`. A migration from a manifest
that has them first drops each function whose parameters or return type
changed, and only the policies that call it; the SQL then creates both again.
So does a function the migration drops because its argument types changed,
with the policies that call it, since a policy whose text is the same would
otherwise keep the old function and the drop would fail.
A manifest written before has no `heads`, so its migration cannot see such a
change and says so in a comment line: drop those functions by hand.
`Manifest` gains `heads` and `Manifest::renamed_since`, and the multi-file
`--file` forms do the same.

### `check`: one row against a permission lent with `predicate`

A predicate-only permission is answered for one row by the function its borrow
emits, `<object>_can_<verb>`. A policy calls that function as the caller, so
PUBLIC may run it, but no spec line makes it yours: it is `internal`, and a
release may change it. A `check` is the form for code of your own:

```demesne
check open_only for select as ledger_open(id text)
```

It emits `ledger_open(p_id text)`, listed `callable`. Its body is the borrow's,
`<object>_can_<verb>` or `<object>_can_<verb>_for_<op>`, with the argument as
the row's key, so it answers exactly what a policy that borrows the permission
enforces, the object's containment and a grant's reach included. It takes no
principal and reads the caller's claims. A key that names no row answers
false; a NULL key answers NULL. `as` names the parameter, which is `p_<key>`
otherwise.

A check is refused when its permission is not predicate-only (an `export`
answers one that maps an operation), when `for` names no table operation, when
its one argument is not the object's key, on an object with a composite key,
and when another generated function has its name. It counts as a use of the
permission it lends, so such a permission that only a check reads is no longer
refused as never borrowed. `demesne_syntax::Object` gains `point_checks`.

### Breaking: a grant gives reach, and the permission's terms still bind its holders

A grant at a scope level lets its holder stand at rows the holder's claims do
not name. On two shapes it also let the holder pass without the rest of the
permission, though nothing in the spec said so: an object whose lowest scope
level is the grant's, and a level's own table. `permission view = @scoped and
<terms>` emitted `<reach> OR (<scope> AND <terms>)`. On an object with a level
below the grant's the same grant only widened that level's column and the
terms applied.

Now the terms apply on every shape. The same permission emits
`(<reach> OR <scope>) AND <terms>`. A permission with no term under the scope
at all (`view = @self(<column>)`) no longer admits the grant's holders. A
permission that is `@scoped` alone emits what it did. An admit arm, a
projection and the evaluator a `@holds_at` hop asks take the grant's reach the
same way, beside the scope and under their own terms, so a grant's holder
passes them where it passes the permission; they used to hold it to the scope
its claims name on these two shapes.

What breaks for an adopter, and how to keep a pass that was meant:

- **A holder of such a grant is refused where it does not satisfy the
  permission's terms.** Read every object scoped at a grant's own level and
  every level table a grant reaches. A holder who has no role, ownership or
  claim the terms ask for is now refused there.
- **A role check no longer counts a grant's holder as holding the role.** The
  check behind `<level>->owner` (`is_<level>_<subject>`) answered yes for a
  caller who held a grant at that level, so such a term admitted the grant's
  holders whatever role they had, and through an identity the check did not
  bind. A grant gives reach, not a role: the check now answers from role
  assignments alone, and from a platform operator's membership only where the
  operator is identified by the same claim as the role's subject. There an
  operator presenting a scope's claims holds every role in it, which the
  operator's own branch, for a caller presenting no scope, does not give.
  Where the claims differ, the membership was asked about the role subject's
  id and answered only for a credential carrying both claims with one value.
- **To keep the pass, name the grant:** `permission view = (@scoped and
  <terms>) + via grant <name>`. That permission emits exactly what it emitted
  before. A `reach <grant> unscoped|bound|via … for <operations>` line on the
  object keeps it too, for the operations it names, and also emits what it
  did.
- **A grant named in a permission where it adds nothing is refused at
  validation.** On an object with a level below the grant's, or where every
  subject reaching by the grant is anchored at the grant's level,
  `+ via grant <name>` was silently dropped: the SQL was the same with it and
  without. The message names the level and says to remove the term. Removing
  it changes no SQL. No spec admits more after this release than before it.
- **A `pinned` borrow on an object whose terms now bind a grant's callers is
  refused.** Drop `pinned` there, or name the grant in the permission
  (`+ via grant <name>`): its holders then pass by the grant, and the pinned
  borrow binds only callers the scope holds, so the permission compiles.
- The reverse listings (`<table>_accessors`) list a grant's holders as they
  did; they are an upper bound there, as they already were on deeper objects.

`demesne_emit_sql`'s write check reports such a reach as part of the write
term it now belongs to, not as "a subject's own reach".

### Breaking: a relation of another subject, and `@session` over several calls, say what they admit

A policy passed a group's `<closure>_member`, a materialized group's
`<flat>_member` and an undeclared closure's `_reachable` the claim of the
object's owner subject, whichever subject the relation names. A relation
typed as another subject (`team: staff via group ...` on an object a customer
owns) so admitted none of that subject. `@session(<relation>)` over a relation
judged by one call per subject (a grant or group relation naming several)
used only the first subject's call.

Now the spec says which it means, or validation refuses it, naming the
relation and showing the line to write:

- **A group relation naming a subject other than the owner** takes
  `from claim <key> [| <key>]` after `on <column>`: `relation team: staff via
  group tc(grp, mem) edge te(mem, grp) on team_id from claim sub`. Each key is
  the identity claim of a subject the relation names. The policy makes one call
  per key and, as a grant relation does, judges a credential that also carries
  the owner's claim only as the owner. To keep the rows v4.0.0 admitted, type
  the relation as the owner subject alone.
- **A closure relation naming a subject other than the owner** takes the
  `from claim <key> missing allow|deny` it already could. A closure relation on
  an object with no owner subject was refused before and still is, now with
  that line shown.
- **`@session(<relation>)` over a relation judged by more than one call**
  names the subjects it admits: `@session(grantee as customer)` keeps v4.0.0's
  meaning, the first subject's call; `@session(grantee as customer | staff)`
  admits each. A subject the relation does not name is refused.

No spec admits more after this release than before it.

Alongside: a materialized group's `<flat>_resources()` matches the claims its
policy passes and returns the spec's identifier type rather than `text`; a
group's `<closure>_member` answers for the subjects of every group relation
over that closure, not only the first; and an undeclared closure's
`_reachable` answers for the claims its relations pass, no longer for every
subject's identity.

A corpus test checks that every call to a function bound to the caller passes,
at the bound parameter, a claim that function binds. A live test admits staff
through a team, a materialized crew and a closure that say `from claim sub` on
a customer's objects, admits a customer through a group whose closure a staff
relation shares, and refuses staff whose credential also carries a customer.

### Breaking: a rule that asks about the admin needs a subject that declares the admin's claim

A role relation (`via role`), a role walk (`tenant->owner`), `@holds`,
`@session` over a role relation, a `memberin … reachedby`, `@self` and
`selfcheck` ask about the admin: they pass the claim of the subject that
`binds admin`. With no such subject they passed `sub`, whether or not any
subject is identified by it. In a spec where no subject binds admin and none
is identified by `sub`, such a rule asked about a claim nothing declares. It
refused every caller whose credential lacks `sub`, and asked about whatever
`sub` held for a caller whose credential carries one.

Validation now refuses each of those constructs in such a spec, wherever it
appears: in a permission, a requirement, an `admit` arm or a relation's path.
The refusal names the construct and the remedy: add `binds admin` to the
subject it asks about. A spec with a subject that binds admin, or one
identified by `sub`, compiles as before and emits the same policies. A
`@holds` in a permission only the decision point answers reads no such claim
and is not refused. A validation test refuses each construct in such a spec,
and accepts each once a subject binds admin or is identified by `sub`.

### `some`: one element of an array column, and what must hold for it

```demesne
permission view = some r in rules_live prefix "read." held rules_held (
    (@element prefix "read.edge." and shared) + (@element prefix "read.open." and mode access = "open")
) @rls maps select
```

`some <name> in <array column> [prefix "<text>"] [held <claim>] ( … )` is true
of a row when one element of the column satisfies the brackets. `prefix` binds
only elements that start with the text, and `held` only elements the claim's
JSON array also holds. Inside the brackets `@element prefix "<text>"` tests the
bound element, and a keyed edge matches it:
`via edge <table>(<principal>, <object>) key <column> [on <row column>] [where <column> = "<value>"]`
compiles to `<object>_<relation>_keyed(principal, object, key)`. The term is one
`EXISTS` over `unnest(<column>)` per row.

`demesne_syntax::Builtin` gains `Some` and `ElementPrefix`, `ViaEdge` gains
`key`, `on`, `filter` and `slot`, and `PermNode` and `Term` derive `PartialEq`.

### `every` and `none`: the rows a table declares for the element

Inside a `some`,
`every <name> in <table>(<key column>) [where <column> = "<value>"] ( … )` holds
when the brackets hold for every row the table has for the bound element, and
`none …` when they hold for no row. `@slot(<column>, "<value>")` tests the
declared row, and `slot <column> [from <declared column>]` on a keyed edge or a
`via composition` matches one of its columns against the declared row's. A
permission reads the declared rows through one generated function per table
and key, `<table>_declared_by_<key>`, which returns only the columns
permissions read.

`none` bars when a row's brackets cannot be decided, and `every` fails on one.
A plain `not` keeps its meaning.

`Builtin` gains `Declared`, `Slot` and `SlotHeld` (`@slot(<column> held <claim>)`:
the declared row's column is one of the claim's JSON array), and
`ViaComposition` gains `slot`.

### `via conditions`: stored conditions compared with what the caller's claim carries

```demesne
relation terms: member via conditions doc_terms(doc_id, term, op) values (num, txt, at, list, lat, lng) key rule on id from claim facts
```

Each stored row names a term, an operator and a value. The caller's claim is a
JSON object keyed by term. The relation holds when every stored row for the
object (and key, inside a `some`) holds against the claim's value for its term.
It is three-valued: false when any condition is decided false, unknown when
one cannot be decided (the claim carries no value for the term, or a value of
the wrong form), and true otherwise. It compiles to
`<object>_<relation>_hold(object[, key], values)`.

The operators are `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `in`, `not_in`,
`includes`, `not_includes`, `contains`, `prefix`, `suffix`, their `caller_` and
`not_` forms, `not_before`, `not_after` and `within_km`. `num` is double
precision and text is compared by code point. `within_km` is the haversine
distance with a radius of 6371.0 km, and is unknown for a latitude or longitude
out of range. With `extension postgis [schema "<name>"]` declared it compiles
to `ST_DWithin` on geography.

A conditions relation only narrows: a rule in which it would admit a caller by
itself is refused.

`demesne_syntax::Repr` gains `Conditions(ViaConditions)` and `Spec` gains
`extensions`.

### A role store's `held claim`: permissions the credential carries

`held claim <key>` in a `rolestore` names a claim holding a JSON array of
permissions. `@holds(<permission>)` is then also true when the array holds the
permission (or one that implies it) and the row stands where the session
stands: at the top level its scope column equals the claim, and at a lower
level the claim is absent or equal. A row whose object is not scoped at a level
the session names is not reached. An assignment in the role store still counts
as before.

`demesne_syntax::RoleStore` gains `held_claim`.

### A role store whose roles have forms, and roles that are in force

```demesne
rolestore staff {
  rolejoin role_id roles id key
  permissions permissions
  form claim channel = "draft" base
  form claim channel = "live" permissions live_permissions
  absent claim reads "live"
  unversioned estate_id null
  active disabled_at null
}
```

A role's definition can exist in more than one form, and a claim picks the one
a session reads. `form claim <key> = "<value>" base` reads the base columns for
that value, and `form … permissions <column> [key <column>]` reads the named
ones. `absent claim reads "<value>"` names the form a session with no value
takes; a store with a `form` line is refused without it. A value no `form`
names reads no role. A form whose permissions column is NULL is no role in
that form, by name as well. `unversioned <column> null` or `= "<value>"` marks
roles that have the base form only. `active <column> null` or `= "<value>"`
says which roles are in force: a role that fails one is no role in any form,
and the line stands alone in a store with no forms.

Every generated read of a role's name or permissions follows the same rule:
`@holds`, a role matched by name, and the access listings. A store with none
of the lines emits what it did.

`demesne_syntax::RoleStore` gains `forms` (a list of the new `RoleForm`),
`absent_form`, `unversioned` and `active`.

### `@clock(<column> reached)`

A row test: true when the row's instant is not in the future. An unset column
is never reached. It compiles to `<column> <= now()`.

`Builtin` gains `Clock`.

### `marker`: a column on a level's row confines the operations it names beneath it

```demesne
object space {
  table spaces
  level space
  scoped estate > space
  marker made_by from claim job_id confines insert, update, delete through closure paths
}
```

Every other object scoped at the level gains, for each named operation, a
restrictive condition: the caller holds the row's container, and the container
is unmarked or its marker equals the session's claim. A marker confines its
ops to callers whose containment, reach or claim-only branch holds the
container, for every container, top-level included: declaring a marker for an
operation makes that operation holder-only. A row that `@self` or `@public`
admits is therefore refused beneath any container the caller does not hold,
whatever its marker column holds. A level value that names no container
refuses, and a row whose level column is NULL is asked nothing. With `through
closure <table>` every marked container above the row's own confines too.
Several markers on one level all apply. The container's own row keeps its own
rule. Each marker compiles to `<table>_<column>_marker_admits(container,
claim)`, and the condition joins the object's `<table>_<operation>_require`
policy, its point checks and any predicate another object borrows. The
function is false for a container the caller does not hold, whatever its
marker column holds, so calling it directly tells a caller nothing about
another tenant's containers.

A marker that confines `select` must confine `update` and `delete` too, or the
spec is refused: Postgres applies a write only to rows the read policy shows.

`demesne_syntax::Object` gains `markers`, a list of the new `Marker`.

### Chains whose hops depend on the caller: `path`, `nested` and the evaluator

A closure table says a row reaches another through a chain. It is shared by
every caller, so it cannot say whether each hop holds for this one.

```demesne
object doc {
  nested 1
  relation lent: member via composition doc_lends(borrower_id, lender_id) slot field from param
      path trail along (
        every h in trail_hops(trail) (
            (@slot(kind, "claim") and @slot(rule held rules_held))
          + (@slot(kind, "live") and @holds_at(doc_id, rule slot field for select)) ) )
}
```

- `path <column> along ( … )` on `via composition`: a closure row counts only
  when the brackets hold of the rows declared for its path key. One column
  serves every operation, or name one each:
  `path select seen, update changed, delete dropped along ( … )`. The chain
  reads those rows through `<table>_along_<key>`, which returns only the
  columns paths read and which no caller may run.
- `@holds_at(<record column>, <element column> [slot <column>] [for <operation>])`:
  the element the hop names holds at the row it names, for this caller, **with
  the composition the path is on taken as followed there**. A slot-bound
  composition names the column that says which slot the hop follows. Without
  `for`, a hop is judged for the operation the composition is followed for.
- The evaluator is the permission's `some` brackets compiled for one element at
  one row: the row is inside the caller's containment, the element is in the
  row's column and passes `prefix` and `held`, and the brackets hold.
  A hop inlines it where it is followed. Nothing calls it as a function of its
  own, so none is emitted: to ask whether the caller passes a permission on one
  row, declare a `check` (above), which reads the stored row.
- `nested <n>` on the object says how many further compositions deep a hop is
  judged. A hop's own composition costs nothing. Another composition in the
  hop's rule is followed through one level less, and at the last level it is
  not followed.

Past the nesting the answer is the safe one. Every generated function has a
lower bound and, where something narrows by it, an upper bound
(`…_upper`). A composition that widens a rule is followed by the lower bound,
so what cannot be followed does not admit. A composition under `not` or inside
`none` is followed by the upper bound, so what cannot be followed, or cannot be
decided, bars. Only the functions something calls are emitted.

A hop is judged inside the chain function's own statement, and a helper
function a chain calls is emitted as PL/pgSQL, so that its plan is kept
between rows. No answer is kept between rows or statements. A row reached
through a chain still costs several times a row its own rule admits; the guide
gives the figures.

On a spec with a chain, a helper bound to the caller (see "Breaking") does not
parse the claims on every call. It remembers the argument it verified and the
exact text of the claims setting, in two transaction-local settings named
`demesne.<definers schema>.<function>.own` and `.seen`, and verifies again
whenever the claims text differs or is empty. A transaction-local setting reads
as empty in the session's later transactions, so an empty claims text is never
taken as the one remembered. A `via conditions` check does the same on
every spec. A generated function that already passes the caller's own claim
calls `<function>_inside`, a copy with no check that PUBLIC cannot run, so a
hop pays nothing for the binding. The copy is `SECURITY INVOKER`: it runs as
the owner of the generated function that calls it, and run directly, under a
grant made by mistake, it reads only what its caller may. `demesne_emit_sql`
gains `Bound` and `Security`, and `GenFn` gains `bound` and `security`.

`demesne_syntax` gains `CompPath`; `ViaComposition` gains `path`, `Object` gains
`nested`, `Builtin` gains `HoldsAt`, and the lexer reads a whole number.
`demesne_model::analysis` gains `Cut`, `CutAt`, `Bounded`, `composition_cut`
and `cut_tree`.

### `nearest … where`, and `@nearest`: a column compared with the nearest value at the caller's node

```demesne
nearest live_skin(id text) via closure paths on folder_id where status = "live"
require view = @claim("folder_id", null) + @nearest(live_skin, skin_id from claim folder_id)
```

`where <column> = "<value>"` on a `nearest` counts only the rows whose column
holds the value. `@nearest(<lookup>, <column> from claim <key>)`, written only
in a `require`, is true of a row whose column equals what the lookup answers at
the node the caller's claim names. It is read live, once a statement. The term
calls `<lookup>_own(<node>)`, emitted when a term asks for it, which answers
only at the caller's own claimed node; the lookup itself stays revoked from
PUBLIC.

`demesne_syntax::Nearest` gains `filter`, and `Builtin` gains `Nearest`.

### Breaking: `<object>_can_<verb>` takes one parameter list, whichever generator makes it

A borrow (`via object <object>-><verb>`) and a `@store_manage` dispatch both
make `<object>_can_<verb>`. The borrow named its parameter `p_<object>_id` and
typed it `text`; the dispatch's copy named it `p_id` and typed it as the
spec's identifiers. A spec that moved between the two failed to apply, since
`CREATE OR REPLACE` cannot rename a parameter, and the migration dropped
nothing, since the function's identity stayed. Both now take
`p_<object>_id`, typed as the spec's identifiers. The SQL drops an earlier copy
whose parameter is named otherwise before it creates the dispatch's, which no
policy calls.

What breaks: on a spec whose identifiers are not `text`, a borrow's function
now takes that type, so it is a new function and a migration drops the `text`
one. So do a grant relation's check (`<acl>_grants…`), a `@kernel` check, a
composition's function, a group's `<closure>_member`, a materialized group's
`<flat>_member` and an undeclared closure's `_reachable`, whose id parameters
were `text` too: a spec with
`identifiers integer` or `uuid` and a grant relation could not be applied
before, since Postgres compares an integer or uuid column with a `text`
parameter only through a cast the SQL did not write. A corpus test now holds
every generated parameter that names an id to the spec's identifier type, and
`testdata/ids` holds an integer and a uuid spec that a live test applies and
judges.

A generated function's parameters are now typed values,
`demesne_emit_sql::Param` with a `ParamKind`, and `GenFn::params` replaces the
`sig` string, which `GenFn::sig()` renders. A parameter that holds an id is
`ParamKind::Id`, and takes the spec's identifier type when the SQL is written,
so no generator can give one another type. The corpus test reads each
function's declared parameters, checks every id against the SQL, and refuses
a parameter whose name says id that its generator declared otherwise. SQL of
your own that names the dispatch copy's argument (`p_id => …`) names
`p_<object>_id` instead.

### A generated function called with the same arguments for every row runs once per statement

A policy or a generated function that calls a generated function with
arguments that are the same for every row now wraps the call in a scalar
subquery, as v1.2.0 did for each claim read:

```sql
(SELECT auth.is_ops((SELECT current_setting('request.jwt.claims', true)::json ->> 'sub')))
```

Such arguments are claims, literals and the calling function's own
parameters. Postgres evaluates the subquery once per statement. The emitter
wraps only calls to the functions it declares `STABLE`, which answer the same
within a statement, and never a call to a `VOLATILE` function. A call that
reads a column of the row stays as it was.

In a policy this changes how often the function runs. These calls ran once
for each row the policy looked at:

- a membership check such as `is_ops`;
- a platform role check, `has_<anchor>_role`;
- `<admin>_memberin_<level>`, and `is_<level>_<admin>` reached by `memberin`;
- `@holds` on a plane above the object's own scope.

On Postgres 17, a filter shaped like such a policy, a membership check ORed
with an owner column over 2000 rows, ran the check 2000 times in 5.5 ms;
wrapped, it runs once in 0.26 ms, and the same rows pass.

In a generated function that answers for one row per call, only the form
changes: `<table>_admits` reuses the policy's predicate, `<store>_manage`
calls each kind's `<object>_can_edit(p_id)`, and a role check
`is_<level>_<admin>` first asks whether its `user_id` is an operator, through
a membership check, where the operator is identified by the same claim (see
the grant entry). Each still runs its call once per call. Over the same 2000
rows, `<store>_manage` called `<object>_can_edit` 2000 times either way.

The policies admit the rows they admitted. The comparison with v1.1.0 sets
these wraps aside as it does the claim reads. A corpus test finds every call
to a generated function that reads claims with arguments fixed for the
statement, and fails if one is left to run per row or if a `VOLATILE`
function is wrapped.

### A worked example: `examples/chains.demesne`

One spec that uses this release's constructs together: a chain whose hops are
judged for the caller, a stored condition, a membership check asked both by
the caller and by the space the caller stands in, and a `nearest … where`
floor. `crates/postgres/tests/chains_example_pg.rs` runs it against Postgres.

### Fixed: a composition under `not` or inside `none` was judged by a lower bound

`member and not parent` asked the same generated function a widening `parent`
asks. That function judges the parent by its own rule with every branch that
needs a composition left out, so it can say "not reached" of a parent the
caller does reach, and the `not` then admitted. A composition that narrows a
rule now calls `<object>_composition_<relation>_upper`, which counts such a
branch as possibly true. The change can only narrow what a spec admits, and a
spec with no composition under `not` or inside `none` emits what it did.

### Fixed: a composition inside an `and` let the parent admit on the other side alone

`via composition` reaches a row because the caller reaches its parent, and the
parent is judged by the object's rule with the composition terms taken out.
Only the composition term itself was taken out. With

```demesne
permission view = owner + (@kind("auditor") and parent) @rls maps select
```

the parent was judged by `owner + @kind("auditor")`, so an auditor read every
row that had a parent, whether or not they could read that parent. The rule as
written admits an auditor to a row only when they reach its parent. A
composition under `not` had the same fault: `member and not parent` judged the
parent by `member`.

Every release since the cascade was added has this: the Go engine from v0.62.1
to v0.93.1, and every Rust release from v0.94.0 to v4.0.0.

The parent is now judged without any branch that needs a composition: the whole
`and` goes, not one side of it. A rule is affected only if it has a composition
relation directly inside an `and` or under a `not`. A rule whose composition
terms are branches of a union, including a union that is one side of an `and`,
emits exactly what it did. The change can only narrow what a spec admits.

To check a spec, look for a `via composition` relation named beside `and` or
after `not` in a permission. The upgrade's migration (see the first
"Breaking" entry) carries the fix, which is in the generated
`<object>_composition_<relation>` functions.

### Fixed: the manifest refused every spec that declares `changelog checked`

`changelog checked` creates each changelog trigger with `CREATE CONSTRAINT
TRIGGER`, and the manifest didn't read that statement. So `demesne emit
manifest`, `demesne emit migrate` and `demesne diff` each refused such a spec
and named the trigger. v4.0.0 has this. The manifest now records a constraint
trigger like any other trigger, a migration drops it with `DROP TRIGGER`, and
`diff` compares it.

A spec in several files that declares it was refused too. Every file after the
first failed on the `ALTER TABLE … ADD COLUMN txid` that the declaration adds
to the changelog table. That statement now goes with the table's own
statement, so a later file writes it only when it writes the table. The SQL
these specs emit as one file doesn't change. `examples/changelog.demesne`
declares one, so the pinned outputs and the corpus tests cover it.

### Fixed: a migration that dropped no function failed to apply

The check a migration runs after its drops, that nothing it dropped is still
present, named its column only in the arm that looks for functions. A
migration that dropped a policy, a trigger or an index and no function failed
with `column "what" does not exist`. Every release from v1.0.0 has this. Each
arm now names the column.

### Fixed: a group's and a closure's triggers ignored `tables schema`

The trigger that rebuilds a group's closure from its edge table, and the one
that keeps an undeclared closure in step with its base table, set their
search path to `pg_catalog, public` and named their tables without a schema.
In a spec that declares `tables schema`, a write to the edge or base table
failed with `relation ... does not exist` where `public` holds no table of
the same name. Where it holds one, the trigger used that table instead: it
wrote `public`'s closure table, which a group's trigger empties and refills
from `public`'s edge table, and the closure in the tables schema missed the
write. Until it is refilled, a closure that missed writes still admits
members removed from the edge or base table since, and refuses members added
since. Every release from v1.0.0 has this. Both now search the tables schema,
as a declared closure's trigger already did; a spec whose tables are in
`public` emits the same SQL. After upgrading, check those tables in `public`
and refill each closure that missed writes: a group's is rebuilt by the next
write to its edge table, and an undeclared closure's trigger trusts the rows
it holds, so refill that one from its base table.

## v4.0.0

The crates are 4.0.0 because public types of `demesne-syntax` and
`demesne-emit-sql` gain fields and variants, named under each change. A spec
that uses none of the constructs below emits exactly what v3.0.0 did. The Go
module's API doesn't change, so it is `go/v1.5.0`.

### A borrowed permission can be asked once a statement

`relation r: s via object space->view on space_id pinned` compiles the borrow
to `(SELECT auth.space_can_view(<space claim>))` where it was
`auth.space_can_view(space_id)`. Postgres evaluates the first once for the
statement and the second for every row. The rows admitted are the same: the
marker is accepted only on a scope column the object's containment holds equal
to the caller's claim, and is refused on a nullable level, on a level a reach
widens for the operation, and inside a `require`.

`demesne_syntax::ViaObject` gains `pinned`.

### `changelog checked`: the application writes the changelog

With `changelog checked`, the triggers generated for `tracked` grants and for
`track owner` and `track visibility` stop writing changelog rows and sending
`NOTIFY`. They become deferred constraint triggers that refuse a commit, with
`check_violation` and `<table>_changelog_written`, when the transaction changed
a tracked source without writing the matching changelog row itself. The
changelog table gains `txid`. Without the declaration the triggers write and
notify as before.

`demesne_syntax::Spec` gains `changelog`, and `ChangelogTrigger` and
`ObjectChangelogTrigger` in `demesne-emit-sql` gain `checked`.

### `probe` asks about rows the caller cannot read

`probe <name>(<column> <type>, ...)` on an object emits a function that answers
whether a row matches the given values inside the caller's containment,
whatever the object's permissions say. `count` answers how many and `key`
answers a matching row's key. The containment comes from the caller's claims
and never from an argument. A probe on an object no claim contains is refused.

`demesne_syntax::Object` gains `probes`, a list of the new `Probe`.

### `@holds` over every value of an array column

`@holds(<permission> every <column> at <level>)` is true when the array column
is not empty and the caller holds the permission at every value in it, each
taken as the scope at the level. Every value must be a row of the object that
declares the level, inside the row's own scope above it. It compiles to a
generated `<admin>_has_perm_every_<level>` function.

`demesne_syntax::Builtin` gains `HoldsEvery`, whose `name()` is `holds_every`.

### `nearest` reads the value declared closest above a node

`nearest <name>(<column> <type>) via closure <closure> on <node column>` on an
object emits `<name>(<node>)`, which returns the column from the nearest row at
or above the node that sets it. The closure must be declared with `depth`. With
a `scope` the object shares, a row naming no node is the fallback for its
scope. `EXECUTE` on the function is revoked from PUBLIC.

`demesne_syntax::Object` gains `nearests`, a list of the new `Nearest`.

### `projection` shows some columns to callers who cannot read the row

`projection <name>(<column> <type>, ...) = <expression>` on an object emits a
function that returns the named columns of the rows the expression admits. The
expression is compiled as an `admit` arm, inside the object's containment and
apart from its permissions, so a caller the read policy hides a row from can
still be shown part of it, by claim and not by database role.

`demesne_syntax::Object` gains `projections`, a list of the new `Projection`.

## v3.0.0

The crates are 3.0.0 because public types of `demesne-syntax`, `demesne-model`
and `demesne-emit-sql` gain fields and variants, listed at the end. A spec that
uses none of the constructs below emits exactly what v2.0.0 did. The Go module's
API doesn't change, so it is `go/v1.4.0`.

### A closure relation reads the edge in the direction it names

`via closure paths(ancestor_id, descendant_id) on folder_id` reaches rows at
the caller's node and beneath it. Written with the columns the other way round,
`paths(descendant_id, ancestor_id)`, a relation is meant to reach rows at the
caller's node and above it. Until now both compiled to the same downward
lookup, with no error.

The order is now honoured: the first column is the caller's side and the second
is the row's. A relation whose columns are not the closure's pair in one order
or the other is refused. The closure's edge is its `closure` declaration (below)
or, without one, the first relation over the table.

One closure has one lookup and one maintenance trigger, and both are built from
that edge. Before, a relation with reversed columns declared first turned the
lookup over for every relation, and a reversed relation carrying the `base`
maintained the closure upside down. Two relations over one closure that name
different bases are refused.

### `closure` declares a closure table once

```demesne
closure paths(ancestor_id, descendant_id)
  base folders(id, parent_id)
  scope space_id
  depth depth
```

A top-level `closure` names the table and which column is the ancestor. Every
option is optional. `named <name>` replaces the table's name at the front of
the functions and triggers generated for it. A spec in several files replaces a
declaration by its table.

Three things follow from declaring a closure.

Relations over it compile to sets. `folder_id IN (SELECT
auth.paths_descendants(<claim>))` reaches downward and `auth.paths_ancestors`
upward, each an uncorrelated subquery that Postgres evaluates once per
statement, where the undeclared form calls `paths_reachable` for every row. One
object can use both directions and give each to different operations: read at
the caller's node, above it and beneath it, and write at the node and beneath.
`paths_reachable` is still generated.

With `depth`, `paths_path(<node>)` returns the node's ancestors and the node,
root first, each with its depth.

With `base`, the generated maintenance is new. It writes the `scope` and
`depth` columns on every pair. It takes
`pg_advisory_xact_lock(hashtext('<closure>'), hashtext(<scope>))` before it
reads or writes the closure, so moves in one scope run one at a time. It
refuses, with `check_violation` and a named constraint, a row made its own
ancestor (`<closure>_acyclic`), a parent the closure does not hold in the row's
scope (`<closure>_parent_known`), and a changed scope column
(`<closure>_scope_fixed`). The update trigger fires only when the parent or the
scope changes.

A relation's own `base` still works and emits the maintenance it always did.

### A reach can read through several grants

`reach descendants via descendants, ancestors for select` takes the subject's
reach through each listed grant, and the list may include the grant itself. The
level's containment term gains one set per grant, joined by OR, so an object
scoped at a tree level is read from above and from beneath at once. One grant
after `via` emits what it did. Each listed grant must be an edge grant at the
level that confers the operations, and none may be listed twice.

### `exact` scopes a level as a partition

```demesne
scoped estate > space exact
```

An `exact` level contains every operation by `space_id IS NOT DISTINCT FROM
<claim>`. A row with a NULL column belongs to the requests that carry no claim
at the level and to no others, and a request that carries one reads and writes
only rows with that value. It is the form a `wildcard` already emits for the
operations its `confers` list leaves out, now available for all of them. The
GUIDE also says what a `wildcard` that confers `insert` lets a session write.

### NULL, absent-claim and exact-level tests

`@row(<column>, null)` is true of a row whose column is NULL. It goes wherever
`@row` goes.

Two tests are for a `require` alone, since neither names anyone a permission
could admit. `@claim("<key>", null)` is true of a request that carries no value
for the claim. `@within(<level> exact)` is true when the row's column at the
level is not distinct from the request's claim.

A `require` now accepts a row test as a branch of a union by itself, negated or
not. A restrictive policy admits nobody, so the branch only exempts rows from
the floor. A `permission` refuses that shape as before.

### What changes for a caller of the crates

- `demesne_syntax::Spec` gains `closures`, a list of the new `Closure`, which
  holds an optional `ClosureBase`. `Object` gains `scope_exact`.
- `demesne_syntax::GrantUse::via` is a list where it was an optional name, and
  `SpecExt::enumerated_grant` is `enumerated_grants`, which returns every grant
  a reader listing follows.
- `demesne_syntax::Builtin` gains the variants `RowNull`, `ClaimAbsent` and
  `WithinExact`. Their `name()` is `row`, `claim` and `within`, and `Term` gains
  `row_null()`, `claim_absent()` and `within_exact()` to tell them apart.
- `Object::scope_is_wildcard` is true for an `exact` level too, since its column
  may be NULL. `scope_is_wildcard_for` is false for every operation there.
- `demesne_emit_sql::ClosureTrigger` gains `declared`, an optional
  `DeclaredMaintenance`.
- `demesne_model::closure` is new: the edge of each closure and the direction
  each relation reads it in.

## v2.0.0

The crates are 2.0.0 because a public struct of `demesne-syntax` gains a field
(below). Nothing else a caller sees changes, and a spec without the new clause
emits exactly what v1.2.1 did. The Go module's API doesn't change, so it is
`go/v1.3.0`; a `go/v2` would move every importer to a new module path.

### A grant class can admit others

A grant relation can say that one access class admits others:
`via grant record_acl(record_id, principal_kind, principal_id, access) read admits write, delete`
makes `grantee:read` admit write and delete grants as well as read ones, so a
caller granted write or delete reads the row it was granted, and its UPDATE or
DELETE, whose WHERE Postgres checks against the select policy, takes effect.

The grant's definer is still one function with the same signature and
strictness; only the class match in its body widens, for a direct grant and for a
group's. No policy changes, and a spec without the clause emits exactly what it
did. Validation refuses a class that admits itself, names a class twice, says
what one class admits on two clauses, or admits a class that admits others,
since admitting is not transitive.

The check that a write term's callers are ones the select permission reaches
counts an admitted class: beside `view = grantee:read`, `edit = grantee:write`
is accepted when read admits write, and still refused when it doesn't.

`demesne_syntax::ViaGrant` gains `admits`, a list of the new `GrantAdmits`. A
caller that builds a `ViaGrant` with a struct literal must add the field.

## v1.2.1

### The crates publish again

v1.2.0 never reached crates.io or npm. Its tests compare the SQL it emits,
and the rows each rule admits, with v1.1.0's, and so `demesne-postgres`
depended on v1.1.0's crates, which crates.io can't hold beside 1.2.0 in one
package. Those tests now live in `demesne-release-check`, a crate that is never
published, and still run on every change. Nothing a caller sees differs from
v1.2.0, which reached only the Go module, as `go/v1.2.0`; 1.2.1 is the first
release of it published everywhere.

## v1.2.0

### Each claim is read once per statement

The SQL emitter now writes every read of the caller's claims as an
uncorrelated scalar subquery, in every policy, definer and point check:

```sql
(SELECT current_setting('request.jwt.claims', true)::json ->> 'sub')
```

where it wrote `(current_setting('request.jwt.claims', true)::json ->> 'sub')`.
Postgres evaluates the subquery once per statement, as an InitPlan, instead of
parsing the whole claims document again for every row a policy looks at, so a
read under row-level security no longer pays for the size of the claims
document once per row. Reads through `claims via` with another setting or cast
change the same way, and so does the identifier read a grant's scopes use,
`(SELECT NULLIF(current_setting(…, true), '')::json ->> …)`.

Every other part of the emitted SQL is byte for byte what v1.1.0 emitted, for
every example spec and every spec in the corpus. Each rule admits the rows it
admitted in v1.1.0: a live test compiles each of those specs that Postgres can
hold with this release and with v1.1.0, lays tables and rows for it, applies
both, and compares the rows every policy's `USING` and `WITH CHECK` admit, the
rows its role sees, and every point check's answers, under a spread of claims:
none at all, an empty set, and sets that give each claim a value of its own,
some of them aimed at a row.

A statement now judges all its rows by the claims as it first reads them. A
function that changes the claims setting part-way through a statement no longer
changes the claims the statement's later rows are judged by.

To pick the change up, apply the regenerated SQL, or the migration
`emit <spec> migrate <manifest>` writes: it recreates every policy and replaces
every definer.

## go/v1.1.1

The Go module only; it embeds the v1.1.0 runtime.

### A hand-built projection with nil fields is read as empty

A projection built in Go with a nil slice or map, such as a `demesne.PDP`
without `Ungoverned` or a `demesne.HoldsResolver` without `ScopeCols`, reached
the runtime as JSON `null`, and the runtime refused it with
`… must be an array of strings`. Each projection type now writes a nil slice
or map as an empty one. The projections `--target go` generates were never
affected, because their JSON always carries every field.

## v1.1.0

### Go applications run the Rust runtime

`demesne emit <spec> --target go <kind> [pkg]` generates Go again, for the new
module `github.com/foir-io/demesne/go`. The module embeds the Rust runtime
compiled to WebAssembly and runs it on wazero, with no cgo, so a Go program
gets the answers the Rust crates and `@foir/demesne` give: CI replays every
case of the runtime oracle through the Go module. The module's version is the
demesne release whose runtime it embeds, tagged `go/vX.Y.Z`.

The kinds are those of `--target ts`. `framework` writes a typed package: a
`Surface` with a check per object and verb, `ListResources` and `CheckMany`,
the holds resolvers, `Caps`, `RoleTiers`, `Check`, and `CheckHandler`, an
`http.Handler`. `projections` (and `all`) writes the projections as Go values
for the lower-level API, and `claims` and `pdp` write the claims contract and
each emit site's policy map. The package is named `authz` unless you name it.
`emit <spec> framework` and `emit <spec> claims` without a target now ask for
`--target ts` or `--target go`.

The generated checks run their SQL through `demesne.Querier`, which
`demesne.FromSQL` makes from `database/sql`. The module under `go/example`
runs the generated packages against a live Postgres in CI, and the Go emitted
for every spec in the corpus is checked to be gofmt-clean and to compile.

### Rust crates

`demesne-emit-go` is new. `demesne_model::framework` holds the plan both
framework emitters follow: which checks an object gets, the caps tree, the
role tiers, and the names that would collide. `demesne_emit_ts::projections::all`
returns every projection a spec has, each with its `Shape`. A projection that
can't be built now reports `projection holdsResolver:` (and so on) where it
said `EmitTS holdsResolver:`.

## v1.0.0


### Breaking: a write that the select permission can't see is refused

Postgres applies an UPDATE or DELETE only to rows the SELECT policies show.
A caller a write permission admits but the select permission doesn't is
matched against no rows, so the statement changes nothing and reports
success. `validate` (and every command that loads a spec) now refuses such a
spec, naming each write term that reaches past select:

```
line 25: permission note.edit maps update, and its term `grantee:write` admits
callers the select permission note.view does not reach; Postgres applies an
UPDATE only to rows the SELECT policy shows, so for those callers it changes
nothing and reports success: …
```

The check compares each write disjunct, its object's subjects' own reach, and
each `admit update`/`admit delete` arm with the select permission, with each
side's `require` applied. A term passes when select reaches every caller it
admits:

- the same term in select, or one the vocabulary says it implies
  (`@holds(records:write)` reaches `@holds(records:read)` when
  `records:write implies records:read`);
- a borrowed write verb (`record->edit`), when the borrowed object's own write
  passes this check against its select;
- a composition's write arm, when its object's other write terms pass.

Terms that select reaches but its `require` refuses are reported together, once
per permission. To keep a write that is meant to run without reading, mark the
permission `blind` (`permission purge = … @rls maps delete blind`): the finding
becomes a warning on stderr, and the spec validates. `blind` on a permission
that doesn't map update or delete under `@rls` is refused.

The check expands each side into alternatives, and stops at 512. A write whose
own predicate, select permission, `require` or subjects' reach expands past
that is refused rather than passed unchecked, and `blind` keeps it as a
warning.

To adopt: reach the writers in the select permission (add the write terms, or
an implication such as `x:write implies x:read`), or mark deliberate blind
writes `blind`. The examples were changed this way: `agnostic` and `example`
reach `grantee:write` and `grantee:delete` in `view`, `manage`, `planes` and
`canonical/rbac` name the write permission in `view`.

### Breaking: the accessor listing names every reader its select admits

`<table>_accessors` used to leave out a select disjunct it couldn't reverse,
so the listing under-reported who can read a row. Every disjunct that admits
callers is now in it:

- **Principals, as rows of `<table>_accessors`:**
  - `@holds(p)`: each assignee whose role grants `p` at the row's scope,
    source `holds`;
  - a role relation, and `@session(role)`: each holder of a role for the
    object's level, source `role`.
- **Conditions, as rows of `<table>_accessors_conditional`** (the object's
  listing becomes conditional, as it did for `@claim`, `mode` and
  `@app_scope`):
  - `@kind("k")`: source `claim`, claim key `kind`, value `k`;
  - `@self(col)`: source `claim`, the identity claim, value the row's `col`;
  - `@session` and `@within(level)`: source `claim`, the level's scope claim,
    value the row's scope column;
  - `@within(level nullable)`: that row, plus one with source `scope` for a
    row whose scope column is NULL (every caller in the row's scope);
  - `@public`: source `public` (every caller).

A select written as a tree (`and`, `not`) that holds one of the principal
terms used to be refused as unenumerable; it now enumerates them.

What adopters see: an object whose select names `@kind`, `@self`, `@session`,
`@within` or `@public` now has `<table>_accessors_conditional` in place of
`<table>_accessors`, and `ResourceAccessSurface` refuses it, as it refuses any
conditional object; read it through `conditional_resource_access_surface` and
decide what each condition means for the caller. Code that switches on
`source` meets `holds`, `role`, `public` and `scope`.

### Breaking: a conditional listing row carries every claim it requires

`<table>_accessors_conditional` had room for one claim per row, in
`via_claim_key` and `via_claim_value`, so a conjunction of conditions kept only
its first claim. `@claim("tier", "gold") and @claim("region", "eu")` listed every
caller with `tier = gold`. A `@kind`, `@session` or `@within` beside a claim, or
beside a `mode`, was dropped. The listing named callers the policy refuses.

The two columns are now `via_claim_keys text[]` and `via_claim_values text[]`.
A row admits a caller whose request carries every key, each with the value at
the same position. Identity rows, and conditional rows that need no claim, have
NULL arrays.

A conjunction of conditions lists one row that carries every `@claim`, `@kind`,
`@session` and non-nullable `@within` in it. A conjunct no row can state is still
dropped, so the listing may over-report and never under-reports: a negation,
`@scoped`, a nullable `@within` or `@holds`. A conjunction of claim-side terms
alone, such as `@kind("admin") and @session`, was refused as unlistable and now
lists its row.

What adopters change:

- Before applying v1's SQL, drop each `<table>_accessors_conditional`: Postgres
  can't change a function's return type with `CREATE OR REPLACE`, refuses, and
  says so.
- Read the two arrays in place of `via_claim_key` and `via_claim_value`, and
  require every pair. A query that names the old columns fails rather than
  reading half an answer.
- In Rust, `demesne_model::ConditionalAdmission` carries `claims: Vec<ClaimMatch>`
  in place of `claim_key`, `claim_val` and `claim_val_col`, and
  `ConditionalExt::conditional_conjunction` takes the object.

### Breaking: `<table>_admits` gives the exact answer, and the listing names candidates

The accessor listing can't state every condition a select policy puts on a
request: the containment every scoped policy starts with, a reach set from a
grant or a closure, an `@external` predicate that takes a claim, or a claim
beside a relation. It named the candidates and left those conditions out, so
nothing answered "can this person read this row?" exactly.

Every object with a listing and a select policy now also gets
`auth.<table>_admits(p_id, p_claims jsonb) → boolean`. It runs the table's own
select policy, `admit` arms included, and its `require view` policy, with
`p_claims` as the request's claims, and puts the caller's claims back when it
returns. Its answer is the database's, for every policy, reach sets and
`@external` included.

- It's emitted with `EXECUTE` revoked from PUBLIC: it answers for any claims,
  so it can probe a row. Grant it to the role your trusted server code uses.
  `demesne diff` reports it as changed when PUBLIC may execute it live.
- `ResourceAccessSurface` gains `admits_fn` and `admits_sql()` (`admitsFn` and
  `admitsSQL` in `@foir/demesne`), which returns
  `SELECT auth.<table>_admits($1, $2::jsonb)`. The runtime refuses a projection
  without `admitsFn`, so regenerate projections made before v1.

The listing changes in three ways:

- A row-side conjunct beside a relation (`@row`, `not @row` or `mode`) used to
  be dropped. It now narrows the listing exactly: `(owner and @row(status,
  "open"))` names the owner only on open rows.
- `@holds` beside a relation narrows the principals of its own store's kind.
  Principals of other kinds stay, so a request that carries two subjects'
  claims is never left out.
- A select `admit` arm was missing from the listing, so a caller only the arm
  admits appeared nowhere. Each arm now adds a conditional row with the `admit`
  source and the claims it states, and an object with one lists through
  `<table>_accessors_conditional`. An arm belongs to the select policy and not
  to the permission, so a `via object` borrow of the permission never reaches
  it. When the arms are all that make the listing conditional, the object also
  gets `<table>_<verb>_accessors`, the permission's readers alone, and a borrow
  lists through it.

What adopters change:

- Apply the new functions, and grant `_admits` only where it's needed.
- Read an object with a select `admit` arm through
  `conditional_resource_access_surface`.
- Treat the listing as the candidates, and ask `_admits` for the exact answer.
- In Rust, `demesne_emit_sql::GenFn` gains `language` and `execute`, so a struct
  literal needs both, or `..Default::default()`.

### Breaking: objects that would overwrite each other's SQL on one table are refused

Two objects on one table that both compile a policy for the same operation
emit two policies with one name (`<table>_select`, say). Each
`DROP POLICY IF EXISTS` and `CREATE POLICY` pair replaced the one before, so
Postgres enforced only the last object's predicate, silently. Two objects that
both `track` one table did the same to their changelog trigger, so only the
last object's changes were logged. Two objects on one table with an `async`
relation of the same name shared an async index name, so the last object's
maintenance functions replaced the others' and filled their indexes from its
grant table. `validate` now refuses all three and names the objects. A table
can still carry several objects when only one of them compiles each policy
and tracks the table, and the rest use `predicate` permissions.

### Breaking: `diff` compares whole definitions, in both directions

`diff` compared only policy names, and only on tables in `public`. A live
policy with the right name and any predicate passed, even `USING (true)`. A
hand-edited or superseded definer passed too, because definers weren't
compared at all. Now `diff` compares the spec's whole SQL with the live
database:

- Policies: command, roles, permissive or restrictive, `USING` and
  `WITH CHECK`.
- Definers and other generated functions: their whole definition, through
  `pg_get_functiondef`.
- Triggers: their whole definition, through `pg_get_triggerdef`.
- Orphans: a policy on a governed table, a function in a definer schema, or a
  trigger calling one, that the spec doesn't generate. After a `migrate`, this
  is the live-to-generated check that nothing was left behind.

Postgres stores expressions in its own form, so each generated object is
created as a temporary copy beside the live one and both are read back as
Postgres prints them. The transaction is then rolled back. `diff` needs the
`TEMP` privilege and a primary database, and it takes no lock on a live table.

Each line names its object's kind, as in `MISSING  policy notes_select on
public.notes`, where the old line read `MISSING  notes.notes_select`. There are
two new kinds:

- `CHANGED`: a live definition differs from the generated one.
- `INVALID`: a generated statement doesn't compile against the live database.

`--allow <file>` lists orphans to leave unreported, such as definers written
by hand, one per line as their `ORPHAN` line names them. An entry that matches
nothing live is reported as `STALE`. `demesne_postgres::drift` replaces
`live_policy_surface` in the Rust API.

### Breaking: `check` looks for schema traps around the governed tables

`check` validated the spec, bound it to the live schema and checked the RLS
role. It now also looks for three traps in the live schema that bypass or
weaken the policies:

- **A view that reads a governed table as its owner.** That is a view without
  `security_invoker = true`, at any depth of views over views, or a
  materialized view. If the owner bypasses RLS, every reader sees every row:
  `check` prints `DANGER` and fails, as it does for a `BYPASSRLS` session role.
  Otherwise it warns, because the policies judge the owner, not the reader.
- **A unique index over a nullable topology or scope column without
  `NULLS NOT DISTINCT`.** Rows where the column is NULL, the shared tier, never
  conflict. Two things count as covering it: a partial unique index on the
  other columns `WHERE col IS NULL`, or a unique index on some of the other
  columns alone, such as the primary key in `(project_id, id)`.
- **A policy comparison whose row column is wrapped** in COALESCE, NULLIF,
  CASE, a cast through text, a function or an operator. The comparison can't
  use an index on the column, so it runs row by row. This is read from each
  policy's stored expression tree, so a bare comparison or a definer call isn't
  flagged, and neither is anything inside a subquery.

demesne's own policies raise none of these. `demesne_postgres::schema_traps`
is the same check in the Rust API.

### Breaking: v1 is Rust and TypeScript; Go stays on v0.93.1

v1 generates no Go and ships no Go module. `demesne emit <spec> claims` and
`demesne emit <spec> framework`, which printed Go, and `--target go` now say so
and point to `--target ts`. The Go code generator is not published as a crate.

The Go engine stays frozen at v0.93.1 on the `release/v0.93` branch, with its
CLI and `pgx` modules, and Go programs keep using it. v1's root `go.mod` holds
no Go code. It retracts v0.94.0 and v1.0.0 through v1.999.999, so `go get -u`
and `@latest` keep Go users on v0.93.1, and it marks the module deprecated with
a pointer to the CLI and `@foir/demesne`. A thin Go layer over the Rust
runtime is planned as its own module.

### Breaking: `@foir/demesne` runs demesne's Rust runtime, compiled to WebAssembly

`@foir/demesne` was an 897-line TypeScript runtime written by hand beside the Go
one, with `goCompat.ts` copying Go's sort and JSON escaping. It now runs
`crates/runtime`, the same Rust runtime Rust adopters link, compiled to
WebAssembly. The hand-written runtime and `goCompat.ts` are gone, so there is
one implementation of every builder.

- **The API is unchanged and still synchronous.** The default entry carries
  the module's bytes and compiles them on import. Cloudflare Workers forbid
  that, so the `workerd` export condition imports the `.wasm` file as a module
  instead.
- **Tested in each environment:**
  - the 716 tests pass in Node, Deno, inside workerd and in headless Chrome;
  - a packed tarball is bundled and run in all three;
  - the example app's live-Postgres round trips pass on top of it.
- **Size:** the module is 179 KB, everything the default entry loads is 95 KB
  gzipped, and the package is 173 KB. A budget on every build holds the first
  two under 200 KB and 105 KB.
- **What changes for callers:**
  - The Go-compatibility helpers `goCmp`, `goSort`, `goEncodeString` and
    `goJSONStringify` are no longer exported.
  - Error messages come from the runtime in Go's words, as in
    `MintClaims: key(s) not in the claims contract: [...]` and
    `BuildClaims: no subject "x" in the spec`. Each keeps the wording after its
    prefix.
  - Permissions and roles sort by UTF-8 bytes, exactly as Go does. The old
    code compared UTF-16 code units, which differs only for characters beyond
    the Basic Multilingual Plane.

For the binding, `demesne-runtime` gains `build_claims` with `Principal`,
`SubjectIdentity` and `LevelClaim`, projection parsers for claims, principals,
the PDP and role assignments, and public `plane_depth`, `within_plane`,
`expand_implications` and `active_predicate`.

### Breaking: a `@self`, `@public` or grant term under `and` or `not` is refused

This is a security fix. A `@self`, `@public` or `via grant` term admits its
callers on its own wherever it is written, so the compiler ignored any `and` or
`not` around it, and the policy was wider than the spec read:

- `owner and @self(actor_col)` compiled as `owner + @self(actor_col)`;
- `not @self(actor_col) and owner` admitted the very callers it reads as
  excluding.

`validate` now refuses such a term anywhere but the permission's top-level
union, and shows what the permission compiled to:

```
line 16: permission invoice.view writes `@self(actor_col)` inside `owner and
@self(actor_col)`, but a @self, @public or `via grant` term admits its callers
on its own wherever it is written, so the permission compiles as `owner +
@self(actor_col)`, wider than it reads: …
```

The Go engine at v0.93.1, and v0.94.0, compile these forms the same way;
earlier Go releases weren't measured. The frozen Go line will not be patched,
so if you wrote a spec for the Go engine, run v1's `validate` over it. No spec
in demesne's corpus uses one of these forms.

### Security: a quote in a spec string can no longer rewrite a policy

A value written as a string in a spec reached the emitted SQL without its
quotes doubled. That covered `@claim`, `@kind`, `@row`, `mode`, a `where` or
`kind` discriminator, a guard, a membership's `active` value and the claims
setting. Only a grant's claim value was escaped. So
`@claim("tier", "x' OR true OR '")` passed `validate` and emitted a policy that
admits every caller, and an apostrophe, as in `"O'Brien"`, broke the SQL.

Every such value now reaches the SQL through `demesne_runtime::quote_literal`,
which quotes as Postgres's `quote_literal` does: each quote is doubled, and a
value holding a backslash is written as `E'…'` with its backslashes doubled, so
it reads the same whatever `standard_conforming_strings` is set to. The
runtime quotes the values in its projections the same way. A `tables schema`
or `definers schema` that isn't a plain identifier is refused, because it lands
where quoting can't help. A spec whose strings hold no quote or backslash emits
exactly what it did.

A test appends a quote, a backslash and quote, and a bare `OR` to every string
in demesne's 373 specs, emits each, and checks that none reaches the SQL outside
a literal under either setting of `standard_conforming_strings`.

The Go engine at v0.93.1 emits the same SQL. With the Go engine, keep `'` and
`\` out of spec strings.

### Breaking: `@scoped` beside an ordinary term is refused

Every ordinary term is already held to the row's scope, so `@scoped` in a
union with one adds no one: `owner + @scoped` compiled to `owner`, though it
reads as "the owner, or anyone in scope". `validate` now refuses it and says
what it compiles to. Write `@scoped` alone to admit every caller in the row's
scope, or drop it. `@scoped and owner` is accepted, and so are
`@scoped + @self(…)` and `@scoped + via grant …`, which compile as written.

### Breaking: the Rust crates return typed errors

Every fallible function in the library crates returned `Result<_, String>`,
so a caller could only branch on the message. Each crate now returns its own
error type. Each one displays exactly the text the `String` held, so the CLI's
output and every message are unchanged.

| Crate | Error | What it tells a caller |
| -- | -- | -- |
| `demesne-syntax` | `Error`, `Finding` | where parsing stopped: `line()` and `message()` |
| `demesne-model` | `Error` | `findings()`: each problem, with its line when it has one |
| `demesne-emit-sql` | `Error`, `ManifestError` | `findings()` from `validate`, and a manifest or SQL it can't read |
| `demesne-emit-go`, `demesne-emit-ts` | `Error` | the spec can't be rendered |
| `demesne-emit-rust` | `Error` | `is_io()`, `is_spec()`, `is_surface()` |
| `demesne-postgres` | `Error` | `is_connection_string()`, `is_connect()`, `is_query()`, `is_sql()` |
| `demesne-runtime` | `Error` | `is_claims()`, `is_consistency()`, `is_vocabulary()`, `is_access()`, `is_capability_gate()` |
| `demesne-gocompat` | `json::ParseError` | malformed JSON |

`validate_warnings` returns `Finding`s. `Structure::Fatal` holds a
`demesne_model::Error` and `Structure::Errors` a `Vec<Finding>`, and the
`SpecExt` and `SurfaceExt` methods return `demesne_model::Error`. The
`demesne-cli` library, which the binary and the WebAssembly build share, keeps
message errors.

To upgrade, use the accessors where you matched on a message, and call
`to_string()` where you need the text.

### Breaking: ten public enums can grow without a major version

These enums are `#[non_exhaustive]`, so a match on one outside its crate needs
a `_` arm:

- `demesne_postgres::DriftKind` and `Severity`, which also displays as
  `DANGER` or `warning`;
- `demesne_emit_sql::Object`;
- `demesne_emit_rust::Surface`;
- `demesne_model::analysis::CostClass`;
- `demesne_runtime::Consistency`, `ConsistencyLevel`, `AffordanceHint`,
  `Freshness` and `AffordanceSource`.

The rest stay exhaustive, so adding a variant to one is a major version:
`demesne_runtime::Decision`, because code that authorizes must handle every
outcome rather than fall into a `_` arm; the syntax tree's enums, because a
grammar addition changes what every consumer of the tree must handle; and
`Structure`, `ReachGrantRef` and `gocompat::json::Value`.

### Breaking: each public Rust item has one path, and the spec traits are sealed

Items that were reachable both at a crate's root and inside a module are now
at the root only:

- `demesne_syntax::ast::*` is `demesne_syntax::*`;
- `demesne_model::analysis::{SpecExt, Principal, ReachGrantRef}`,
  `conditional::{ConditionalExt, ConditionalAdmission}`, and everything in
  `schema`, `surfaces` and `validate` are at `demesne_model::`.

The helper functions stay in `demesne_model::analysis` and
`demesne_model::conditional`. `validate::perm_positive` and
`validate::row_term_admitting` are no longer public, and
`SpecExt::runtime_vocab`, which only called `demesne_model::vocab::to_runtime`,
is removed.

`SpecExt` is sealed: `Spec` is its only implementation, and `SurfaceExt` and
`ConditionalExt` are implemented for every `SpecExt` type, so they are sealed
with it. A minor version can add a method to any of the three. To upgrade,
import from the crate root. A type of your own can no longer implement
`SpecExt`; hold a `Spec` and call the methods on it.

### Breaking: deeply nested input is refused

A permission or requirement whose parentheses nest more than 64 deep is a parse
error on its line. JSON nested more than 128 deep, in the runtime's arguments
or a migration manifest, is refused with Go's message, `invalid character '['
exceeded max depth`. Go allows 10,000 levels; this parser runs out of stack in
WebAssembly well before that.

Both parsers recurse once per level, and nothing stopped them:

- natively, a permission about 5,700 levels deep overflowed the stack and
  aborted the process;
- in WebAssembly, which has no stack guard, the compiler failed at about 1,500
  levels and the runtime at about 50,000, and every later call on that module
  failed too, valid ones included, until it was reloaded.

Real specs nest a few levels, and the runtime's arguments two or three.
`demesne_syntax::MAX_NESTING` and `demesne_gocompat::json::MAX_DEPTH` name the
limits.

### Breaking: runtime and schema calls name their choice instead of taking a `bool`

- `Session::set_role_sql`, `claims_set_sql` and `session_setup_sql` take a
  `SettingLifetime` in place of `local: bool`. `Transaction` is `SET LOCAL`
  and `set_config(…, true)`; `Session` is `SET` and `set_config(…, false)`.
  On a pooled connection, `Transaction` keeps the role and the caller's claims
  from reaching the next caller to use the connection.
- `compose_can(point, pdp)` takes the row's point check as a `Decision`:
  `NotGoverned` when no row check governs the call, otherwise `Allow` or
  `Deny`. The old `point_governed, point_allow` pair could be swapped without
  a compile error, and two of its four combinations meant the same thing. The
  order of the two arguments no longer matters.
- `compose_affordance` takes `IndexAnswer::Allowed` or `IndexAnswer::Denied`.
- `Schema::add_column` takes `Nullability::Nullable` or `Nullability::NotNull`.

The TypeScript runtime and the generated TypeScript are unchanged.

### Breaking: the runtime refuses an argument or projection of the wrong type

`@foir/demesne`'s operations, and the decoders in `demesne_runtime::projection`,
read a missing or mistyped field as empty, `false` or zero. Two of those
readings widened access:

- `composeCan` read a decision it didn't recognise, such as `"DENY"`, as
  ungoverned, so a call the PDP denied came back allowed;
- a PDP projection dropped a procedure whose permission wasn't a string, so the
  procedure read as ungoverned.

Others chose without saying so. A missing `local` chose a connection-wide
`SET ROLE`. A list holding `null`, such as a scope read from a NULL column, lost
that element and shifted the positions after it.

Each operation now throws an error that names the operation and the field, such
as `demesne runtime: holds.scopeContains: assignment must be an array of
strings`, and each decoder returns an error whose `is_input()` is true. Every
field the TypeScript types require is required. A vocabulary's
`implications`, a preset's `level` and a resolver's `plane` are optional, and
`planeDepth` is required beside `plane`. A caller passing what the TypeScript
types declare sees no change. One passing `null` for a NULL scope column
passes `""`, the runtime's wildcard, instead.

In `demesne_gocompat::json`, `Value::entries` and `Value::string_list`, which
skipped what didn't fit, are replaced by `as_object`, `as_strings` and
`as_string_map`, which return `None` instead.

### Migrations drop what a spec stops emitting

`emit all` writes `CREATE OR REPLACE` for the current surface only. So a
definer, policy or trigger that a spec renamed or removed stayed in the
database, still callable and still answering, and nothing generated could see
it. Two new emit kinds close this:

- `demesne emit <spec> manifest` prints a JSON record of everything the SQL
  creates:
  - functions, by identity signature;
  - policies, triggers and indexes, each with its table;
  - tables;
  - the tables it enables RLS on.
- `demesne emit <spec> migrate <manifest.json>` prints `emit all`, then drops
  everything that manifest records and this spec no longer emits:
  - Each drop names its object exactly: a function by its argument types,
    since `DROP FUNCTION IF EXISTS f(text)` does nothing on `f(text, text)`.
  - The order is triggers, policies, indexes, then functions, all after the
    creates, so no retained object still depends on what is dropped.
  - A final check re-queries the catalogs and raises if anything it dropped
    survived, which includes an overload of a dropped function's name. The
    migration then fails whole.
  - Tables are not dropped, as they hold data. RLS stays enabled and forced on
    a table that is no longer governed, so it fails closed. A comment names
    each.

`Sql::manifest`, `Sql::migration` and `Manifest` are the same in the
`demesne-emit-sql` API, and `Sql::write_all_sql` is the `emit all` text.

### A spec can be written in several files

Several `.demesne` files can be compiled as one model, given in order, as in
`demesne validate core.demesne extra.demesne`. Each file may refer to what the
files before it declare. Split where each prefix still validates, a spec emits
what its text emits in one file: a property test splits every valid corpus spec
at each declaration where the prefix validates, and checks that the files emit
the same objects. A spec in one file emits exactly what it did.

- Findings name their file, as in `extra.demesne:12: …`. A spec in one file
  still reports `line 12: …`.
- `emit <files> --file <file>` prints that file's share of the SQL: what its
  prefix adds or changes, then drops of what the prefix before it had. A later
  file that changes a function, such as a `@store_manage` dispatch gaining an
  object, writes it again, and its `CREATE OR REPLACE` replaces the earlier
  body. `--file` takes `all`, `manifest` and `migrate`.
- A later file may write `replace` before a declaration, to take the place of
  an earlier file's declaration of the same kind and name.
- `check`, `diff` and `coverage` take several files too.
- In Rust: `demesne_syntax::parse_files` and `SpecFiles`,
  `demesne_emit_sql::validate_files`, `validate_files_warnings`, `file_sql` and
  `file_migration`, `Finding::file`, and `Builder::spec` in `demesne-emit-rust`.
  The compiler's WebAssembly build gains `diagnostics_files`.

### VS Code validates specs as you type

The VS Code extension had only a grammar. It now runs the compiler, built to
WebAssembly from `crates/wasm`, over each open `.demesne` file after a 200 ms
pause in typing. It underlines every parse and validation error on the line
it names, in `demesne validate`'s words, and shows a valid spec's warnings,
such as a `blind` write. The compiler build gains a `diagnostics` export
returning each finding's severity, line and message as JSON. A spec in several
files is checked as one when the `demesne.specs` setting lists its files, and
each finding shows in the file it names.

### Fixes to behaviour carried over from the Go engine

- **Permission implications under a custom definer schema.** A rolestore
  whose vocabulary has `implies` emitted a holds definer that called
  `auth.<rolestore>_perm_implied_by`, while the function itself was created
  in the declared definer schema. Without an `auth` schema the call failed;
  with one, it could reach another spec's function. It now calls the function
  the SQL creates. A new test re-emits every corpus spec under a custom
  definer schema and checks every call to a generated function names it.
- **Accessor refusals name the real definer schema.** The two refusals for a
  select permission whose readers can't be listed named
  `auth.<table>_accessors` whatever the definer schema was.
- **Definers are created after the functions they call.** They were written
  in spec order, so when an object borrowed from one written later in the
  spec, its listing came before the function it calls, and Postgres refused
  the SQL with `function … does not exist`. Each generated function now
  follows every generated function it calls, and SQL with no such call keeps
  its order. A new test checks this for every corpus spec.
- **Breaking: multi-host URLs follow libpq.** Each host keeps its own port. A
  host without one takes the default port (`PGPORT`, or 5432), and an empty
  host takes the default host. Two cases change:
  - A URL whose last host had no port, such as `postgres://h1:5432,h2/db`,
    was refused. It now connects.
  - A host without a port borrowed the first port given. So
    `postgres://h1,h2,h3:5009/db` put all three hosts on 5009, and now puts
    only `h3` there.

  IPv6 hosts can be listed too. A single `port=` in keyword/value form still
  serves every host.
- **A `min_protocol_version` the server can't meet is refused by name.** The
  message read `server protocol version too low: %!w(<nil>)`.
- The example app's Supabase golden is labelled `supabase.demesne`, not
  `roundtrip.demesne`.

### Output order no longer depends on Go's sort

Lists in the output (policies, triggers, async indexes, field grants and
scaffold levels) are ordered by an explicit total order, each with a
tie-breaker on a unique key, instead of by a reproduction of Go's unstable
`sort.Slice`. The order differed only when two entries tied, and every tie a
valid spec could reach was one of the overwrites above, so no valid spec's
output changes. `demesne-gocompat` no longer carries the sort.

### Validation messages show each term as written

A term in an error message is printed as the spec writes it, with its
arguments: `@claim("tier", "gold")`, `@kind("member")`, `@session(workspace)`,
`@app_scope(exclude owner)` and `mode visibility = "open"`, where earlier
messages printed `@claim`, `@kind`, `@session`, `@app_scope` and nothing for
a `mode` term.

## v0.94.0

### The compiler, CLI and runtime are Rust, and their output is unchanged

demesne is now a Cargo workspace under `crates/`: the parser, model and
validation, the SQL, Go and TypeScript emitters, the runtime, the Postgres
support and the CLI. Every output is byte-identical to v0.93.1: the SQL
(definers, policies, enablement, triggers, closure, changelog, async, require
and the Supabase profile), the emitted Go and TypeScript, both framework
modules, `oracle.json` and the claims contract. That was checked over every
example, every spec the Go test suites parse and 10,800 fuzzed
specs, and the runtime passes `oracle.json`.

The Go engine stays at v0.93.x. It is the full Go library for anyone who uses
it, and the reference the Rust build is diffed against.

### `demesne` and `@foir/demesne-cli` run the Rust binary

The release binaries and the five `@foir/demesne-cli` platform packages carry
the Rust CLI. Its seven subcommands print what the Go CLI printed, including
the connection errors for every case tested (refused, unknown host, timeout,
missing database, wrong password, certificate checks). A connection string
means what it meant to pgx: the
`PG*` environment, `.pgpass`, service files, every listed host in order, and
libpq's `sslmode` rules, so `prefer` (the default) and `require` encrypt
without checking the certificate, and `verify-ca` and `verify-full` check it.

What changes:

- Release archives are named `demesne-cli-<target>.tar.gz` (`.zip` on
  Windows), each with a `.sha256` beside it and all of them in `sha256.sum`,
  instead of `demesne_<version>_<os>_<arch>.tar.gz` and `checksums.txt`. The
  Linux binaries are static.
- To build from source, run `cargo build --release -p demesne-cli`, or
  `cargo install demesne-cli`.
- A client key in the legacy encrypted PEM format (`DEK-Info`, decrypted with
  `sslpassword`) is refused with a message that says so. Decrypt it, or use
  PKCS#8.

### Rust crates

- `demesne-runtime`: the holds resolver, the access, grant and
  role-assignment surfaces, claims, sessions and the PDP, with no parser.
- `demesne-emit-rust`: compiles a spec into Rust tables from `build.rs`, for
  only the surfaces a crate names. Nothing is parsed at runtime, and a spec
  error fails the build.
- `demesne-syntax`, `demesne-model`, `demesne-emit-sql`, `demesne-emit-go` and
  `demesne-emit-ts`: the compiler, as libraries.
- `demesne-postgres` and `demesne-cli`: live-database support and the CLI.

### The compiler runs as WebAssembly

`demesne-wasm` builds the compiler for `wasm32-unknown-unknown`. `run` is the
CLI's `validate` and `emit` over in-memory files, byte-identical to the
native binary, and `validate` checks one spec, for editors and the TypeScript
packages.

## v0.93.1

### The TypeScript runtime lists a conditional surface's claim columns

A resource-access surface whose read admits a claim lists, beside each
principal, the claim key and value a row is reached by. The Go builder selected
`via_claim_key` and `via_claim_value` on such a surface and the TypeScript
`accessorsSQL` did not, so the two disagreed on that surface and the emitted
projection did not typecheck against the runtime's types. The surface now
carries `accessorsConditional`, and `accessorsSQL` selects the claim columns
when it is set, as the Go builder does.

### The npm packages are published again

`@foir/demesne` and the `@foir/demesne-cli` packages were last published at
0.89.0: the token the release used to publish them stopped working, so 0.90.0
to 0.93.0 exist as Go module tags and GitHub releases but not on npm. Releases
now publish to npm through npm's trusted publishing, from this repository's
release workflow with no stored token, and each version is staged for a
maintainer to approve before it is installable. 0.93.1 is the first version
published this way.

### Release notes keep a commit's `@` words out of mentions

A commit subject that names a builtin, such as `@row`, went into the release
notes as written, and GitHub read it as a mention of the account with that
name. A subject that contains `@` is now set as code in the notes.

## v0.93.0

### A composition definer is one statement per access

A composition definer answers read, write and delete. It was one SQL
statement that chose between the three with `CASE p_access`. Postgres plans a
SQL function's statement without knowing its arguments, so every plan held all
three access checks, and a policy that calls the definer for each row planned
all three again in every statement that read the table.

It is now PL/pgSQL with an arm per access:

```sql
#variable_conflict use_column
BEGIN
  IF p_access = 'read' THEN
    RETURN EXISTS (SELECT 1 FROM edges e WHERE e.child_id = p_doc_id AND EXISTS (...the parent's read check...));
  END IF;
  IF p_access = 'write' THEN
    RETURN EXISTS (...);
  END IF;
  IF p_access = 'delete' THEN
    RETURN EXISTS (...);
  END IF;
  RETURN false;
END
```

Each arm is a statement of its own, so its plan holds one access's check and
is kept for the session. The signature, the policies that call it and the
answer for every access are unchanged. An access with no arm, and a null one,
answer false as before. `#variable_conflict use_column` keeps SQL's rule that a
column name wins over a parameter of the same name.

Measured on Postgres 17 on a table whose rows borrow their readability from a
parent: a read that checked 150 rows took 13.1 ms with the single statement and
7.9 ms with the arms.

It also matters on Postgres 18, which caches a SQL function's plan across
calls. With the `CASE` the cached plan is always dearer than one made for the
call's arguments, so Postgres 18 planned the statement again on every call: the
same read took 77.5 ms, against 13.4 ms on Postgres 17 on the same machine. With
the arms and strict definers it takes 6.3 ms on Postgres 18 and 6.4 ms on 17.

### A definer whose every argument is compared to a column is STRICT

A policy passes a claim to a definer, and a claim can be absent. When every
argument of a definer is equal to a column in a conjunct of every branch of its
body, a null argument can only answer false or no rows, so the definer is now
`STRICT` and Postgres skips the call instead of planning and running it.

That covers grant edges and their reach and set forms, the unscoped ladder,
cross-object `_can_<verb>` and `_can_edit` definers, closure reachability,
membership flags and composition definers. A scoped probe (`_reach_in_<level>`)
tests its scope argument for absence and is not strict.

A strict definer answers null where it answered false. Every emitted predicate
reads a definer's answer through AND, OR, `IS NOT TRUE` or a `CASE` condition,
and a policy admits a row only when its predicate is true, so null and false
admit the same rows everywhere the floor reads them.

On the same read on Postgres 17, with the arms: 5.7 ms with strict definers,
against 7.9 ms without.

## v0.92.0

### A transient set: a claim that lists several values

A transient subject is identified by one value: the owner a write is made for,
the one row a request acts on. `transient set` declares a subject whose claim
holds a JSON array, and a relation to it admits a row whose column is any
element. It is for the case where one request has the same standing over
several values of a column and no other.

```demesne
subject curator { anchor tenant reach self identifies curates roles none transient set }
relation curated: curator via category
permission view = owner + curated   @rls maps select
```

The relation compiles to `category = ANY(ARRAY(SELECT e FROM
jsonb_array_elements_text(<curates claim>::jsonb) e))`, with each element cast
to the identifier type where one is declared. The array is read once for a
statement. The claim is read as an array whether it was minted as one or as
its text in a string.

No claim and an empty array admit nothing. A claim that is not an array fails
the statement, so a set minted wrongly is never read as empty or as everything.
A `null` element matches no row.

The accessor listing reports it as it reports any transient subject: a
conditional row keyed on the claim and valued from the row's column.

Validation holds a set to everything a transient subject is held to, and
refuses a relation that names a set beside another subject. `set` is read only
after `transient`.

A one-value transient subject compiles as it did.

### `@row`: narrow a term to rows with a value

`@row(<column>, "<value>")` is true of a row whose column holds the value. It
tests the row and names nobody, so it is written inside an `and`, beside a term
that grants, and narrows that term:

```demesne
permission view = owner + (member and not @row(owner_kind, "customer"))   @rls maps select
```

It compiles to `<column> = '<value>'`, and negated to `(<column> = '<value>')
IS NOT TRUE`, which is true of a row whose column is NULL.

Until now the only term that tested a row was `mode`, and `mode` is the
object's visibility: its column is what `track visibility` records and its
values are the visibilities the access surface accepts. A spec that used it to
test another column moved both to that column. `@row` reads any column and
changes neither.

Validation refuses a row term wherever it would admit a caller by itself: as a
branch of a union, as the only term, and inside an `and` with no term that
grants. It is legal in a `require` on the same rule. The accessor listing drops
it beside a relation, and anchors a conditional row on it exactly.

## v0.91.0

### A transient subject: a claim that stands for one request

`subject <name> { ... transient }` declares a subject the adopter mints for one
request rather than a principal that exists between requests: a caller the
application has already judged may write a row belonging to someone else
carries that owner in a claim for the one transaction, and a relation to the
transient subject admits rows whose column equals the claim.

```demesne
subject delegate { anchor tenant reach self identifies acting_for roles none transient }
relation acting_for: delegate via owner_id where owner_kind = "member"
permission create = owner + acting_for   @rls maps insert
```

The policy compiles as any column relation does: `owner_id = <acting_for claim>
AND owner_kind = 'member'`, inside the object's containment. What changes is
the accessor listing. A relation to a standing subject lists the principal the
column names; a transient subject is nobody who could be listed, so its
relation contributes a conditional row instead, keyed on the claim and valued
from the row: `('claim', NULL, NULL, 'read', 'acting_for', owner_id)`. Listed as
a principal, it named the row's owner a second time under a kind no caller
recognises.

Validation refuses a transient subject that holds roles, binds a plane,
reaches beyond itself or is identified via a membership, and a relation that
mixes it with standing subjects or reaches it through anything but a column.

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

This bit the first real spec with two rolestores. One vocabulary backed a
rolestore, and a second, a scope set for API keys, backed nothing. The two
shared several permission names, because they named the same actions on the
same data at different planes. Adding a second rolestore made `@holds` on one of
those permissions fail to compile at existing sites that were correct and
unchanged.

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
