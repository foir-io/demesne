# Demesne

An authorization engine that compiles to Postgres Row-Level Security.

Demesne takes Zanzibar's declarative relationship schema but drops its runtime:
no separate authorization service, no check-API round-trip, no consistency
tokens. One platform-agnostic spec compiles into the two places authorization
has to live:

1. Layer 1, Postgres Row-Level Security. The compiler emits the `pg_policies`
   that decide which rows a principal can reach. Authorization runs inside the
   database, on every query, for every client, with no way around it: a
   forgotten `WHERE` clause in application code cannot leak data the RLS policy
   already forbids. This is the moat.
2. Layer 2, an application Policy Decision Point (PDP). The compiler emits the Go
   capability map that decides which verbs a principal may invoke (the RPC →
   permission table), plus the public-API scope gate.

From the same spec it derives the JWT claims contract (which claims the policies
read) and the complete `SECURITY DEFINER` kernel. Every trusted SQL function the
emitted policies call is generated, so the isolation proof has no opaque
hand-written function to trust.

A spec describes a topology (a linear containment chain, e.g. `tenant → project`), the
subjects that act in it, the objects they act on, and the relations and
permissions that connect them. This includes a first-class access descriptor (owner,
per-record mode, and an app-managed grant store) that subsumes ad-hoc record
sharing.

## Status — what's live today

Demesne is the source of truth for the authorization layer. An adopting
application no longer hand-authors policies or the PDP map:

- A generator (`cmd/gen` in your repo) reads the spec and writes the admin
  PDP maps + the JWT claims contract as committed Go, and the idempotent
  `CREATE OR REPLACE FUNCTION` + `DROP/CREATE POLICY` set as a goose migration.
  The migration applies that SQL; a spec change emits a new migration (goose
  migrations are immutable, so changes supersede rather than edit history).
- Every emitted `USING`/`WITH CHECK` and `SECURITY DEFINER` body is the same
  expression the differential oracle verified against `pg_policies` /
  `pg_get_functiondef`, so switching to the generated set is a proven
  byte-for-byte no-op: a fresh DB with the generated migration matches a
  hand-written set.

The oracle still runs, but with generation as the source of truth its
generated-vs-live comparison is now (correctly) a convergence / no-drift check rather than a
fidelity-to-hand-written gate. The real semantic gate is forward isolation, proving
the emitted policies actually isolate, in two halves:

- the engine's template-level V7 property test (this module, `isolation_test.go`):
  the §6.2 scope-column model fails closed between siblings and grants
  unconditional reach only to a virtual-anchored subject, independent of the
  emitted SQL, no database;
- an adopter's SQL-level forward-isolation gate (where the DB is,
  `demesne_isolation_test.go`): it seeds sibling tenants + customers + records of
  every access mode and drives real principals against the LIVE generated
  policies, asserting tenant / project / owner / operator-grant (incl. expired) /
  public-mode / app-scope / write isolation all hold.

Demesne owns the idempotent policy + definer + closure-trigger + RLS
enablement layer. `EnablementSQL` emits `ENABLE`/`FORCE ROW LEVEL SECURITY` per
governed table; a policy is inert without it. Tables, columns, indexes, and
`GRANT`s remain hand-written migrations.

## Known limitations

The engine is policy-agnostic in shape. The original single-deployment
assumptions are now spec-declared parameters: the claims accessor (`claims via`),
the definer schema (`definers schema`), the descriptor mode vocabulary
(`private` / `read "<sentinel>"` / `list "<kind>"`), the owner principal kind
(the grant + realtime-gate signatures name the spec's own owner principal), the
owner/admin plane bindings (`binds owner|admin`, explicit rather than
shape-inferred), and the role-definer affixes (derived from the admin plane's
name, `is_<level>_<admin>` / `<admin>_has_<obj>_role`, so a spec whose admin
plane is named `staff` gets `is_tenant_staff`, not a baked `admin`).

That generalization also lifts the topology beyond linear. Levels form a DAG: a
branching tree (multiple children) and multi-parent levels (`parents A, B`, whose
object containment is a sargable OR of per-lineage predicates). Unbounded-depth
hierarchies are expressible with `via closure`, where the compiler generates a
trigger-maintained transitive-closure table + an indexed reachability lookup (the
RLS-native Leopard index; its write-amplification is an explicit, opt-in cost class).

What remains:

- Second claim-bearing owner principal. A descriptor's owner resolves a single
  claim-bearing principal (plus the no-claim app/service plane); a record owned
  by two distinct claim-bearing principals isn't modelled (no spec needs it — deliberately not built).
- Multi-parent subjects/roles. Multi-parent is confined to object containment; a
  subject or role at a multi-parent level fails closed (its pinned columns would
  be ambiguous) rather than picking a lineage.

## This module is pure

`github.com/eidestudio/demesne` depends on the standard library only. It
parses a spec to an AST, validates it (rules V1–V10, including a generative
sibling-isolation property), and emits SQL / Go / the claims contract. It never
touches a database.

The product CLI (`cmd/demesne`) is a separate module so this purity holds:
only the CLI links a Postgres driver, for its live-database subcommands
(`introspect` / `scaffold` / `check` / `diff`). It introspects `information_schema`
into the engine's plain-data `Schema` and hands it in; the engine still never
opens a connection. See [GUIDE.md](GUIDE.md) for adopting Demesne on your own
database (`scaffold → edit → check → emit → apply → diff`), plus the runtime glue
(`MintClaims` / `PDP.Authorize` / `PointCheckSQL`).

The strongest possible test of a security generator is differential equivalence: apply the
generated artifacts to a real database in a rolled-back transaction, read back
`pg_policies` / `pg_get_functiondef`, and assert the live objects equal the
generated ones byte-for-byte. That oracle, along with an adopter's actual spec
and its generated migrations, lives in the adopter's repo, where the database is.
This module's own tests prove the language and the emitter mechanics on synthetic
specs; see [`examples/example.demesne`](examples/example.demesne) for one complete
worked instance.

## Usage

```go
import "github.com/eidestudio/demesne"

spec, err := demesne.Parse(src)        // text → AST
err = demesne.Validate(spec)           // V1–V10

rls, err := spec.EmitRLS()             // Postgres RLS policies (Layer 1)
pdp, err := spec.EmitPDP()             // Go capability maps (Layer 2)
defs, err := spec.EmitDefiners()       // the SECURITY DEFINER kernel
claims, err := spec.ClaimsContract()   // the JWT claims the policies read
```

## The spec language

See [`examples/example.demesne`](examples/example.demesne) for a fully worked spec (a fictional document app). In brief:

| Block | Declares |
| --- | --- |
| `topology` | the linear level chain; a `virtual` root has no scope column |
| `vocabulary` | permissions + `preset`s (`@ level`) + a `rank` ladder |
| `rolestore` | where role assignments live → generates the role definers |
| `subject` | who acts: anchor level, reach (`self`/`descendants`/`via grant <name>`), identifying claim, membership or configurable roles |
| `grant` | `grant <name> at <level> via edge <table>(grantee_col, level_col) [active <col>] [expires <col>]` — a level-scoped reachability grant store: an edge whose rows confer reach into a topology level. The general form of "a relationship grants access" (a `descriptor`'s grants confer reach to one object row; a `grant` confers it to a whole level subtree). Compiles to a `SECURITY DEFINER` `EXISTS` that is both a disjunct of the level's role definer and a top-level branch on objects under that level — a scoped, revocable, expiring operator in place of an unconditional god-flag |
| `object` | a governed table: relations + permissions (`@rls` / `@pdp` / `@kernel`), and an optional `descriptor` (owner + mode + grants) |
| `procedures` / `ungoverned` | the RPC → permission map for the PDP emit-site |

Each permission names the layer(s) it compiles to (`@rls`, `@pdp`, `@kernel`) and,
for RLS, the SQL command it maps to (`select`/`insert`/`update`/`delete`).

## Canonical examples — the spec, not the SQL

The hard patterns from the Zanzibar / Keto literature are each a few lines of `.demesne` that
compile to the RLS you would otherwise hand-write (and get subtly wrong). Each ships with a
test asserting the emitted policy actually encodes the reachability — running proof, not prose:

| Pattern | Spec | Compiles to |
| --- | --- | --- |
| Folder → document inheritance (unbounded nesting) | [`inheritance.demesne`](examples/canonical/inheritance.demesne) | a `SECURITY DEFINER` reachability lookup over a trigger-maintained transitive-closure table — a viewer of any ancestor folder can read the document |
| Groups of groups (transitive membership) | [`groups.demesne`](examples/canonical/groups.demesne) | a group-closure check — membership flows through nested groups |
| Role-based access control | [`rbac.demesne`](examples/canonical/rbac.demesne) | role-resolution definers + the rank ladder (viewer / editor / owner) gating `select` vs `update` |
| `viewer ∩ member − banned` (boolean algebra) | [`boolean.demesne`](examples/canonical/boolean.demesne) | one RLS predicate intersecting viewer and member and excluding the banned set |

Proof: `go test . -run TestCanonical` (see the `canonical_*_test.go` files).

## How it compares

Demesne is a Zanzibar-class ReBAC model whose enforcement compiles into Postgres RLS rather
than a runtime Check service. See [CAPABILITIES.md](CAPABILITIES.md) for a capability
matrix and an honest comparison against Zanzibar, Ory Keto, OpenFGA, Cerbos, and Oso.

## Development

```sh
go build ./...
go vet ./...
go test ./...
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
