# Demesne

**An RLS-compiled ReBAC + topology authorization engine.**

Demesne borrows Zanzibar's best idea — a declarative relationship schema — and
rejects its runtime. There is no separate authorization service to call, no
check-API round-trip, no consistency tokens. Instead, Demesne compiles **one**
platform-agnostic spec into the two places authorization actually has to live:

1. **Layer 1 — Postgres Row-Level Security.** The compiler emits the `pg_policies`
   that decide *which rows a principal can reach*. Authorization runs **inside the
   database**, on every query, for every client, with no way around it. This is
   the moat: a forgotten `WHERE` clause in application code cannot leak data the
   RLS policy already forbids.
2. **Layer 2 — an application Policy Decision Point.** The compiler emits the Go
   capability map that decides *which verbs a principal may invoke* (the RPC →
   permission table), plus the public-API scope gate.

From the same spec it also derives the **JWT claims contract** (which claims the
policies read) and the complete **`SECURITY DEFINER` kernel** — every trusted SQL
function the emitted policies call is *generated*, so the isolation proof has no
opaque hand-written function to trust.

A spec describes a **topology** (a linear containment chain — e.g. `tenant →
project`), the **subjects** that act in it, the **objects** they act on, and the
**relations + permissions** that connect them — including a first-class **access
descriptor** (owner + per-record mode + an app-managed grant store) that
subsumes ad-hoc record sharing.

## Status — what's live today

Demesne is the **source of truth** for the authorization layer (EID-252 Phase B,
complete). The platform no longer hand-authors policies or the PDP map:

- A generator (`cmd/gen` in the platform) reads the spec and writes the admin
  PDP maps + the JWT claims contract as committed Go, and the idempotent
  `CREATE OR REPLACE FUNCTION` + `DROP/CREATE POLICY` set as a goose migration.
  The migration applies that SQL; a spec change emits a new migration (goose
  migrations are immutable, so changes supersede rather than edit history).
- Because every emitted `USING`/`WITH CHECK` and `SECURITY DEFINER` body is the
  same expression the differential oracle verified against `pg_policies` /
  `pg_get_functiondef`, the cutover was a proven byte-for-byte **no-op** (fresh
  DB with the generated migration == the prior hand-written set).

The oracle still runs, but with generation as the source of truth (EID-265 WS1)
its generated-vs-live comparison is now (correctly) a **convergence / no-drift**
check, not a fidelity-to-hand-written gate. The real semantic gate is **forward
isolation** — proving the emitted policies actually isolate — in two halves:

- the engine's **template-level** V7 property test (this module, `isolation_test.go`):
  the §6.2 scope-column model fails closed between siblings and grants
  unconditional reach only to a virtual-anchored subject — independent of the
  emitted SQL, no database;
- the platform's **SQL-level** forward-isolation gate (where the DB is,
  `demesne_isolation_test.go`): it seeds sibling tenants + customers + records of
  every access mode and drives real principals against the LIVE generated
  policies, asserting tenant / project / owner / operator-grant (incl. expired) /
  public-mode / app-scope / write isolation all hold.

Tables, columns, indexes, `ENABLE ROW LEVEL SECURITY` and `GRANT`s remain
hand-written migrations; Demesne owns only the idempotent policy + definer + PDP
+ claims layer.

## Known limitations

The engine is policy-agnostic in shape. The original single-deployment
assumptions have been lifted into spec-declared parameters (EID-265 WS2): the
claims accessor (`claims via`), the definer schema (`definers schema`), the
descriptor mode vocabulary (`private` / `read "<sentinel>"` / `list "<kind>"`),
the owner principal kind (the grant + realtime-gate signatures name the spec's
own owner principal), the owner/admin plane bindings (`binds owner|admin`,
explicit rather than shape-inferred), and the role-definer affixes (derived from
the admin plane's name — `is_<level>_<admin>` / `<admin>_has_<obj>_role` — so a
spec whose admin plane is named `staff` gets `is_tenant_staff`, not a baked
`admin`). What honestly remains:

The topology is no longer linear (EID-265 WS3): levels form a **DAG** — a
branching tree (multiple children) and multi-parent levels (`parents A, B`, whose
object containment is a sargable OR of per-lineage predicates) — and
unbounded-depth hierarchies are expressible with `via closure`, where the
compiler generates a trigger-maintained transitive-closure table + an indexed
reachability lookup (the RLS-native Leopard index; its write-amplification is an
explicit, opt-in cost class). What honestly remains:

- **Second claim-bearing owner principal.** A descriptor's owner resolves a
  single claim-bearing principal (plus the no-claim app/service plane); a record
  owned by two *distinct* claim-bearing principals isn't modelled (no spec needs
  it — deliberately not built).
- **Multi-parent subjects/roles.** Multi-parent is confined to object
  containment; a subject or role at a multi-parent level fails closed (its pinned
  columns would be ambiguous) rather than picking a lineage.

## This module is pure

`github.com/eidestudio/demesne` depends on the **standard library only**. It
parses a spec to an AST, validates it (rules V1–V10, including a generative
sibling-isolation property), and emits SQL / Go / the claims contract. It never
touches a database.

The product CLI (`cmd/demesne`) is a **separate module** so this purity holds:
only the CLI links a Postgres driver, for its live-database subcommands
(`introspect` / `scaffold` / `check` / `diff`). It introspects `information_schema`
into the engine's plain-data `Schema` and hands it in — the engine still never
opens a connection. See [GUIDE.md](GUIDE.md) for adopting Demesne on your own
database (`scaffold → edit → check → emit → apply → diff`), plus the runtime glue
(`MintClaims` / `PDP.Authorize` / `PointCheckSQL`).

That is deliberate. The strongest possible test of a security generator is
**differential equivalence**: apply the generated artifacts to a real database
in a rolled-back transaction, read back `pg_policies` / `pg_get_functiondef`, and
assert the live objects equal the generated ones byte-for-byte. That oracle —
along with a platform's actual spec and its generated migrations — lives in the
*platform* repo, where the database is. Verification belongs where it can run.
This module's own tests prove the **language and the emitter mechanics** on
synthetic specs; see [`examples/example.demesne`](examples/example.demesne) for
one complete, annotated worked instance.

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

See [`examples/example.demesne`](examples/example.demesne) for a fully worked,
commented spec (a fictional document app). In brief:

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

## Development

```sh
go build ./...
go vet ./...
go test ./...
```
