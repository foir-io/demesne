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

## This module is pure

`github.com/eidestudio/demesne` depends on the **standard library only**. It
parses a spec to an AST, validates it (rules V1–V10, including a generative
sibling-isolation property), and emits SQL / Go / the claims contract. It never
touches a database.

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
| `subject` | who acts: anchor level, reach (`self`/`descendants`), identifying claim, membership or configurable roles |
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
