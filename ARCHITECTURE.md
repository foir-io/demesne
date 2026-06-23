# How Demesne works

Demesne lets you write your authorization rules once and have Postgres enforce them on every query. You describe your tenancy and access rules in one declarative spec. The compiler turns that spec into the trusted SQL functions and Row-Level Security (RLS) policies the database applies automatically, plus a thin app-layer check for the permissions RLS can't express.

This is the Zanzibar idea — a declarative schema of who-relates-to-what — without the separate authorization service. The relationships Demesne reasons over are your existing domain tables: foreign keys, junction or edge tables, role assignments. There is no separate tuple store and no dual-write.

This document explains the model from the inside: how a spec maps to SQL, what each construct costs to evaluate, how it compares to Zanzibar systems, and how a request flows through the generated policies. If you want to adopt Demesne on a real database, start with [GUIDE.md](GUIDE.md); this is the conceptual companion.

---

## 1. The mental model

One declarative file is your policy. The compiler turns it into three things that ship together: the database enforcement layer, the app-layer check for verbs, and the runtime glue that carries claims into each request. The diagram below shows that fan-out and where each piece lands.

```
                    ┌─────────────────────────────────────────────┐
                    │            app.demesne  (the spec)           │
                    │  topology · subjects · objects · relations · │
                    │  permissions · vocabularies · descriptors    │
                    │      ONE declarative file = your policy      │
                    └───────────────────────┬─────────────────────┘
                                             │  demesne compile  (CLI / library)
                       ┌─────────────────────┼──────────────────────┐
                       ▼                     ▼                      ▼
         ┌──────────────────────┐ ┌────────────────────┐ ┌───────────────────┐
         │   DATABASE LAYER     │ │   APP / PDP LAYER   │ │   RUNTIME GLUE    │
         │   (the moat)         │ │  (verbs RLS can't   │ │                   │
         │ • SECURITY DEFINER   │ │   see: publish,     │ │ • claims contract │
         │   functions  auth.*  │ │   execute, …)       │ │ • MintClaims      │
         │ • RLS policies       │ │ • Policy map        │ │ • ClaimsSetSQL    │
         │ • ENABLE/FORCE RLS   │ │   proc → permission │ │ • PointCheckSQL   │
         └──────────┬───────────┘ └─────────┬──────────┘ └─────────┬─────────┘
                    │ goose migration        │ linked into the app  │
                    ▼                        ▼                      ▼
         ┌────────────────────────────────────────────────────────────────────┐
         │                         POSTGRES  +  YOUR APP                        │
         │  every query the app runs is filtered by RLS using the request's    │
         │  claims; the DATABASE itself is the decision point — no Check RPC,   │
         │  no separate tuple store, no dual-write, no consistency lag.         │
         └────────────────────────────────────────────────────────────────────┘
```

The database layer is the moat: the part of the system an unguarded query path can't get around, because the policy lives on the data itself. The app-layer check handles permissions that aren't about rows, such as "can this user publish?". The runtime glue mints the JWT claims a session carries and sets them on the connection so the policies can read them.

---

## 2. How it models any multi-tenant app

A tenancy and authorization model breaks down into a handful of declarative primitives. The point of this section is that each primitive compiles to a known SQL shape with a known cost, so you can reason about performance from the spec alone.

Every primitive lands in one of three cost classes:

- **Inline**: a sargable column comparison (`x = claim`). The planner uses your indexes. Cheapest.
- **Definer**: a `SECURITY DEFINER EXISTS(...)` over an edge or role table. One indexed subquery.
- **Closure**: a trigger-maintained transitive-closure table plus an indexed lookup. Cheap to read, costly to write, and opt-in.

The table below lists each construct, the SQL it compiles to, and its cost class.

```
WHAT YOU DECLARE                          WHAT IT COMPILES TO              COST
───────────────────────────────────────  ──────────────────────────────  ───────
topology { level org > team > project }   AND-chain of scope columns      Inline
  the containment hierarchy (tree / DAG)    project_id = claim ∧ team … ∧ …
  level <x> virtual → a plane ABOVE
  tenancy (a platform / global plane)

subject <s> { anchor <lvl> reach <r> }    which claim identifies the        —
  WHO acts (user / customer / staff):       actor; how far it reaches
  anchor = where it sits in the tree        (self | descendants | grant)
  reach  = how far down it sees

object <o> { table T  scoped <path> }      RLS policies on table T           —
  a governed table

relation … via <repr>   ← the EDGES, each a cost-classed reachability:
  via <fk_col>           owner / parent column      col = claim         Inline
  via role               a role assignment          is_<role>(…) EXISTS Definer
  via edge   E(a,b)      an ACL / junction table    auth.E(…) EXISTS    Definer
  via memberin L(p,s)    "holds a role at scope L"  memberin(…) EXISTS  Definer
  via object  O->verb    borrow another object's    O_can_<verb>(id)    Definer
                         permission  (tuple→userset)
  via closure C base B   unbounded-depth hierarchy  reachable(…)+trigger Closure
  via group   C edge E   nested groups (DAG)        member(…)  +trigger  Closure

permission p = a + b           union        (∪)  →  A OR B
             = a and b         intersection (∩)  →  A AND B
             = a and not b     exclusion    (∖)  →  A AND (B) IS NOT TRUE   (fail-closed)
             = content:publish @pdp   capability  →  app-layer PDP  (RLS can't see verbs)

descriptor { owner … ; mode … ; grants via edge … }   ← the per-record ACL primitive
  owner-origination  +  public/private modes  +  a principal-kinded grant list
```

Together these cover the whole space: single- or multi-level tenancy, multi-parent DAGs, owner and ACL sharing, roles, nested groups, cross-object borrowing, unbounded hierarchies, boolean composition, and a platform or global plane above tenancy.

---

## 3. Demesne vs. the Zanzibar-inspired systems

Zanzibar systems — Google Zanzibar, SpiceDB/AuthZed, OpenFGA, Ory Keto — keep a central relation-tuple store and answer a runtime `Check` RPC by walking the tuple graph. Demesne keeps the same expressive model but compiles the decision into the database and reads the relationships in place. The table below puts the two side by side, row by row, so you can see where the design diverges.

```
            ZANZIBAR-STYLE (SpiceDB / OpenFGA / Keto)     DEMESNE
            ─────────────────────────────────────────     ───────────────────────────────

POLICY      a schema  +  a CENTRAL tuple store            one .demesne spec, compiled
                                                          (no tuple store at all)

"WHO IS     tuples  object#relation@subject,              your EXISTING domain tables:
 RELATED"   written to the authz store — you              FK columns, junction/edge tables,
            DUAL-WRITE (domain DB + authz DB)             role_assignments. read in place,
                                                          NO dual-write

DECISION    RUNTIME:  app → Check(obj,rel,user)           COMPILE-TIME → Postgres RLS.
            the service walks the graph per call          the DB decides on EVERY query,
                                                          automatically. no RPC.

BYPASS      only code that CALLS Check is guarded;        AMBIENT: even a raw SQL query as
            a direct DB query is unprotected              the app role is RLS-filtered

CONSISTENCY Zookies / snapshot tokens to dodge the        none needed — authz reads the SAME
            "new enemy" problem (the store can lag)       rows in the SAME txn as the query

REWRITES    computed_userset · tuple_to_userset ·         roles · via object/closure/group ·
            userset_rewrite (∪ ∩ ∖)                       boolean algebra (∪ ∩ ∖)

NESTED      Leopard index (precomputed flattening)        Closure cost class
GROUPS                                                    (trigger-maintained closure table)

REACH       any datastore, language-agnostic, its         Postgres-specific (that IS the moat);
            own scaling tier                              predicates must be SQL-expressible;
                                                          no extra service to run or scale
```

Because enforcement is RLS, authorization rides every query, including ad-hoc ones, and can't be forgotten or bypassed. There is no second source of truth to keep consistent, and no `Check` service on the hot path. The trade-off: Demesne is Postgres-bound, and every rule must be expressible as a SQL predicate.

---

## 4. From spec to running database, then to a live request

This section follows the spec through two phases. At build time the CLI introspects your schema, validates the spec, and emits the SQL. At request time Postgres applies the generated policy to each query using the caller's claims. The diagram traces both phases end to end.

```
  ══════════════ BUILD TIME   (demesne CLI / library) ══════════════════════════

  $ demesne introspect  --dsn $DATABASE_URL      read information_schema → Schema
  $ demesne scaffold    --from-schema            infer a starter spec from the FK graph
        … you edit app.demesne  (this is your policy) …
  $ demesne validate    app.demesne              V1–V11 semantic checks (bounded emitter:
                                                 never emits weaker SQL than you wrote)
  $ demesne check       --dsn $DATABASE_URL      ValidateAgainst: every table/column exists
  $ demesne emit        app.demesne              → definers.sql + policies.sql + PDP + claims
  $ demesne diff        --dsn $DATABASE_URL      generated == live pg_policies?  (the oracle)

  emit produces:
     auth.<fn>(…)  SECURITY DEFINER         the trusted EXISTS kernel (compiler owns 100%)
     CREATE POLICY … USING(<predicate>)     one per (table, operation)
     ALTER TABLE … ENABLE / FORCE RLS       (a policy is inert until enabled+forced)
     Policy{ proc → permission }            the app-layer PDP map (verb gate)
     ClaimsContract{ keys… }                the claims the policies read
            │
            ▼   goose migration  (idempotent; the diff-oracle proves generated == live)
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  POSTGRES   tables + auth.* definers + RLS policies  (ENABLED + FORCED)     │
  └──────────────────────────────────────────────────────────────────────────┘

  ══════════════ REQUEST TIME ══════════════════════════════════════════════════

   incoming request  (a principal: user / customer / staff  +  an operation)
        │
        │ 1.  spec.MintClaims(values)        → { sub, org_id, project_id, … }   (claims contract)
        │ 2.  PDP.Authorize(proc, claims)    → Allow | Deny | NotGoverned       (verb gate, app)
        │        only for verbs RLS can't express: publish ≡ update, execute, …
        ▼
   BEGIN;  SET LOCAL ROLE app;  SELECT set_config('request.jwt.claims', <blob>, true);
        │ 3.  ClaimsSetSQL(…) sets the GUC the policies read
        ▼
   SELECT … FROM documents WHERE …;          ← your ordinary application query
        │ 4.  Postgres applies the RLS USING predicate, reading the claims:
        │        owner_id = sub  OR  auth.doc_acl(sub, documents.id, 'read')
        │        AND project_id = claim  AND org_id = claim
        ▼
   only the rows the principal may see are returned.        ← the DB IS the decision point
   COMMIT;
```

A few details the diagram leans on:

- The validation steps run V1 through V11, a numbered set of semantic checks. The emitter is bounded: it never emits SQL weaker than what you wrote.
- `demesne diff` is the oracle that compares the generated output against the live database. It proves the policies in Postgres match what the compiler emitted, byte for byte.
- The app role is a non-`BYPASSRLS` role. System and bootstrap paths use a separate `BYPASSRLS` pool. The only way to read a governed table on the request path is through the policy.

---

## 5. One relationship, end to end

This worked example shows the whole pipeline at the smallest scale: one rule in the spec, the RLS predicate it generates, and what happens when a query runs. The rule:

> *"A document is visible to its owner, to platform staff, or to anyone it's been
> shared with — and only ever within its own org+project."*

```
  SPEC                                       GENERATED RLS  (USING on documents_select)
  ─────────────────────────────────────      ─────────────────────────────────────────────
  object document {                          (   auth.has_platform_role(sub)            ← staff
    table  documents                             OR owner_id = (claims->>'user_id')      ← owner   (Inline)
    scoped org > project                         OR auth.doc_acl(sub, documents.id,      ← share   (Definer)
    descriptor {                                            'read')
      owner  user via owner_id               )
      grants via edge doc_acl(doc,user,acc)  AND project_id = (claims->>'project_id')     ← containment
    }                                        AND org_id     = (claims->>'org_id')           (Inline)
    permission view = @descriptor
                      @rls maps select
  }

  RUNTIME:  SELECT * FROM documents;   →   Postgres injects the predicate above using the
            caller's claims and returns exactly the documents they may read.
            No application authz code. No Check RPC. No tuple store.
```

Each change to the rule is one spec line that recompiles into the same kind of RLS predicate, in a known cost class, with the diff oracle proving the live database matches. For example: change `+ staff` to `and not banned`, add `via group team_members(...)` for team sharing, or add `via closure folder_tree(...)` for inherited folder permissions.

---

## 6. Limitations

Two modelling boundaries are worth stating plainly, because they shape what you can express:

- **A descriptor owner resolves to a single claim-bearing principal.** Each governed record has one owning principal, identified by one claim. A record owned jointly by two distinct claim-bearing principals is not modelled. Co-ownership has to be expressed through a grant list or a shared role, not through two owners.
- **Multi-parent is confined to object containment.** A DAG with more than one parent is supported for objects in the containment hierarchy. A subject or a role sitting at a multi-parent level is not: rather than pick one lineage to follow, the model fails closed and grants nothing through that path.
